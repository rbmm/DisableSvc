#include "stdafx.h"

_NT_BEGIN

#include "impersonate.h"
#include "sd.h"

volatile const UCHAR guz = 0;
const TOKEN_PRIVILEGES tp_ctp = { 1, { { { SE_CREATE_TOKEN_PRIVILEGE   }, SE_PRIVILEGE_ENABLED } } };

const SID LocalSystemSid = {
	SID_REVISION, 1, SECURITY_NT_AUTHORITY, { SECURITY_LOCAL_SYSTEM_RID }
};

struct SID6 : public SID {
	DWORD SubAuthority[6];
};

const SID6 TrustedInstallerSid = {
	{ 
		SID_REVISION, SECURITY_SERVICE_ID_RID_COUNT, SECURITY_NT_AUTHORITY, { SECURITY_SERVICE_ID_BASE_RID } 
	},
	{ 
		SECURITY_TRUSTED_INSTALLER_RID1, 
			SECURITY_TRUSTED_INSTALLER_RID2, 
			SECURITY_TRUSTED_INSTALLER_RID3, 
			SECURITY_TRUSTED_INSTALLER_RID4, 
			SECURITY_TRUSTED_INSTALLER_RID5, 
	}
};

EXTERN_C NTSYSCALLAPI NTSTATUS NTAPI NtCreateToken(
	_Out_ PHANDLE  	TokenHandle,
	_In_ ACCESS_MASK  	DesiredAccess,
	_In_opt_ POBJECT_ATTRIBUTES  	ObjectAttributes,
	_In_ TOKEN_TYPE  	TokenType,
	_In_ PLUID  	AuthenticationId,
	_In_ PLARGE_INTEGER  	ExpirationTime,
	_In_ PTOKEN_USER  	User,
	_In_ PTOKEN_GROUPS  	Groups,
	_In_ PTOKEN_PRIVILEGES  	Privileges,
	_In_opt_ PTOKEN_OWNER  	Owner,
	_In_ PTOKEN_PRIMARY_GROUP  	PrimaryGroup,
	_In_opt_ PTOKEN_DEFAULT_DACL  	DefaultDacl,
	_In_ PTOKEN_SOURCE  	TokenSource 
	);

HRESULT GetLastHrEx(BOOL fOk)
{
	if (fOk)
	{
		return S_OK;
	}
	ULONG dwError = GetLastError();
	NTSTATUS status = RtlGetLastNtStatus();
	return RtlNtStatusToDosErrorNoTeb(status) == dwError ? HRESULT_FROM_NT(status) : HRESULT_FROM_WIN32(dwError);
}

NTSTATUS SetTrustedToken(PSID Sid)
{
	NTSTATUS status;
	PVOID stack = alloca(guz);
	PVOID buf = 0;

	union {
		ULONG GroupCount;
		ULONG rcb;
	};
	ULONG cb = 0;

	struct {
		PTOKEN_GROUPS ptg; // must be first
		PTOKEN_DEFAULT_DACL ptdd;
	} s;

	void** ppv = (void**)&s.ptdd;

	static const ULONG rcbV[] = {
		sizeof(TOKEN_GROUPS)+0x80, // must be first
		sizeof(TOKEN_DEFAULT_DACL)+0x40,
	};

	static TOKEN_INFORMATION_CLASS TokenInformationClassV[] = { 
		TokenGroups, 
		TokenDefaultDacl, 
	};

	ULONG n = _countof(TokenInformationClassV);

	BEGIN_PRIVILEGES(tp, 7)
		LAA(SE_CREATE_TOKEN_PRIVILEGE),
		LAA(SE_BACKUP_PRIVILEGE),
		LAA(SE_RESTORE_PRIVILEGE),
		LAA(SE_SECURITY_PRIVILEGE),
		LAA(SE_TAKE_OWNERSHIP_PRIVILEGE),
		LAA(SE_CHANGE_NOTIFY_PRIVILEGE),
		LAA(SE_IMPERSONATE_PRIVILEGE),
	END_PRIVILEGES	

	HANDLE hToken;

	if (0 <= (status = NtOpenThreadToken(NtCurrentThread(), TOKEN_QUERY|TOKEN_QUERY_SOURCE, FALSE, &hToken)))
	{
		do 
		{
			TOKEN_INFORMATION_CLASS TokenInformationClas = TokenInformationClassV[--n];

			rcb = rcbV[n], cb = 0;

			do 
			{
				if (cb < rcb)
				{
					cb = RtlPointerToOffset(buf = alloca(rcb - cb), stack);
				}

				status = NtQueryInformationToken(hToken, TokenInformationClas, buf, cb, &rcb);

			} while (status == STATUS_BUFFER_TOO_SMALL);

			if (0 > status)
			{
				NtClose(hToken);
				return status;
			}

			*(ppv--) = buf, stack = buf;

		} while (n);

		// reserve stack space for extend groups
		alloca(sizeof(SID_AND_ATTRIBUTES));

		PSID_AND_ATTRIBUTES Groups = s.ptg->Groups - 1;
		PTOKEN_GROUPS ptg = CONTAINING_RECORD(Groups, TOKEN_GROUPS, Groups);
		ptg->GroupCount = (GroupCount = s.ptg->GroupCount) + 1;

		Groups->Sid = Sid;
		Groups->Attributes = SE_GROUP_ENABLED|SE_GROUP_ENABLED_BY_DEFAULT|SE_GROUP_OWNER;

		if (GroupCount)
		{
			do 
			{
				if (((++Groups)->Attributes & (SE_GROUP_INTEGRITY|SE_GROUP_INTEGRITY_ENABLED)) == (SE_GROUP_INTEGRITY|SE_GROUP_INTEGRITY_ENABLED))
				{
					static const SID_IDENTIFIER_AUTHORITY LabelAuthority = SECURITY_MANDATORY_LABEL_AUTHORITY;
					if (*RtlSubAuthorityCountSid(Sid = Groups->Sid) == 1 &&
						!memcmp(RtlIdentifierAuthoritySid(Sid), &LabelAuthority, sizeof(SID_IDENTIFIER_AUTHORITY)))
					{
						*RtlSubAuthoritySid(Sid, 0) = SECURITY_MANDATORY_SYSTEM_RID;
					}
					break;
				}
			} while (--GroupCount);
		}

		NtClose(hToken);

		const static TOKEN_USER tu = {{const_cast<SID*>(&LocalSystemSid)}};
		const static TOKEN_OWNER to = {const_cast<SID*>(&LocalSystemSid)};
		const static LUID AuthenticationId = SYSTEM_LUID;
		const static LARGE_INTEGER ExpirationTime = { MAXULONG, MAXLONG };
		const static TOKEN_SOURCE ts = {{ '*', 'S', 'Y', 'S', 'T', 'E', 'M', '*' }};

		if (0 <= (status = NtCreateToken(&hToken, TOKEN_ALL_ACCESS, 
			const_cast<POBJECT_ATTRIBUTES>(&oa_sqos), TokenImpersonation, 
			const_cast<PLUID>(&AuthenticationId), const_cast<PLARGE_INTEGER>(&ExpirationTime), 
			const_cast<PTOKEN_USER>(&tu), ptg, const_cast<PTOKEN_PRIVILEGES>(&tp), 
			const_cast<PTOKEN_OWNER>(&to), (PTOKEN_PRIMARY_GROUP)&to, s.ptdd, const_cast<PTOKEN_SOURCE>(&ts))))
		{
			status = NtSetInformationThread(NtCurrentThread(), ThreadImpersonationToken, &hToken, sizeof(hToken));
			NtClose(hToken);
		}
	}

	return status;
}

#define GLOBALROOT L"\\\\?\\globalroot"
#define SYSTEM32 GLOBALROOT L"\\systemroot\\system32\\"

HRESULT UtilMan(_In_ WLog& log, _In_ WCHAR c, _In_ PCWSTR FileName, _In_opt_ PCWSTR szCopy = 0)
{
	ULONG FileNameLength = (ULONG)wcslen(FileName) * sizeof(WCHAR);

	PWSTR psz = (PWSTR)alloca(sizeof(SYSTEM32) + FileNameLength);

	int len = swprintf_s(psz, _countof(SYSTEM32) + FileNameLength / sizeof(WCHAR), SYSTEM32 L"%s", FileName);

	if (0 > len)
	{
		return STATUS_INTERNAL_ERROR;
	}

	UNICODE_STRING ObjectName;
	OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, &ObjectName };
	RtlInitUnicodeString(&ObjectName, psz + _countof(GLOBALROOT) - 1);

	HANDLE hFile;
	IO_STATUS_BLOCK iosb;
	NTSTATUS status = NtOpenFile(&hFile, DELETE, &oa, &iosb, 0, FILE_NON_DIRECTORY_FILE);

	log(L"open(%wZ)=%x\r\n", &ObjectName, status);
	if (0 > status) log[HRESULT_FROM_NT(status)];

	if (0 <= status)
	{
		PFILE_RENAME_INFORMATION fri = (PFILE_RENAME_INFORMATION)alloca(sizeof(FILE_RENAME_INFORMATION) + FileNameLength);

		fri->ReplaceIfExists = TRUE;
		fri->RootDirectory = 0;
		fri->FileNameLength = FileNameLength;

		PWSTR fFileName = fri->FileName;
		wcscpy(fFileName, FileName);
		*(WCHAR*)RtlOffsetToPointer(fFileName, FileNameLength - sizeof(WCHAR)) = c;

		status = NtSetInformationFile(hFile, &iosb, fri, sizeof(FILE_RENAME_INFORMATION) + FileNameLength, FileRenameInformation);

		NtClose(hFile);

		log(L"rename(%.*s)=%x\r\n", FileNameLength / sizeof(WCHAR), fFileName, status);
		if (0 > status) log[HRESULT_FROM_NT(status)];

		if (0 <= status && szCopy)
		{
			len = (int)wcslen(szCopy);

			PWSTR lpExistingFileName = (PWSTR)alloca(sizeof(SYSTEM32) + len * sizeof(WCHAR));

			len = swprintf_s(lpExistingFileName, _countof(SYSTEM32) + len, SYSTEM32 L"%s", szCopy);

			if (0 > len)
			{
				return STATUS_INTERNAL_ERROR;
			}

			status = GetLastHrEx(CopyFileW(lpExistingFileName, psz, TRUE));

			log(L"[%x]: %s -> %s\r\n", status, lpExistingFileName + _countof(SYSTEM32) - 1, psz + _countof(SYSTEM32) - 1);
			if (0 > status) log[status];
		}
	}

	return status;
}

#define SERVICES L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\"

void DisableService(_In_ WLog& log, _In_ PCWSTR lpServiceName)
{
	WCHAR sz[0x100] = SERVICES;

	UNICODE_STRING ObjectName;
	OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, &ObjectName, OBJ_CASE_INSENSITIVE };

	if (!wcscpy_s(sz + _countof(SERVICES) - 1, _countof(sz) - _countof(SERVICES) + 1, lpServiceName))
	{
		RtlInitUnicodeString(&ObjectName, sz);
		HANDLE hKey;

		NTSTATUS status = ZwOpenKey(&hKey, KEY_READ|KEY_WRITE, &oa);

		log(L"open key(%s)\r\n", lpServiceName);

		if (0 > status)
		{
			log[HRESULT_FROM_NT(status)];
		}
		else
		{
			KEY_VALUE_PARTIAL_INFORMATION kvpi;
			STATIC_UNICODE_STRING_(Start);
			status = ZwQueryValueKey(hKey, &Start, KeyValuePartialInformation, &kvpi, sizeof(kvpi), &kvpi.TitleIndex);

			log(L"query(%s)=%x {%x}\r\n", lpServiceName, status, *(ULONG*)kvpi.Data);
			if (0 > status) log[HRESULT_FROM_NT(status)];

			if (0 > status || kvpi.Type != REG_DWORD || kvpi.DataLength != sizeof(ULONG) || 
				SERVICE_DISABLED != *(ULONG*)kvpi.Data)
			{
				static const ULONG d = SERVICE_DISABLED;
				status = ZwSetValueKey(hKey, &Start, 0, REG_DWORD, const_cast<ULONG*>(&d), sizeof(d));
				log(L"set(%s)=%x {%x}\r\n", lpServiceName);
				if (0 > status) log[HRESULT_FROM_NT(status)];
			}
			NtClose(hKey);
		}
	}
}

PCWSTR GetStateName(ULONG dwCurrentState)
{
	switch (dwCurrentState)
	{
	case SERVICE_STOPPED: return L"STOPPED";
	case SERVICE_START_PENDING: return L"START_PENDING";
	case SERVICE_STOP_PENDING: return L"STOP_PENDING";
	case SERVICE_RUNNING: return L"RUNNING";
	case SERVICE_CONTINUE_PENDING: return L"CONTINUE_PENDING";
	case SERVICE_PAUSE_PENDING: return L"PAUSE_PENDING";
	case SERVICE_PAUSED: return L"PAUSED";
	}

	return L"?";
}

ULONG ChangeServiceOwner(_In_ WLog& log, _In_ SC_HANDLE hSCManager, _In_ PCWSTR lpServiceName)
{
	ULONG dwError;

	if (SC_HANDLE hService = OpenServiceW(hSCManager, lpServiceName, WRITE_OWNER ))
	{
		const static SECURITY_DESCRIPTOR sd = {SECURITY_DESCRIPTOR_REVISION, 0, 0, const_cast<SID*>(&LocalSystemSid) };

		dwError = BOOL_TO_ERROR(SetServiceObjectSecurity(hService, DACL_SECURITY_INFORMATION, const_cast<SECURITY_DESCRIPTOR*>(&sd)));
		log(L"SetDacl(%s)=%u\r\n", lpServiceName, dwError)[dwError];

		CloseServiceHandle(hService);
	}
	else
	{
		dwError = GetLastError();
		log(L"Open[wo](%s)=%u\r\n", lpServiceName, dwError)[dwError];
	}

	return dwError;
}

BOOLEAN ChangeServiceAccess(_In_ WLog& log, _In_ SC_HANDLE hSCManager, _In_ PCWSTR lpServiceName)
{
	ULONG dwError;

	BOOL b = FALSE;
__0:
	if (SC_HANDLE hService = OpenServiceW(hSCManager, lpServiceName, READ_CONTROL|WRITE_DAC ))
	{
		PVOID stack = alloca(guz);
		union {
			PVOID buf;
			PSECURITY_DESCRIPTOR lpSecurityDescriptor;
		};

		ULONG cb = 0, rcb = 0x100;
		do 
		{
			if (cb < rcb)
			{
				cb = RtlPointerToOffset(buf = alloca(rcb - cb), stack);
			}

			dwError = BOOL_TO_ERROR(QueryServiceObjectSecurity(hService, DACL_SECURITY_INFORMATION, lpSecurityDescriptor, cb, &rcb));

		} while (dwError == ERROR_INSUFFICIENT_BUFFER);

		if (dwError == NOERROR)
		{
			dwError = ERROR_NOT_FOUND;

			BOOLEAN bpresent, bDefaulted;
			PACL Dacl;
			NTSTATUS status = RtlGetDaclSecurityDescriptor(lpSecurityDescriptor, &bpresent, &Dacl, &bDefaulted);
			
			if (0 <= status && bpresent && Dacl)
			{
				if (USHORT AceCount = Dacl->AceCount)
				{
					union {
						PACCESS_ALLOWED_ACE pAce;
						PACE_HEADER pHead;
						PVOID pv;
						PBYTE pb;
					};

					pv = ++Dacl;

					do
					{
						if (pHead->AceType == ACCESS_ALLOWED_ACE_TYPE)
						{
							if (RtlEqualSid(&pAce->SidStart, const_cast<SID*>(&LocalSystemSid)))
							{
								pAce->Mask |= SERVICE_CHANGE_CONFIG|SERVICE_STOP;

								dwError = BOOL_TO_ERROR(SetServiceObjectSecurity(hService, DACL_SECURITY_INFORMATION, lpSecurityDescriptor));
								break;
							}
						}

					} while (pb += pHead->AceSize, --AceCount);
				}
			}
		}

		if (dwError)
		{
			log(L"QueryDacl(%s)=%u\r\n", lpServiceName, dwError);
			log[dwError];

			// D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)
			//DACL:
			//T FL AcessMsK Sid
			//A 00 000201FD [S-1-5-18] 'NT AUTHORITY\SYSTEM'
			//A 00 000F01FF [S-1-5-32-544] 'BUILTIN\Administrators'
			//A 00 0002018D [S-1-5-4] 'NT AUTHORITY\INTERACTIVE'
			//A 00 0002018D [S-1-5-6] 'NT AUTHORITY\SERVICE'
			//SACL:
			// NULL
			static const UCHAR bSd[] = {
				0x01,0x00,0x04,0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				0x14,0x00,0x00,0x00,0x02,0x00,0x5c,0x00,0x04,0x00,0x00,0x00,0x00,0x00,0x14,0x00,
				0xfd,0x01,0x02,0x00,0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x05,0x12,0x00,0x00,0x00,
				0x00,0x00,0x18,0x00,0xff,0x01,0x0f,0x00,0x01,0x02,0x00,0x00,0x00,0x00,0x00,0x05,
				0x20,0x00,0x00,0x00,0x20,0x02,0x00,0x00,0x00,0x00,0x14,0x00,0x8d,0x01,0x02,0x00,
				0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x05,0x04,0x00,0x00,0x00,0x00,0x00,0x14,0x00,
				0x8d,0x01,0x02,0x00,0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x05,0x06,0x00,0x00,0x00,
			};

			dwError = BOOL_TO_ERROR(SetServiceObjectSecurity(hService, DACL_SECURITY_INFORMATION, (PSECURITY_DESCRIPTOR)bSd));
			log(L"SetDacl(%s)=%u\r\n", lpServiceName, dwError);
			log[dwError];
		}

		CloseServiceHandle(hService);
	}
	else
	{
		dwError = GetLastError();
		log(L"Open[wd](%s)=%u\r\n", lpServiceName, dwError);
		log[dwError];

		if (!b && dwError == ERROR_ACCESS_DENIED)
		{
			b = TRUE;
			if (!ChangeServiceOwner(log, hSCManager, lpServiceName))
			{
				goto __0;
			}
		}
	}

	return dwError == NOERROR;
}

BOOLEAN SetTokenForService(_In_ LSA_LOOKUP& ll, _In_ WLog& log, _In_ SC_HANDLE hSCManager, _In_ PCWSTR lpServiceName)
{
	ULONG dwError;

	if (SC_HANDLE hService = OpenServiceW(hSCManager, lpServiceName, READ_CONTROL))
	{
		PVOID stack = alloca(guz);

		union {
			PVOID buf;
			PSECURITY_DESCRIPTOR lpSecurityDescriptor;
		};

		ULONG cb = 0, rcb = 0x100;
		do 
		{
			if (cb < rcb)
			{
				cb = RtlPointerToOffset(buf = alloca(rcb - cb), stack);
			}

			dwError = BOOL_TO_ERROR(QueryServiceObjectSecurity(hService, 
				DACL_SECURITY_INFORMATION|LABEL_SECURITY_INFORMATION|OWNER_SECURITY_INFORMATION, 
				lpSecurityDescriptor, cb, &rcb));

		} while (dwError == ERROR_INSUFFICIENT_BUFFER);

		if (dwError == NOERROR)
		{
			dwError = ERROR_NOT_FOUND;

			ll.DumpSecurityDescriptor(lpSecurityDescriptor);

			BOOLEAN bpresent, bDefaulted;
			PACL Dacl;
			NTSTATUS status = RtlGetDaclSecurityDescriptor(lpSecurityDescriptor, &bpresent, &Dacl, &bDefaulted);

			if (0 <= status && bpresent && Dacl)
			{
				if (USHORT AceCount = Dacl->AceCount)
				{
					union {
						PACCESS_ALLOWED_ACE pAce;
						PACE_HEADER pHead;
						PVOID pv;
						PBYTE pb;
					};

					pv = ++Dacl;

					do
					{
						if (pHead->AceType == ACCESS_ALLOWED_ACE_TYPE)
						{
							if ((pAce->Mask & (SERVICE_CHANGE_CONFIG|SERVICE_STOP)) == (SERVICE_CHANGE_CONFIG|SERVICE_STOP))
							{
								if (0 > (status = SetTrustedToken(&pAce->SidStart)))
								{
									log(L"SetTrustedToken=%x\r\n", status)[HRESULT_FROM_NT(status)];
									dwError = RtlNtStatusToDosErrorNoTeb(status);
								}
								else
								{
									dwError = NOERROR;
								}
								break;
							}
						}

					} while (pb += pHead->AceSize, --AceCount);
				}
			}
		}

		CloseServiceHandle(hService);
	}
	else
	{
		dwError = GetLastError();
		log(L"Open[r](%s)=%u\r\n", lpServiceName, dwError);
		log[dwError];
	}

	return dwError == NOERROR;
}

void DisableAndStopServices(_In_ LSA_LOOKUP& ll, _In_ WLog& log, _In_ SC_HANDLE hSCManager, _In_ const PCWSTR lpServiceNames[])
{
	ULONG _t = GetTickCount();

	HANDLE hOriginalToken = 0;
	BOOLEAN hOriginalTokenValid = FALSE;
	switch (NtOpenThreadToken(NtCurrentThread(), TOKEN_IMPERSONATE, TRUE, &hOriginalToken))
	{
	case STATUS_NO_TOKEN:
	case STATUS_SUCCESS:
		hOriginalTokenValid = TRUE;
		break;
	}

	while (PCWSTR lpServiceName = *lpServiceNames++)
	{
		ULONG t = GetTickCount() - _t;

		log(L"\r\n[%u.%u] ============== %s ==============\r\n", t / 1000, t % 1000, lpServiceName);

		BOOLEAN bTokenSet = FALSE;
		ULONG dwError;
		BOOL SecondTry = FALSE;
__0:
		if (SC_HANDLE hService = OpenServiceW(hSCManager, lpServiceName, SERVICE_CHANGE_CONFIG|SERVICE_STOP ))
		{
			SERVICE_STATUS ss;

			dwError = BOOL_TO_ERROR(ControlService(hService, SERVICE_CONTROL_STOP, &ss));

			log(L"STOP(%s)=%u (%s: %x, %x) %u(%x)\r\n", lpServiceName, dwError, 
				GetStateName(ss.dwCurrentState), ss.dwCheckPoint, ss.dwWaitHint, 
				ss.dwWin32ExitCode, ss.dwServiceSpecificExitCode)[dwError];
			
			dwError = BOOL_TO_ERROR(ChangeServiceConfigW(hService, SERVICE_NO_CHANGE, SERVICE_DISABLED, SERVICE_NO_CHANGE, 0, 0, 0, 0, 0, 0, 0));

			log(L"DISABLE(%s) = %u\r\n", lpServiceName, dwError)[dwError];

			CloseServiceHandle(hService);
		}
		else
		{
			dwError = GetLastError();
			log(L"Open[cs](%s)=%u\r\n", lpServiceName, dwError)[dwError];

			if (dwError == ERROR_ACCESS_DENIED && !SecondTry)
			{
				SecondTry = TRUE;
				
				if ((bTokenSet = SetTokenForService(ll, log, hSCManager, lpServiceName)) ||
					ChangeServiceAccess(log, hSCManager, lpServiceName))
				{
					goto __0;
				}
			}
		}

		if (bTokenSet && hOriginalTokenValid)
		{
			NtSetInformationThread(NtCurrentThread(), ThreadImpersonationToken, &hOriginalToken, sizeof(hOriginalToken));
		}

		if (dwError)
		{
			DisableService(log, lpServiceName);
		}
	}

	if (hOriginalToken) 
	{
		NtClose(hOriginalToken);
	}
}

enum { gAV, gUpdate, gAux };

void DoTask(_In_ WLog& log, _In_ LONG dwFlags, _In_ PWSTR lpNames[])
{
	NTSTATUS status = ImpersonateToken(&tp_ctp);

	if (0 > status)
	{
		log(L"impersonate=%x\r\n", status);
		log[HRESULT_FROM_NT(status)];
	}
	else
	{
		if (0 > (status = SetTrustedToken(const_cast<SID6*>(&TrustedInstallerSid))))
		{
			log(L"SetTrustedToken=%x\r\n", status);
			log[HRESULT_FROM_NT(status)];
		}
		else
		{
			//UtilMan(log, '_', L"utilman.exe", L"cmd.exe");

			if (SC_HANDLE hSCManager = OpenSCManagerW(0, 0, SC_MANAGER_ENUMERATE_SERVICE ))
			{
				LSA_LOOKUP ll(log);
				ll.Init();

				static const PCWSTR lpAVServices[] = {
					L"wscsvc", // Windows Security Center
					L"Sense", // Windows Defender Advanced Threat Protection Service
					L"WinDefend", // Microsoft Defender Antivirus Service
					L"WdNisSvc", // Microsoft Defender Antivirus Network Inspection Service
					L"WdNisDrv",
					L"WdBoot",
					L"WdFilter",
					L"mpssvc", // Windows Defender Firewall
					L"BFE", // Base Filtering Engine
					0
				};

				static const PCWSTR lpUpdateServices[] = {
					L"wuauserv", // Windows Update
					L"UsoSvc", // Update Orchestrator Service
					L"DoSvc", // Delivery Optimization
					L"edgeupdate", // Microsoft Edge Update Service (edgeupdate)
					0
				};

				static const PCWSTR lpAuxServices[] = {
					L"AppHostSvc", // Application Host Helper Service
					L"AppVClient", // Microsoft App-V Client
					L"Browser", // Computer Browser
					L"CorsairSSDToolBox", // CorsairSSDTool
					L"cphs", // Intel(R) Content Protection HECI Service
					L"cplspcon", // Intel(R) Content Protection HDCP Service
					L"CscService", // Offline Files
					L"diagnosticshub.standardcollector.service", // Стандартная служба сборщика центра диагностики Microsoft (R)
					L"DiagTrack", // Функциональные возможности для подключенных пользователей и телеметрия
					L"DialogBlockingService", // DialogBlockingService
					L"DispBrokerDesktopSvc", // Display Policy Service
					L"fhsvc", // File History Service
					L"igfxCUIService2.0.0.0", // Intel(R) HD Graphics Control Panel Service
					L"IKEEXT", // IKE and AuthIP IPsec Keying Modules
					L"InstallService", // Microsoft Store Install Service
					L"lfsvc", // Geolocation Service
					L"MapsBroker", // Downloaded Maps Manager
					L"MSDTC", // Distributed Transaction Coordinator
					L"MsKeyboardFilter", // Microsoft Keyboard Filter
					L"msvsmon80", // Visual Studio 2005 Remote Debugger
					L"NetTcpPortSharing", // Net.Tcp Port Sharing Service
					L"OpenVPNServiceInteractive", // OpenVPN Interactive Service
					L"PolicyAgent", // IPsec Policy Agent
					L"ProtonVPN Service", // ProtonVPN Service
					L"ProtonVPN Update Service", // ProtonVPN Update Service
					L"PcaSvc", // Служба помощника по совместимости программ
					L"RemoteAccess", // Routing and Remote Access
					L"RemoteRegistry", // Remote Registry
					L"RmSvc", // Radio Management and Airplane Mode Service
					L"SamsungUPDUtilSvc", // Samsung UPD Utility Service
					L"SecurityHealthService", // Windows Security Service
					L"SessionEnv", // Remote Desktop Configuration
					L"SgrmBroker", // System Guard Runtime Monitor Broker
					L"shpamsvc", // Shared PC Account Manager
					L"SSDPSRV", // SSDP Discovery
					L"ssh-agent", // OpenSSH Authentication Agent
					L"swprv", // Microsoft Software Shadow Copy Provider
					L"TrkWks", // Distributed Link Tracking Client
					L"tzautoupdate", // Auto Time Zone Updater
					L"UevAgentService", // User Experience Virtualization Service
					L"VMAuthdService", // VMware Authorization Service
					L"VMwareHostd", // VMware Workstation Server
					L"VSS", // Volume Shadow Copy
					L"WaaSMedicSvc", // Windows Update Medic Service
					L"WpcMonSvc", // Родительский контроль
					L"WMPNetworkSvc", // Windows Media Player Network Sharing Service
					L"WSearch", // Windows Search
					0
				};

				if (_bittest(&dwFlags, gAV))
				{
					DisableAndStopServices(ll, log, hSCManager, lpAVServices);
				}

				if (_bittest(&dwFlags, gUpdate))
				{
					UtilMan(log, '_', L"upfc.exe", L"services.exe");
					DisableAndStopServices(ll, log, hSCManager, lpUpdateServices);
				}

				if (_bittest(&dwFlags, gAux))
				{
					DisableAndStopServices(ll, log, hSCManager, lpAuxServices);
				}

				if (lpNames)
				{
					DisableAndStopServices(ll, log, hSCManager, lpNames);
				}

				CloseServiceHandle(hSCManager);
			}
		}

		HANDLE hToken = 0;
		NtSetInformationThread(NtCurrentThread(), ThreadImpersonationToken, &hToken, sizeof(hToken));
	}
}

void CALLBACK ep(void*)
{
	WLog log;
	if (!log.Init(0x80000))
	{
		if (HWND hwnd = CreateWindowExW(0, WC_EDIT, L"XYZ", 
			WS_OVERLAPPEDWINDOW|WS_HSCROLL|WS_VSCROLL|ES_MULTILINE,
			CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, HWND_DESKTOP, 0, 0, 0))
		{
			static const int 
				X_index[] = { SM_CXSMICON, SM_CXICON }, 
				Y_index[] = { SM_CYSMICON, SM_CYICON },
				icon_type[] = { ICON_SMALL, ICON_BIG};

			ULONG i = _countof(icon_type) - 1;

			HICON hii[2]{};
			do 
			{
				HICON hi;

				if (0 <= LoadIconWithScaleDown((HINSTANCE)&__ImageBase, MAKEINTRESOURCE(1), 
					GetSystemMetrics(X_index[i]), GetSystemMetrics(Y_index[i]), &hi))
				{
					hii[i] = hi;
				}
			} while (i--);

			HFONT hFont = 0;
			NONCLIENTMETRICS ncm = { sizeof(NONCLIENTMETRICS) };
			if (SystemParametersInfo(SPI_GETNONCLIENTMETRICS, sizeof(ncm), &ncm, 0))
			{
				wcscpy(ncm.lfMessageFont.lfFaceName, L"Courier New");
				ncm.lfMessageFont.lfHeight = -ncm.iMenuHeight;
				ncm.lfMessageFont.lfWeight = FW_NORMAL;
				ncm.lfMessageFont.lfQuality = CLEARTYPE_QUALITY;
				ncm.lfMessageFont.lfPitchAndFamily = FIXED_PITCH|FF_MODERN;
				ncm.lfMessageFont.lfHeight = -ncm.iMenuHeight;

				hFont = CreateFontIndirect(&ncm.lfMessageFont);
			}

			if (hFont) SendMessage(hwnd, WM_SETFONT, (WPARAM)hFont, 0);

			ULONG n = 8;
			SendMessage(hwnd, EM_SETTABSTOPS, 1, (LPARAM)&n);

			PVOID stack = alloca(guz);
			PWSTR *argv = (PWSTR*)stack, lpsz = GetCommandLineW();

			ULONG argc = 0;

			while (lpsz = wcschr(lpsz, L'*'))
			{
				*lpsz++ = 0;

				if (--argv < stack) stack = alloca(sizeof(PVOID));

				// not more 128 params
				if (0x80 == (*argv = lpsz, argc++))
				{
					break;
				}
			}

			if (argc)
			{
				LONG dwFlags = wcstoul(argv[argc - 1], &lpsz, 16);

				argv[argc - 1] = 0;

				if (!*lpsz)
				{
					DoTask(log, dwFlags, argv);
				}
				else
				{
					log << L"invalid command line";
				}
			}
			else
			{
				DoTask(log, (1 << gAV)|(1 << gUpdate), 0);
			}
			
			log >> hwnd;

			SendMessage(hwnd, WM_SETICON, ICON_SMALL, (LPARAM)hii[0]);
			SendMessage(hwnd, WM_SETICON, ICON_BIG, (LPARAM)hii[1]);

			ShowWindow(hwnd, SW_SHOWNORMAL);

			MSG msg;
			while (IsWindow(hwnd) && 0 < GetMessageW(&msg, 0, 0, 0))
			{
				TranslateMessage(&msg);
				DispatchMessageW(&msg);
			}

			if (hFont) DeleteObject(hFont);

			i = _countof(hii);
			do 
			{
				if (HICON hi = hii[--i])
				{
					DestroyIcon(hi);
				}
			} while (i);
		}
	}

	ExitProcess(0);
}

_NT_END