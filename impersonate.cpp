#include "stdafx.h"

_NT_BEGIN

#include "impersonate.h"

extern const SECURITY_QUALITY_OF_SERVICE sqos = {
	sizeof (sqos), SecurityImpersonation, SECURITY_DYNAMIC_TRACKING, FALSE
};

extern const OBJECT_ATTRIBUTES oa_sqos = { sizeof(oa_sqos), 0, 0, 0, 0, const_cast<SECURITY_QUALITY_OF_SERVICE*>(&sqos) };

extern const TOKEN_PRIVILEGES tp_Debug =		{ 1, { { { SE_DEBUG_PRIVILEGE }, SE_PRIVILEGE_ENABLED } } };
extern const TOKEN_PRIVILEGES tp_Permanent =   { 1, { { { SE_CREATE_PERMANENT_PRIVILEGE   }, SE_PRIVILEGE_ENABLED } } };
extern const TOKEN_PRIVILEGES tp_TCB =			{ 1, { { { SE_TCB_PRIVILEGE   }, SE_PRIVILEGE_ENABLED } } };

NTSTATUS GetToken(PVOID buf, const TOKEN_PRIVILEGES* RequiredSet)
{
	NTSTATUS status;

	union {
		PVOID pv;
		PBYTE pb;
		PSYSTEM_PROCESS_INFORMATION pspi;
	};

	pv = buf;
	ULONG NextEntryOffset = 0;

	do 
	{
		pb += NextEntryOffset;

		HANDLE hProcess, hToken, hNewToken;

		CLIENT_ID ClientId = { pspi->UniqueProcessId };

		if (ClientId.UniqueProcess)
		{
			if (0 <= NtOpenProcess(&hProcess, PROCESS_QUERY_LIMITED_INFORMATION, 
				const_cast<POBJECT_ATTRIBUTES>(&oa_sqos), &ClientId))
			{
				status = NtOpenProcessToken(hProcess, TOKEN_DUPLICATE, &hToken);

				NtClose(hProcess);

				if (0 <= status)
				{
					status = NtDuplicateToken(hToken, TOKEN_ADJUST_PRIVILEGES|TOKEN_IMPERSONATE, 
						const_cast<POBJECT_ATTRIBUTES>(&oa_sqos), FALSE, TokenImpersonation, &hNewToken);

					NtClose(hToken);

					if (0 <= status)
					{
						status = NtAdjustPrivilegesToken(hNewToken, FALSE, const_cast<PTOKEN_PRIVILEGES>(RequiredSet), 0, 0, 0);

						if (STATUS_SUCCESS == status)	
						{
							status = NtSetInformationThread(NtCurrentThread(), ThreadImpersonationToken, &hNewToken, sizeof(hNewToken));
						}

						NtClose(hNewToken);

						if (STATUS_SUCCESS == status)
						{
							return STATUS_SUCCESS;
						}
					}
				}
			}
		}

	} while (NextEntryOffset = pspi->NextEntryOffset);

	return STATUS_UNSUCCESSFUL;
}

NTSTATUS WINAPI AdjustPrivileges(_In_ const TOKEN_PRIVILEGES* ptp)
{
	NTSTATUS status;
	HANDLE hToken, hNewToken;

	if (0 <= (status = NtOpenProcessToken(NtCurrentProcess(), TOKEN_DUPLICATE, &hToken)))
	{
		status = NtDuplicateToken(hToken, TOKEN_ADJUST_PRIVILEGES|TOKEN_IMPERSONATE, 
			const_cast<OBJECT_ATTRIBUTES*>(&oa_sqos), FALSE, TokenImpersonation, &hNewToken);

		NtClose(hToken);

		if (0 <= status)
		{
			if (STATUS_SUCCESS == (status = NtAdjustPrivilegesToken(hNewToken, FALSE, 
				const_cast<PTOKEN_PRIVILEGES>(ptp), 0, 0, 0)))
			{
				status = NtSetInformationThread(NtCurrentThread(), ThreadImpersonationToken, &hNewToken, sizeof(hNewToken));
			}

			NtClose(hNewToken);
		}
	}

	return status;
}

NTSTATUS WINAPI ImpersonateToken(_In_ const TOKEN_PRIVILEGES* RequiredSet)
{
	NTSTATUS status = AdjustPrivileges(&tp_Debug);

	ULONG cb = 0x40000;

	do 
	{
		status = STATUS_INSUFFICIENT_RESOURCES;

		if (PBYTE buf = new BYTE[cb += PAGE_SIZE])
		{
			if (0 <= (status = NtQuerySystemInformation(SystemProcessInformation, buf, cb, &cb)))
			{
				status = GetToken(buf, RequiredSet);

				if (status == STATUS_INFO_LENGTH_MISMATCH)
				{
					status = STATUS_UNSUCCESSFUL;
				}
			}

			delete [] buf;
		}

	} while(status == STATUS_INFO_LENGTH_MISMATCH);

	return status;
}

AutoImpesonate::~AutoImpesonate()
{
	if (bRevert) NtSetInformationThread(NtCurrentThread(), ThreadImpersonationToken, &hOriginalToken, sizeof(hOriginalToken));

	if (hOriginalToken) 
	{
		NtClose(hOriginalToken);
	}
}

AutoImpesonate::AutoImpesonate()
{
	switch (NtOpenThreadToken(NtCurrentThread(), TOKEN_IMPERSONATE, TRUE, &(hOriginalToken = 0)))
	{
	case STATUS_NO_TOKEN:
	case STATUS_SUCCESS:
		bRevert = TRUE;
		break;
	}
}

_NT_END