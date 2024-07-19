# DisableSvc

for disable service - we need call ChangeServiceConfigW with SERVICE_DISABLED
and for this we need open service with SERVICE_CHANGE_CONFIG (0x0002) access right
(in worst case we can direct change value in registry and reboot)

for stop service we need call ControlService with SERVICE_CONTROL_STOP
and for this we need open service with SERVICE_STOP (0x0020) access right

are we can open service with such rights, depend from service security descriptor and our token
but for some services system do additional checks, as described here - https://www.alex-ionescu.com/?paged=2&cat=2
this done inside function ScCheckServiceProtectedProcess
the system check are TrustedInstaller service SID exist in caller token (
create this sid via RtlInitUnicodeString + RtlCreateServiceSid 
and check via CheckTokenMembership
)
and if not - RtlTestProtectedAccess will be called, where we fail

(for more details look tvi files (https://github.com/rbmm/DisableSvc/tree/main/TVI) with https://github.com/rbmm/TVI/tree/main/X64 and 
https://github.com/rbmm/DisableSvc/tree/main/IMG)

so we need have TrustedInstaller SID in token.


early SD for WinDefend look like

D:(A;;CCLCSWRPLOCRRC;;;BU)(A;;CCLCSWRPLOCRRC;;;SY)(A;;CCLCSWRPLOCRRC;;;BA)(A;;CCLCSWRPLOCRRC;;;IU)(A;;CCLCSWRPLOCRRC;;;SU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;S-1-5-80-1913148863-3492339771-4165695881-2087618961-4109116736)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)

DACL:
T FL AcessMsK Sid
A 00 0002019D [S-1-5-32-545] 'BUILTIN\Users' [Alias]
A 00 0002019D [S-1-5-18] 'NT AUTHORITY\SYSTEM' [WellKnownGroup]
A 00 0002019D [S-1-5-32-544] 'BUILTIN\Administrators' [Alias]
A 00 0002019D [S-1-5-4] 'NT AUTHORITY\INTERACTIVE' [WellKnownGroup]
A 00 0002019D [S-1-5-6] 'NT AUTHORITY\SERVICE' [WellKnownGroup]
A 00 000F01FF [S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464] 'NT SERVICE\TrustedInstaller' [WellKnownGroup]
A 00 000F01FF [S-1-5-80-1913148863-3492339771-4165695881-2087618961-4109116736] 'NT SERVICE\WinDefend' [WellKnownGroup]
SACL:
T FL AcessMsK Sid
U 80 000F01FF [S-1-1-0] '\Everyone' [WellKnownGroup]

(we can get string sid from sc sdshow windefend and convert it to more redable form with for instance such tool - https://github.com/rbmm/SDDL/blob/master/SDDL.exe)

visible that 'NT SERVICE\TrustedInstaller' have full ( 000F01FF ) access to service, which included SERVICE_CHANGE_CONFIG|SERVICE_STOP (0x0022) access right

but than service SD is changed to

D:(A;;CCLCSWRPLOCRRC;;;BU)(A;;CCLCSWRPLOCRRC;;;SY)(A;;CCLCSWRPLOCRRC;;;BA)(A;;CCLCSWRPLOCRRC;;;IU)(A;;CCLCSWRPLOCRRC;;;SU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;S-1-5-80-1913148863-3492339771-4165695881-2087618961-4109116736)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)


DACL:
T FL AcessMsK Sid
A 00 0002019D [S-1-5-32-545] 'BUILTIN\Users' [Alias]
A 00 0002019D [S-1-5-18] 'NT AUTHORITY\SYSTEM' [WellKnownGroup]
A 00 0002019D [S-1-5-32-544] 'BUILTIN\Administrators' [Alias]
A 00 0002019D [S-1-5-4] 'NT AUTHORITY\INTERACTIVE' [WellKnownGroup]
A 00 0002019D [S-1-5-6] 'NT AUTHORITY\SERVICE' [WellKnownGroup]
A 00 000F01FF [S-1-5-80-1913148863-3492339771-4165695881-2087618961-4109116736] 'NT SERVICE\WinDefend' [WellKnownGroup]
SACL:
T FL AcessMsK Sid
U 80 000F01FF [S-1-1-0] '\Everyone' [WellKnownGroup]

so now - TrustedInstaller no more any access to windefend - and we must have 'NT SERVICE\WinDefend' sid in token. but still need have 'NT SERVICE\TrustedInstaller' too,
for not fail in ScCheckServiceProtectedProcess

so main task in got such token. if we have debug privilege it token, this is not hard task really.
we not need start TrustedInstaller and got it token.
we simply need found process with token where, exist SE_CREATE_TOKEN_PRIVILEGE and impersonate with it. after this we can create by self any token.
token with 'NT SERVICE\TrustedInstaller' as well
also not heed hardcode any process name (lsass.exe)
simply need open processes tokens and check - are token have required for us privilege set or/and another properties ( tcb, system luid, etc)

and for stop/disable services which not let 'NT SERVICE\TrustedInstaller' do this by self SD - we have 2 ways - of create and set token with required SID or change service SD
better first try set SID in self token (create new token and impersonate with it) than try change something in registry
however change SD in registry also must work

possible run https://github.com/rbmm/DisableSvc/tree/main/x64 app without params, in this case it try stop and disable next services:

				static const PCWSTR lpAVServices[] = {
					L"wscsvc", // Windows Security Center
					L"WinDefend", // Microsoft Defender Antivirus Service
					L"Sense", // Windows Defender Advanced Threat Protection Service
					L"WdNisSvc", // Microsoft Defender Antivirus Network Inspection Service
          				L"WdNisDrv", // Microsoft Defender Antivirus Network Inspection System Driver
				        L"WdBoot", // Microsoft Defender Antivirus Boot Driver
          				L"WdFilter", // Microsoft Defender Antivirus Mini-Filter Driver
					L"mpssvc", // Windows Defender Firewall
					L"BFE", // Base Filtering Engine
					0
				};

				static const PCWSTR lpUpdateServices[] = {
					L"wuauserv", // Windows Update
					L"UsoSvc", // Update Orchestrator Service
					L"DoSvc", // Delivery Optimization
                                        L"WaaSMedicSvc", // 
					L"edgeupdate", // Microsoft Edge Update Service (edgeupdate)
					0
				};

or use cmd line for direct set what to disable:

btsp *flags[*srv1[*svc2...]

flags:

1 - disable AV related services	
2 - disable update related services
4 - different aux services


 
