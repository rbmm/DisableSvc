#pragma once

NTSTATUS 
WINAPI 
ImpersonateToken(_In_ const TOKEN_PRIVILEGES* RequiredSet);

NTSTATUS
WINAPI
AdjustPrivileges(_In_ const TOKEN_PRIVILEGES* ptp);

class AutoImpesonate
{
	HANDLE hOriginalToken;
	BOOLEAN bRevert;
public:
	AutoImpesonate();
	~AutoImpesonate();
};

extern const SECURITY_QUALITY_OF_SERVICE sqos;
extern const OBJECT_ATTRIBUTES oa_sqos;

extern const TOKEN_PRIVILEGES tp_Debug;
extern const TOKEN_PRIVILEGES tp_Permanent;
extern const TOKEN_PRIVILEGES tp_TCB;