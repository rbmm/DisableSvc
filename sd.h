#pragma once

#include "wlog.h"

class LSA_LOOKUP
{
	LSA_HANDLE PolicyHandle;
	WLog& log;
public:

	LSA_LOOKUP(WLog& log) : log(log), PolicyHandle(0)
	{
	}

	~LSA_LOOKUP()
	{
		if (LSA_HANDLE h = PolicyHandle)
		{
			LsaClose(h);
		}
	}

	NTSTATUS Init();
	NTSTATUS DumpGroups(PTOKEN_GROUPS ptg);
	NTSTATUS DumpACEList(ULONG AceCount, PVOID FirstAce);
	void DumpSid(PCWSTR Prefix, PSID Sid);
	void DumpAcl(PACL acl, PCWSTR caption);

	void DumpSecurityDescriptor(PSECURITY_DESCRIPTOR SecurityDescriptor);
	void DumpStringSecurityDescriptor(PCWSTR StringSecurityDescriptor);
};