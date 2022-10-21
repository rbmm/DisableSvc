#include "stdafx.h"

_NT_BEGIN

#include "sd.h"

// /RTCs must be dissabled !
const static UNICODE_STRING emptyUS{};

extern volatile UCHAR guz;

PCWSTR GetSidNameUseName(SID_NAME_USE snu)
{
	switch (snu)
	{
	case SidTypeUser: return L"User";
	case SidTypeGroup: return L"Group";
	case SidTypeDomain: return L"Domain";
	case SidTypeAlias: return L"Alias";
	case SidTypeWellKnownGroup: return L"WellKnownGroup";
	case SidTypeDeletedAccount: return L"DeletedAccount";
	case SidTypeInvalid: return L"Invalid";
	case SidTypeUnknown: return L"Unknown";
	case SidTypeComputer: return L"Computer";
	case SidTypeLabel: return L"Label";
	case SidTypeLogonSession: return L"LogonSession";
	}
	return L"?";
}

NTSTATUS LSA_LOOKUP::Init()
{
	LSA_OBJECT_ATTRIBUTES ObjectAttributes = { sizeof(ObjectAttributes) };
	NTSTATUS status = LsaOpenPolicy(0, &ObjectAttributes, POLICY_LOOKUP_NAMES, &PolicyHandle);
	if (0 > status)
	{
		PolicyHandle = 0;
	}

	return status;
}

NTSTATUS LSA_LOOKUP::DumpGroups(PTOKEN_GROUPS ptg)
{
	ULONG GroupCount = ptg->GroupCount;

	if (!GroupCount)
	{
		return STATUS_SUCCESS;
	}

	PSID* Sids = (PSID*)alloca(GroupCount * sizeof(PSID)), *pSid = Sids;

	ULONG n = GroupCount;

	PSID_AND_ATTRIBUTES Groups = ptg->Groups;
	do 
	{
		*pSid++ = Groups++->Sid;
	} while (--n);

	PLSA_TRANSLATED_NAME Names = 0;
	PLSA_REFERENCED_DOMAIN_LIST ReferencedDomains = 0;

	ULONG Entries = 0;
	PLSA_TRUST_INFORMATION Domains = 0;

	NTSTATUS status = PolicyHandle ? 
		LsaLookupSids(PolicyHandle, GroupCount, Sids, &ReferencedDomains, &Names) : STATUS_INVALID_HANDLE;

	if (ReferencedDomains)
	{
		Entries = ReferencedDomains->Entries;
		Domains = ReferencedDomains->Domains;
	}

	PVOID bufNames = Names;

	UNICODE_STRING StringSid;
	Groups = ptg->Groups;
	do 
	{
		if (0 > RtlConvertSidToUnicodeString(&StringSid, Groups->Sid, TRUE))
		{
			StringSid.Length = 0;
			StringSid.Buffer = 0;
		}

		PCUNICODE_STRING Name = &emptyUS;
		PCUNICODE_STRING Domain = &emptyUS;
		SID_NAME_USE Use = SidTypeUnknown;

		if (Names)
		{
			ULONG DomainIndex = Names->DomainIndex;

			if (DomainIndex < Entries)
			{
				Domain = &Domains[DomainIndex].Name;
			}

			Name = &Names->Name;
			Use = Names++->Use;
		}

		if (ULONG Attributes = Groups->Attributes)
		{
			WCHAR sz[10];

			sz[0] = Attributes & SE_GROUP_MANDATORY ? 'M' : ' ';
			sz[1] = Attributes & SE_GROUP_ENABLED ? 'E' : ' ';
			sz[2] = Attributes & SE_GROUP_ENABLED_BY_DEFAULT ? '+' : ' ';
			sz[3] = Attributes & SE_GROUP_OWNER ? 'O' : ' ';
			sz[4] = Attributes & SE_GROUP_USE_FOR_DENY_ONLY ? 'D' : ' ';
			sz[5] = Attributes & SE_GROUP_INTEGRITY ? 'I' : ' ';
			sz[6] = Attributes & SE_GROUP_INTEGRITY_ENABLED ? '+' : ' ';
			sz[7] = Attributes & SE_GROUP_LOGON_ID ? 'L' : ' ';
			sz[8] = Attributes & SE_GROUP_RESOURCE ? 'R' : ' ';
			sz[9] = 0;

			switch (Use)
			{
			case SidTypeUnknown:
			case SidTypeInvalid:
				log(L"%08X %s [%wZ] [%s]\r\n", 
					Attributes, sz, &StringSid, GetSidNameUseName(Use));
				break;
			default:
				log(L"%08X %s [%wZ] '%wZ\\%wZ' [%s]\r\n", 
					Attributes, sz, &StringSid, Domain, Name, GetSidNameUseName(Use));
			}
		}
		else
		{
			switch (Use)
			{
			case SidTypeUnknown:
			case SidTypeInvalid:
				log(L"[%wZ] [%s]\r\n", &StringSid, GetSidNameUseName(Use));
				break;
			default:
				log(L"[%wZ] '%wZ\\%wZ' [%s]\r\n", &StringSid, Domain, Name, GetSidNameUseName(Use));
			}
		}

	} while (RtlFreeUnicodeString(&StringSid), Groups++, --GroupCount);

	if (ReferencedDomains) LsaFreeMemory(ReferencedDomains);
	if (bufNames) LsaFreeMemory(bufNames);

	return status;
}

PSID GetSidFromACE(PACE_HEADER ph)
{
	if ((ULONG)ph->AceType - ACCESS_MIN_MS_OBJECT_ACE_TYPE <= 
		ACCESS_MAX_MS_OBJECT_ACE_TYPE - ACCESS_ALLOWED_OBJECT_ACE_TYPE)
	{
		switch (reinterpret_cast<PACCESS_ALLOWED_OBJECT_ACE>(ph)->Flags & (ACE_OBJECT_TYPE_PRESENT|ACE_INHERITED_OBJECT_TYPE_PRESENT))
		{
		case 0:
			return &reinterpret_cast<PACCESS_ALLOWED_OBJECT_ACE>(ph)->ObjectType;
		case ACE_OBJECT_TYPE_PRESENT:
		case ACE_INHERITED_OBJECT_TYPE_PRESENT:
			return &reinterpret_cast<PACCESS_ALLOWED_OBJECT_ACE>(ph)->InheritedObjectType;
			//case ACE_OBJECT_TYPE_PRESENT|ACE_INHERITED_OBJECT_TYPE_PRESENT:
		default:
			return &reinterpret_cast<PACCESS_ALLOWED_OBJECT_ACE>(ph)->SidStart;
		}
	}

	return &reinterpret_cast<PACCESS_ALLOWED_ACE>(ph)->SidStart;
}

NTSTATUS LSA_LOOKUP::DumpACEList(ULONG AceCount, PVOID FirstAce)
{
	union {
		PVOID pv;
		PBYTE pb;
		PACE_HEADER ph;
		PACCESS_ALLOWED_ACE pah;
	};

	pv = FirstAce;

	PSID* Sids = (PSID*)alloca(AceCount * sizeof(PSID)), *pSid = Sids, Sid;

	ULONG SidCount = 0, n = AceCount;

	do 
	{
		if (RtlValidSid(Sid = GetSidFromACE(ph)))
		{
			*pSid++ = Sid;
			SidCount++;
		}
		pb += ph->AceSize;
	} while (--n);

	pv = FirstAce;

	PLSA_TRANSLATED_NAME Names = 0;
	PLSA_REFERENCED_DOMAIN_LIST ReferencedDomains = 0;

	ULONG Entries = 0;
	PLSA_TRUST_INFORMATION Domains = 0;

	NTSTATUS status = PolicyHandle ? 
		LsaLookupSids (PolicyHandle, SidCount, Sids, &ReferencedDomains, &Names) : STATUS_INVALID_HANDLE;

	if (ReferencedDomains)
	{
		Entries = ReferencedDomains->Entries;
		Domains = ReferencedDomains->Domains;
	}
	PVOID bufNames = Names;

	WCHAR sz[16], sz2[16];

	UNICODE_STRING StringSid={};

	do
	{
		if (!RtlValidSid(Sid = GetSidFromACE(ph)))
		{
			continue;
		}

		PCUNICODE_STRING Name = &emptyUS;
		PCUNICODE_STRING Domain = &emptyUS;
		SID_NAME_USE Use = SidTypeUnknown;

		if (Names)
		{
			ULONG DomainIndex = Names->DomainIndex;

			if (DomainIndex < Entries)
			{
				Domain = &Domains[DomainIndex].Name;
			}

			Name = &Names->Name;
			Use = Names++->Use;
		}

		ACCESS_MASK Mask = pah->Mask;
		swprintf_s(sz2, _countof(sz2), L"%08X", Mask);

		switch (pah->Header.AceType)
		{
		case SYSTEM_AUDIT_ACE_TYPE:
			sz[0] = 'U', sz[1] = 0;
			break;
		case SYSTEM_ALARM_ACE_TYPE:
			sz[0] = 'R', sz[1] = 0;
			break;
		case ACCESS_ALLOWED_ACE_TYPE:
			sz[0] = 'A', sz[1] = 0;
			break;
		case ACCESS_DENIED_ACE_TYPE:
			sz[0] = 'D', sz[1] = 0;
			break;
		case SYSTEM_MANDATORY_LABEL_ACE_TYPE:
			sz[0] = 'L', sz[1] = 0;
			sz2[0] = Mask & SYSTEM_MANDATORY_LABEL_NO_READ_UP ? 'R' : ' ';
			sz2[1] = Mask & SYSTEM_MANDATORY_LABEL_NO_WRITE_UP ? 'W' : ' ';
			sz2[2] = Mask & SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP ? 'E' : ' ';
			sz2[3] = 0;
			break;
		default:
			swprintf_s(sz, _countof(sz2), L"0x%x", pah->Header.AceType);
		}

		if (0 > RtlConvertSidToUnicodeString(&StringSid, Sid, TRUE))
		{
			StringSid.Length = 0;
			StringSid.Buffer = 0;
		}

		switch (Use)
		{
		case SidTypeInvalid: 
		case SidTypeUnknown:
			log(L"%s %02X %s [%wZ] [%s]\r\n", sz, ph->AceFlags, sz2, 
				&StringSid, GetSidNameUseName(Use));
			break;
		default:
			log(L"%s %02X %s [%wZ] '%wZ\\%wZ' [%s]\r\n", sz, ph->AceFlags, sz2, 
				&StringSid, Domain, Name, GetSidNameUseName(Use));
		}

	} while (RtlFreeUnicodeString(&StringSid), pb += ph->AceSize, --AceCount);

	if (ReferencedDomains) LsaFreeMemory(ReferencedDomains);
	if (bufNames) LsaFreeMemory(bufNames);

	return status;
}

void LSA_LOOKUP::DumpSid(PCWSTR Prefix, PSID Sid)
{
	log(Prefix);
	TOKEN_GROUPS tg = { 1, { { Sid, 0 }} };
	DumpGroups(&tg);
}

void LSA_LOOKUP::DumpAcl(PACL acl, PCWSTR caption)
{
	log(caption);

	if (!acl)
	{
		log(L"NULL\r\n");
		return;
	}

	if (!acl->AceCount)
	{
		log(L"empty\r\n");
		return;
	}

	log(L"T FL AcessMsK Sid\r\n");

	DumpACEList(acl->AceCount, acl + 1);
}

void LSA_LOOKUP::DumpSecurityDescriptor(PSECURITY_DESCRIPTOR SecurityDescriptor)
{
	if (!PolicyHandle)
	{
		return;
	}

	PACL Acl;
	BOOLEAN bPresent, bDefault;

	if (0 <= RtlGetDaclSecurityDescriptor(SecurityDescriptor, &bPresent, &Acl, &bDefault))
	{
		DumpAcl(bPresent ? Acl : 0, L"DACL:\r\n");
	}

	if (0 <= RtlGetSaclSecurityDescriptor(SecurityDescriptor, &bPresent, &Acl, &bDefault))
	{
		DumpAcl(bPresent ? Acl : 0, L"SACL:\r\n");
	}

	PSID Owner;
	if (0 <= RtlGetOwnerSecurityDescriptor(SecurityDescriptor, &Owner, &bDefault) && Owner)
	{
		DumpSid(L"Owner: ", Owner);
	}
}

_NT_END