#include "stdafx.h"

_NT_BEGIN

#include "wlog.h"

void WLog::operator >> (HWND hwnd)
{
	HLOCAL hMem = (HLOCAL)SendMessage(hwnd, EM_GETHANDLE, 0, 0);
	
	SendMessage(hwnd, EM_SETHANDLE, (WPARAM)_BaseAddress, 0);
	
	_BaseAddress = 0;
	
	LocalFree(hMem);
}

ULONG WLog::Init(SIZE_T RegionSize)
{
	if (PVOID BaseAddress = LocalAlloc(0, RegionSize))
	{
		_RegionSize = (ULONG)RegionSize, _Ptr = 0, _BaseAddress = BaseAddress;
		*(WCHAR*)BaseAddress = 0;
		return NOERROR;
	}
	return GetLastError();
}

WLog::~WLog()
{
	if (_BaseAddress)
	{
		LocalFree(_BaseAddress);
	}
}

WLog& WLog::operator ()(PCWSTR format, ...)
{
	va_list args;
	va_start(args, format);

	int len = _vsnwprintf_s(_buf(), _cch(), _TRUNCATE, format, args);

	if (0 < len)
	{
		_Ptr += len * sizeof(WCHAR);
	}

	va_end(args);

	return *this;
}

WLog& WLog::operator << (PCWSTR str)
{
	if (!wcscpy_s(_buf(), _cch(), str))
	{
		_Ptr += (ULONG)wcslen(str) * sizeof(WCHAR);
	}
	return *this;
}

WLog& WLog::operator[](HRESULT dwError)
{
	LPCVOID lpSource = 0;
	ULONG dwFlags = FORMAT_MESSAGE_FROM_SYSTEM|FORMAT_MESSAGE_IGNORE_INSERTS;

	if (dwError & FACILITY_NT_BIT)
	{
		dwError &= ~FACILITY_NT_BIT;
__nt:
		dwFlags = FORMAT_MESSAGE_FROM_HMODULE|FORMAT_MESSAGE_IGNORE_INSERTS;

		static HMODULE ghnt;
		if (!ghnt && !(ghnt = GetModuleHandle(L"ntdll"))) return *this;
		lpSource = ghnt;
	}

	if (dwFlags = FormatMessageW(dwFlags, lpSource, dwError, 0, _buf(), _cch(), 0))
	{
		_Ptr += dwFlags * sizeof(WCHAR);
	}
	else if (dwFlags & FORMAT_MESSAGE_FROM_SYSTEM)
	{
		goto __nt;
	}
	return *this;
}

_NT_END