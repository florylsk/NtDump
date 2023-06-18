#pragma once
#include <windows.h>
#include <inttypes.h>
#include <stdio.h>
#include <dbghelp.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <winver.h>

#pragma region Defines

#define HWSYSCALLS_DEBUG 0 // 0 disable, 1 enable
#define UP -32
#define DOWN 32
#define STACK_ARGS_LENGTH 8
#define STACK_ARGS_RSP_OFFSET 0x28
#define X64_PEB_OFFSET 0x60

#pragma endregion
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define NtCurrentProcess() ( (HANDLE)(LONG_PTR) -1 )
#define STATUS_SUCCESS 0
#pragma region Macros

#if HWSYSCALLS_DEBUG == 0
#define DEBUG_PRINT( STR, ... )
#else
#define DEBUG_PRINT( STR, ... ) printf(STR, __VA_ARGS__ ); 
#endif

#pragma endregion

#pragma region Type Defintions
typedef LONG       KPRIORITY;
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
    BYTE           Reserved1[16];
    PVOID          Reserved2[10];
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB_LDR_DATA {
    BYTE       Reserved1[8];
    PVOID      Reserved2[3];
    LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY {
    PVOID Reserved1[2];
    LIST_ENTRY InMemoryOrderLinks;
    PVOID Reserved2[2];
    PVOID DllBase;
    PVOID EntryPoint;
    PVOID Reserved3;
    UNICODE_STRING FullDllName;
    BYTE Reserved4[8];
    PVOID Reserved5[3];
    union {
        ULONG CheckSum;
        PVOID Reserved6;
    };
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[21];
    PPEB_LDR_DATA LoaderData;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
    BYTE Reserved3[520];
    PVOID PostProcessInitRoutine;
    BYTE Reserved4[136];
    ULONG SessionId;
} PEB, * PPEB;

typedef BOOL(WINAPI* GetThreadContext_t)(
    _In_ HANDLE hThread,
    _Inout_ LPCONTEXT lpContext
    );

typedef BOOL(WINAPI* SetThreadContext_t)(
    _In_ HANDLE hThread,
    _In_ CONST CONTEXT* lpContext
    );

#pragma endregion
typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation = 0,
    SystemPerformanceInformation = 2,
    SystemTimeOfDayInformation = 3,
    SystemProcessInformation = 5,
    SystemProcessorPerformanceInformation = 8,
    SystemInterruptInformation = 23,
    SystemExceptionInformation = 33,
    SystemRegistryQuotaInformation = 37,
    SystemLookasideInformation = 45,
    SystemCodeIntegrityInformation = 103,
    SystemPolicyInformation = 134,
} SYSTEM_INFORMATION_CLASS;

typedef struct _OBJECT_ATTRIBUTES
{
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef struct _CLIENT_ID
{
    PVOID UniqueProcess;
    PVOID UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef NTSTATUS(WINAPI* NtOpenProcess_t)(
    OUT          PHANDLE            ProcessHandle,
    IN           ACCESS_MASK        DesiredAccess,
    IN           POBJECT_ATTRIBUTES ObjectAttributes,
    IN OPTIONAL  PCLIENT_ID         ClientId
    );

typedef NTSTATUS(NTAPI* NtCreateSection_t)(
    OUT PHANDLE SectionHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN PLARGE_INTEGER MaximumSize OPTIONAL,
    IN ULONG SectionPageProtection,
    IN ULONG AllocationAttributes,
    IN HANDLE FileHandle OPTIONAL);



typedef NTSTATUS(NTAPI* NtReadVirtualMemory_t)(IN HANDLE ProcessHandle, IN OPTIONAL PVOID BaseAddress, OUT PVOID Buffer, IN SIZE_T BufferSize, OUT OPTIONAL PSIZE_T NumberOfBytesRead);


typedef NTSTATUS(NTAPI* NtOpenProcessToken_t)(
    IN  HANDLE      ProcessHandle,
    IN  ACCESS_MASK DesiredAccess,
    OUT PHANDLE     TokenHandle
    );

typedef NTSTATUS(NTAPI* NtAdjustPrivilegesToken_t)(



    IN HANDLE               TokenHandle,
    IN BOOLEAN              DisableAllPrivileges,
    IN PTOKEN_PRIVILEGES    TokenPrivileges,
    IN ULONG                PreviousPrivilegesLength,
    OUT OPTIONAL PTOKEN_PRIVILEGES   PreviousPrivileges,
    OUT OPTIONAL PULONG              RequiredLength);

typedef NTSTATUS (NTAPI* NtOpenProcessToken_t)(
    IN  HANDLE      ProcessHandle,
    IN  ACCESS_MASK DesiredAccess,
    OUT PHANDLE     TokenHandle
);

typedef NTSTATUS (NTAPI* NtQuerySystemInformation_t)(
    IN            SYSTEM_INFORMATION_CLASS SystemInformationClass,
    IN OUT       PVOID                    SystemInformation,
    IN            ULONG                    SystemInformationLength,
    OUT OPTIONAL PULONG                   ReturnLength
);

typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    BYTE Reserved1[48];
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    PVOID Reserved2;
    ULONG HandleCount;
    ULONG SessionId;
    PVOID Reserved3;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG Reserved4;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    PVOID Reserved5;
    SIZE_T QuotaPagedPoolUsage;
    PVOID Reserved6;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER Reserved7[6];
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;
#pragma region Function Declerations

BOOL MaskCompare(const BYTE* pData, const BYTE* bMask, const char* szMask);
DWORD_PTR FindPattern(DWORD_PTR dwAddress, DWORD dwLen, PBYTE bMask, PCHAR szMask);
DWORD_PTR FindInModule(LPCSTR moduleName, PBYTE bMask, PCHAR szMask);
UINT64 GetModuleAddress(LPWSTR sModuleName);
UINT64 GetSymbolAddress(UINT64 moduleBase, const char* functionName);
UINT64 PrepareSyscall(char* functionName);
bool SetMainBreakpoint();
DWORD64 FindSyscallNumber(DWORD64 functionAddress);
DWORD64 FindSyscallReturnAddress(DWORD64 functionAddress, WORD syscallNumber);
LONG HWSyscallExceptionHandler(EXCEPTION_POINTERS* ExceptionInfo);
bool InitHWSyscalls();
bool DeinitHWSyscalls();

#pragma endregion
typedef struct _THREAD_BASIC_INFORMATION
{
    NTSTATUS                ExitStatus;
    PVOID                   TebBaseAddress;
    CLIENT_ID               ClientId;
    KAFFINITY               AffinityMask;
    KPRIORITY               Priority;
    KPRIORITY               BasePriority;
} THREAD_BASIC_INFORMATION, * PTHREAD_BASIC_INFORMATION;

typedef DWORD   RVA;
typedef ULONG64 RVA64;

struct process
{
    struct process* next;
    HANDLE                      handle;
    const struct loader_ops* loader;
    WCHAR* search_path;
    WCHAR* environment;

    PSYMBOL_REGISTERED_CALLBACK64       reg_cb;
    PSYMBOL_REGISTERED_CALLBACK reg_cb32;
    BOOL                        reg_is_unicode;
    DWORD64                     reg_user;

    struct module* lmodules;
    ULONG_PTR                   dbg_hdr_addr;

    IMAGEHLP_STACK_FRAME        ctx_frame;

    unsigned                    buffer_size;
    void* buffer;

    BOOL                        is_64bit;
};

struct dump_context
{
    /* process & thread information */
    struct process* process;
    DWORD                               pid;
    HANDLE                              handle;
    unsigned                            flags_out;
    /* thread information */
    struct dump_thread* threads;
    unsigned                            num_threads;
    /* module information */
    struct dump_module* modules;
    unsigned                            num_modules;
    unsigned                            alloc_modules;
    /* exception information */
    /* output information */
    MINIDUMP_TYPE                       type;
    HANDLE                              hFile;
    RVA                                 rva;
    struct dump_memory* mem;
    unsigned                            num_mem;
    unsigned                            alloc_mem;
    struct dump_memory64* mem64;
    unsigned                            num_mem64;
    unsigned                            alloc_mem64;
    /* callback information */
    MINIDUMP_CALLBACK_INFORMATION* cb;
};

struct line_info
{
    ULONG_PTR                   is_first : 1,
        is_last : 1,
        is_source_file : 1,
        line_number;
    union
    {
        ULONG_PTR                   pc_offset;   /* if is_source_file isn't set */
        unsigned                    source_file; /* if is_source_file is set */
    } u;
};

struct module_pair
{
    struct process* pcs;
    struct module* requested; /* in:  to module_get_debug() */
    struct module* effective; /* out: module with debug info */
};

enum pdb_kind { PDB_JG, PDB_DS };

struct pdb_lookup
{
    const char* filename;
    enum pdb_kind               kind;
    DWORD                       age;
    DWORD                       timestamp;
    GUID                        guid;
};

struct cpu_stack_walk
{
    HANDLE                      hProcess;
    HANDLE                      hThread;
    BOOL                        is32;
    struct cpu* cpu;
    union
    {
        struct
        {
            PREAD_PROCESS_MEMORY_ROUTINE        f_read_mem;
            PTRANSLATE_ADDRESS_ROUTINE          f_xlat_adr;
            PFUNCTION_TABLE_ACCESS_ROUTINE      f_tabl_acs;
            PGET_MODULE_BASE_ROUTINE            f_modl_bas;
        } s32;
        struct
        {
            PREAD_PROCESS_MEMORY_ROUTINE64      f_read_mem;
            PTRANSLATE_ADDRESS_ROUTINE64        f_xlat_adr;
            PFUNCTION_TABLE_ACCESS_ROUTINE64    f_tabl_acs;
            PGET_MODULE_BASE_ROUTINE64          f_modl_bas;
        } s64;
    } u;
};

struct dump_memory
{
    ULONG64                             base;
    ULONG                               size;
    ULONG                               rva;
};

struct dump_memory64
{
    ULONG64                             base;
    ULONG64                             size;
};

struct dump_module
{
    unsigned                            is_elf;
    ULONG64                             base;
    ULONG                               size;
    DWORD                               timestamp;
    DWORD                               checksum;
    WCHAR                               name[MAX_PATH];
};

struct dump_thread
{
    ULONG                               tid;
    ULONG                               prio_class;
    ULONG                               curr_prio;
};