#include "ntdll_detached.h"
#include "peconv.h"

NTSTATUS (NTAPI *ntdll_NtCreateProcessEx)
(
    OUT PHANDLE ProcessHandle,
    IN ACCESS_MASK  DesiredAccess,
    IN POBJECT_ATTRIBUTES   ObjectAttributes  OPTIONAL,
    IN HANDLE   ParentProcess,
    IN ULONG    Flags,
    IN HANDLE   SectionHandle OPTIONAL,
    IN HANDLE   DebugPort OPTIONAL,
    IN HANDLE   ExceptionPort OPTIONAL,
    IN BOOLEAN  InJob
) = NULL;

NTSTATUS (NTAPI *ntdll_RtlCreateProcessParametersEx)(
    _Out_ PRTL_USER_PROCESS_PARAMETERS *pProcessParameters,
    _In_ PUNICODE_STRING ImagePathName,
    _In_opt_ PUNICODE_STRING DllPath,
    _In_opt_ PUNICODE_STRING CurrentDirectory,
    _In_opt_ PUNICODE_STRING CommandLine,
    _In_opt_ PVOID Environment,
    _In_opt_ PUNICODE_STRING WindowTitle,
    _In_opt_ PUNICODE_STRING DesktopInfo,
    _In_opt_ PUNICODE_STRING ShellInfo,
    _In_opt_ PUNICODE_STRING RuntimeData,
    _In_ ULONG Flags // pass RTL_USER_PROC_PARAMS_NORMALIZED to keep parameters normalized
) = NULL;

NTSTATUS (NTAPI *ntdll_NtCreateThreadEx) (
    OUT  PHANDLE ThreadHandle, 
    IN  ACCESS_MASK DesiredAccess, 
    IN  POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL, 
    IN  HANDLE ProcessHandle,
    IN  LPTHREAD_START_ROUTINE StartRoutine,
    IN  PVOID Argument OPTIONAL,
    IN  ULONG CreateFlags,
    IN  ULONG_PTR ZeroBits, 
    IN  SIZE_T StackSize OPTIONAL,
    IN  SIZE_T MaximumStackSize OPTIONAL, 
    IN  PVOID AttributeList OPTIONAL
) = NULL;

NTSTATUS (NTAPI *ntdll_NtAllocateVirtualMemory)(
  _In_    HANDLE    ProcessHandle,
  _Inout_ PVOID     *BaseAddress,
  _In_    ULONG_PTR ZeroBits,
  _Inout_ PSIZE_T   RegionSize,
  _In_    ULONG     AllocationType,
  _In_    ULONG     Protect
) = NULL;

NTSTATUS (NTAPI *ntdll_NtWriteVirtualMemory)(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress,
    IN PVOID Buffer,
    IN ULONG NumberOfBytesToWrite,
    OUT PULONG NumberOfBytesWritten OPTIONAL
) = NULL;

NTSTATUS (NTAPI *ntdll_NtCreateSection) (
    OUT PHANDLE SectionHandle,
    IN  ACCESS_MASK DesiredAccess,
    IN  POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN  PLARGE_INTEGER MaximumSize OPTIONAL,
    IN  ULONG SectionPageProtection,
    IN  ULONG AllocationAttributes,
    IN  HANDLE FileHandle OPTIONAL
) = NULL;

HMODULE load_ntdll(size_t &v_size)
{
    CHAR ntdllPath[MAX_PATH];
    ExpandEnvironmentStrings("%SystemRoot%\\system32\\ntdll.dll", ntdllPath, MAX_PATH);

    HMODULE ntdll_module = (HMODULE) peconv::load_pe_module(ntdllPath, v_size, true, true);
    return ntdll_module;
}

bool init_ntdll_func(HMODULE lib)
{
    if (lib == nullptr) {
        return false;
    }
    FARPROC proc = peconv::get_exported_func(lib, "NtCreateProcessEx");
    if (proc == nullptr) {
        return false;
    }
    ntdll_NtCreateProcessEx = (NTSTATUS (NTAPI *)(
        PHANDLE,
        ACCESS_MASK,
        POBJECT_ATTRIBUTES,
        HANDLE,
        ULONG,
        HANDLE,
        HANDLE,
        HANDLE,
        BOOLEAN
    )) proc;

    proc = peconv::get_exported_func(lib, "RtlCreateProcessParametersEx");
    if (proc == nullptr) {
        return false;
    }
    ntdll_RtlCreateProcessParametersEx = (NTSTATUS (NTAPI *)(
        PRTL_USER_PROCESS_PARAMETERS*,
        PUNICODE_STRING,
        PUNICODE_STRING,
        PUNICODE_STRING,
        PUNICODE_STRING,
        PVOID,
        PUNICODE_STRING,
        PUNICODE_STRING,
        PUNICODE_STRING,
        PUNICODE_STRING,
        ULONG 
    )) proc;

    proc = peconv::get_exported_func(lib, "NtCreateThreadEx");
    if (proc == nullptr) {
        return false;
    }
    ntdll_NtCreateThreadEx = (NTSTATUS (NTAPI *)(
      PHANDLE, 
      ACCESS_MASK, 
      POBJECT_ATTRIBUTES, 
      HANDLE,
      LPTHREAD_START_ROUTINE,
      PVOID,
      ULONG,
      ULONG_PTR, 
      SIZE_T,
      SIZE_T, 
      PVOID
    )) proc;

    proc = peconv::get_exported_func(lib, "NtAllocateVirtualMemory");
    if (proc == nullptr) {
        return false;
    }
    ntdll_NtAllocateVirtualMemory = (NTSTATUS (NTAPI *)(
        HANDLE,
        PVOID*,
        ULONG_PTR,
        PSIZE_T,
        ULONG,
        ULONG
    )) proc;

    proc = peconv::get_exported_func(lib, "NtWriteVirtualMemory");
    if (proc == nullptr) {
        return false;
    }
    ntdll_NtWriteVirtualMemory = (NTSTATUS (NTAPI *)(
        HANDLE, //ProcessHandle
        PVOID, // BaseAddress
        PVOID, //Buffer
        ULONG, //NumberOfBytesToWrite
        PULONG //NumberOfBytesWritten OPTIONAL
    )) proc;

    proc = peconv::get_exported_func(lib, "NtCreateSection");
    if (proc == nullptr) {
        return false;
    }
    ntdll_NtCreateSection = (NTSTATUS (NTAPI *)(
        PHANDLE ,
        ACCESS_MASK,
        POBJECT_ATTRIBUTES,
        PLARGE_INTEGER,
        ULONG,
        ULONG,
        HANDLE
    )) proc;

    return true;
}

