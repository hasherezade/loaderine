#pragma once

#include <Windows.h>
#include "ntddk.h"
#include "ntdll_types.h"

#define ntdll_NtCurrentProcess() ((HANDLE) -1)
#define ntdll_NtCurrentThread()  ((HANDLE) -2)

//Functions:
extern NTSTATUS (NTAPI *ntdll_NtCreateProcessEx)
(
    OUT PHANDLE     ProcessHandle,
    IN ACCESS_MASK  DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes  OPTIONAL,
    IN HANDLE   ParentProcess,
    IN ULONG    Flags,
    IN HANDLE SectionHandle     OPTIONAL,
    IN HANDLE DebugPort     OPTIONAL,
    IN HANDLE ExceptionPort     OPTIONAL,
    IN BOOLEAN  InJob
);

extern NTSTATUS (NTAPI *ntdll_RtlCreateProcessParametersEx)(
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
);

extern NTSTATUS (NTAPI *ntdll_NtCreateThreadEx) (
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
);

extern NTSTATUS (NTAPI *ntdll_NtAllocateVirtualMemory)(
  _In_    HANDLE    ProcessHandle,
  _Inout_ PVOID     *BaseAddress,
  _In_    ULONG_PTR ZeroBits,
  _Inout_ PSIZE_T   RegionSize,
  _In_    ULONG     AllocationType,
  _In_    ULONG     Protect
);

extern NTSTATUS (NTAPI * ntdll_NtWriteVirtualMemory)(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress,
    IN PVOID Buffer,
    IN ULONG NumberOfBytesToWrite,
    OUT PULONG NumberOfBytesWritten OPTIONAL
);

extern NTSTATUS (NTAPI *ntdll_NtCreateSection) (
    OUT PHANDLE SectionHandle,
    IN  ACCESS_MASK DesiredAccess,
    IN  POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN  PLARGE_INTEGER MaximumSize OPTIONAL,
    IN  ULONG SectionPageProtection,
    IN  ULONG AllocationAttributes,
    IN  HANDLE FileHandle OPTIONAL
);

// Load NTDLL by PEconv:
HMODULE load_ntdll(size_t &v_size);

// Initialize functions by PEconv
bool init_ntdll_func(HMODULE ntdll_hndl);
