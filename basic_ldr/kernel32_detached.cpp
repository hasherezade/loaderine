#include "kernel32_detached.h"

HANDLE  (WINAPI *kernel32_OpenProcess)(
    _In_ DWORD dwDesiredAccess,
    _In_ BOOL bInheritHandle,
    _In_ DWORD dwProcessId
    ) = NULL;

BOOL (WINAPI *kernel32_WriteProcessMemory)(
    _In_ HANDLE hProcess,
    _In_ LPVOID lpBaseAddress,
    _In_reads_bytes_(nSize) LPCVOID lpBuffer,
    _In_ SIZE_T nSize,
    _Out_opt_ SIZE_T * lpNumberOfBytesWritten
) = NULL;

HANDLE (WINAPI *kernel32_CreateFileW)(
    _In_ LPCWSTR lpFileName,
    _In_ DWORD dwDesiredAccess,
    _In_ DWORD dwShareMode,
    _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    _In_ DWORD dwCreationDisposition,
    _In_ DWORD dwFlagsAndAttributes,
    _In_opt_ HANDLE hTemplateFile
) = NULL;

HMODULE load_kernel32(buffered_dlls_resolver *my_resolver)
{
    CHAR path[MAX_PATH];
    ExpandEnvironmentStrings("%SystemRoot%\\system32\\kernel32.dll", path, MAX_PATH);
    size_t v_size = 0;

    PBYTE module = peconv::load_pe_executable(
        path, 
        v_size,
        reinterpret_cast<peconv::t_function_resolver*>(my_resolver)
    );
    if (!module) {
        return nullptr;
    }
    printf("base: %p\n", module);
    return (HMODULE) module;
}

bool init_kernel32_func(HMODULE lib)
{
    if (lib == nullptr) {
        return false;
    }

    //OpenProcess:
    FARPROC proc = peconv::get_exported_func(lib, "OpenProcess");
    if (proc == nullptr) {
        return false;
    }
    kernel32_OpenProcess = (HANDLE (WINAPI *)(
        DWORD,
        BOOL,
        DWORD
    )) proc;

    //WriteProcessMemory
    proc = peconv::get_exported_func(lib, "WriteProcessMemory");
    if (proc == nullptr) {
        return false;
    }
    kernel32_WriteProcessMemory = (BOOL (WINAPI *)(
        HANDLE,
        LPVOID,
        LPCVOID,
        SIZE_T,
        SIZE_T *
    )) proc;

    //CreateFileW
    proc = peconv::get_exported_func(lib, "CreateFileW");
    if (proc == nullptr) {
        return false;
    }
    kernel32_CreateFileW = (HANDLE (WINAPI *)(
        LPCWSTR,
        DWORD,
        DWORD,
        LPSECURITY_ATTRIBUTES,
        DWORD,
        DWORD,
        HANDLE
    )) proc;

    return true;
}
