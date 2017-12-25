#include <stdio.h>
#include <windows.h>

#include "ntdll_detached.h"
#include "peconv.h"
#include "shellcodes.h"

HANDLE run_shellcode_in_new_thread(HANDLE hProcess, LPVOID remote_shellcode_ptr)
{
    HANDLE hMyThread = NULL;
    NTSTATUS status = ntdll_NtCreateThreadEx(&hMyThread,
        THREAD_ALL_ACCESS,
        NULL,
        hProcess,
        (LPTHREAD_START_ROUTINE) remote_shellcode_ptr,
        NULL,
        0,
        0,
        0,
        0,
        NULL
    );
    if (status != STATUS_SUCCESS) {
        std::cerr << "[ERROR] NtCreateThreadEx failed, status : " << status << std::endl;
        return INVALID_HANDLE_VALUE;
    }
    return hMyThread;
}

int main(int argc, char *argv[])
{
    size_t ntdll_size = 0;
    HMODULE ntdll_mod = load_ntdll(ntdll_size);
    if (!init_ntdll_func(ntdll_mod)) {
        std::cerr << "Init failed!" << std:: endl;
        system("pause");
        return -1;
    }
    
    HANDLE hProcess = ntdll_NtCurrentProcess();
    PVOID base_addr = 0;
    SIZE_T buffer_size = 0x200;
    NTSTATUS status = ntdll_NtAllocateVirtualMemory(
        hProcess, 
        &base_addr, 0,
        &buffer_size, 
        MEM_COMMIT | MEM_RESERVE, 
        PAGE_EXECUTE_READWRITE
    );
    if (status != STATUS_SUCCESS) {
        std::cout << "Alloc failed!" << std::endl;
        system("pause");
        return -1;
    }
    std::cout << "Success" << std::endl;
    std::cout << base_addr << std::endl;
    PVOID shellcode_ptr = NULL;
    ULONG shellcode_size = 0;

#ifndef _WIN64
    shellcode_ptr = messageBox32bit_sc;
    shellcode_size = sizeof(messageBox32bit_sc);
#else
    shellcode_ptr = messageBox64bit_sc;
    shellcode_size = sizeof(messageBox64bit_sc);
#endif

    status = ntdll_NtWriteVirtualMemory(hProcess, base_addr, shellcode_ptr, shellcode_size, nullptr);
    if (status != STATUS_SUCCESS) {
        std::cout << "Writing failed!" << std::endl;
        system("pause");
        return -1;
    }
    HANDLE hThread = run_shellcode_in_new_thread(hProcess, base_addr);
    if (hThread != INVALID_HANDLE_VALUE) {
        std::cout << "Created Thread, id " << std::hex <<  GetThreadId(hThread);
        WaitForSingleObject(hThread, INFINITE);
    }
    return 0;
}
