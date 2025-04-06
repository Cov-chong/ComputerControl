#include <windows.h>
#include <tlhelp32.h>
#include <iostream>

// 挂起目标进程的主线程
bool SuspendMainThread(DWORD dwProcessID) {
    HANDLE hThreadSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThreadSnapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "无法创建线程快照！" << std::endl;
        return false;
    }

    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);

    if (!Thread32First(hThreadSnapshot, &te32)) {
        std::cerr << "无法获取第一个线程！" << std::endl;
        CloseHandle(hThreadSnapshot);
        return false;
    }

    do {
        if (te32.th32OwnerProcessID == dwProcessID) {
            // 找到目标进程的线程
            HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te32.th32ThreadID);
            if (hThread) {
                // 挂起线程
                if (SuspendThread(hThread) != -1) {
                    std::cout << "已挂起线程: " << te32.th32ThreadID << std::endl;
                    CloseHandle(hThread);
                    CloseHandle(hThreadSnapshot);
                    return true;
                }
                CloseHandle(hThread);
            }
        }
    } while (Thread32Next(hThreadSnapshot, &te32));

    CloseHandle(hThreadSnapshot);
    std::cerr << "未找到目标进程的主线程！" << std::endl;
    return false;
}

int get_pid_by_name(const std::string &process_name) {
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    // 创建一个快照
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to take process snapshot" << std::endl;
        return false;
    }

    // 遍历所有进程
    if (Process32First(hProcessSnap, &pe32)) {
        do {
            // 如果进程名匹配，打印 PID
            if (process_name == pe32.szExeFile) {
                CloseHandle(hProcessSnap);
                return pe32.th32ProcessID;
            }
        } while (Process32Next(hProcessSnap, &pe32));
    }

    CloseHandle(hProcessSnap);
    std::cerr << "Process not found!" << std::endl;
    return false;
}

int main() {
	std::string process_name = "vmware.exe"; // 要查找的进程名
    DWORD pid = get_pid_by_name(process_name);
    if (SuspendMainThread(pid)) {
        std::cout << "目标进程的主线程已挂起！" << std::endl;
    } else {
        std::cerr << "挂起目标进程的主线程失败！" << std::endl;
    }
    return 0;
}
