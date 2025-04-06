#include <windows.h>
#include <tlhelp32.h>
#include <iostream>

// 挂起目标进程的所有线程
bool SuspendAllThreads(DWORD dwProcessID) {
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
                } else {
                    std::cerr << "无法挂起线程: " << te32.th32ThreadID << std::endl;
                }
                CloseHandle(hThread);
            }
        }
    } while (Thread32Next(hThreadSnapshot, &te32));

    CloseHandle(hThreadSnapshot);
    return true;
}

// 获取所有进程 ID
void SuspendAllProcesses() {
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    // 创建一个进程快照
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        std::cerr << "无法创建进程快照！" << std::endl;
        return;
    }

    // 遍历所有进程
    if (Process32First(hProcessSnap, &pe32)) {
        do {
            DWORD dwProcessID = pe32.th32ProcessID;
            if (dwProcessID != 0) { // 排除系统进程（PID为0）
                std::cout << "正在挂起进程: " << pe32.szExeFile << " (PID: " << dwProcessID << ")" << std::endl;
                if (!SuspendAllThreads(dwProcessID)) {
                    std::cerr << "无法挂起进程 " << pe32.szExeFile << " 的线程！" << std::endl;
                }
            }
        } while (Process32Next(hProcessSnap, &pe32));
    } else {
        std::cerr << "无法获取第一个进程！" << std::endl;
    }

    CloseHandle(hProcessSnap);
}

int main() {
    SuspendAllProcesses();
    std::cout << "所有进程的线程已挂起！" << std::endl;
    return 0;
}

