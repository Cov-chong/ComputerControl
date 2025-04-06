#include <windows.h>
#include <tlhelp32.h>
#include <iostream>

// ����Ŀ����̵����߳�
bool SuspendMainThread(DWORD dwProcessID) {
    HANDLE hThreadSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThreadSnapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "�޷������߳̿��գ�" << std::endl;
        return false;
    }

    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);

    if (!Thread32First(hThreadSnapshot, &te32)) {
        std::cerr << "�޷���ȡ��һ���̣߳�" << std::endl;
        CloseHandle(hThreadSnapshot);
        return false;
    }

    do {
        if (te32.th32OwnerProcessID == dwProcessID) {
            // �ҵ�Ŀ����̵��߳�
            HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te32.th32ThreadID);
            if (hThread) {
                // �����߳�
                if (SuspendThread(hThread) != -1) {
                    std::cout << "�ѹ����߳�: " << te32.th32ThreadID << std::endl;
                    CloseHandle(hThread);
                    CloseHandle(hThreadSnapshot);
                    return true;
                }
                CloseHandle(hThread);
            }
        }
    } while (Thread32Next(hThreadSnapshot, &te32));

    CloseHandle(hThreadSnapshot);
    std::cerr << "δ�ҵ�Ŀ����̵����̣߳�" << std::endl;
    return false;
}

int get_pid_by_name(const std::string &process_name) {
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    // ����һ������
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to take process snapshot" << std::endl;
        return false;
    }

    // �������н���
    if (Process32First(hProcessSnap, &pe32)) {
        do {
            // ���������ƥ�䣬��ӡ PID
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
	std::string process_name = "vmware.exe"; // Ҫ���ҵĽ�����
    DWORD pid = get_pid_by_name(process_name);
    if (SuspendMainThread(pid)) {
        std::cout << "Ŀ����̵����߳��ѹ���" << std::endl;
    } else {
        std::cerr << "����Ŀ����̵����߳�ʧ�ܣ�" << std::endl;
    }
    return 0;
}
