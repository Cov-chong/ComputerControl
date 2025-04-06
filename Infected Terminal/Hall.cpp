#include <windows.h>
#include <tlhelp32.h>
#include <iostream>

// ����Ŀ����̵������߳�
bool SuspendAllThreads(DWORD dwProcessID) {
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
                } else {
                    std::cerr << "�޷������߳�: " << te32.th32ThreadID << std::endl;
                }
                CloseHandle(hThread);
            }
        }
    } while (Thread32Next(hThreadSnapshot, &te32));

    CloseHandle(hThreadSnapshot);
    return true;
}

// ��ȡ���н��� ID
void SuspendAllProcesses() {
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    // ����һ�����̿���
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        std::cerr << "�޷��������̿��գ�" << std::endl;
        return;
    }

    // �������н���
    if (Process32First(hProcessSnap, &pe32)) {
        do {
            DWORD dwProcessID = pe32.th32ProcessID;
            if (dwProcessID != 0) { // �ų�ϵͳ���̣�PIDΪ0��
                std::cout << "���ڹ������: " << pe32.szExeFile << " (PID: " << dwProcessID << ")" << std::endl;
                if (!SuspendAllThreads(dwProcessID)) {
                    std::cerr << "�޷�������� " << pe32.szExeFile << " ���̣߳�" << std::endl;
                }
            }
        } while (Process32Next(hProcessSnap, &pe32));
    } else {
        std::cerr << "�޷���ȡ��һ�����̣�" << std::endl;
    }

    CloseHandle(hProcessSnap);
}

int main() {
    SuspendAllProcesses();
    std::cout << "���н��̵��߳��ѹ���" << std::endl;
    return 0;
}

