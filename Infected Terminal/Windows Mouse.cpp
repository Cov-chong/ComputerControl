#include <windows.h>
#include <iostream>

// ȫ�ֹ��Ӿ��
HHOOK g_hMouseHook = NULL;

// ��깳�ӻص�����
LRESULT CALLBACK MouseHookProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode >= 0) {
        // �������������Ϣ
        return 1;  // ���ط���ֵ��ʾ��ֹ��Ϣ����
    }
    return CallNextHookEx(g_hMouseHook, nCode, wParam, lParam);
}

int main() {
    // ��װ��깳��
    g_hMouseHook = SetWindowsHookEx(WH_MOUSE_LL, MouseHookProc, NULL, 0);
    if (!g_hMouseHook) {
        std::cerr << "�޷���װ��깳�ӣ�" << std::endl;
        return 1;
    }

    std::cout << "��깳���Ѱ�װ������¼��������أ�" << std::endl;

    // ��Ϣѭ��
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    // ж����깳��
    UnhookWindowsHookEx(g_hMouseHook);
    std::cout << "��깳����ж�أ�����¼��ָ�������" << std::endl;

    return 0;
}
