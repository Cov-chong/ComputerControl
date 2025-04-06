#include <windows.h>
#include <iostream>

// 全局钩子句柄
HHOOK g_hMouseHook = NULL;

// 鼠标钩子回调函数
LRESULT CALLBACK MouseHookProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode >= 0) {
        // 拦截所有鼠标消息
        return 1;  // 返回非零值表示阻止消息传递
    }
    return CallNextHookEx(g_hMouseHook, nCode, wParam, lParam);
}

int main() {
    // 安装鼠标钩子
    g_hMouseHook = SetWindowsHookEx(WH_MOUSE_LL, MouseHookProc, NULL, 0);
    if (!g_hMouseHook) {
        std::cerr << "无法安装鼠标钩子！" << std::endl;
        return 1;
    }

    std::cout << "鼠标钩子已安装，鼠标事件将被拦截！" << std::endl;

    // 消息循环
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    // 卸载鼠标钩子
    UnhookWindowsHookEx(g_hMouseHook);
    std::cout << "鼠标钩子已卸载，鼠标事件恢复正常！" << std::endl;

    return 0;
}
