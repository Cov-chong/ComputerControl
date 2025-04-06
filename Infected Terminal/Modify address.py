import sqlite3

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

if __name__ == "__main__":
    db_name = "server_info.db"  # 数据库名称

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

    input("按任意键退出...")
