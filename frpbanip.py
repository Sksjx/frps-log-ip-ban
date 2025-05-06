import os
import re
import subprocess
import ipaddress
import logging
from datetime import datetime, timedelta
from datetime import time as dt_time  # 重命名以避免冲突
from logging.handlers import TimedRotatingFileHandler
from time import sleep  # 直接导入sleep
import json

#---------软件日志输出----------
# 设置日志目录和文件
log_directory = 'log'
if not os.path.exists(log_directory):
    os.makedirs(log_directory)

log_file_name = os.path.join(log_directory, 'log_monitor.log')

# 设置日志和控制台输出
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# 使用 TimedRotatingFileHandler 进行日志管理
log_file_handler = TimedRotatingFileHandler(
    log_file_name,
    when='midnight',
    interval=1,
    backupCount=7,  # 保留7天的日志文件
    encoding='utf-8',
    atTime=dt_time(0, 0, 0)  # 确保午夜时切换日志文件
)
log_file_handler.suffix = "%Y-%m-%d.log"
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
log_file_handler.setFormatter(formatter)
logger.addHandler(log_file_handler)

console_handler = logging.StreamHandler()
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)
#---------软件日志输出----------
#---------变量配置--------------
with open("config.json", 'r', encoding='utf-8') as file:
    config = json.load(file)
LOG_FILE_PATH = config['LOG_FILE_PATH'] # frps的日志输出位置
TARGET_NAME = config['TARGET_NAME']
WHITELIST = config['WHITELIST'].split(';') # 白名单ip地址
BAN_FILE_PATH = config['BAN_FILE_PATH'] # 黑名单ip的储存位置
PYTHON_PATH = config['PYTHON_PATH'] # python环境位置
REMOTE_IP_NAME = config['REMOTE_IP_NAME']
EXECUTE_PATH = config['EXECUTE_PATH'] # banip.ps1文件的绝对地址
CHECK_INTERVAL = int(config['CHECK_INTERVAL'])
THRESHOLD_COUNT = int(config['THRESHOLD_COUNT'])
# 每'CHECK_INTERVAL'内,连接'THRESHOLD_COUNT'次,则判定为异常并加入黑名单
ANALIZE_TOTLE_LOG = int(config['ANALIZE_TOTLE_LOG']) # 是否追溯检查整个log文件,1为是,0为否
CHECK_FREQUENCY = int(config['CHECK_FREQUENCY']) # 程序每CHECK_FREQUENCY分钟检测一次
check_range = 0 # analyze_log中本次检测范围由log文件中第check_range行至末尾为止
print(check_range)
#---------变量配置--------------
def update_firewall_rule(ip_address): #更新防火墙规则
    rule_name = "Block IP"
    # 获取现有规则的详细信息
    try:
        # 先查看当前规则中的 remoteip 参数
        result = subprocess.run(['netsh', 'advfirewall', 'firewall', 'show', 'rule', f'name={rule_name}'],capture_output=True, text=True, check=True)
        # 获取已有的 remoteip 地址
    except subprocess.CalledProcessError: # 防火墙中没有Block IP规则
        command = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            "name=Block IP",
            "dir=in",
            "action=block",
            "protocol=TCP",
            "localport=8100",
            f"remoteip={ip_address}",
            "profile=any",
            "enable=yes"
        ]
        subprocess.run(command, check=True)
        print(f"New rules applied: Blocked {ip_address}")
        return
    
    output = result.stdout
    start = output.find(REMOTE_IP_NAME)  # 查找 "RemoteIP" 字段位置
    if start != -1:
        # 获取 RemoteIP 后面的地址列表
        remoteip = output[start:].splitlines()[0].split(':')[1].strip()
    else:
        remoteip = ""
    
    # 如果规则中已经有 IP 地址，添加新的 IP 到现有的 remoteip 地址列表
    if remoteip:
        ip_list = remoteip.split(',')
        if ip_address not in ip_list:
            ip_list.append(ip_address)  # 添加新 IP 地址
        new_remoteip = ','.join(ip_list)
    else:
        new_remoteip = ip_address  # 如果没有地址，直接设置新 IP 地址

    # 删除现有规则
    subprocess.run(['netsh', 'advfirewall', 'firewall', 'delete', 'rule', f'name={rule_name}'])
    
    # 重新添加规则（包含新的 IP 地址）
    command = [
        'netsh', 'advfirewall', 'firewall', 'add', 'rule',
        f'name={rule_name}',  # 规则名称
        'dir=in',  # 入站规则
        'action=block',  # 阻止访问
        'protocol=TCP',  # 协议
        f'remoteip={new_remoteip}',  # 更新后的 IP 地址
        'enable=yes',  # 启用规则
        'profile=any'  # 明确指定适用的配置文件
    ]
    
    subprocess.run(command, check=True)
    print(f"规则已更新：阻止 IP {new_remoteip} 对 TCP 访问")

def check_ip_whitelisted(ip): # 检查ip是否存在于白名单内
    try:
        for network in WHITELIST:
            # 如果是单独的IP地址，转换为网络格式
            if '/' not in network:
                network = f"{network}/32"
            if ipaddress.ip_address(ip) in ipaddress.ip_network(network, strict=False):
                logger.info(f"Whitelisted IP: {ip}")
                return True
    except ValueError as e:
        logger.error(f"Invalid IP address or network: {e}")
    return False


def execute_script(ip):
    script_extension = os.path.splitext(EXECUTE_PATH)[-1].lower()
    if script_extension == '.py': # 如果在linux系统,则用户设置EXECUTE_PATH为banip.py的路径,后缀为.py
        # 假设Python脚本需要以命令行参数的形式接收IP地址
        command = [PYTHON_PATH, EXECUTE_PATH, ip]
        try:
            subprocess.run(command, check=True)
            logger.info(f"Executed script for IP {ip}")
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to execute script for IP {ip}: {e}")
    else:
        update_firewall_rule(ip) # windows平台下直接执行


def update_ban_list(ip): # 更新黑名单
    if not ip:
        logger.error("Attempted to ban an empty IP address. Skipping.")
        return

    # 确保BAN_FILE_PATH目录存在
    os.makedirs(os.path.dirname(BAN_FILE_PATH), exist_ok=True)

    today_date = datetime.now().strftime("%Y/%m/%d")
    found = False
    updated_content = []

    # Reading the entire file and updating the memory copy
    if os.path.exists(BAN_FILE_PATH):
        with open(BAN_FILE_PATH, 'r') as file:
            lines = file.readlines()

        for line in lines:
            # Skip empty lines and malformed entries
            line = line.strip()
            if not line:
                logger.debug("Skipped empty line.")
                continue

            try:
                file_ip, file_date = line.split()
            except ValueError:
                logger.warning(f"Malformed line skipped: {line}")
                continue

            if file_ip == ip:
                updated_content.append(f"{ip}   {today_date}\n")  # Update the date for existing IP
                found = True
            else:
                updated_content.append(f"{file_ip}   {file_date}\n")  # Ensure proper format with newline

    if not found:
        updated_content.append(f"{ip}   {today_date}\n")  # Add new IP with the current date

    # Rewriting the updated content to the file
    with open(BAN_FILE_PATH, 'w') as file:
        file.writelines(updated_content)

    if found:
        logger.info(f"Updated existing IP {ip} in ban list with new date {today_date}.")   
    else:
        logger.info(f"Added new IP {ip} to ban list with date {today_date}.")
    execute_script(ip)


def analyze_log(check_range):
    now = datetime.now()
    time_threshold = now - timedelta(minutes=CHECK_INTERVAL)
    logger.info(f"Analyzing logs after {time_threshold}")

    ip_list = []  # 记录IP出现次数,形式如[["ip1","time1-1","time1-2",...],["ip2",...],...]
    try:
        with open(LOG_FILE_PATH, 'r') as file:
            lines = file.readlines()
            lines_len = len(lines)
            new_check_range = check_range
            if not ANALIZE_TOTLE_LOG:
                for i in range(check_range,lines_len+1): # 倒序查找包含TARGET_NAME的那一行
                    if TARGET_NAME in lines[-i]:
                        check_range = lines_len - i
            for i in range(check_range,lines_len):
                match_date = re.search(r'\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}',lines[i]) # 日期,格式如 2025/03/17 19:20:29
                ip_all = re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',lines[i]) # 匹配0-999.0-999.0-999.0-999
                ip = re.search(r'(?:(?:1[0-9][0-9]\.)|(?:2[0-4][0-9]\.)|(?:25[0-5]\.)|(?:[1-9][0-9]\.)|(?:[0-9]\.)){3}(?:(?:1[0-9][0-9])|(?:2[0-4][0-9])|(?:25[0-5])|(?:[1-9][0-9])|(?:[0-9]))',lines[i]) # 匹配0-255.0-255.0-255.0-255
                if ip_all and not ip:
                    logger.error(f"Detected wrong IP address {ip_all.group()} in line {i} in {LOG_FILE_PATH}")
                    continue
                # print("line:",line,"\nmatch:",match,"\nip_all:",ip_all,"\nip:",ip)
                if match_date and ip:
                    if datetime.strptime(match_date.group(), "%Y/%m/%d %H:%M:%S") > time_threshold: # 假如该行的时间早于本次检测时间的CHECK_INTERVAL分钟前,则下次检测由该行开始
                        new_check_range = i
                    do_ip = False
                    for j in range(len(ip_list)): # 将本次检测范围中的所有ip和时间都归入ip_list中
                        if ip_list[j][0] == ip.group():
                            ip_list[j].append(match_date.group())
                            do_ip = True
                            break
                    if not do_ip:
                        ip_list.append([ip.group(),match_date.group()])
                file.close()
                check_range = new_check_range
        for i in range(len(ip_list)):
            if len(ip_list[i]) > THRESHOLD_COUNT:
                ip = ip_list[i][0]
                if check_ip_whitelisted(ip): # 在白名单则跳过一次循环
                    continue
                for j in range(1,len(ip_list[i])):
                    count = 0
                    for k in range(j+1,len(ip_list[i])): # 以j为起点正序遍历并计数直到超过CHECK_INTERVAL
                        if datetime.strptime(ip_list[i][k],"%Y/%m/%d %H:%M:%S") < datetime.strptime(ip_list[i][j],"%Y/%m/%d %H:%M:%S") + timedelta(minutes=CHECK_INTERVAL):
                            count += 1
                        else: # 超过CHECK_INTERVAL
                            break
                        if count >= THRESHOLD_COUNT:
                            break
                    if count >= THRESHOLD_COUNT: # 检查IP出现次数是否达到阈值
                        logger.info(f"Detected ip {ip} log in too many times between {ip_list[i][j]} to {ip_list[i][k]}")
                        update_ban_list(ip)
                        break
    except FileNotFoundError as e:
        logger.error(f"Log file not found: {e}")
    except Exception as e:
        logger.error(f"Error reading log file: {e}")


def main_loop():
    while True:
        analyze_log(check_range)
        next_check = datetime.now() + timedelta(minutes=CHECK_FREQUENCY)
        logger.info(f"Next check scheduled at {next_check.strftime('%Y-%m-%d %H:%M:%S')}")
        sleep(CHECK_FREQUENCY * 60)


if __name__ == "__main__":
    try:
        main_loop()
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
