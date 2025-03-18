# Fork
- 本程序由[zsanjin-p/frps-log-ip-ban](https://github.com/zsanjin-p/frps-log-ip-ban)修改而来
# 改动
- 使用json库代替dotenv库,好处是本程序现在可以在白板python下运行,所有依赖库都是python自带库,且防止了环境变量可能造成的bug
- 将特征检测改为手动配置
- 修复了原程序中正则表达式匹配失效的情况
- 增加了python未被配置到环境变量的情况
# FRPS 日志 IP 封禁工具

此工具旨在增强 FRP (Fast Reverse Proxy) 的安全性，通过监控 FRPS 日志文件，自动封禁频繁尝试连接的异常 IP 地址。

## 功能特性
- 在frp 0.61.2测试通过，如果日志格式改动的话请修改[frpbanip.py](https://github.com/Sksjx/frps-log-ip-ban/blob/main/banip.py)的第156-158行的正则表达式来重新匹配
- 自动监控 FRPS 日志文件(注:请参照[frpc_full_example.toml](https://github.com/fatedier/frp/blob/dev/conf/frpc_full_example.toml)中前25行来启用frps的日志)。
- 根据配置的时间阈值和尝试次数自动封禁异常 IP。
- 支持设置白名单 IP。
- 封禁的 IP 地址会记录并在设定时间后自动解封。
- 支持 Windows 和 Linux 系统（宝塔面板所用的ufw管理防火墙）。
- 仅支持ipv4

## 快速开始

1. 克隆仓库或下载项目文件。
   ```
   git clone https://github.com/zsanjin-p/frps-log-ip-ban
   ```

2. 修改 `config.json` 环境变量文件(用UTF-8打开)，根据您的环境配置以下变量：

   - `LOG_FILE_PATH` : FRPS 日志文件路径。
   - `TARGET_NAME` : 在日志中表示frps开始服务的标志
   - `WHITELIST` : 白名单ip,支持单个ip如0.0.0.0和网段如1.2.3.4/32
   - `BAN_FILE_PATH` : 储存封禁ip的文件路径
   - `PYTHON_PATH` : python运行环境路径,如果环境变量中有python的话,此次直接填python即可,反之则填写python.exe的绝对路径
   - `EXECUTE_PATH` : windows下请填写banip.ps1的绝对路径,linux下请填写banip.py的绝对路径
   - `CHECK_INTERVAL` : 
   - `THRESHOLD_COUNT` : 如果一个ip在 CHECK_INTERVAL 分钟内,尝试连接了 THRESHOLD_COUNT 次,则判定为异常
   - `ANALIZE_TOTLE_LOG` : 是否追溯检查整个log文件,1为是,0为否
   - `CHECK_FREQUENCY` : 每 CHECK_FREQUENCY 分钟,程序检测一次日志

3. 根据您的操作系统选择对应的封禁 IP 脚本：

   - Windows: `banip.ps1`
   - Linux (宝塔面板UFW): `banip.py`

## 配置和使用

### Windows

1. 修改 `banip.ps1` 脚本，设置黑名单文件路径和封禁天数（默认为当天往前数30天）。
黑名单文件所在的位置：必改，大概在第7行左右，banip.ps1脚本默认为C:\Users\Administrator\Desktop\frps-log-ip-ban-main\banip.txt
封禁天数：把banip.ps1大概第4行$thresholdDate = (Get-Date).AddDays(-30)改为$thresholdDate = (Get-Date).AddDays(-99999)或者$thresholdDate = (Get-Date).AddDays(-30)改为$thresholdDate = (Get-Date).AddDays(99999)

2. 点击运行frpbanip.py即可。

3. 创建批处理文件 `.bat` 并通过计划任务程序可设置开机启动：
   ```bat
   @echo off
   cd C:\Users\Administrator\Desktop\frps-log-ip-ban-main\
   python frpbanip.py
   ```

### Linux

1. 修改 `banip.py` 脚本，适用于使用宝塔面板（UFW）管理防火墙的系统，设置黑名单文件路径和封禁天数（默认为当天往前数30天）。
黑名单文件所在的位置：必改，大概在第9行左右，banip.py脚本默认为/root/firewall/banipufw/banip.txt
封禁天数：把banip.py大概第6行threshold_date = (datetime.datetime.now() - datetime.timedelta(days=30)).strftime('%Y-%m-%d')改为threshold_date = (datetime.datetime.now() - datetime.timedelta(days=99999)).strftime('%Y-%m-%d')

2. 输入命令 `pyhton frpbanip.py` 即可运行。

3. 创建 Systemd 服务文件 `/etc/systemd/system/frpbanip.service`，将下面内容添加进去，注意修改 Python 路径和工作目录路径。

```
[Unit]
Description=FRP Log Ban IP Service
After=network.target

[Service]
ExecStart=/usr/bin/python3 /path/to/frpbanip.py
WorkingDirectory=/path/to
Restart=always
User=root

[Install]
WantedBy=multi-user.target
```


   重新加载 Systemd 配置并启动服务：
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl start frpbanip
   sudo systemctl enable frpbanip
   ```

## 许可证

本项目采用 BSD 2-Clause 或 3-Clause 许可证。

BSD 3-Clause License

Copyright (c) 2024, zsanjin
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the zsanjin nor the names of its contributors may be used
   to endorse or promote products derived from this software without specific
   prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


## 贡献

如果您喜欢此项目，请考虑给我们一个星标（star）！


