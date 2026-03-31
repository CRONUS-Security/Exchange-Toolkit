#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
配置文件
"""

# Exchange服务器地址（如果不设置，将使用自动发现）
exchange_server = "owa.example.com"

# 邮箱配置
# 注意：Exchange连接不需要指定端口，会自动使用HTTPS (443)

EMAIL_CONFIG = {
    "user1@example.com": {
        "email_address": "user1@example.com", 
        "password": "password1", 
        "exchange_server": exchange_server
    },
    
    # NTLM 哈希认证示例（Pass-the-Hash）
    # 当客户安全策略不允许提供明文密码时使用
    # username 需包含域名，格式为 "DOMAIN\\username"
    # ntlm_hash 支持两种格式：
    #   - 纯 NT 哈希：32位十六进制字符串，如 "8846f7eaee8fb117ad06bdd830b7586c"
    #   - LM:NT 格式：两段哈希以冒号分隔，如 "aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c"
    "user3@example.com": {
        "email_address": "user3@example.com",
        "username": "DOMAIN\\user3",          # 必须包含域名前缀
        "ntlm_hash": "8846f7eaee8fb117ad06bdd830b7586c",  # 或 "LMhash:NThash"
        "exchange_server": exchange_server,
    },
}

# 爬虫配置
CRAWLER_CONFIG = {"days": 3, "output_dir": "eml_exports", "log_file": "email_crawler.log"}  # 要获取的天数（设置为0则获取所有邮件，不限制时间）  # 输出目录  # 日志文件
