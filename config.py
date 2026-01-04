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
    "user2@example.com": {
        "email_address": "user2@example.com", 
        "password": "password2", 
        "username":"admin123",  # 可选，默认使用邮箱地址作为用户名
        "exchange_server": exchange_server
    },
}

# 爬虫配置
CRAWLER_CONFIG = {"days": 3, "output_dir": "eml_exports", "log_file": "email_crawler.log"}  # 要获取的天数（设置为0则获取所有邮件，不限制时间）  # 输出目录  # 日志文件
