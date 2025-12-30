#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
使用配置文件运行邮箱爬虫程序 - Exchange版本
"""

import os
import sys
import logging
import datetime
from typing import List, Dict, Tuple
from exchangelib import Credentials, Account, DELEGATE, Configuration, Version, Build
from exchangelib.folders import FolderCollection
from exchangelib.protocol import BaseProtocol, NoVerifyHTTPAdapter
import urllib3
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TimeRemainingColumn
import re

# 禁用SSL警告（如果使用自签名证书）
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# UUID Regex
UUID_REGEX = re.compile(r'[0-9a-fA-F]{8}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{12}', re.IGNORECASE)

# Pure Integer Regex
PURE_INTEGER_REGEX = re.compile(r'^\d+$')

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("email_crawler.log", encoding="utf-8"), logging.StreamHandler()],
)
logger = logging.getLogger(__name__)

CHECK_ONLY = False

def check_folder_name(folder_name: str) -> bool:
    """
    检查文件夹名称是否有效

    Args:
        folder_name: 文件夹名称

    Returns:
        bool: 是否有效
    """
    black_list=["System", "Versions"]
    # 检查是否为UUID
    if UUID_REGEX.fullmatch(folder_name):
        return False
    # 检查是否为纯数字
    if PURE_INTEGER_REGEX.fullmatch(folder_name):
        return False
    # 检查是否在黑名单中
    if folder_name in black_list:
        return False
    return True


class EmailCrawler:
    def __init__(self, email_address: str, username:str|None, password: str, exchange_server: str = None, port: int = None):
        """
        初始化邮箱爬虫 - Exchange版本

        Args:
            email_address: 邮箱地址
            password: 邮箱密码
            exchange_server: Exchange服务器地址（可选，会自动发现）
            port: Exchange端口（可选）
        """
        self.email_address = email_address
        self.username = username
        self.password = password
        self.exchange_server = exchange_server
        self.port = port
        self.account = None
        self.output_dir = "exports"

        # 创建输出目录
        os.makedirs(self.output_dir, exist_ok=True)

    def connect(self) -> bool:
        """
        连接到Exchange服务器

        Returns:
            bool: 连接是否成功
        """
        try:
            logger.info(f"正在连接到Exchange服务器: {self.email_address}")
            
            # 创建凭据
            if self.username:
                credentials = Credentials(username=self.username, password=self.password)
            else:
                credentials = Credentials(username=self.email_address, password=self.password)
            
            # 禁用SSL验证（如果使用自签名证书）
            BaseProtocol.HTTP_ADAPTER_CLS = NoVerifyHTTPAdapter
            
            if self.exchange_server:
                # 如果提供了服务器地址，使用手动配置
                config = Configuration(
                    server=self.exchange_server,
                    credentials=credentials,
                    auth_type='NTLM'  # 或者使用 'basic'
                )
                self.account = Account(
                    primary_smtp_address=self.email_address,
                    config=config,
                    autodiscover=False,
                    access_type=DELEGATE
                )
            else:
                # 使用自动发现
                self.account = Account(
                    primary_smtp_address=self.email_address,
                    credentials=credentials,
                    autodiscover=True,
                    access_type=DELEGATE
                )
            
            logger.info("Exchange连接成功")
            return True
        except Exception as e:
            logger.error(f"Exchange连接失败: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return False

    def get_all_folders(self) -> List[Tuple[str, str]]:
        """
        获取所有邮箱文件夹

        Returns:
            List[Tuple[str, str]]: 文件夹列表，元组格式为 (文件夹对象, 文件夹名称)
        """
        try:
            logger.info("正在获取Exchange文件夹列表...")
            folder_list = []
            
            # 递归获取所有文件夹
            def get_folders_recursive(folder):
                try:
                    folder_name = folder.name
                    folder_list.append((folder, folder_name))
                    
                    # 递归获取子文件夹
                    if hasattr(folder, 'children') and folder.children:
                        for child in folder.children:
                            get_folders_recursive(child)
                except Exception as e:
                    logger.warning(f"处理文件夹时出错: {e}")
            
            # 从根文件夹开始
            get_folders_recursive(self.account.root)
            
            logger.info(f"找到 {len(folder_list)} 个文件夹")
            return folder_list
        except Exception as e:
            logger.error(f"获取文件夹列表时出错: {e}")
            return []

    def get_recent_emails(self, days: int = 30) -> Dict[str, List[Tuple[str, object]]]:
        """
        获取近期的邮件

        Args:
            days: 天数，默认30天

        Returns:
            Dict[str, List[Tuple[str, object]]]: 按文件夹分组的邮件列表
        """
        try:
            # 计算日期范围
            since_date = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=days)

            logger.info(f"搜索 {days} 天内的邮件 (从 {since_date.strftime('%Y-%m-%d')} 开始)")

            folders = self.get_all_folders()
            all_emails = {}
    
            # 使用 rich 进度条
            with Progress() as progress:
                folders_task = progress.add_task("[green]文件夹遍历中...", total=len(folders))
                
                for folder_obj, folder_name in folders:
                    # 检查文件夹名称有效性
                    if not check_folder_name(folder_name):
                        logger.info(f"跳过无效文件夹: {folder_name}")
                        progress.update(folders_task, advance=1)
                        continue
                    try:
                        # 更新进度条显示当前文件夹
                        progress.update(folders_task, folder_name=f"[{folder_name}]")
                        logger.info(f"正在处理文件夹: {folder_name}")

                        # 获取文件夹中的邮件
                        try:
                            # 过滤近期邮件
                            items = folder_obj.filter(datetime_received__gte=since_date)
                            email_count = items.count()
                            
                            logger.info(f"在文件夹 {folder_name} 中找到 {email_count} 封邮件")

                            emails_in_folder = []
                            
                            # 遍历邮件
                            with Progress() as progress:
                                emails_task = progress.add_task(f"[cyan]处理邮件...", total=email_count)
                                for idx, item in enumerate(items):
                                    try:
                                        # 保存邮件对象和ID
                                        email_id = f"{idx+1}"
                                        emails_in_folder.append((email_id, item))
                                    except Exception as e:
                                        logger.error(f"处理邮件时出错: {e}")
                                        continue
                                    finally:
                                        progress.update(emails_task, advance=1)

                            all_emails[folder_name] = emails_in_folder

                        except Exception as e:
                            logger.warning(f"文件夹 {folder_name} 不支持邮件操作或为空: {e}")
                            progress.update(folders_task, advance=1)
                            continue

                        # folders_task
                        progress.update(folders_task, advance=1)

                    except Exception as e:
                        logger.error(f"处理文件夹 {folder_name} 时出错: {e}")
                        progress.update(folders_task, advance=1)
                        continue

            return all_emails

        except Exception as e:
            logger.error(f"获取邮件时出错: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return {}

    def save_eml_files(self, emails: Dict[str, List[Tuple[str, object]]]) -> int:
        """
        将邮件保存为eml文件

        Args:
            emails: 邮件数据

        Returns:
            int: 成功保存的文件数量
        """
        saved_count = 0
        
        # 计算总邮件数
        total_emails = sum(len(email_list) for email_list in emails.values())
        
        if total_emails == 0:
            logger.info("没有邮件需要保存")
            return 0

        # 使用 rich 进度条
        with Progress() as progress:
            emails_task = progress.add_task("[green]保存邮件...", total=total_emails)

            for folder, email_list in emails.items():
                # 创建文件夹对应的目录
                folder_dir = os.path.join(self.output_dir, self._sanitize_folder_name(folder))
                os.makedirs(folder_dir, exist_ok=True)

                for email_id, item in email_list:
                    try:
                        # 获取邮件主题
                        subject = item.subject if item.subject else "无主题"
                        
                        # 截断主题用于显示
                        display_subject = subject[:40] + "..." if len(subject) > 40 else subject
                        progress.update(emails_task, current_info=f"[{folder}] {display_subject}")
                        
                        # 获取邮件接收时间
                        email_datetime = item.datetime_received

                        # 生成文件名
                        filename = self._generate_filename(email_id, subject, email_datetime)
                        filepath = os.path.join(folder_dir, filename)

                        # 获取MIME内容并保存为eml文件
                        mime_content = item.mime_content
                        with open(filepath, "wb") as f:
                            f.write(mime_content)

                        logger.info(f"已保存: {filepath}")
                        saved_count += 1
                        
                        # 更新进度
                        progress.update(emails_task, advance=1)

                    except Exception as e:
                        logger.error(f"保存邮件 {email_id} 时出错: {e}")
                        # 即使出错也要更新进度
                        progress.update(emails_task, advance=1)
                        continue

        return saved_count

    def _sanitize_folder_name(self, folder_name: str) -> str:
        """
        清理文件夹名称，使其适合作为目录名

        Args:
            folder_name: 原始文件夹名称

        Returns:
            str: 清理后的文件夹名称
        """
        # 替换不安全的字符
        unsafe_chars = ["/", "\\", ":", "*", "?", '"', "<", ">", "|"]
        for char in unsafe_chars:
            folder_name = folder_name.replace(char, "_")
        return folder_name

    def _generate_filename(self, email_id: str, subject: str, email_datetime: datetime.datetime = None) -> str:
        """
        生成文件名

        Args:
            email_id: 邮件ID
            subject: 邮件主题
            email_datetime: 邮件的接收时间

        Returns:
            str: 文件名
        """
        # 清理主题中的不安全字符
        unsafe_chars = ["/", "\\", ":", "*", "?", '"', "<", ">", "|"]
        for char in unsafe_chars:
            subject = subject.replace(char, "_")

        # 限制文件名长度
        if len(subject) > 100:
            subject = subject[:100] + "..."

        # 使用邮件的接收时间，如果没有则使用当前时间
        if email_datetime:
            # 转换为本地时间
            timestamp = email_datetime.astimezone().strftime("%Y%m%d_%H%M%S")
        else:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        
        filename = f"{timestamp}_{email_id}_{subject}.eml"

        return filename

    def disconnect(self):
        """断开邮箱连接"""
        if self.account:
            try:
                logger.info("Exchange连接已关闭")
                self.account = None
            except Exception as e:
                logger.error(f"关闭Exchange连接时出错: {e}")

    def run_crawler(self, days: int = 30) -> bool:
        """
        运行爬虫程序

        Args:
            days: 要获取的天数，默认30天

        Returns:
            bool: 是否成功
        """
        try:
            # 连接邮箱
            if not self.connect():
                return False
            if CHECK_ONLY:
                logger.info("仅检查连接成功，未进行邮件下载。")
                return True

            # 获取邮件
            emails = self.get_recent_emails(days)

            if not emails:
                logger.warning("没有找到符合条件的邮件")
                return True

            total_emails = sum(len(email_list) for email_list in emails.values())
            logger.info(f"总共找到 {total_emails} 封邮件")

            # 保存邮件
            saved_count = self.save_eml_files(emails)
            logger.info(f"成功保存 {saved_count} 封邮件到 {self.output_dir} 目录")

            return True

        except Exception as e:
            logger.error(f"运行爬虫程序时出错: {e}")
            return False
        finally:
            self.disconnect()


def load_config():
    """加载配置文件"""
    try:
        # 尝试导入配置文件
        sys.path.append(".")
        from config import EMAIL_CONFIG, CRAWLER_CONFIG

        print("=" * 50)
        print("邮箱爬虫程序 - 配置版本")
        print("=" * 50) 

        # 显示可用的配置
        print("可用的邮箱配置:")
        for key in EMAIL_CONFIG.keys():
            print(f"  - {key}")

        return EMAIL_CONFIG, CRAWLER_CONFIG

    except ImportError:
        print("❌ 配置文件 config.py 不存在！")
        print("请先复制 config_example.py 为 config.py 并填入您的配置")
        return None, None
    except Exception as e:
        print(f"❌ 加载配置时出错: {e}")
        return None, None


def main():
    """主函数"""
    # 加载配置
    email_configs, crawler_config = load_config()

    if not email_configs or not crawler_config:
        return

    days = crawler_config.get("days", 30)
    total_saved = 0

    # 遍历所有邮箱配置
    for key, email_config in email_configs.items():
        print(f"\n{'='*50}")
        print(f"正在处理: {key}")
        print(f"{'='*50}")
        
        print(f"邮箱地址: {email_config['email_address']}")
        print(f"Exchange服务器: {email_config.get('exchange_server', '自动发现')}")
        print(f"获取天数: {days}天")

        # 创建爬虫实例
        if "username" in email_config.keys():
            crawler = EmailCrawler(
                email_address=email_config["email_address"],
                username=email_config["username"],
                password=email_config["password"],
                exchange_server=email_config.get("exchange_server"),
                port=email_config.get("port"),
            )
        else:
            crawler = EmailCrawler(
                email_address=email_config["email_address"],
                username=None,
                password=email_config["password"],
                exchange_server=email_config.get("exchange_server"),
                port=email_config.get("port"),
            )

        # 设置输出目录为以key命名的子文件夹
        key_output_dir = os.path.join("exports", key)
        crawler.output_dir = key_output_dir
        os.makedirs(key_output_dir, exist_ok=True)

        print(f"开始获取近 {days} 天的邮件...")

        success = crawler.run_crawler(days)

        if success:
            print(f"✅ {key} 邮件导出完成！")
            print(f"邮件已保存到: {key_output_dir} 目录")
        else:
            print(f"❌ {key} 邮件导出失败，请检查日志文件: email_crawler.log")

    print(f"\n{'='*50}")
    print("所有邮箱处理完成！")
    print(f"{'='*50}")


if __name__ == "__main__":
    main()
