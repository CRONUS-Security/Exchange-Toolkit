#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Mail Crawler - Exchange Version
"""

import os
import sys
import logging
import datetime
from typing import List, Dict, Tuple
from exchangelib import Credentials, Account, DELEGATE, Configuration, Version, Build
from exchangelib.folders import FolderCollection
from exchangelib.protocol import BaseProtocol, NoVerifyHTTPAdapter
from exchangelib.protocol import Protocol, CachingProtocol
import urllib3
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TimeRemainingColumn
import re
from requests_ntlm import HttpNtlmAuth
from spnego._credential import NTLMHash

# disable InsecureRequestWarning when connecting to servers with self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# UUID Regex
UUID_REGEX = re.compile(r"[0-9a-fA-F]{8}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{12}", re.IGNORECASE)

# Pure Integer Regex
PURE_INTEGER_REGEX = re.compile(r"^\d+$")

# setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("email_crawler.log", encoding="utf-8"), logging.StreamHandler()],
)
logger = logging.getLogger(__name__)

CHECK_ONLY = False


def _parse_ntlm_hash(ntlm_hash_str: str) -> tuple[str, str | None]:
    """
    parse NTLM hash string into NT and LM components.

    Supports two formats:
      - Pure NT hash (32 hex characters): lm_hash returns None
      - LM:NT format: colon-separated two-part hash

    Returns:
        (nt_hash_hex, lm_hash_hex_or_None)
    """
    ntlm_hash_str = ntlm_hash_str.strip()
    if ":" in ntlm_hash_str:
        lm_part, nt_part = ntlm_hash_str.split(":", 1)
        lm_part = lm_part.strip() or None
        nt_part = nt_part.strip()
    else:
        lm_part = None
        nt_part = ntlm_hash_str
    return nt_part, lm_part


class HttpNtlmHashAuth(HttpNtlmAuth):
    """
    NTLM Pass-the-Hash authentication.

    Based on requests-ntlm + spnego.NTLMHash credentials, injects NT/LM hashes directly into the NTLM handshake,
    without requiring a plaintext password. protocol="ntlm" ensures the use of pure Python NTLM implementation instead of SSPI.
    """

    def __init__(self, username: str, nt_hash_hex: str, lm_hash_hex: str | None = None, send_cbt: bool = True):
        # spnego.NTLMHash accepts hexadecimal strings; username should include the domain (DOMAIN\\user)
        ntlm_cred = NTLMHash(username=username, nt_hash=nt_hash_hex, lm_hash=lm_hash_hex)
        # The parent class's retry_using_http_NTLM_auth will pass self.username directly to spnego.client()
        # When username is an NTLMHash credential object, spnego uses the hash instead of a password for authentication
        self.username = ntlm_cred
        self.password = None
        self.send_cbt = send_cbt
        self.session_security = None


class NTLMHashProtocol(Protocol):
    """
    exchangelib Protocol subclass that injects HttpNtlmHashAuth into create_session().
    """

    def __init__(self, *args, ntlm_hash_auth: HttpNtlmHashAuth = None, **kwargs):
        super().__init__(*args, **kwargs)
        self._ntlm_hash_auth = ntlm_hash_auth

    def create_session(self):
        session = super().create_session()
        if self._ntlm_hash_auth is not None:
            session.auth = self._ntlm_hash_auth
        return session


def load_config():
    """Load configuration file"""
    try:
        # Try to import the configuration file
        sys.path.append(".")
        from config import EMAIL_CONFIG, CRAWLER_CONFIG

        print("=" * 50)
        print("Mail Crawler - Exchange Version")
        print("=" * 50)

        # Display available configurations
        print("Available email configurations:")
        for key in EMAIL_CONFIG.keys():
            print(f"  - {key}")

        return EMAIL_CONFIG, CRAWLER_CONFIG

    except ImportError:
        print("❌ Configuration file config.py does not exist!")
        print("Please copy config_example.py to config.py and fill in your configuration")
        return None, None
    except Exception as e:
        print(f"❌ Error loading configuration: {e}")
        return None, None


def check_folder_name(folder_name: str) -> bool:
    """
    Check if the folder name is valid

    Args:
        folder_name: Folder name

    Returns:
        bool: Whether the folder name is valid
    """
    black_list = ["System", "Versions"]
    # Check if UUID exists
    if UUID_REGEX.search(folder_name):
        return False
    # Check if it is a pure integer
    if PURE_INTEGER_REGEX.fullmatch(folder_name):
        return False
    # Check if it is in the blacklist
    if folder_name in black_list:
        return False
    return True


class EmailCrawler:
    def __init__(
        self,
        email_address: str,
        username: str | None,
        password: str | None = None,
        exchange_server: str = None,
        port: int = None,
        ntlm_hash: str | None = None,
    ):
        """
        Initialize the email crawler - Exchange version

        Args:
            email_address: Email address
            username: Username (must include domain for hash authentication, e.g., DOMAIN\\username)
            password: Email password (used for plaintext authentication)
            exchange_server: Exchange server address (optional, autodiscover will be used if not provided)
            port: Exchange port (optional)
            ntlm_hash: NTLM hash string, takes precedence over password.
                       Supports pure NT hash (32 hexadecimal characters) or LM:NT format.
        """
        self.email_address = email_address
        self.username = username
        self.password = password
        self.ntlm_hash = ntlm_hash
        self.exchange_server = exchange_server
        self.port = port
        self.account = None
        self.output_dir = "exports"

        # Create output directory
        os.makedirs(self.output_dir, exist_ok=True)

    def connect(self) -> bool:
        """
        Connect to the Exchange server

        Returns:
            bool: Whether the connection was successful
        """
        try:
            logger.info(f"Connecting to Exchange server: {self.email_address}")

            # Disable SSL verification (if using self-signed certificates)
            BaseProtocol.HTTP_ADAPTER_CLS = NoVerifyHTTPAdapter

            if self.ntlm_hash:
                # --- NTLM Hash Authentication (Pass-the-Hash) Path ---
                logger.info("Using NTLM Hash Authentication (Pass-the-Hash)")

                raw_username = self.username or self.email_address

                # Parse the hash (returns hexadecimal strings)
                nt_hash_hex, lm_hash_hex = _parse_ntlm_hash(self.ntlm_hash)

                # Construct the hash authentication object (using full DOMAIN\\username as the spnego credential username)
                hash_auth = HttpNtlmHashAuth(
                    username=raw_username,
                    nt_hash_hex=nt_hash_hex,
                    lm_hash_hex=lm_hash_hex,
                )

                if not self.exchange_server:
                    raise ValueError("NTLM hash authentication requires manual specification of exchange_server, autodiscover is not supported")

                # exchangelib requires Credentials, pass a placeholder (actual authentication is handled by hash_auth)
                credentials = Credentials(username=raw_username, password="placeholder_unused")
                config = Configuration(
                    server=self.exchange_server,
                    credentials=credentials,
                    auth_type="NTLM",
                )
                # Account internally creates Protocol(config=config) and does not accept an external protocol parameter.
                # First, create the Account normally (at this point, CachingProtocol caches the original Protocol instance),
                # then delete the cache entry, create NTLMHashProtocol (cache miss → actual instantiation),
                # and finally replace account.protocol to ensure the replacement is done before any EWS requests are made.
                self.account = Account(
                    primary_smtp_address=self.email_address,
                    config=config,
                    autodiscover=False,
                    access_type=DELEGATE,
                )
                # Delete the cache entry in CachingProtocol to trigger actual instantiation of NTLMHashProtocol(config=...)
                del Protocol[config]
                self.account.protocol = NTLMHashProtocol(
                    config=config,
                    ntlm_hash_auth=hash_auth,
                )
            else:
                # --- Plain Password Authentication Path (keep original logic)---
                logger.info("Using plain password authentication")
                if self.username:
                    credentials = Credentials(username=self.username, password=self.password)
                else:
                    credentials = Credentials(username=self.email_address, password=self.password)

                if self.exchange_server:
                    config = Configuration(server=self.exchange_server, credentials=credentials, auth_type="NTLM")
                    self.account = Account(primary_smtp_address=self.email_address, config=config, autodiscover=False, access_type=DELEGATE)
                else:
                    self.account = Account(primary_smtp_address=self.email_address, credentials=credentials, autodiscover=True, access_type=DELEGATE)

            logger.info("Exchange connection successful")
            return True
        except Exception as e:
            logger.error(f"Exchange connection failed: {e}")
            import traceback

            logger.error(traceback.format_exc())
            return False

    def get_all_folders(self) -> List[Tuple[str, str]]:
        """
        Get all mailbox folders

        Returns:
            List[Tuple[str, str]]: List of folders, tuple format is (folder object, folder name)
        """
        try:
            logger.info("Fetching Exchange folder list...")
            folder_list = []

            # Recursively get all folders
            def get_folders_recursive(folder):
                try:
                    folder_name = folder.name
                    folder_list.append((folder, folder_name))

                    # Recursively get child folders
                    if hasattr(folder, "children") and folder.children:
                        for child in folder.children:
                            get_folders_recursive(child)
                except Exception as e:
                    logger.warning(f"Error processing folder: {e}")

            # Start from the root folder
            get_folders_recursive(self.account.root)

            logger.info(f"Found {len(folder_list)} folders")
            return folder_list
        except Exception as e:
            logger.error(f"Error fetching folder list: {e}")
            return []

    def get_recent_emails(self, days: int = 30) -> Dict[str, List[Tuple[str, object]]]:
        """
        Get recent emails

        Args:
            days: Number of days, default is 30. If set to 0, fetch all emails (no time limit).

        Returns:
            Dict[str, List[Tuple[str, object]]]: Emails grouped by folder
        """
        try:
            # Calculate date range
            if days == 0:
                logger.info(f"Fetching all emails (no time limit)")
                since_date = None
            else:
                since_date = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=days)
                logger.info(f"Fetching emails from the last {days} days (since {since_date.strftime('%Y-%m-%d')})")

            folders = self.get_all_folders()
            all_emails = {}

            # Using rich progress bar
            with Progress() as progress:
                folders_task = progress.add_task("[green]Traversing folders...", total=len(folders))

                for folder_obj, folder_name in folders:
                    # Check folder name validity
                    if not check_folder_name(folder_name):
                        logger.info(f"Skipping invalid folder: {folder_name}")
                        progress.update(folders_task, advance=1)
                        continue
                    try:
                        # Update progress bar with current folder
                        progress.update(folders_task, folder_name=f"[{folder_name}]")
                        logger.info(f"Processing folder: {folder_name}")

                        # Get emails in the folder
                        try:
                            # Decide whether to filter emails based on days value
                            if since_date is None:
                                # If days=0, get all emails
                                items = folder_obj.all()
                            else:
                                # Filter recent emails
                                items = folder_obj.filter(datetime_received__gte=since_date)
                            email_count = items.count()

                            logger.info(f"Found {email_count} emails in folder {folder_name}")

                            emails_in_folder = []

                            # Iterate through emails
                            with Progress() as progress:
                                emails_task = progress.add_task(f"[cyan]Processing emails...", total=email_count)
                                for idx, item in enumerate(items):
                                    try:
                                        # Save email object and ID
                                        email_id = f"{idx+1}"
                                        emails_in_folder.append((email_id, item))
                                    except Exception as e:
                                        logger.error(f"Error processing email: {e}")
                                        continue
                                    finally:
                                        progress.update(emails_task, advance=1)

                            all_emails[folder_name] = emails_in_folder

                        except Exception as e:
                            logger.warning(f"Folder {folder_name} does not support email operations or is empty: {e}")
                            progress.update(folders_task, advance=1)
                            continue

                        # folders_task
                        progress.update(folders_task, advance=1)

                    except Exception as e:
                        logger.error(f"Error processing folder {folder_name}: {e}")
                        progress.update(folders_task, advance=1)
                        continue

            return all_emails

        except Exception as e:
            logger.error(f"Error fetching emails: {e}")
            import traceback

            logger.error(traceback.format_exc())
            return {}

    def save_eml_files(self, emails: Dict[str, List[Tuple[str, object]]]) -> int:
        """
        Save emails as eml files

        Args:
            emails: Email data

        Returns:
            int: Number of successfully saved files
        """
        saved_count = 0

        # Calculate total number of emails
        total_emails = sum(len(email_list) for email_list in emails.values())

        if total_emails == 0:
            logger.info("No emails to save")
            return 0

        # Use rich progress bar
        with Progress() as progress:
            emails_task = progress.add_task("[green]Saving emails...", total=total_emails)

            for folder, email_list in emails.items():
                # Create directory corresponding to the folder
                folder_dir = os.path.join(self.output_dir, self._sanitize_folder_name(folder))
                os.makedirs(folder_dir, exist_ok=True)

                for email_id, item in email_list:
                    try:
                        # Get email subject
                        subject = item.subject if item.subject else "No Subject"

                        # Truncate subject for display
                        display_subject = subject[:40] + "..." if len(subject) > 40 else subject
                        progress.update(emails_task, current_info=f"[{folder}] {display_subject}")

                        # Get email received time
                        email_datetime = item.datetime_received

                        # Generate filename
                        filename = self._generate_filename(email_id, subject, email_datetime)
                        filepath = os.path.join(folder_dir, filename)

                        # Get MIME content and save as eml file
                        mime_content = item.mime_content
                        with open(filepath, "wb") as f:
                            f.write(mime_content)

                        logger.info(f"Saved: {filepath}")
                        saved_count += 1

                        # Update progress
                        progress.update(emails_task, advance=1)

                    except Exception as e:
                        logger.error(f"Error saving email {email_id}: {e}")
                        # Update progress even if an error occurs
                        progress.update(emails_task, advance=1)
                        continue

        return saved_count

    def _sanitize_folder_name(self, folder_name: str) -> str:
        """
        Sanitize folder name to make it suitable as a directory name

        Args:
            folder_name: Original folder name

        Returns:
            str: Sanitized folder name
        """
        # Replace unsafe characters
        unsafe_chars = ["/", "\\", ":", "*", "?", '"', "<", ">", "|"]
        for char in unsafe_chars:
            folder_name = folder_name.replace(char, "_").strip()
        return folder_name

    def _generate_filename(self, email_id: str, subject: str, email_datetime: datetime.datetime = None) -> str:
        """
        Generate filename

        Args:
            email_id: Email ID
            subject: Email subject
            email_datetime: Email received time

        Returns:
            str: Filename
        """
        # Sanitize subject to remove unsafe characters
        unsafe_chars = ["/", "\\", ":", "*", "?", '"', "<", ">", "|"]
        for char in unsafe_chars:
            subject = subject.replace(char, "_").strip()

        # Limit filename length
        if len(subject) > 100:
            subject = subject[:100] + "..."

        # Use email received time, if not available use current time
        if email_datetime:
            # Convert to local time
            timestamp = email_datetime.astimezone().strftime("%Y%m%d_%H%M%S")
        else:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

        filename = f"{timestamp}_{email_id}_{subject}.eml"

        return filename

    def disconnect(self):
        """Disconnect from the Exchange server"""
        if self.account:
            try:
                logger.info("Exchange connection closed")
                self.account = None
            except Exception as e:
                logger.error(f"Error closing Exchange connection: {e}")

    def run_crawler(self, days: int = 30) -> bool:
        """
        Run the crawler

        Args:
            days: Number of days to fetch, default is 30. If set to 0, fetch all emails (no time limit)

        Returns:
            bool: Whether the crawler ran successfully
        """
        try:
            # Connect to the mailbox
            if not self.connect():
                return False
            if CHECK_ONLY:
                logger.info("Only checking connection, not downloading emails.")
                return True

            # Fetch emails
            emails = self.get_recent_emails(days)

            if not emails:
                logger.warning("No emails found matching the criteria")
                return True

            total_emails = sum(len(email_list) for email_list in emails.values())
            logger.info(f"Total emails found: {total_emails}")

            # Save emails
            saved_count = self.save_eml_files(emails)
            logger.info(f"Successfully saved {saved_count} emails to {self.output_dir} directory")

            return True

        except Exception as e:
            logger.error(f"Error running crawler: {e}")
            return False
        finally:
            self.disconnect()


def main():
    """Main function"""
    # Load configuration
    email_configs, crawler_config = load_config()

    if not email_configs or not crawler_config:
        return

    days = crawler_config.get("days", 30)
    total_saved = 0

    # Iterate through all email configurations
    for key, email_config in email_configs.items():
        print(f"\n{'='*50}")
        print(f"Processing: {key}")
        print(f"{'='*50}")

        print(f"Email address: {email_config['email_address']}")
        print(f"Exchange server: {email_config.get('exchange_server', 'Auto-discover')}")
        if days == 0:
            print(f"Fetch range: All emails (no time limit)")
        else:
            print(f"Fetch days: {days} days")

        # Determine authentication mode
        use_ntlm_hash = "ntlm_hash" in email_config and email_config["ntlm_hash"]
        if use_ntlm_hash:
            print(f"Authentication mode: NTLM hash authentication (Pass-the-Hash)")
        else:
            print(f"Authentication mode: Plain text password")

        # Create crawler instance
        crawler = EmailCrawler(
            email_address=email_config["email_address"],
            username=email_config.get("username"),
            password=email_config.get("password"),
            exchange_server=email_config.get("exchange_server"),
            port=email_config.get("port"),
            ntlm_hash=email_config.get("ntlm_hash"),
        )

        # Set output directory as a subfolder named after the key
        key_output_dir = os.path.join("exports", key)
        crawler.output_dir = key_output_dir
        os.makedirs(key_output_dir, exist_ok=True)

        if days == 0:
            print(f"Fetching all emails...")
        else:
            print(f"Fetching emails from the past {days} days...")

        success = crawler.run_crawler(days)

        if success:
            print(f"✅ {key} emails exported successfully!")
            print(f"Emails saved to: {key_output_dir} directory")
        else:
            print(f"❌ {key} email export failed, please check the log file: email_crawler.log")

    print(f"\n{'='*50}")
    print("All mailboxes processed!")
    print(f"{'='*50}")


if __name__ == "__main__":
    main()
