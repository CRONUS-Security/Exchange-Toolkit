#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Mail Crawler - Exchange Version
"""

import json
import os
import sys
import logging
import datetime
from pathlib import Path
from typing import List, Dict, Optional, Tuple
import typer
from exchangelib import Credentials, Account, DELEGATE, Configuration, Version, Build
from exchangelib.folders import FolderCollection
from exchangelib.protocol import BaseProtocol, NoVerifyHTTPAdapter
from exchangelib.protocol import Protocol, CachingProtocol
import urllib3
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TimeRemainingColumn
import re

# Import custom NTLM hash authentication
from core.ntlm_auth import HttpNtlmHashAuth, NTLMHashProtocol, _parse_ntlm_hash

# disable InsecureRequestWarning when connecting to servers with self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# UUID Regex
UUID_REGEX = re.compile(r"[0-9a-fA-F]{8}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{12}", re.IGNORECASE)

# Pure Integer Regex
PURE_INTEGER_REGEX = re.compile(r"^\d+$")

# setup logging (handlers will be reconfigured once config is loaded)
logger = logging.getLogger(__name__)


app = typer.Typer(
    name="mailcrawler",
    help="Mail Crawler - Exchange Dump Tool",
    no_args_is_help=True,
)

_DEFAULT_CONFIG = Path("config.json")


def _resolve_config_path(config: Optional[Path]) -> Path:
    """Parse configuration file path, defaulting to config.json in the same directory as the executable when packaged as EXE"""
    if config is not None:
        return config
    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent / "config.json"
    return _DEFAULT_CONFIG


def _setup_logging(log_file: str) -> None:
    """Initialize logging handlers based on configuration"""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[
            logging.FileHandler(log_file, encoding="utf-8"),
            logging.StreamHandler(),
        ],
    )


def load_config_json(config_path: Path) -> tuple[dict, dict]:
    """Load configuration from a JSON file"""
    if not config_path.exists():
        typer.echo(f"❌ Configuration file {config_path} does not exist!", err=True)
        raise typer.Exit(1)
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        accounts = {k: v for k, v in data.get("accounts", {}).items() if not k.startswith("_")}
        crawler = data.get("crawler", {})
        return accounts, crawler
    except json.JSONDecodeError as e:
        typer.echo(f"❌ Configuration file format error: {e}", err=True)
        raise typer.Exit(1)


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
            ntlm_hash: NTLM hash string, takes precedence over password. Supports pure NT hash (32 hexadecimal characters) or LM:NT format.
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


def _run_account(key: str, email_config: dict, days: int, base_output_dir: str, check_only: bool) -> bool:
    """Execute crawling (or connection check) for a single account"""
    typer.echo(f"\n{'='*50}")
    typer.echo(f"Processing account: {key}")
    typer.echo(f"{'='*50}")

    typer.echo(f"Email address: {email_config['email_address']}")
    typer.echo(f"Exchange server: {email_config.get('exchange_server', 'Auto Discover')}")
    if days == 0:
        typer.echo("Fetch range: All emails (no time limit)")
    else:
        typer.echo(f"Fetch days: Last {days} days")

    use_ntlm_hash = bool(email_config.get("ntlm_hash"))
    auth_mode = "NTLM hash authentication (Pass-the-Hash)" if use_ntlm_hash else "Plain password authentication"
    typer.echo(f"Authentication mode: {auth_mode}")

    crawler = EmailCrawler(
        email_address=email_config["email_address"],
        username=email_config.get("username"),
        password=email_config.get("password"),
        exchange_server=email_config.get("exchange_server"),
        port=email_config.get("port"),
        ntlm_hash=email_config.get("ntlm_hash"),
    )

    key_output_dir = os.path.join(base_output_dir, key)
    crawler.output_dir = key_output_dir
    if not check_only:
        os.makedirs(key_output_dir, exist_ok=True)

    if check_only:
        ok = crawler.connect()
        crawler.disconnect()
        if ok:
            typer.echo(f"✅ {key} Connection successful!")
        else:
            typer.echo(f"❌ {key} Connection failed, please check the logs.")
        return ok
    else:
        success = crawler.run_crawler(days)
        if success:
            typer.echo(f"✅ {key} Emails exported successfully!")
            typer.echo(f"Emails saved to: {key_output_dir}")
        else:
            typer.echo(f"❌ {key} Email export failed, please check the logs.")
        return success


@app.command()
def run(
    accounts: Optional[List[str]] = typer.Argument(None, help="Email addresses to process (process all if not specified)"),
    days: Optional[int] = typer.Option(None, "--days", "-d", help="Fetch emails from the last N days, 0 for no limit"),
    output_dir: Optional[str] = typer.Option(None, "--output-dir", "-o", help="Root directory for email output"),
    config: Optional[Path] = typer.Option(None, "--config", "-c", help="Configuration file path (default: config.json)"),
    check_only: bool = typer.Option(False, "--check-only", help="Only check connection, do not download emails"),
):
    """Download emails and save as EML files"""
    config_path = _resolve_config_path(config)
    email_configs, crawler_config = load_config_json(config_path)

    log_file = crawler_config.get("log_file", "email_crawler.log")
    _setup_logging(log_file)

    effective_days = days if days is not None else crawler_config.get("days", 30)
    effective_output = output_dir or crawler_config.get("output_dir", "eml_exports")

    typer.echo("=" * 50)
    typer.echo("Mail Crawler - Exchange Version")
    typer.echo("=" * 50)
    typer.echo(f"Configuration file: {config_path}")
    typer.echo(f"Configured accounts: {', '.join(email_configs.keys())}")

    targets = accounts if accounts else list(email_configs.keys())
    unknown = [a for a in targets if a not in email_configs]
    if unknown:
        typer.echo(f"❌ The following accounts do not exist in the configuration file: {', '.join(unknown)}", err=True)
        raise typer.Exit(1)

    for key in targets:
        _run_account(key, email_configs[key], effective_days, effective_output, check_only)

    typer.echo(f"\n{'='*50}")
    typer.echo("All accounts processed!")
    typer.echo(f"{'='*50}")


@app.command("list")
def list_accounts(
    config: Optional[Path] = typer.Option(None, "--config", "-c", help="Configuration file path (default: config.json)"),
):
    """List all configured email accounts in the configuration file"""
    config_path = _resolve_config_path(config)
    email_configs, crawler_config = load_config_json(config_path)

    typer.echo(f"Configuration file: {config_path}")
    typer.echo(f"\nTotal {len(email_configs)} accounts:\n")
    for key, cfg in email_configs.items():
        auth = "NTLM hash" if cfg.get("ntlm_hash") else "Plaintext password"
        server = cfg.get("exchange_server", "(Auto-discover)")
        typer.echo(f"  [{key}]")
        typer.echo(f"    Email Address : {cfg.get('email_address', key)}")
        typer.echo(f"    Server        : {server}")
        typer.echo(f"    Authentication: {auth}")
        if cfg.get("username"):
            typer.echo(f"    Username      : {cfg['username']}")


@app.command()
def check(
    accounts: Optional[List[str]] = typer.Argument(None, help="Email addresses to check (check all if not specified)"),
    config: Optional[Path] = typer.Option(None, "--config", "-c", help="Configuration file path (default: config.json)"),
):
    """Check if email connections are working (do not download emails)"""
    config_path = _resolve_config_path(config)
    email_configs, crawler_config = load_config_json(config_path)

    log_file = crawler_config.get("log_file", "email_crawler.log")
    _setup_logging(log_file)

    targets = accounts if accounts else list(email_configs.keys())
    unknown = [a for a in targets if a not in email_configs]
    if unknown:
        typer.echo(f"❌ The following accounts do not exist in the configuration file: {', '.join(unknown)}", err=True)
        raise typer.Exit(1)

    effective_output = crawler_config.get("output_dir", "eml_exports")

    results = {}
    for key in targets:
        ok = _run_account(key, email_configs[key], 0, effective_output, check_only=True)
        results[key] = ok

    typer.echo(f"\n{'='*50}")
    typer.echo("Connection Check Summary:")
    for key, ok in results.items():
        status = "✅ Success" if ok else "❌ Failure"
        typer.echo(f"  {key}: {status}")
    typer.echo("=" * 50)


if __name__ == "__main__":
    app()
