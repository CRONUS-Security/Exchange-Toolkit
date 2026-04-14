"""
NTDS Hash Helper
================
Utilities for parsing impacket ``secretsdump`` output and building
MailCrawler ``config.json`` account entries from NT hashes.

Typical secretsdump output format (``-just-dc-ntlm``)::

    DOMAIN\\Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
    DOMAIN\\user1:1104:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::

Usage
-----
>>> from core.ntds_helper import parse_secretsdump_output, build_accounts_config
>>> hash_map = parse_secretsdump_output("ntds_dump.txt")
>>> accounts = build_accounts_config(hash_map, mailbox_list, "owa.example.com")
"""

from __future__ import annotations

import re
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Match lines like: DOMAIN\user:RID:LM:NT:::
# Also handles lines without domain prefix (user:RID:LM:NT:::)
_DUMP_LINE_RE = re.compile(
    r"^(?P<domain>[^\\:]+\\)?(?P<username>[^:]+):(?P<rid>\d+):(?P<lm>[0-9a-fA-F]{32}):(?P<nt>[0-9a-fA-F]{32}):::",
    re.MULTILINE,
)


def parse_secretsdump_output(filepath: str | Path) -> dict[str, dict]:
    """
    Parse an impacket ``secretsdump`` NTLM dump file.

    Parameters
    ----------
    filepath : str or Path
        Path to the secretsdump output file.

    Returns
    -------
    dict
        Mapping of lower-cased ``DOMAIN\\username`` (or just ``username`` when
        no domain prefix is present) to a dict with keys:

        - ``username`` : original username without domain, lower-cased
        - ``domain``   : domain prefix (stripped of trailing backslash), or ``""``
        - ``full_name``: ``DOMAIN\\username`` or just ``username``
        - ``lm_hash``  : 32-char hex LM hash
        - ``nt_hash``  : 32-char hex NT hash
        - ``ntlm_hash``: formatted as ``LM:NT`` (ready for config.json)
    """
    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"secretsdump file not found: {filepath}")

    text = path.read_text(encoding="utf-8", errors="replace")
    entries: dict[str, dict] = {}

    for match in _DUMP_LINE_RE.finditer(text):
        domain_raw = (match.group("domain") or "").rstrip("\\")
        username = match.group("username")
        lm_hash = match.group("lm")
        nt_hash = match.group("nt")

        full_name = f"{domain_raw}\\{username}" if domain_raw else username
        key = full_name.lower()

        entries[key] = {
            "username": username,
            "domain": domain_raw,
            "full_name": full_name,
            "lm_hash": lm_hash,
            "nt_hash": nt_hash,
            "ntlm_hash": f"{lm_hash}:{nt_hash}",
        }

    logger.info("Parsed %d hash entries from %s", len(entries), filepath)
    return entries


def _normalize_username(name: str) -> str:
    """Return a lower-cased username with only the SAMAccountName part."""
    # Strip domain prefix (DOMAIN\user or user@domain)
    if "\\" in name:
        return name.split("\\", 1)[1].lower()
    if "@" in name:
        return name.split("@", 1)[0].lower()
    return name.lower()


def find_hash_for_mailbox(
    hash_map: dict[str, dict],
    mailbox_address: str,
) -> Optional[dict]:
    """
    Attempt to locate a hash entry for the given mailbox address.

    Matching strategy (in priority order):

    1. Exact key match (``domain\\user`` lower-cased)
    2. SAMAccountName extracted from the mailbox local-part (``user@domain`` → ``user``)
    3. Any entry whose ``username`` field matches the local-part

    Returns the matching entry dict, or ``None`` if not found.
    """
    # Strategy 1: exact key (e.g. "domain\\user@domain.com" won't match, but worth trying)
    if mailbox_address.lower() in hash_map:
        return hash_map[mailbox_address.lower()]

    local_part = _normalize_username(mailbox_address)

    # Strategy 2: look for DOMAIN\local_part key
    for key, entry in hash_map.items():
        if entry["username"].lower() == local_part:
            return entry

    return None


def build_accounts_config(
    hash_map: dict[str, dict],
    mailbox_list: list[str],
    exchange_server: str,
) -> dict:
    """
    Cross-reference a hash map with a list of mailbox SMTP addresses and
    produce a ``config.json``-compatible ``accounts`` dictionary.

    For each mailbox in ``mailbox_list``, a matching hash entry is searched
    using :func:`find_hash_for_mailbox`.  Mailboxes without a matching hash
    are skipped with a warning.

    Parameters
    ----------
    hash_map : dict
        Output of :func:`parse_secretsdump_output`.
    mailbox_list : list[str]
        List of primary SMTP addresses (e.g. from ``enum-mailboxes``).
    exchange_server : str
        Exchange server hostname to embed in every account entry.

    Returns
    -------
    dict
        Ready to merge into ``config.json["accounts"]``.  Each key is the
        mailbox address and each value is a MailCrawler account config dict.
    """
    accounts: dict = {}
    matched = 0
    skipped = 0

    for mailbox in mailbox_list:
        entry = find_hash_for_mailbox(hash_map, mailbox)
        if entry is None:
            logger.warning("No hash found for mailbox: %s — skipping", mailbox)
            skipped += 1
            continue

        accounts[mailbox] = {
            "email_address": mailbox,
            "username": (
                f"{entry['domain']}\\{entry['username']}"
                if entry["domain"]
                else entry["username"]
            ),
            "ntlm_hash": entry["ntlm_hash"],
            "exchange_server": exchange_server,
        }
        matched += 1

    logger.info(
        "build_accounts_config: %d matched, %d skipped (no hash)", matched, skipped
    )
    return accounts
