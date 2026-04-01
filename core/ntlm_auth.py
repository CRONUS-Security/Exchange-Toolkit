from exchangelib.protocol import Protocol
from requests_ntlm import HttpNtlmAuth
from spnego._credential import NTLMHash

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