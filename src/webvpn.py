"""
WebVPN URL encoding and authentication for Fudan University with TOTP MFA support.
"""

import base64
import html as html_mod
import re
import time
from binascii import hexlify, unhexlify
from urllib.parse import quote, urljoin, urlparse

import pyotp
import requests
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA

from . import config


def _find_field(obj, key: str):
    """Recursively locate a non-empty field in nested dict/list JSON responses."""
    if isinstance(obj, dict):
        if obj.get(key):
            return obj[key]
        for value in obj.values():
            found = _find_field(value, key)
            if found:
                return found
    elif isinstance(obj, list):
        for item in obj:
            found = _find_field(item, key)
            if found:
                return found
    return None


def encrypt_host(hostname: str) -> str:
    key = config.WEBVPN_AES_KEY
    iv = config.WEBVPN_AES_IV
    cipher = AES.new(key, AES.MODE_CFB, iv, segment_size=128)
    plaintext = hostname.encode("utf-8")
    encrypted = cipher.encrypt(plaintext)
    return hexlify(encrypted).decode("ascii")


def decrypt_host(ciphertext_hex: str) -> str:
    key = config.WEBVPN_AES_KEY
    iv = config.WEBVPN_AES_IV
    cipher = AES.new(key, AES.MODE_CFB, iv, segment_size=128)
    decrypted = cipher.decrypt(unhexlify(ciphertext_hex))
    return decrypted.decode("utf-8")


def get_vpn_url(url: str) -> str:
    parsed = urlparse(url)
    protocol = parsed.scheme
    hostname = parsed.hostname
    port = parsed.port
    path = parsed.path
    if parsed.query:
        path += "?" + parsed.query
    if parsed.fragment:
        path += "#" + parsed.fragment

    path = path.lstrip("/")
    encrypted = encrypt_host(hostname)
    iv_hex = hexlify(config.WEBVPN_AES_IV).decode("ascii")

    port_suffix = ""
    if port and not (
        (protocol == "http" and port == 80)
        or (protocol == "https" and port == 443)
    ):
        port_suffix = f"-{port}"

    vpn_url = f"{config.WEBVPN_BASE}/{protocol}{port_suffix}/{iv_hex}{encrypted}"
    if path:
        vpn_url += f"/{path}"
    return vpn_url


def get_ordinary_url(vpn_url: str) -> str:
    parsed = urlparse(vpn_url)
    path_parts = parsed.path.strip("/").split("/", 2)
    if len(path_parts) < 2:
        raise ValueError(f"Invalid WebVPN URL: {vpn_url}")

    protocol_part = path_parts[0]
    encoded_host = path_parts[1]
    rest = path_parts[2] if len(path_parts) > 2 else ""

    if "-" in protocol_part:
        protocol, port_str = protocol_part.rsplit("-", 1)
        port = f":{port_str}"
    else:
        protocol = protocol_part
        port = ""

    iv_hex_len = 32
    ciphertext_hex = encoded_host[iv_hex_len:]
    hostname = decrypt_host(ciphertext_hex)

    original = f"{protocol}://{hostname}{port}"
    if rest:
        original += f"/{rest}"
    if parsed.query:
        original += f"?{parsed.query}"
    return original


class WebVPNSession:
    """Manages a WebVPN session with full IDP authentication & OTP MFA."""

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": config.USER_AGENT})
        self.logged_in = False

    def login(self, student_id: str = None, password: str = None) -> bool:
        """Execute the full 7-step IDP authentication flow."""
        student_id = student_id or config.STUDENT_ID
        password = password or config.PASSWORD

        if not student_id or not password:
            raise ValueError(
                "Student ID and password are required. "
                "Set STUID and UISPsw environment variables."
            )

        print("[1/7] Getting authentication context...")
        lck, entity_id = self._get_auth_context()

        print("[2/7] Querying authentication methods...")
        auth_chain_code, request_type = self._query_auth_methods(lck, entity_id)

        print("[3/7] Getting RSA public key...")
        pub_key_pem = self._get_public_key()

        print("[4/7] Encrypting password...")
        encrypted_password = self._encrypt_password(password, pub_key_pem)

        print("[5/7] Executing authentication...")
        login_token = self._auth_execute(
            student_id,
            encrypted_password,
            lck,
            entity_id,
            auth_chain_code,
            request_type,
            use_vpn=False,
        )

        print("[6/7] Getting CAS ticket...")
        ticket_url = self._get_cas_ticket(login_token)

        print("[7/7] Establishing WebVPN session...")
        self._establish_session(ticket_url)

        self.logged_in = True
        print("[*] WebVPN login successful!")
        return True

    def _is_icourse_authenticated(self) -> bool:
        """Check if iCourse session is already active via userapi."""
        test_url = get_vpn_url(f"{config.ICOURSE_BASE}/userapi/v1/infosimple")
        try:
            resp = self.session.get(test_url, timeout=15)
            if resp.status_code == 200:
                user_data = resp.json()
                if user_data.get("code") in (0, 200):
                    return True
        except Exception:
            pass
        return False

    def authenticate_icourse(
        self, student_id: str = None, password: str = None
    ) -> bool:
        """Authenticate to iCourse via CAS/IDP through WebVPN."""
        student_id = student_id or config.STUDENT_ID
        password = password or config.PASSWORD

        print("[*] Starting iCourse CAS authentication through WebVPN...")

        if self._is_icourse_authenticated():
            print("    Verified: already logged in to iCourse via active WebVPN session.")
            print("[*] iCourse authentication successful!")
            return True

        casapi_url = (
            f"{config.ICOURSE_BASE}/casapi/index.php"
            f"?r=auth/login&school_login=1"
            f"&tenant_code={config.TENANT_CODE}"
            f"&forward={quote(config.ICOURSE_BASE + '/', safe='')}"
        )
        vpn_casapi_url = get_vpn_url(casapi_url)
        idp_vpn_base = get_vpn_url(config.IDP_BASE)

        print("[1/7] Initiating CAS login via casapi...")
        resp = self.session.get(vpn_casapi_url, allow_redirects=False, timeout=30)
        lck = None
        for _ in range(15):
            location = resp.headers.get("Location", "")
            if resp.status_code not in (301, 302, 303, 307) or not location:
                break

            if "ticket=" in location:
                ticket_url = location
                if not ticket_url.startswith("http"):
                    ticket_url = urljoin(resp.url, ticket_url)
                if not ticket_url.startswith(config.WEBVPN_BASE):
                    ticket_url = get_vpn_url(ticket_url)
                self.session.get(ticket_url, allow_redirects=True, timeout=30)
                if self._is_icourse_authenticated():
                    print("    Verified: login OK via auto-ticket")
                    print("[*] iCourse authentication successful!")
                    return True

            lck_match = re.search(r'lck=([^&#"]+)', location)
            if lck_match:
                lck = lck_match.group(1)
                break
            if not location.startswith("http"):
                location = urljoin(resp.url, location)
            resp = self.session.get(location, allow_redirects=False, timeout=30)

        if not lck:
            for source in [resp.url, resp.text[:5000]]:
                m = re.search(r'lck=([^&#"]+)', source)
                if m:
                    lck = m.group(1)
                    break

        if not lck:
            if self._is_icourse_authenticated():
                print("    Verified: login OK (SSO session active)")
                print("[*] iCourse authentication successful!")
                return True
            raise RuntimeError(
                f"Failed to extract lck from CAS redirect chain (status={resp.status_code})"
            )

        entity_id = config.ICOURSE_BASE
        print("    lck: OK")

        # Step 2: Query auth methods
        print("[2/7] Querying auth methods (via WebVPN)...")
        url = get_vpn_url(f"{config.IDP_BASE}/idp/authn/queryAuthMethods")
        resp = self.session.post(
            url,
            json={"lck": lck, "entityId": entity_id},
            headers={
                "Content-Type": "application/json",
                "Referer": f"{idp_vpn_base}/ac/",
                "Origin": config.WEBVPN_BASE,
            },
            timeout=30,
        )
        data = resp.json()
        auth_method_list = data.get("data", [])
        request_type = data.get("requestType", "chain_type")

        auth_chain_code = ""
        for method in auth_method_list:
            if method.get("moduleCode") == "userAndPwd":
                auth_chain_code = method.get("authChainCode", "")
                break
        if not auth_chain_code:
            raise RuntimeError("No authChainCode found in response")
        print("    authChainCode: OK")

        # Step 3: Get RSA public key
        print("[3/7] Getting RSA public key (via WebVPN)...")
        url = get_vpn_url(f"{config.IDP_BASE}/idp/authn/getJsPublicKey")
        resp = self.session.get(
            url,
            headers={"Referer": f"{idp_vpn_base}/ac/"},
            timeout=30,
        )
        data = resp.json()
        pub_key_b64 = data.get("data", "")
        if not pub_key_b64:
            raise RuntimeError("Failed to get public key via WebVPN")
        print("    Got RSA public key")

        # Step 4: Encrypt password
        print("[4/7] Encrypting password...")
        encrypted_password = self._encrypt_password(password, pub_key_b64)

        # Step 5: Execute authentication with OTP support
        print("[5/7] Executing authentication (via WebVPN)...")
        login_token = self._auth_execute(
            student_id,
            encrypted_password,
            lck,
            entity_id,
            auth_chain_code,
            request_type,
            use_vpn=True,
        )

        # Step 6: Get CAS ticket
        print("[6/7] Getting CAS ticket (via WebVPN)...")
        url = get_vpn_url(f"{config.IDP_BASE}/idp/authCenter/authnEngine")
        resp = self.session.post(
            url,
            data={"loginToken": login_token},
            headers={
                "Referer": f"{idp_vpn_base}/ac/",
                "Origin": config.WEBVPN_BASE,
            },
            timeout=30,
        )
        html = resp.text

        ticket_match = re.search(
            r'locationValue\s*=\s*"([^"]*ticket=[^"]*)"', html
        )
        if not ticket_match:
            ticket_match = re.search(
                r'(https?://[^\s"\'<>]*ticket=[^\s"\'<>]*)', html
            )
        if not ticket_match:
            raise RuntimeError(
                f"Failed to extract iCourse ticket URL (response length: {len(html)})"
            )

        ticket_url = html_mod.unescape(ticket_match.group(1))
        print("    Ticket extracted.")

        # Step 7: Follow ticket to iCourse
        print("[7/7] Following ticket to iCourse (via WebVPN)...")
        if not ticket_url.startswith(config.WEBVPN_BASE):
            ticket_url = get_vpn_url(ticket_url)

        resp = self.session.get(ticket_url, allow_redirects=True, timeout=90)
        print(f"    Status: {resp.status_code}")

        if self._is_icourse_authenticated():
            print("    Verified: login OK")
            print("[*] iCourse authentication successful!")
            return True

        print("    Could not verify iCourse auth via API, proceeding...")
        return True

    def _auth_execute(
        self,
        student_id: str,
        encrypted_password: str,
        lck: str,
        entity_id: str,
        auth_chain_code: str,
        request_type: str,
        use_vpn: bool = False,
    ) -> str:
        """Step 5: Execute auth and automatically satisfy userAndOtp MFA if prompted."""
        base_endpoint = f"{config.IDP_BASE}/idp/authn/authExecute"
        url = get_vpn_url(base_endpoint) if use_vpn else base_endpoint
        referer = f"{get_vpn_url(config.IDP_BASE) if use_vpn else config.IDP_BASE}/ac/"
        origin = config.WEBVPN_BASE if use_vpn else config.IDP_BASE

        payload = {
            "authModuleCode": "userAndPwd",
            "authChainCode": auth_chain_code,
            "entityId": entity_id,
            "requestType": request_type,
            "lck": lck,
            "authPara": {
                "loginName": student_id,
                "password": encrypted_password,
                "verifyCode": "",
            },
        }
        resp = self.session.post(
            url,
            json=payload,
            headers={
                "Content-Type": "application/json",
                "Referer": referer,
                "Origin": origin,
            },
            timeout=30,
        )
        data = resp.json()

        if str(data.get("code")) != "200":
            raise RuntimeError(
                f"Auth failed (code={data.get('code')}, msg={data.get('message') or data.get('msg')})"
            )

        login_token = _find_field(data, "loginToken")
        if login_token:
            print("    loginToken: OK")
            return login_token

        print("    [MFA] Secondary authentication required. Submitting userAndOtp...")
        if not config.MFA_SECRET:
            raise ValueError(
                "MFA secondary authentication triggered but MFA_SECRET is not configured."
            )

        secret = config.MFA_SECRET.replace(" ", "").strip()
        remaining = 30 - (int(time.time()) % 30)
        if remaining <= 3:
            time.sleep(remaining + 1)

        otp_code = pyotp.TOTP(secret).now()
        print(f"    [MFA] Generated 6-digit dynamic code: {otp_code}")

        req_num = _find_field(data, "requestNumber")
        second_chain = _find_field(data, "authChainCode") or auth_chain_code

        mfa_payload = {
            "authModuleCode": "userAndOtp",
            "authChainCode": second_chain,
            "entityId": entity_id,
            "requestType": request_type,
            "lck": lck,
            "authPara": {
                "loginName": student_id,
                "otpCode": otp_code,
            },
        }
        if req_num:
            mfa_payload["requestNumber"] = req_num

        mfa_resp = self.session.post(
            url,
            json=mfa_payload,
            headers={
                "Content-Type": "application/json",
                "Referer": referer,
                "Origin": origin,
            },
            timeout=30,
        )
        mfa_data = mfa_resp.json()

        login_token = _find_field(mfa_data, "loginToken")
        if not login_token:
            raise RuntimeError(
                f"Failed to obtain loginToken via userAndOtp: {mfa_data} | step1_data: {data}"
            )

        print("    loginToken (via OTP): OK")
        return login_token

    def _get_cas_ticket(self, login_token: str) -> str:
        url = f"{config.IDP_BASE}/idp/authCenter/authnEngine"
        resp = self.session.post(
            url,
            data={"loginToken": login_token},
            headers={
                "Referer": f"{config.IDP_BASE}/ac/",
                "Origin": config.IDP_BASE,
            },
            timeout=30,
        )
        html = resp.text
        ticket_match = re.search(
            r'locationValue\s*=\s*"([^"]*ticket=[^"]*)"', html
        )
        if not ticket_match:
            ticket_match = re.search(
                r'(https?://[^\s"\'<>]*ticket=[^\s"\'<>]*)', html
            )
        if not ticket_match:
            raise RuntimeError(
                f"Failed to extract ticket URL (response length: {len(html)})"
            )
        ticket_url = html_mod.unescape(ticket_match.group(1))
        print("    Ticket extracted.")
        return ticket_url

    def _establish_session(self, ticket_url: str):
        for attempt in range(3):
            try:
                resp = self.session.get(ticket_url, allow_redirects=True, timeout=90)
                if resp.status_code == 200:
                    print("    Session established.")
                    return
                raise RuntimeError(
                    f"Failed to establish WebVPN session (status={resp.status_code})"
                )
            except requests.exceptions.Timeout:
                has_ticket = any(
                    "wengine_vpn_ticket" in c.name
                    for c in self.session.cookies
                )
                if has_ticket:
                    print("    Session cookie set despite timeout.")
                    return
                if attempt < 2:
                    print(f"    Timeout, retrying ({attempt + 2}/3)...")
                    continue
                raise

    def _get_auth_context(self) -> tuple[str, str]:
        service_url = f"{config.WEBVPN_BASE}/login?cas_login=true"
        url = (
            f"{config.IDP_BASE}/idp/authCenter/authenticate"
            f"?service={quote(service_url, safe='')}"
        )
        resp = self.session.get(url, allow_redirects=False, timeout=30)
        location = resp.headers.get("Location", "")
        while resp.status_code in (301, 302) and "lck=" not in location:
            resp = self.session.get(location, allow_redirects=False, timeout=30)
            location = resp.headers.get("Location", "")

        lck_match = re.search(r"[?&]lck=([^&]+)", location)
        if not lck_match:
            raise RuntimeError(
                f"Failed to extract lck from redirect (status={resp.status_code})"
            )
        lck = lck_match.group(1)
        entity_id = config.WEBVPN_BASE
        print("    lck: OK")
        return lck, entity_id

    def _query_auth_methods(self, lck: str, entity_id: str) -> tuple[str, str]:
        url = f"{config.IDP_BASE}/idp/authn/queryAuthMethods"
        resp = self.session.post(
            url,
            json={"lck": lck, "entityId": entity_id},
            headers={
                "Content-Type": "application/json",
                "Referer": f"{config.IDP_BASE}/ac/",
                "Origin": config.IDP_BASE,
            },
            timeout=30,
        )
        data = resp.json()
        auth_method_list = data.get("data", [])
        request_type = data.get("requestType", "chain_type")

        auth_chain_code = ""
        for method in auth_method_list:
            if method.get("moduleCode") == "userAndPwd":
                auth_chain_code = method.get("authChainCode", "")
                break
        if not auth_chain_code:
            raise RuntimeError("No authChainCode found in response")
        print("    authChainCode: OK")
        return auth_chain_code, request_type

    def _get_public_key(self) -> str:
        url = f"{config.IDP_BASE}/idp/authn/getJsPublicKey"
        resp = self.session.get(
            url,
            headers={"Referer": f"{config.IDP_BASE}/ac/"},
            timeout=30,
        )
        data = resp.json()
        pub_key_b64 = data.get("data", "")
        if not pub_key_b64:
            raise RuntimeError("Failed to get public key")
        print("    Got RSA public key")
        return pub_key_b64

    def _encrypt_password(self, password: str, pub_key_b64: str) -> str:
        pem = (
            "-----BEGIN PUBLIC KEY-----\n"
            + pub_key_b64
            + "\n-----END PUBLIC KEY-----"
        )
        rsa_key = RSA.import_key(pem)
        cipher = PKCS1_v1_5.new(rsa_key)
        encrypted = cipher.encrypt(password.encode("utf-8"))
        return base64.b64encode(encrypted).decode("ascii")

    def get(self, url: str, **kwargs) -> requests.Response:
        vpn_url = get_vpn_url(url)
        kwargs.setdefault("timeout", 60)
        return self.session.get(vpn_url, **kwargs)

    def post(self, url: str, **kwargs) -> requests.Response:
        vpn_url = get_vpn_url(url)
        kwargs.setdefault("timeout", 60)
        return self.session.post(vpn_url, **kwargs)

    def get_raw(self, url: str, **kwargs) -> requests.Response:
        kwargs.setdefault("timeout", 30)
        return self.session.get(url, **kwargs)

    def post_raw(self, url: str, **kwargs) -> requests.Response:
        kwargs.setdefault("timeout", 30)
        return self.session.post(url, **kwargs)
