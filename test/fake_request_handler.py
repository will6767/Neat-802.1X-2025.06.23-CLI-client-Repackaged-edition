import io
import json
import types
import urllib

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

SERIAL = "NB10000000000"
HOST_OR_IP = f"{SERIAL}.local"
USERNAME = "oob"
PASSWORD = SERIAL


class FakeRequestHandler:
    AUTH_TOKEN = "AUTHENTICATION TOKEN"
    FW_VERSION = "FAKE.20231107"
    DN = x509.Name(
        [
            x509.NameAttribute(x509.NameOID.COMMON_NAME, SERIAL),
        ]
    )

    def __init__(self, ca=None, expect_server_ca=None):
        self.ca = ca
        self.expect_server_ca = expect_server_ca
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        self.hostname = ""
        self.rebooted = False

    def __enter__(self):
        self._orig_request = requests.request
        requests.request = self.request
        return self

    def __exit__(self, *_):
        requests.request = self._orig_request

    def request(self, method, url, verify, auth, data, json, files):
        assert verify == False
        assert data is None
        assert files is None
        action = (
            urllib.parse.urlsplit(url).path.replace("/api/v1/", "").replace("/", "_")
        )
        if action == "admin_login":
            assert auth is None
        else:
            assert auth is not None
            request = types.SimpleNamespace()
            request.headers = {}
            auth(request)
            assert request.headers == {"Authorization": f"Bearer {self.AUTH_TOKEN}"}
        (status_code, content) = getattr(self, action)(method, json)
        response = requests.Response()
        response.status_code = status_code
        response.raw = io.BytesIO(content)
        return response

    def admin_login(self, method, json_args):
        assert method == "POST"
        assert json_args == dict(userName=USERNAME, password=PASSWORD)
        return (requests.codes.ok, self.AUTH_TOKEN.encode())

    def status(self, method, json_args):
        assert method == "GET"
        assert json_args == None
        return (
            requests.codes.ok,
            json.dumps(dict(firmwareVersion=self.FW_VERSION)).encode(),
        )

    def network_config_csr(self, method, json_args):
        assert method == "POST"
        assert json_args == dict()
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(self.DN)
            .sign(self.key, hashes.SHA256())
        )
        return (requests.codes.ok, csr.public_bytes(serialization.Encoding.PEM))

    def network_config_ethernet(self, method, json_args):
        assert method == "POST"
        expected_credentials = dict(
            method="TLS",
            identity=SERIAL,
            deviceCertificate=bytes()
            .join(
                cert.public_bytes(serialization.Encoding.PEM)
                for cert in self.ca.issued_cert_chain
            )
            .decode(),
        )
        if self.expect_server_ca:
            expected_credentials.update(
                dict(
                    caCertificate=self.ca.cert.public_bytes(
                        serialization.Encoding.PEM
                    ).decode()
                )
            )
        assert json_args == dict(credentials=expected_credentials)
        self.network_config_ethernet_called = True
        return (
            requests.codes.ok,
            "Successfully configured the wired eap tls network".encode(),
        )

    def network_config_hostname(self, method, json_args):
        assert method in ("GET", "POST")
        if method == "GET":
            return (
                requests.codes.ok,
                json.dumps(dict(hostname=self.hostname)).encode(),
            )
        elif method == "POST":
            self.hostname = json_args["hostname"]
            return (requests.codes.ok, "".encode())
        else:
            assert False

    def device_reboot(self, method, json_args):
        assert method == "PUT"
        assert json_args is None
        self.rebooted = True
        return (requests.codes.ok, "".encode())

    def network_config_wifi(self, method, json_args):
        assert method == "POST"
        self.wifi_config = json_args
        return (requests.codes.ok, "".encode())
