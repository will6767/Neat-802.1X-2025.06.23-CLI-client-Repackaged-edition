from cryptography.hazmat.primitives import serialization

from .web_api import WebApiClient


class Dot1xClient:
    def __init__(self, host, username, password, verbose=True):
        self.client = WebApiClient(host, verbose=verbose).login(username, password)
        self.firmware_version = self.client.status()["firmwareVersion"]
        if self.firmware_version.split(".")[1] < "20220902":
            raise RuntimeError(
                f"Neat firmware version {self.firmware_version!r} does not support 802.1X"
            )
        self.legacy = self.firmware_version.split(".")[1] < "20221007"
        self.no_scep = self.firmware_version.split(".")[1] < "20230504"
        self.scep_only_https = self.firmware_version.split(".")[1] < "20230928"
        self.no_hostname = self.firmware_version.split(".")[1] < "20231107"
        self.no_web_cert_upload = self.firmware_version.split(".")[1] < "20250205"

    def csr(self, subject=None):
        subject = subject if subject is not None else {}
        return self.client.post(
            "/api/v1/network/config/csr", json=subject
        ).text.encode()

    def init(self, identity, device_cert_chain, server_ca_cert=None):
        if self.legacy:
            return self._legacy_init(identity, device_cert_chain, server_ca_cert)
        return self.init_ethernet(
            dict(credentials=dict(method="TLS", identity=identity)),
            device_cert_chain,
            server_ca_cert,
        )

    def _legacy_init(self, identity, device_cert_chain, server_ca_cert):
        args = dict(
            identity=identity,
            deviceCertificate=b"".join(
                cert.public_bytes(serialization.Encoding.PEM)
                for cert in device_cert_chain
            ).decode(),
        )
        if server_ca_cert is not None:
            args.update(
                serverCaCertificate=server_ca_cert.public_bytes(
                    serialization.Encoding.PEM
                ).decode()
            )
        return self.client.post("/api/v1/network/config/ethernet/init/tls", json=args)

    def _common_init(self, route, config_json, device_cert_chain, server_ca_cert):
        if self.legacy:
            raise self._unsupported_operation()
        args = config_json["credentials"]
        if device_cert_chain is not None:
            args.update(
                deviceCertificate=b"".join(
                    cert.public_bytes(serialization.Encoding.PEM)
                    for cert in device_cert_chain
                ).decode()
            )
        if server_ca_cert is not None:
            args.update(
                caCertificate=server_ca_cert.public_bytes(
                    serialization.Encoding.PEM
                ).decode()
            )
        return self.client.post(route, json=config_json)

    def init_ethernet(self, config_json, device_cert_chain=None, server_ca_cert=None):
        return self._common_init(
            "/api/v1/network/config/ethernet",
            config_json,
            device_cert_chain,
            server_ca_cert,
        )

    def delete_ethernet(self):
        if self.legacy:
            raise self._unsupported_operation()
        return self.client.delete("/api/v1/network/config/ethernet")

    def delete_wifi(self):
        if self.legacy:
            raise self._unsupported_operation()
        return self.client.delete("/api/v1/network/config/wifi")

    def delete_certificates(self):
        if self.legacy:
            raise self._unsupported_operation()
        return self.client.delete("/api/v1/network/config/certificates")

    def init_wifi(self, config_json, device_cert_chain=None, server_ca_cert=None):
        return self._common_init(
            "/api/v1/network/config/wifi",
            config_json,
            device_cert_chain,
            server_ca_cert,
        )

    def init_scep(self, config_json, server_ca_cert=None):
        if self.no_scep:
            raise self._unsupported_operation()
        if server_ca_cert is not None:
            config_json.update(
                caCertificate=server_ca_cert.public_bytes(
                    serialization.Encoding.PEM
                ).decode()
            )
        return self.client.post("/api/v1/network/config/scep", json=config_json)

    def renew_scep(self):
        if self.no_scep:
            raise self._unsupported_operation()
        return self.client.get("/api/v1/network/config/scep/renew")

    def certificates(self):
        return self.client.get("/api/v1/network/config/certificates").json()

    def trust_ca(self, ca_cert):
        if self.no_scep:
            raise self._unsupported_operation()
        return self.client.post(
            "/api/v1/certificates",
            files=dict(ca_cert=ca_cert.public_bytes(serialization.Encoding.PEM)),
        )

    def set_web_cert(self, pem_file, pem_password, reboot):
        if self.no_web_cert_upload:
            raise self._unsupported_operation()

        with open(pem_file, "rb") as f:
            pem_data = f.read()

            data = {}
            if pem_password is None:
                data["pem_password"] = ""
            else:
                data["pem_password"] = f"{pem_password}"

            request_call = self.client.post(
                "/api/v1/webserver/certificates",
                data=data,
                files=dict(ca_cert=("bundle.pem", pem_data, "application/x-x509-ca-cert")),
            )

            if request_call.ok and reboot:
                self.reboot()
                print("Neat device reboot in progress.")
            elif request_call.ok:
                print("Successfully uploaded the .pem file.")
                print("Reboot the device to apply the changes.")

        return request_call

    def list_trusted_ca(self):
        if self.no_scep:
            raise self._unsupported_operation()
        return self.client.get("/api/v1/certificates").json()

    def set_hostname(self, hostname):
        if self.no_hostname:
            raise self._unsupported_operation()
        return self.client.post(
            "/api/v1/network/config/hostname", json=dict(hostname=hostname)
        )

    def get_hostname(self):
        if self.no_hostname:
            raise self._unsupported_operation()
        return self.client.get("/api/v1/network/config/hostname").json()["hostname"]

    def reboot(self):
        return self.client.put("/api/v1/device/reboot")

    def _unsupported_operation(self):
        return RuntimeError(
            f"Neat firmware version {self.firmware_version!r} does not support this operation"
        )
