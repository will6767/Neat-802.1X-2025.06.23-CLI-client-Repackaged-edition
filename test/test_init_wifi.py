import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from neat_dot1x_client.cli import cli

from ca import CA
from fake_request_handler import (
    HOST_OR_IP,
    PASSWORD,
    SERIAL,
    USERNAME,
    FakeRequestHandler,
)


def test_device_cert_is_optional(tmp_path: Path):
    with FakeRequestHandler() as fake_request_handler:
        wifi_config_json_path = tmp_path / "wifi_config.json"

        WIFI_CONFIG = {
            "ssid": "my wifi",
            "isHidden": False,
            "wifiSecurity": "WPA2",
            "credentials": {"password": "my password"},
        }

        wifi_config_json_path.write_text(json.dumps(WIFI_CONFIG), encoding="utf-8")

        cli([HOST_OR_IP, USERNAME, PASSWORD, "init_wifi", str(wifi_config_json_path)])

        assert fake_request_handler.wifi_config == WIFI_CONFIG


def csr_and_init_wifi(tmp_path: Path, use_server_ca_cert: bool):
    ca = CA()

    with FakeRequestHandler() as fake_request_handler:
        # CSR path: do not open it before the CLI writes it (Windows lock avoidance)
        csr_path = tmp_path / "device.csr"
        cli([HOST_OR_IP, USERNAME, PASSWORD, "csr", str(csr_path)])
        csr = csr_path.read_bytes()

        cert_chain = ca.sign(csr)

        wifi_config_json_path = tmp_path / "wifi_eap_config.json"
        WIFI_CONFIG = {
            "ssid": "my wifi",
            "isHidden": False,
            "wifiSecurity": "EAP",
            "credentials": {
                "method": "TLS",
                "altSubjectMatch": "DNS:radius.company.local",
                "identity": SERIAL,
                "caCertificate": "-----BEGIN CERTIFICATE-----\nMIIEMzCCAxugAwIBAgIUKi2RbFT55VyHneHIQnE0gkyPUekwDQYJKoZIhvcNAQEL\nBQAwgagxCzAJBgNVBAYTAk5PMQ0wCwYDVQQIDARPc2xvMQ0wCwYDVQQHDARPc2xv\nMRUwEwYDVQQKDAxGYWtlIENvbXBhbnkxGzAZBgNVBAsMElRlc3RpbmcgRGVwYXJ0\nbWVudDEaMBgGA1UEAwwRcm9vdC5jYS50ZXN0Lm9ubHkxKzApBgkqhkiG9w0BCQEW\nHG9ubHkudXNlZC5mb3IudGVzdEBob21lLmFycGEwHhcNMjUxMDEwMDk1NjUxWhcN\nMjYxMDEwMDk1NjUxWjCBqDELMAkGA1UEBhMCTk8xDTALBgNVBAgMBE9zbG8xDTAL\nBgNVBAcMBE9zbG8xFTATBgNVBAoMDEZha2UgQ29tcGFueTEbMBkGA1UECwwSVGVz\ndGluZyBEZXBhcnRtZW50MRowGAYDVQQDDBFyb290LmNhLnRlc3Qub25seTErMCkG\nCSqGSIb3DQEJARYcb25seS51c2VkLmZvci50ZXN0QGhvbWUuYXJwYTCCASIwDQYJ\nKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOkjiGG3ukCQFd1WJM3OTIKV35BBakx8\nvAeCh9y51lgj4xBDdHQ2du13bVpoNj2NeWC6BI2RvKT3WLwQAaGzWyQXqYR0zlli\nvwcpRW28sNSP6L9gdbcKOu92GAjIulvP/nx+cvGLhGI9Whml4xFpcZlThBURIXN0\nrOxtVUG4aW/kqNRaIBKyJNrc/RqVqPWkvQ59oJcunz5pLsatZatKhStgz86jFBwv\nSUp7YuOYnKnua84BrYSmG6e7RO1WiFsUpTdWexs9gyqAD+eu+bqNVwbx91L4Jmyw\n2nU64RXQ5tnjjwGGHgd0a3UG0Dx8NW55Gwqteun72B3PAb36hjolW98CAwEAAaNT\nMFEwHQYDVR0OBBYEFBSsOmLRPORNahOu2etO/oYP4hCPMB8GA1UdIwQYMBaAFBSs\nOmLRPORNahOu2etO/oYP4hCPMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQEL\nBQADggEBAFY/mVtB3/w91oe/VKM1rQEkguCrgU41+9adL+pZE78yt+GsvVmwNg9G\nmBSMcUxpQGchhpW3t2HedcwjHFx6uy8S9rr1ue/KagbahcbRYp5rSvbU0VQTmD5G\ncitc7+mrNcSwsgw4FZ3VlaMe3J1Ol+omJ/aTnCrEIXIIKo5kP1pj7rxU+3t2Hkng\nNoAy/saTkI+VjIK/HoqrRenKX2vkPeaELp/X4koXCWQzmGLheYP5VGjCmIGAHMWT\n608RkzvgwXtatbMQlTJYvFU4FP6WW9587jSr6ByyKoVL70EkK5wITJOuHZiUoIyU\nTazma7AHC3ycd+Wl3UppEsmQ6QkO4Ok=\n-----END CERTIFICATE-----\n",
            },
        }

        wifi_config_json_path.write_text(json.dumps(WIFI_CONFIG), encoding="utf-8")

        # Write cert chain file to disk (closed before CLI uses it)
        cert_chain_path = tmp_path / "cert_chain.pem"
        cert_chain_path.write_bytes(
            b"".join(cert.public_bytes(serialization.Encoding.PEM) for cert in cert_chain)
        )

        # Write server CA file (only used if use_server_ca_cert)
        server_ca_path = tmp_path / "server_ca.pem"
        server_ca_path.write_bytes(ca.cert.public_bytes(serialization.Encoding.PEM))

        args = [
            HOST_OR_IP,
            USERNAME,
            PASSWORD,
            "init_wifi",
            str(wifi_config_json_path),
            str(cert_chain_path),
        ]
        if use_server_ca_cert:
            args.append(str(server_ca_path))

        cli(args)

        # Match original test behavior: populate deviceCertificate from cert_chain file content
        WIFI_CONFIG["credentials"]["deviceCertificate"] = cert_chain_path.read_text(encoding="utf-8")

        # Match original behavior: if server CA is provided, overwrite caCertificate with server CA file content
        if use_server_ca_cert:
            WIFI_CONFIG["credentials"]["caCertificate"] = server_ca_path.read_text(encoding="utf-8")

        assert fake_request_handler.wifi_config == WIFI_CONFIG


def test_csr_and_init_wifi_without_server_ca(tmp_path: Path):
    csr_and_init_wifi(tmp_path, False)


def test_csr_and_init_wifi_with_server_ca(tmp_path: Path):
    csr_and_init_wifi(tmp_path, True)
