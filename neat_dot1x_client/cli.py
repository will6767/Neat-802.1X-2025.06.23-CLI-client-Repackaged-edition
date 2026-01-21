import json
import re
import sys
import urllib.parse

import cryptography.hazmat.primitives.hashes
import cryptography.x509
import requests
import OpenSSL
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from . import Dot1xClient
from .doc import get_argparser

SUBJECT_PARAMS = {
    "commonName",
    "organizationName",
    "organizationalUnit",
    "locality",
    "state",
    "country",
    "email",
    "subjectAlternativeName"
}
DN_TO_PARAM_MAP = {
    "CN": "commonName",
    "O": "organizationName",
    "OU": "organizationalUnit",
    "L": "locality",
    "ST": "state",
    "C": "country",
    "EMAIL": "email",
}
ALLOWED_SAN_PARAMS = {
    "dNSNames",
    "iPAddress",
}

def csr(client, args, stdout):
    subject = (
        json.loads(args.subject_json_str)
        if args.subject_json_str is not None
        else json.load(args.subject_json_file.open())
        if args.subject_json_file is not None
        else {}
    )

    # Normalize known DN keys to our parameter names
    subject = {
        DN_TO_PARAM_MAP.get(k.upper(), k): v
        for k, v in subject.items()
    }

    # Check for unknown parameters in top-level
    unknown_subject_params = subject.keys() - SUBJECT_PARAMS
    if len(unknown_subject_params) > 0:
        raise RuntimeError(
            "unknown subject parameters: {}".format(unknown_subject_params)
        )

    # If subjectAlternativeName exists, enforce a whitelist of SAN params
    san = subject.get("subjectAlternativeName")
    if san is not None:
        unknown_san_params = san.keys() - ALLOWED_SAN_PARAMS
        if unknown_san_params:
            raise RuntimeError(f"unknown subjectAltName parameters: {unknown_san_params}")

        if "dNSNames" in san and isinstance(san["dNSNames"], str):
            san["dNSNames"] = [dns.strip() for dns in san["dNSNames"].split(",")]
        if "iPAddress" in san and isinstance(san["iPAddress"], str):
            san["iPAddress"] = [ip.strip() for ip in san["iPAddress"].split(",")]

    print(f"Sending subject: {subject}")
    csr_bytes = client.csr(subject)

    with args.csr_file_path.open("wb") as file:
        file.write(csr_bytes)
    print(f"CSR was saved to file '{args.csr_file_path}'.", file=stdout)
    return 0


def _check_device_cert(certs_bytes, client, stdout):
    try:
        certs = cryptography.x509.load_pem_x509_certificates(certs_bytes)
    except ValueError:
        raise RuntimeError("unable to load X.509 device certificate in PEM format")
    csr = cryptography.x509.load_pem_x509_csr(client.csr())
    for i in range(len(certs)):
        if certs[i].public_key().public_numbers() == csr.public_key().public_numbers():
            cert_chain = [certs.pop(i)]
            break
    else:
        raise RuntimeError("device certificate does not belong to this device")
    i = 0
    while i < len(certs) and not _is_root(cert_chain[-1]):
        try:
            cert_chain[-1].verify_directly_issued_by(certs[i])
            cert_chain.append(certs.pop(i))
            i = 0
        except:
            i += 1
    if len(certs) > 0:
        print(
            f"WARNING: {len(certs)} unused certificate{'s' if len(certs) > 1 else ''} found in device certificate PEM bundle:",
            file=stdout,
        )
        for i, cert in enumerate(certs):
            print(f"  {i + 1}:", file=stdout)
            _print_single_cert_info(cert, stdout)
        print(file=stdout)
    if not _is_root(cert_chain[-1]):
        print(
            f"WARNING: device certificate trust chain does not include a root certificate",
            file=stdout,
        )
    return cert_chain


def _check_server_ca_cert(cert_bytes):
    try:
        certs = cryptography.x509.load_pem_x509_certificates(cert_bytes)
    except ValueError:
        raise RuntimeError("unable to load X.509 CA server certificate in PEM format")
    if len(certs) != 1:
        raise RuntimeError(
            "server verification file should contain only one certificate"
        )
    return certs[0]


def _verify_pem_file(pem_data, pem_password: str = None) -> bool:
    """
    Verifies that the PEM file contains a valid private key and certificate chain.
    
    :param pem_data: The content of the PEM file as bytes.
    :param pem_password: The password of the private key.
    :return: True if verification is successful, otherwise raises an exception.
    """
    password = str(pem_password).encode() if pem_password else None
    private_key = load_pem_private_key(pem_data, password=password, backend=default_backend())

    #  Validate the private key type (RSA or EC) and enforce key requirements
    _validate_private_key(private_key)

    # Load all certificates from the PEM data
    certificates = x509.load_pem_x509_certificates(pem_data)
    if not certificates:
        raise ValueError("No certificates found in the PEM data.")

    _verify_certificate_chain(certificates)

    print("PEM file verification successful.")
    return True


def _validate_private_key(private_key) -> None:
    """
    Ensures the private key is of a supported type and size/curve
    required by the Android Keystore.

    https://developer.android.com/privacy-and-security/keystore#HardwareSecurityModule
    """
    if isinstance(private_key, rsa.RSAPrivateKey):
        if private_key.key_size != 2048:
            raise ValueError(
                "RSA key size is not 2048 bits, which is required by the Android Keystore."
            )
    elif isinstance(private_key, ec.EllipticCurvePrivateKey):
        if private_key.curve.name != "secp256r1":
            raise ValueError(
                f"Elliptic curve {private_key.curve.name} is not supported by the Android Keystore. "
                f"Only P-256 (secp256r1) is supported."
            )
    else:
        raise ValueError("Private key algorithm is not supported by the Android Keystore.")


def _verify_certificate_chain(certificates: list[x509.Certificate]) -> None:
    """
    Verifies that certificates form a valid chain from the last
    element to the first (i.e., leaf to root).
    Raises an exception if any step fails.
    """
    certs = []
    for cert in certificates:
        pem_data = cert.public_bytes(serialization.Encoding.PEM)
        print(f"Found Certificate:")
        _print_single_cert_info(cert, None)
        certs.append(OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, pem_data))

    try:
        # If there's only one certificate, treat it as self-signed
        if len(certs) == 1:
            single_cert = certs[0]
            store = OpenSSL.crypto.X509Store()
            store.add_cert(single_cert)  # trust anchor
            store_ctx = OpenSSL.crypto.X509StoreContext(store, single_cert)
            store_ctx.verify_certificate()
            return

        leaf_cert = certs[0]
        intermediates = certs[1:-1]
        root_cert = certs[-1]

        store = OpenSSL.crypto.X509Store()
        store.add_cert(root_cert)

        store_ctx = OpenSSL.crypto.X509StoreContext(store, leaf_cert, intermediates)
        store_ctx.verify_certificate()
    except OpenSSL.crypto.X509StoreContextError as err:
        print(f"\n\nMake sure the .pem order is correct leaf -> intermediate(s) -> root.\n"
              f"Private-Key can be at the begin or end.\n\n")
        raise err

def _is_root(cert):
    try:
        cert.verify_directly_issued_by(cert)
        return True
    except (ValueError, TypeError, cryptography.exceptions.InvalidSignature):
        return False


def _isoformat(dt):
    return dt.isoformat().replace("+00:00", "Z")


def _print_single_cert_info(cert, stdout):
    print(f"  | Subject: {cert.subject.rfc4514_string()}", file=stdout)
    print(f"  | Issuer : {cert.issuer.rfc4514_string()}", file=stdout)
    print(
        f"  | Validity: {_isoformat(cert.not_valid_before_utc)} - {_isoformat(cert.not_valid_after_utc)}",
        file=stdout,
    )
    print(
        f"  | Fingerprint (SHA-256): {cert.fingerprint(cryptography.hazmat.primitives.hashes.SHA256()).hex(':')}",
        file=stdout,
    )
    if _is_root(cert):
        print("  which is a root certificate", file=stdout)


def _print_cert_info(device_cert_chain, server_ca_cert, stdout):
    if device_cert_chain is not None:
        print(
            "The following device certificate was installed into the Neat device:",
            file=stdout,
        )
        for i, cert in enumerate(device_cert_chain):
            _print_single_cert_info(cert, stdout)
            if i < len(device_cert_chain) - 1:
                print("  which is trusted by CA with certificate:", file=stdout)
        print(
            "EAP TLS server needs to trust at least one issuer listed above.",
            file=stdout,
        )
    if server_ca_cert is not None:
        print(file=stdout)
        print(
            "Neat device was configured to trust the following certificate when connecting to EAP TLS server:",
            file=stdout,
        )
        _print_single_cert_info(server_ca_cert, stdout)


def init_eth(client, args, stdout):
    with args.device_cert_file_path.open("rb") as file:
        device_cert_chain = _check_device_cert(file.read(), client, stdout)
    if args.server_ca_cert_file_path is not None:
        with args.server_ca_cert_file_path.open("rb") as file:
            server_ca_cert = _check_server_ca_cert(file.read())
    else:
        server_ca_cert = None
    init_call = client.init(args.identity, device_cert_chain, server_ca_cert)
    print(init_call.text, file=stdout)
    assert init_call.status_code == requests.codes.ok
    _print_cert_info(device_cert_chain, server_ca_cert, stdout)
    return 0


init = init_eth


def delete_eth(client, _, stdout):
    print(client.delete_ethernet().text, file=stdout)


def delete_wifi(client, _, stdout):
    print(client.delete_wifi().text, file=stdout)


def delete_certs(client, _, stdout):
    print(client.delete_certificates().text, file=stdout)


def init_wifi(client, args, stdout):
    with args.wifi_config_file_path.open("rb") as file:
        config_json = json.load(file)
    if args.device_cert_file_path is not None:
        with args.device_cert_file_path.open("rb") as file:
            device_cert_chain = _check_device_cert(file.read(), client, stdout)
    else:
        if "deviceCertificate" in config_json["credentials"]:
            device_cert_chain = _check_device_cert(
                config_json["credentials"]["deviceCertificate"].encode(), client, stdout
            )
        else:
            device_cert_chain = None
    if args.server_ca_cert_file_path is not None:
        with args.server_ca_cert_file_path.open("rb") as file:
            server_ca_cert = _check_server_ca_cert(file.read())
    else:
        if "caCertificate" in config_json["credentials"]:
            server_ca_cert = _check_server_ca_cert(
                config_json["credentials"]["caCertificate"].encode()
            )
        else:
            server_ca_cert = None
    init_call = client.init_wifi(config_json, device_cert_chain, server_ca_cert)
    print(init_call.text, file=stdout)
    assert init_call.status_code == requests.codes.ok
    _print_cert_info(device_cert_chain, server_ca_cert, stdout)
    return 0


def init_scep(client, args, stdout):
    if client.no_scep:
        raise client._unsupported_operation()
    with args.scep_config_file_path.open("rb") as file:
        config_json = json.load(file)
    if client.scep_only_https:
        serverUrl = config_json["serverUrl"]
        if urllib.parse.urlsplit(serverUrl).scheme != "https":
            raise RuntimeError(
                f"SCEP configruation error: serverUrl: '{serverUrl}': Only HTTPS supported."
            )
    caFingerprint = config_json.get("caFingerprint", None)
    if caFingerprint is not None:
        if re.match("^[0-9a-fA-F]{64}$", caFingerprint) is None:
            raise RuntimeError(
                f"SCEP configruation error: caFingerprint: '{caFingerprint}': Expected SHA-256 digest consisting of 64 hexadecimal digits."
            )
    connectionType = config_json.get("connectionType", None)
    if connectionType is not None:
        if connectionType.upper() not in ("ETHERNET", "WIFI"):
            raise RuntimeError(
                f"SCEP configruation error: connectionType: '{connectionType}': Should be either 'ETHERNET' or 'WIFI'."
            )
    if args.server_ca_cert_file_path is not None:
        with args.server_ca_cert_file_path.open("rb") as file:
            server_ca_cert = _check_server_ca_cert(file.read())
    else:
        server_ca_cert = None
    scep_call = client.init_scep(config_json, server_ca_cert)
    print(scep_call.text, file=stdout)
    assert scep_call.status_code == requests.codes.ok


def renew_scep(client, _, stdout):
    scep_call = client.renew_scep()
    print(scep_call.text, file=stdout)
    assert scep_call.status_code == requests.codes.ok


def list(client, _, stdout):
    print(json.dumps(client.certificates(), indent=2), file=stdout)
    return 0


def list_https_ca(client, _, stdout):
    print(json.dumps(client.list_trusted_ca(), indent=2), file=stdout)
    return 0


def trust_https_ca(client, args, stdout):
    with args.ca_cert_path.open("rb") as file:
        ca_cert = _check_server_ca_cert(file.read())
    upload_call = client.trust_ca(ca_cert)
    print(upload_call.text, file=stdout)
    assert upload_call.status_code == requests.codes.ok


def set_webserver_cert(client, args, stdout):
    with args.set_webserver_cert.open("rb") as file:
        verify = _verify_pem_file(file.read(), args.pem_password)
    upload_call = client.set_web_cert(args.set_webserver_cert, args.pem_password, args.reboot)
    print(upload_call.text, file=stdout)
    assert upload_call.status_code == requests.codes.ok


def reboot(client, args, stdout):
    reboot_call = client.reboot()
    if reboot_call.status_code != requests.codes.ok:
        print(reboot_call.text, file=stdout)
    assert reboot_call.status_code == requests.codes.ok
    print("Neat device reboot in progress.", file=stdout)


def set_hostname(client, args, stdout):
    set_hostname_call = client.set_hostname(args.hostname)
    if set_hostname_call.status_code != requests.codes.ok:
        print(set_hostname_call.text, file=stdout)
    assert set_hostname_call.status_code == requests.codes.ok
    if args.reboot:
        reboot_call = client.reboot()
        if reboot_call.status_code != requests.codes.ok:
            print(reboot_call.text, file=stdout)
        assert reboot_call.status_code == requests.codes.ok
        print("Neat device reboot in progress.", file=stdout)


def get_hostname(client, _, stdout):
    print(client.get_hostname(), file=stdout)


def main(args, stdout):
    return globals()[args.cmd](
        Dot1xClient(args.host, args.username, args.password, args.verbose), args, stdout
    )


def cli(args=None, stdout=sys.stdout):
    return main(get_argparser().parse_args(args), stdout)
