from pathlib import Path

from cryptography.hazmat.primitives import serialization

from ca import CA
from fake_request_handler import (
    HOST_OR_IP,
    PASSWORD,
    SERIAL,
    USERNAME,
    FakeRequestHandler,
)


def cli_csr_and_init(tmp_path: Path, use_server_ca_cert: bool, cert_chain_manipulator=lambda cert_chain: cert_chain):
    from neat_dot1x_client.cli import cli

    ca = CA()

    with FakeRequestHandler(ca, expect_server_ca=use_server_ca_cert) as fake_request_handler:
        # CSR output path (do not pre-open it, let the CLI create/write it)
        csr_path = tmp_path / "device.csr"
        cli([HOST_OR_IP, USERNAME, PASSWORD, "csr", str(csr_path)])
        csr = csr_path.read_bytes()

        cert_chain = cert_chain_manipulator(ca.sign(csr))

        # Cert chain file
        cert_chain_path = tmp_path / "cert-chain.pem"
        cert_chain_path.write_bytes(
            b"".join(cert.public_bytes(serialization.Encoding.PEM) for cert in cert_chain)
        )

        # Optional server CA file
        args = [HOST_OR_IP, USERNAME, PASSWORD, "init", SERIAL, str(cert_chain_path)]
        if use_server_ca_cert:
            server_ca_path = tmp_path / "server-ca.pem"
            server_ca_path.write_bytes(ca.cert.public_bytes(serialization.Encoding.PEM))
            args.append(str(server_ca_path))

        cli(args)

        assert fake_request_handler.network_config_ethernet_called is True


def test_cli_csr_and_init(tmp_path):
    cli_csr_and_init(tmp_path, False)


def test_cli_csr_and_init_with_server_ca(tmp_path):
    cli_csr_and_init(tmp_path, True)


def test_reverse_cert_chain(tmp_path):
    cli_csr_and_init(tmp_path, True, reversed)


def test_shuffled_cert_chain(tmp_path):
    cli_csr_and_init(tmp_path, True, lambda cert_chain: [cert_chain[i] for i in (0, 2, 1)])


def test_cert_chain_with_duplicates(tmp_path):
    cli_csr_and_init(tmp_path, True, lambda cert_chain: [cert_chain[i] for i in (1, 2, 0, 1, 2)])


def test_cert_chain_with_unrelated_certs(tmp_path):
    unrelated_ca = CA("unrelated CA")
    cli_csr_and_init(tmp_path, True, lambda cert_chain: list(cert_chain) + [unrelated_ca.cert])
