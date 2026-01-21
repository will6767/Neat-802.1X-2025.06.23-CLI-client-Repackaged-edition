import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa


class CA:
    def __init__(self, common_name="CA"):
        CA_DN = x509.Name(
            [
                x509.NameAttribute(x509.NameOID.COMMON_NAME, common_name),
            ]
        )
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        self.cert = (
            x509.CertificateBuilder()
            .subject_name(CA_DN)
            .issuer_name(CA_DN)
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
            .not_valid_after(
                datetime.datetime.now(datetime.timezone.utc)
                + datetime.timedelta(hours=1)
            )
            .serial_number(x509.random_serial_number())
            .public_key(self.key.public_key())
            .sign(self.key, hashes.SHA256())
        )

    def sign(self, csr):
        csr = x509.load_pem_x509_csr(csr)
        assert csr.is_signature_valid
        SUB_CA_DN = x509.Name(
            [
                x509.NameAttribute(x509.NameOID.COMMON_NAME, "sub-CA"),
            ]
        )
        sub_ca_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        sub_ca_cert = (
            x509.CertificateBuilder()
            .subject_name(SUB_CA_DN)
            .issuer_name(self.cert.subject)
            .not_valid_before(self.cert.not_valid_before_utc)
            .not_valid_after(self.cert.not_valid_after_utc)
            .serial_number(x509.random_serial_number())
            .public_key(sub_ca_key.public_key())
            .sign(self.key, hashes.SHA256())
        )
        issued_cert = (
            x509.CertificateBuilder()
            .subject_name(csr.subject)
            .issuer_name(sub_ca_cert.subject)
            .not_valid_before(sub_ca_cert.not_valid_before_utc)
            .not_valid_after(sub_ca_cert.not_valid_after_utc)
            .serial_number(x509.random_serial_number())
            .public_key(csr.public_key())
            .sign(sub_ca_key, hashes.SHA256())
        )
        self.issued_cert_chain = [issued_cert, sub_ca_cert, self.cert]
        return self.issued_cert_chain
