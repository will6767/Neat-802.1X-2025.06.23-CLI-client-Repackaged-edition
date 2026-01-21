import argparse
import getpass
import importlib.metadata
import pathlib


def get_argparser():
    parser = argparse.ArgumentParser(description="Neat 802.1X configuration client.")
    parser.add_argument(
        "-V",
        "--version",
        action="version",
        version=f"neat-dot1x-cli 2025.06.23 - Repackaged edition",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="log web-API interaction to terminal",
    )
    parser.add_argument(
        "host", metavar="HOST_OR_IP", help="Neat device's host name or IP-address"
    )
    parser.add_argument("username", metavar="USERNAME", help="'admin' or 'oob'")
    parser.add_argument("password", metavar="PASSWORD", help="password")
    subparsers = parser.add_subparsers(dest="cmd", required=True, help="sub-commands")
    parser_csr = subparsers.add_parser(
        "csr", help="generate CSR (Certificate Signing Request)"
    )
    parser_csr.add_argument(
        "csr_file_path",
        metavar="CSR_PEM_FILE",
        type=pathlib.Path,
        help="where to save PEM-formatted PKCS #10 CSR received from device",
    )
    group = parser_csr.add_mutually_exclusive_group()
    group.add_argument(
        "subject_json_str",
        metavar="SUBJECT_JSON_STRING",
        nargs="?",
        help="JSON-formatted string specifying CSR subject",
    )
    group.add_argument(
        "--subject-file",
        dest="subject_json_file",
        metavar="SUBJECT_JSON_FILE",
        type=pathlib.Path,
        help="path to JSON-formatted file specifying CSR subject",
    )
    parser_init = subparsers.add_parser(
        "init_eth", aliases=["init"], help="initialize 802.1X for Ethernet"
    )
    parser_init.add_argument("identity", metavar="IDENTITY", help="802.1X identity")
    parser_init.add_argument(
        "device_cert_file_path",
        metavar="DEVICE_CERTIFICATE_CHAIN_PEM_FILE",
        type=pathlib.Path,
        help="path to PEM-formatted file containing X.509 device certificate and its trust chain",
    )
    parser_init.add_argument(
        "server_ca_cert_file_path",
        metavar="SERVER_VERIFICATION_PEM_FILE",
        type=pathlib.Path,
        nargs="?",
        help="path to optional PEM-formatted file containing one X.509 CA certificate used to verify the 802.1X server",
    )
    parser_init_wifi = subparsers.add_parser(
        "init_wifi", help="initialize 802.1X for Wi-Fi"
    )
    parser_init_wifi.add_argument(
        "wifi_config_file_path",
        metavar="WIFI_CONFIG_JSON",
        type=pathlib.Path,
        help="path to JSON-formatted Wi-Fi configuration file",
    )
    parser_init_wifi.add_argument(
        "device_cert_file_path",
        metavar="DEVICE_CERTIFICATE_CHAIN_PEM_FILE",
        type=pathlib.Path,
        nargs="?",
        help="path to PEM-formatted file containing X.509 device certificate and its trust chain",
    )
    parser_init_wifi.add_argument(
        "server_ca_cert_file_path",
        metavar="SERVER_VERIFICATION_PEM_FILE",
        type=pathlib.Path,
        nargs="?",
        help="path to optional PEM-formatted file containing one X.509 CA certificate used to verify the 802.1X server",
    )
    parser_init_scep = subparsers.add_parser(
        "init_scep", help="initialize 802.1X via SCEP"
    )
    parser_init_scep.add_argument(
        "scep_config_file_path",
        metavar="SCEP_CONFIG_JSON_FILE",
        type=pathlib.Path,
        help="path to JSON-formatted SCEP configuration file",
    )
    parser_init_scep.add_argument(
        "server_ca_cert_file_path",
        metavar="SERVER_VERIFICATION_PEM_FILE",
        type=pathlib.Path,
        nargs="?",
        help="path to optional PEM-formatted file containing one X.509 CA certificate used to verify the SCEP server",
    )
    subparsers.add_parser("renew_scep", help="renew scep managed 802.1X certificates")
    subparsers.add_parser("list", help="list installed 802.1X certificates")
    subparsers.add_parser("delete_eth", help="clear 802.1X Ethernet configuration")
    subparsers.add_parser("delete_wifi", help="clear active Wi-Fi configuration")
    subparsers.add_parser("delete_certs", help="clear all 802.1X certificates")
    subparsers.add_parser(
        "list_https_ca", help="list installed CA certificates in the HTTPS trust store"
    )
    subparsers.add_parser(
        "reboot", help="reboot the device"
    )
    parser_trust_ca = subparsers.add_parser(
        "trust_https_ca", help="install CA certificate into the HTTPS trust store"
    )
    parser_trust_ca.add_argument(
        "ca_cert_path",
        metavar="HTTPS_TRUST_PEM_FILE",
        type=pathlib.Path,
        help="path to PEM-formatted file containing one X.509 CA certificate used to verify HTTPS servers",
    )

    parser_set_webserver_cert = subparsers.add_parser(
        "set_webserver_cert", help="install certificate for the web server"
    )
    parser_set_webserver_cert.add_argument(
        "set_webserver_cert",
        metavar="WEB_SERVER_PEM_FILE",
        type=pathlib.Path,
        help="Path to PEM-formatted file containing a private-key and X.509 CA certificates."
    )
    parser_set_webserver_cert.add_argument(
        '--pem-password',
        action=Password,
        nargs='?',
        help="Password for the PEM private-key",
    )
    parser_set_webserver_cert.add_argument(
        "--reboot",
        action="store_true",
        help="Reboots Neat device after successfully uploading the certificate to activate the new pem certificate.",
    )

    parser_set_hostname = subparsers.add_parser("set_hostname", help="set host name")
    parser_set_hostname.add_argument(
        "hostname",
        metavar="HOSTNAME",
        help="host name to be set",
    )
    parser_set_hostname.add_argument(
        "--reboot",
        action="store_true",
        help="reboot Neat device to activate new host name",
    )
    subparsers.add_parser("get_hostname", help="get host name")
    return parser


class Password(argparse.Action):
    def __call__(self, parser, namespace, values, option_string):
        if values is None:
            values = getpass.getpass()
        setattr(namespace, self.dest, values)
