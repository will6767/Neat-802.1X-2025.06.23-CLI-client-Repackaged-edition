#!/usr/bin/env python3

from neat_dot1x_client import Dot1xClient


def main(ca, address, password, identity):
    client = Dot1xClient(address, "oob", password)
    csr = client.csr()
    cert_chain = ca.sign(csr)
    server_ca = ca.cert
    result = client.init(identity, cert_chain, server_ca)
    result.raise_for_status()
    print(result.text)


if __name__ == "__main__":
    import sys

    from ca import CA

    main(CA(), *sys.argv[1:])
