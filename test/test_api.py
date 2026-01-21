import requests

from ca import CA
from fake_request_handler import (
    HOST_OR_IP,
    PASSWORD,
    SERIAL,
    USERNAME,
    FakeRequestHandler,
)


def test_csr_and_init():
    from neat_dot1x_client import Dot1xClient

    ca = CA()
    with FakeRequestHandler(ca, expect_server_ca=False):
        client = Dot1xClient(HOST_OR_IP, USERNAME, PASSWORD)
        csr = client.csr()
        cert_chain = ca.sign(csr)
        response = client.init(SERIAL, cert_chain)
        assert response.status_code == requests.codes.ok
        assert response.text == "Successfully configured the wired eap tls network"
