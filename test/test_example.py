from ca import CA
from fake_request_handler import HOST_OR_IP, PASSWORD, SERIAL, FakeRequestHandler


def test_example():
    from example import main

    ca = CA()
    with FakeRequestHandler(ca, expect_server_ca=True) as fake_request_handler:
        main(ca, HOST_OR_IP, PASSWORD, SERIAL)
        assert fake_request_handler.network_config_ethernet_called == True
