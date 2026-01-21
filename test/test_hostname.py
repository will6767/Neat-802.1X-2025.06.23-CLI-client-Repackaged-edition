import io

from fake_request_handler import HOST_OR_IP, PASSWORD, USERNAME, FakeRequestHandler


def test_set_and_get_hostname():
    from neat_dot1x_client.cli import cli

    with FakeRequestHandler() as fake_request_handler:
        hostname = "CustomHostname"
        cli([HOST_OR_IP, USERNAME, PASSWORD, "set_hostname", hostname])
        assert fake_request_handler.hostname == hostname
        assert not fake_request_handler.rebooted
        fake_stdout = io.StringIO()
        cli([HOST_OR_IP, USERNAME, PASSWORD, "get_hostname"], fake_stdout)
        assert fake_stdout.getvalue() == f"{hostname}\n"


def test_set_hostname_and_reboot():
    from neat_dot1x_client.cli import cli

    with FakeRequestHandler() as fake_request_handler:
        hostname = "CustomHostname"
        fake_stdout = io.StringIO()
        cli(
            [HOST_OR_IP, USERNAME, PASSWORD, "set_hostname", "--reboot", hostname],
            fake_stdout,
        )
        assert fake_request_handler.hostname == hostname
        assert fake_request_handler.rebooted
        assert fake_stdout.getvalue() == "Neat device reboot in progress.\n"
