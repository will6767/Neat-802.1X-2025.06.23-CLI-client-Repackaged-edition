import sys
import time
import warnings

import requests
import urllib3

warnings.simplefilter("ignore", urllib3.exceptions.InsecureRequestWarning)


class TokenAuth(requests.auth.AuthBase):
    def __init__(self, token):
        assert isinstance(token, str)
        self.token = token

    def __call__(self, request):
        request.headers["Authorization"] = "Bearer {}".format(self.token)
        return request

    def __str__(self):
        return self.__class__.__name__


class WebApiClient:
    def __init__(self, host, auth=None, verbose=True):
        self.host = host
        self.auth = auth
        self.verbose = verbose

    def request(self, method, route, data, json, files):
        url = "https://{}{}".format(self.host, route)
        if self.verbose:
            print(
                '{} "{}" (auth: {}) '.format(method, url, self.auth),
                file=sys.stderr,
                end="",
                flush=True,
            )
            t = time.time()
        response = requests.request(
            method, url, verify=False, auth=self.auth, data=data, json=json, files=files
        )
        if self.verbose:
            print(
                "-> {} (Length: {}, Type: {!r}) [{:.2f}s]".format(
                    response.status_code,
                    len(response.content),
                    response.headers.get("Content-Type", None),
                    time.time() - t,
                ),
                file=sys.stderr,
                flush=True,
            )
        return response

    def get(self, route):
        return self.request("GET", route, None, None, None)

    def post(self, route, data=None, json=None, files=None):
        return self.request("POST", route, data, json, files)

    def put(self, route, data=None, json=None, files=None):
        return self.request("PUT", route, data, json, files)

    def delete(self, route):
        return self.request("DELETE", route, None, None, None)

    def login(self, username, password):
        response = self.post(
            "/api/v1/admin_login", json=dict(userName=username, password=password)
        )
        if response.status_code == requests.codes.too_many_requests:
            raise RuntimeError(f"Too many login attempts. {response.text}")
        if response.status_code != requests.codes.ok:
            raise RuntimeError(
                "Login failed - please check that the username and password are correct"
            )
        self.auth = TokenAuth(response.text)
        return self

    def status(self):
        return self.get("/api/v1/status").json()


def create_logged_in_client(host, username, password):
    return WebApiClient(host).login(username, password)
