import asyncio
import json

import pytest
import requests
from tornado.httpclient import HTTPRequest

from crawler_utils.async_proxy import AsyncProxyClient


@pytest.fixture
def async_client():
    return AsyncProxyClient()


def test_proxies(async_client):
    non_proxy_body = requests.get("http://ip-api.com/json").json()

    el = asyncio.get_event_loop()
    res = el.run_until_complete(async_client.fetch(HTTPRequest(method="GET", url="http://ip-api.com/json")))
    body = json.loads(res.body.decode())

    assert non_proxy_body['query'] != body['query']

    used_ips = set()
    for i in range(10):
        res = el.run_until_complete(async_client.fetch(HTTPRequest(method="GET", url="http://ip-api.com/json")))
        body = json.loads(res.body.decode())
        used_ips.add(body['query'])
    assert len(used_ips) > 1
