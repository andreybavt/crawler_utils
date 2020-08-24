import asyncio
import json
import logging
import os
import random
import re
import sys
import time
import traceback
import urllib.parse
from asyncio import CancelledError

import jsonpickle
import requests
from bs4 import BeautifulSoup
from tornado.curl_httpclient import AsyncHTTPClient, CurlAsyncHTTPClient
from tornado.httpclient import HTTPRequest
from tornado.httputil import parse_cookie

from crawler_utils.utils import nofail, nofail_async, chunks

logging.basicConfig(stream=sys.stdout, level=os.environ.get('LOGLEVEL', 'INFO').upper(),
                    format='%(asctime)s %(levelname)s %(name)s: %(message)s')


class TornadoLoggerFilter(logging.Filter):

    def filter(self, record):
        if 'Exception after Future was cancelled' in record.msg:
            return False
        return record.exc_info[0] != UserCancelException


logging.getLogger("tornado.application").addFilter(TornadoLoggerFilter())


@nofail(retries=1)
def create_browser():
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    chrome_options = Options()
    chrome_options.add_argument('--headless')
    chrome_options.add_argument('--no-sandbox')
    chrome_options.add_argument('--disable-dev-shm-usage')
    logging.info(f"CHROME: {os.getenv('CHROMEDRIVER_PATH', 'chromedriver')}")
    browser = webdriver.Chrome(executable_path=os.getenv('CHROMEDRIVER_PATH', 'chromedriver'),
                               options=chrome_options)
    return browser


class AsyncProxyClient(object):
    AsyncHTTPClient.configure('tornado.curl_httpclient.CurlAsyncHTTPClient')

    def __init__(self, enable_proxy=True, penalty_fn=None, promote_fn=None, max_clients=50,
                 before_retry_callback=None) -> None:
        super().__init__()
        self.shuffle_proxy_for_each_request = True
        self.fetch_opts = {}
        self.enable_proxy = enable_proxy
        self.before_retry_callback = before_retry_callback
        if self.enable_proxy:
            self.proxy_manager = ProxyManager(penalty_fn, promote_fn)
        self._client = CurlAsyncHTTPClient(max_clients=max_clients, defaults=dict(validate_cert=True))

    async def patient_fetch(self, request, proxy=None, use_proxy_for_request=True, redundancy=1, **kwargs):
        impatient_fetch = nofail_async(before_retry_callback=self.before_retry_callback)(self.impatient_fetch)
        return await impatient_fetch(request, proxy, use_proxy_for_request, redundancy, **kwargs)

    async def impatient_fetch(self, request, proxy=None, use_proxy_for_request=True, redundancy=1, **kwargs):
        res = await asyncio.wait(
            [self.fetch(request, proxy=proxy, use_proxy_for_request=use_proxy_for_request, **kwargs) for _ in
             range(redundancy)], return_when=asyncio.FIRST_COMPLETED)
        for task in [j for e in res for j in e if not j.done()]:
            task.cancel()
        result = [j for e in res for j in e if j.done()][0].result()
        return result

    async def fetch(self, request: HTTPRequest, proxy=None, use_proxy_for_request=True, **kwargs):
        ok_statuses = set([200] + kwargs.get('ok_statuses', []))
        logging.debug(f"Sending {request.method} : {request.url}")
        if kwargs.get('cookies'):
            cookies = ';'.join([f'{i[0]}={i[1]}' for i in
                                {**parse_cookie(request.headers.get('Cookie', '')), **kwargs.get('cookies')}.items()])
            request.headers['Cookie'] = cookies
        is_proxying = self.enable_proxy and use_proxy_for_request
        curr_proxy = None
        try:
            if is_proxying:
                while not self.proxy_manager.has_proxies():
                    await asyncio.sleep(1)
                self.shuffle_proxy_for_each_request and self.proxy_manager.shuffle_proxy()
                curr_proxy: Proxy = self.proxy_manager.current_proxy if not proxy else proxy
                request.proxy_host = curr_proxy.ip
                request.proxy_port = curr_proxy.port
                if curr_proxy.username:
                    request.proxy_username = curr_proxy.username
                if curr_proxy.password:
                    request.proxy_password = curr_proxy.password

            request.connect_timeout = kwargs.get('connect_timeout', 10)
            request.request_timeout = kwargs.get('request_timeout', 60)
            if is_proxying and curr_proxy:
                logging.debug(f"using proxy: {curr_proxy.ip}")

            res = await self._client.fetch(request, raise_error=False)
            if res.code not in ok_statuses:
                # not self.shuffle_proxy_for_each_request and self.proxy_manager.shuffle_proxy()
                logging.error(f"BadResponseCodeException: {res.code}")
                raise BadResponseCodeException(res.code)
            if is_proxying:
                self.proxy_manager.promote_proxy(curr_proxy)
            return self.enhance_response(res)
        except CancelledError:
            pass
        except Exception as e:
            if kwargs.get('error_handler'):
                kwargs.get('error_handler')(e, self.proxy_manager, curr_proxy)
            if is_proxying:
                await self.proxy_manager.punish_proxy(curr_proxy, e)
            raise e

    def enhance_response(self, res):
        import json as JSON

        def json():
            return JSON.loads(res.body.decode())

        res.json = json
        return res


class Proxy(object):
    UNKNOWN = '¯\\_(ツ)_/¯'

    def __init__(self, ip: str, port: int, c_code=UNKNOWN, country=UNKNOWN, username=None, password=None) -> None:
        super().__init__()
        self.ip = ip
        self.port = port
        self.c_code = c_code
        self.country = country
        self.username = username
        self.password = password

    def __repr__(self) -> str:
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True)

    # def __eq__(self, o: object) -> bool:
    #     if not isinstance(o, Proxy):
    #         return False
    #
    #     return self.ip == o.ip and self.port == o.port


class TorProxy(Proxy):

    def __init__(self, ip, port=9050, api_port=9052) -> None:
        super().__init__('socks5://' + ip, port, c_code="TOR", country="TOR", username=None, password=None)
        self.api_port = api_port
        self.tor_host_ip = ip
        self.__proxy_data = self.reload()
        self.country = self.__proxy_data['country']

    def reload(self):
        import requests
        self.__proxy_data = requests.post(f'http://{self.tor_host_ip}:{self.api_port}/change').json()
        self.country = self.__proxy_data['country']
        logging.info("Reloaded TOR proxy, now: " + json.dumps(self.__proxy_data))
        return self.__proxy_data


class ProxyManager(object):
    def __init__(self, penalty_fn=None, promote_fn=None) -> None:
        super().__init__()
        self.initializing_proxies = False
        self._proxy_list = []
        self.current_proxy = None
        asyncio.get_event_loop().run_until_complete(self.initialize_proxy_list(force=False))
        self.shuffle_proxy()
        self.penalty_fn = penalty_fn if penalty_fn is not None else self.default_penalty_fn
        self.promote_fn = promote_fn if promote_fn is not None else self.default_promote_fn

    async def fetch_proxies(self, https_only=False, force=False):
        from datetime import date
        # proxy_file_path = os.path.join(os.path.dirname(__file__), "proxies.json")
        proxy_file_path = "../proxies.json"
        all_found_proxies_result = []
        if not force and os.path.exists(proxy_file_path):
            with open(proxy_file_path, "r") as f:
                try:
                    proxy_cache_file = jsonpickle.decode(f.read())
                    if proxy_cache_file['date'] == str(date.today()) or os.getenv('DEV'):
                        logging.debug(
                            f"Found today's proxy list, giving it: {len(proxy_cache_file['proxies'])} proxies")
                        all_found_proxies_result = proxy_cache_file['proxies']
                        return all_found_proxies_result
                except:
                    logging.error(f"Error while fetching proxies \n {traceback.format_exc()}")

        def fetch_proxydb():
            headers = {
                'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.86 Safari/537.36'}

            def fetch_countries():
                # url = "http://proxydb.net/?protocol=https&min_uptime=80&max_response_time=4"
                url = "http://proxydb.net/?protocol=https&min_uptime=80"
                res = requests.get(url=url, headers=headers)
                soup = BeautifulSoup(res.content.decode(), 'lxml')
                countries = [e['value'] for e in soup.select('#country option') if e['value']]
                return countries

            def collect_proxydb_for_country(c, browser):
                res = []
                logging.info(f"Collecting proxies for {c}")
                i = 0
                retry = 0
                table_el = None
                while True:
                    try:
                        # &offset={i}
                        page_res = requests.get(
                            url=f"http://proxydb.net/?protocol=https&min_uptime=80&max_response_time=4&country={c}",
                            headers=headers)
                        html = page_res.content.decode()

                        # browser.get(
                        #     f"http://proxydb.net/?protocol=https&min_uptime=80&max_response_time=4&country={c}&offset={i}")
                        if not len(html):
                            logging.info(f"Empty response page for {c}")
                            break
                        if "No proxies found. Try other filter settings or" in html:
                            break
                        soup = BeautifulSoup(html, 'lxml')
                        table_el = soup.select_one(".table-responsive")
                        data_divs = [e for e in soup.select('div') if
                                     len(list(filter(lambda x: x.startswith('data-'), e.attrs.keys())))]
                        if len(data_divs) == 0:
                            logging.info(f"No data_divs found for {c}")
                            break
                        data_key_attrs = data_divs[0].attrs
                        for (k, v) in data_key_attrs.items():
                            if k.startswith('data-'):
                                data_key = v
                                break
                        break
                    except Exception as e:
                        if retry > 10:
                            logging.error(e)
                            return res
                        else:
                            browser.quit()
                            time.sleep(15)
                            browser = create_browser()
                            retry += 1
                try:
                    if table_el:
                        if len(table_el.select('tr')[1:]):
                            logging.info(f'Proxies for {c}')
                        for r in table_el.select('tr')[1:]:
                            cells_els = r.select('td')
                            js = re.sub('document.*getAttribute\(.*?\)', data_key, cells_els[0].text.strip())
                            browser.execute_script("document.body.innerText = ''")
                            browser.execute_script(js)
                            cells = [c.text for c in cells_els]
                            addr = browser.find_element_by_tag_name('a').text
                            res.append(Proxy(
                                ip=addr.split(':')[0],
                                port=int(addr.split(':')[1]),
                                c_code=cells[2].strip(),
                                country=cells_els[2].select_one('img')['title']
                            ))
                except Exception as e:
                    logging.error(e)
                logging.info(f"Got {len(res)} proxies from {c}")
                return res

            result = []

            # countries = fetch_countries()
            countries = ["AF", "AL", "DZ", "AD", "AO", "AR", "AM", "AU", "AT", "AZ", "BS", "BD", "BY", "BE", "BZ", "BJ",
                         "BO", "BA", "BW", "BR", "BG", "BF", "BI", "KH", "CM", "CA", "CV", "TD", "CL", "CN", "CO", "CG",
                         "CD", "CR", "CI", "HR", "CU", "CY", "CZ", "DK", "DJ", "DO", "EC", "EG", "SV", "GQ", "EE", "EU",
                         "FI", "FR", "GF", "GA", "GE", "DE", "GH", "GR", "GU", "GT", "GN", "GY", "HT", "HN", "HK", "HU",
                         "IN", "ID", "IR", "IQ", "IE", "IM", "IL", "IT", "JM", "JP", "KZ", "KE", "KR", "KW", "KG", "LA",
                         "LV", "LB", "LS", "LR", "LY", "LT", "LU", "MK", "MG", "MW", "MY", "MV", "ML", "MT", "MU", "MX",
                         "MD", "MN", "ME", "MA", "MZ", "MM", "NA", "NP", "NL", "NC", "NZ", "NI", "NG", "NO", "PK", "PS",
                         "PA", "PG", "PY", "PE", "PH", "PL", "PT", "PR", "RO", "RU", "RW", "MF", "RS", "SC", "SL", "SG",
                         "SK", "SI", "SB", "SO", "ZA", "SS", "ES", "LK", "SD", "SZ", "SE", "CH", "SY", "TW", "TJ", "TZ",
                         "TH", "TL", "TT", "TR", "UG", "UA", "AE", "GB", "US", "UY", "UZ", "VE", "VN", "VI", "ZM", "ZW"]
            chrome_options = Options()
            chrome_options.add_argument("--headless")
            browser = create_browser()

            logging.info(f"found Countries {countries}")
            for c_num, c in enumerate(countries):
                result += collect_proxydb_for_country(c, browser)
            browser.quit()
            logging.info(f"Found  {len(result)}  proxies with fetch_proxydb")
            return result

        @nofail(retries=3, failback_result=[])
        def fetch_clarketm():
            result = []
            import requests
            resp = requests.get(
                'https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list.txt').text.split(
                '\n')
            for p in resp[4:]:
                if len(p.split(' ')) < 2:
                    continue
                properties = p.split(' ')[1].split('-')
                if len(properties) > 2 and properties[2] == 'S':
                    result.append(Proxy(ip=p.split(' ')[0].split(':')[0],
                                        port=int(p.split(' ')[0].split(':')[1]),
                                        c_code=p.split(' ')[1].split('-')[0],
                                        country=p.split(' ')[1].split('-')[0]))

            logging.info(f"Found {len(result)} proxies with fetch_clarketm")
            return result

        @nofail(retries=3, failback_result=[])
        def fetch_a2u():
            result = []
            import requests
            resp = requests.get(
                'https://raw.githubusercontent.com/a2u/free-proxy-list/master/free-proxy-list.txt').text.split(
                '\n')
            for p in resp:
                if len(p.split(':')) < 2:
                    continue
                result.append(Proxy(ip=p.split(':')[0], port=int(p.split(':')[1])))

            logging.info(f"Found {len(result)} proxies with a2u")
            return result

        @nofail_async(retries=3, failback_result=[])
        async def fetch_proxyrotator():
            result = []
            client = AsyncHTTPClient()

            async def fetch_proxy(i):
                logging.info(f'fetching froxy #{i} from proxyrotator')
                resp = await client.fetch(HTTPRequest(method='GET',
                                                      url='http://falcon.proxyrotator.com:51337/?apiKey=9EKVT48tBSANFXkxWbeMhCUZqwzypfPa&get=true&post=true'))
                data = json.loads(resp.body.decode())
                result.append(
                    Proxy(ip=data['ip'], port=int(data['port']), c_code=data['country'], country=data['country']))

            for chunk in chunks(range(300), 10):
                await asyncio.wait([fetch_proxy(i) for i in chunk])
            logging.info(f"Found {len(result)} proxies with proxyrotator")
            return result

        @nofail(retries=3, failback_result=[])
        def fetch_proxymesh():
            proxies = [
                # Proxy(username='idwangmo', password='951024001x', ip='fr.proxymesh.com', port=31280),
                # Proxy(username='idwangmo', password='951024001x', ip='jp.proxymesh.com', port=31280),
                Proxy(username='idwangmo', password='951024001x', ip='us-wa.proxymesh.com', port=31280),
                Proxy(username='kevinbond', password='kevinbond', ip='us.proxymesh.com', port=31280),
            ]
            return proxies

        @nofail(retries=30, failback_result=[])
        def fetch_gimmeproxy():
            result = []
            import requests
            for i in range(200):
                logging.info(f'fetching froxy #{i} from gimmeproxy')
                resp = requests.get(
                    'https://gimmeproxy.com/api/getProxy?protocol=http&get=true&post=true&supportsHttps=true&api_key=5a1a1257-cf8a-4975-b2fb-f01f13a3d023').text
                data = json.loads(resp)
                result.append(
                    Proxy(ip=data['ip'], port=int(data['port']), c_code=data['country'], country=data['country']))
            logging.info(f"Found {len(result)} proxies with proxyrotator")
            return result

        @nofail(retries=3, failback_result=[])
        def fetch_proxy_list():
            from lxml import html
            import re
            import base64
            import urllib
            import requests
            result = []
            with requests.Session() as ses:
                ses.headers.update({
                    'User-Agent': (
                        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
                        ' (KHTML, like Gecko) Chrome/63.0.3239.108 Safari/537.36'
                    )})
                url = 'https://proxy-list.org/english/index.php'
                while url is not None:
                    res = ses.get(url)
                    if res is None:
                        url = None
                        continue
                    parsed = html.fromstring(res.content)
                    sel = (
                        '#proxy-table > div.table-wrap > div > ul'
                    )
                    for ul_elem in parsed.cssselect(sel):
                        ip_port = ul_elem.cssselect('li.proxy script')[0].text
                        patt = "'(.+)'"
                        match = re.search(patt, ip_port)
                        if not match:
                            continue
                        ip_port = base64.b64decode(match.group(1)).decode('utf-8')
                        patt = r'(\d+\.\d+\.\d+\.\d+):(\d+)'
                        match = re.match(patt, ip_port)
                        if not match:
                            continue
                        ip = match.group(1)
                        port = match.group(2)
                        proxy_type = (''.join(ul_elem.cssselect(
                            'li.https'
                        )[0].itertext())).strip().lower()

                        if proxy_type == 'https':
                            result.append(Proxy(ip=ip, port=int(port)))

                    if url is None:
                        break
                    try:
                        url = urllib.parse.urljoin(
                            url,
                            parsed.cssselect('a.next')[0].get('href')
                        )
                    except IndexError:
                        url = None
            logging.info(f"Found {len(result)} proxies with proxy_list")
            return result

        @nofail(retries=3, failback_result=[])
        def fetch_proxynova():
            logging.info('fetching proxynova')
            import re
            import requests
            result = []
            with requests.Session() as ses:
                ses.headers.update({
                    'User-Agent': (
                        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
                        ' (KHTML, like Gecko) Chrome/63.0.3239.108 Safari/537.36'
                    )})
                url = 'https://www.proxynova.com/proxy-server-list'
                soup = BeautifulSoup(ses.get(url).text, 'lxml')
                options = soup.find(attrs={'name': 'proxy_country'}).find_all('option')
                countries = []
                for o in options:
                    search_res = re.search(r'.*\((\d+)\)', o.text)
                    if not search_res:
                        continue
                    proxy_cnt = int(search_res.string[search_res.regs[1][0]:search_res.regs[1][1]])
                    if proxy_cnt:
                        countries.append(o['value'])

            chrome_options = Options()
            chrome_options.add_argument("--headless")
            browser = create_browser()

            for (c_id, c) in enumerate(countries):
                logging.info(f"      running for {c} ({c_id + 1}/{len(countries)}), total fetched: {len(result)}")
                c_url = f"https://www.proxynova.com/proxy-server-list/country-{c}"
                browser.get(c_url)
                for r in browser.find_elements_by_css_selector("#tbl_proxy_list tr"):
                    cells = r.find_elements_by_tag_name('td')
                    if len(cells) < 2:
                        continue
                    result.append(
                        Proxy(ip=cells[0].text, port=int(cells[1].text), c_code=c.upper(), country=cells[5].text))
            logging.info(f"Found {len(result)} proxies with proxy_list")
            return result

        # all_found_proxies_result += fetch_proxymesh()
        all_found_proxies_result += [
            # TorProxy('localhost')
            Proxy("173.249.9.253", 8080, "AWS", "AWS", "admin", "awslambdaproxy")
        ]

        # all_found_proxies_result += fetch_proxydb()  # Bastards are blocking requests :(
        # all_found_proxies_result += await fetch_proxyrotator()
        # all_found_proxies_result += fetch_a2u()
        # all_found_proxies_result += fetch_proxy_list()
        # all_found_proxies_result += fetch_proxynova()  # it's just pretty dirty

        all_found_proxies_result = list({f"{v.ip}:{v.port}": v for v in all_found_proxies_result}.values())
        with open(proxy_file_path, "w") as f:
            f.write(jsonpickle.encode({"date": str(date.today()), "proxies": all_found_proxies_result}))

        return all_found_proxies_result

    @classmethod
    def default_penalty_fn(cls, e):
        return 1

    @classmethod
    def default_promote_fn(cls):
        return 0.2

    async def punish_proxy(self, proxy, e):
        pid = f"{proxy.ip}:{proxy.port}"
        penalty = self.penalty_fn(e)
        if pid not in self._punished_proxies:
            self._punished_proxies[pid] = penalty
        else:
            self._punished_proxies[pid] += penalty

        logging.debug(f"Giving penalty {pid}, now: {self._punished_proxies[pid]}, {e}")
        if self._punished_proxies[pid] > 10 and proxy in self._proxy_list:
            self._proxy_list.remove(proxy)
            logging.info(f"kicked proxy: {pid}, left: {len(self._proxy_list)}")

        if not len(self._proxy_list):
            logging.info("Ran out of proxies, starting to fetch new ones...")
            await self.initialize_proxy_list()

    def promote_proxy(self, proxy):
        pid = f"{proxy.ip}:{proxy.port}"
        penalty = self.promote_fn()
        if pid not in self._punished_proxies:
            self._punished_proxies[pid] = -penalty
        else:
            self._punished_proxies[pid] -= penalty

        logging.debug(f"Promoting {pid}, now: {self._punished_proxies[pid]}")

    async def initialize_proxy_list(self, force=True):
        while self.initializing_proxies:
            await asyncio.sleep(1)
        if len(self._proxy_list):
            return

        self.initializing_proxies = True
        self._punished_proxies = {}
        if not len(self._proxy_list):
            self._proxy_list = await self.fetch_proxies(force=force)
        self.initializing_proxies = False

    def has_proxies(self):
        return len(self._proxy_list) > 0

    def shuffle_proxy(self):
        logging.debug("Shuffling proxy")
        self.current_proxy = self._proxy_list[random.randint(0, len(self._proxy_list) - 1)]
        if isinstance(self.current_proxy, TorProxy):
            logging.debug(f"Reloading a TOR proxy")
            self.current_proxy.reload()
        logging.debug(f"After Shuffling proxy: {self.current_proxy}")


class UserCancelException(Exception):
    pass


class BadResponseCodeException(Exception):
    def __init__(self, code) -> None:
        super().__init__()
        self.message = f"Bad HTTP response code: {code}"
        self.code = code

    def __repr__(self) -> str:
        return f"BadResponseCodeException(message={self.message}, code={self.code})"
