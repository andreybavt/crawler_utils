import asyncio
import hashlib
import json
import logging
import os
import random
import shutil
import time
import traceback
from asyncio import Lock
from functools import partial

from telegram.error import RetryAfter

SEPARATOR = '\n' + '-' * 100 + '\n'


class PersistentSet:
    def __init__(self, path='data/persistent-hash', buckets=2000, recreate=False):
        if recreate and os.path.exists(path):
            shutil.rmtree(path)
        self.locks = {}
        for i in range(buckets):
            self.locks[i] = Lock()
        self.path = path
        self.buckets = buckets
        if not os.path.exists(path):
            os.makedirs(path)
            # else:
            #     raise Exception("PersistentHash path already exists")

    async def get_all(self):
        result = set()
        for bucket in os.listdir(self.path):
            bucket_no = int(bucket.split('-')[1])
            try:
                await self.locks[bucket_no].acquire()
                with open('{}/{}'.format(self.path, bucket), 'r') as f:
                    read = f.read()
                    for i in json.loads(read):
                        result.add(i)
            finally:
                self.locks[bucket_no].release()
        return result

    async def bucket_content(self, bucket):
        try:
            await self.locks[bucket].acquire()
            bucket_filename = '{}/bucket-{}'.format(self.path, bucket)
            if os.path.isfile(bucket_filename):
                with open(bucket_filename, 'r') as f:
                    return set(json.loads(f.read()))
            else:
                return set()
        finally:
            self.locks[bucket].release()

    async def has(self, value):
        _, bucket = self.get_hash(str(value))

        try:
            await self.locks[bucket].acquire()
            bucket_filename = '{}/bucket-{}'.format(self.path, bucket)
            if os.path.isfile(bucket_filename):
                with open(bucket_filename, 'r') as f:
                    return value in set(json.loads(f.read()))
            else:
                return False
        finally:
            self.locks[bucket].release()

    async def add(self, value):
        _, bucket = self.get_hash(str(value))

        try:
            await self.locks[bucket].acquire()
            bucket_filename = '{}/bucket-{}'.format(self.path, bucket)
            bucket_content = set()

            if os.path.isfile(bucket_filename):
                if os.path.isfile(bucket_filename):
                    with open(bucket_filename, 'r') as f:
                        bucket_content = set(json.loads(f.read()))
                os.remove(bucket_filename)

            with open(bucket_filename, 'wb') as f:
                bucket_content.add(value)
                f.write(json.dumps(list(bucket_content)).encode('utf8'))
        finally:
            self.locks[bucket].release()

    async def remove(self, value):
        _, bucket = self.get_hash(str(value))
        await self.remove_from_bucket(bucket, {value})

    async def remove_from_bucket(self, bucket, visited_users_in_bucket_list):
        try:
            await self.locks[bucket].acquire()
            bucket_filename = '{}/bucket-{}'.format(self.path, bucket)
            bucket_content = set()

            if os.path.isfile(bucket_filename):
                with open(bucket_filename, 'r') as f:
                    bucket_content = set(json.loads(f.read()))

            bucket_content = bucket_content.difference(visited_users_in_bucket_list)

            with open(bucket_filename, 'wb') as f:
                f.write(json.dumps(list(bucket_content)).encode('utf8'))
        finally:
            self.locks[bucket].release()

    def get_hash(self, value):
        hashval = hashlib.sha512(value.encode()).hexdigest()
        return hashval, int(hashval, 16) % self.buckets


def chunks(l, n):
    """Yield successive n-sized chunks from l."""
    for i in range(0, len(l), n):
        yield l[i:i + n]


from json import JSONEncoder


class MyEncoder(JSONEncoder):
    def default(self, o):
        return o.__dict__ if hasattr(o, '__dict__') else str(o)


def to_str(obj):
    try:
        return MyEncoder().encode(obj)
    except Exception:
        return str(obj)


UNDEFINED_FAILBACK_RESULT = "$^!#"


def nofail_async(retries=20, failback_result=UNDEFINED_FAILBACK_RESULT, before_retry_callback=None):
    def nofail_async_fn(func):
        async def func_wrapper(*args, **kwargs):
            r = 0
            last_exception = None
            while r < retries:
                r += 1
                try:
                    if r > 1 and before_retry_callback:
                        args, kwargs = before_retry_callback(*args, **kwargs)
                    return await func(*args, **kwargs)
                except Exception as e:
                    last_exception = e
                    # logging.warning(f"@nofail_async: {func.__name__}, {r}/{retries}, {e}")
                    args_str = '\n\n'.join([to_str(a) for a in args])

                    logging.log(logging.DEBUG if r < retries else logging.WARN,
                                f"{SEPARATOR}@nofail_async: {func.__name__}, args={args_str}, kwargs={kwargs}\n, {r}/{retries}, {e}\n{traceback.format_exc()}{SEPARATOR}")
            if failback_result is not UNDEFINED_FAILBACK_RESULT:
                return failback_result
            raise Exception(
                f"Exceeded number of retries: {func.__name__}, nb.retries: {retries}, exception: {last_exception} ")

        return func_wrapper

    return nofail_async_fn


def nofail(retries=20, sleep=None, failback_result=UNDEFINED_FAILBACK_RESULT):
    def nofail_fn(func):
        def func_wrapper(*args, **kwargs):
            r = 0
            last_exception = None
            while r < retries:
                r += 1
                try:
                    return func(*args, **kwargs)
                except RetryAfter as e:
                    logging.info(f"Telegram.RetryAfter: sleeping for {e.retry_after} sec before retrying")
                    time.sleep(e.retry_after)
                except Exception as e:
                    last_exception = e
                    logging.log(logging.DEBUG if r < retries else logging.WARN,
                                f"@nofail_async: {func.__name__}, {r}/{retries}, {e}\n{traceback.format_exc()}")
                    if sleep:
                        time.sleep(sleep)
                    # logging.warning()
            if failback_result is not UNDEFINED_FAILBACK_RESULT:
                return failback_result
            raise Exception(
                f"Exceeded number of retries: {func.__name__}, nb.retries: {retries}, exception: {last_exception} ")

        return func_wrapper

    return nofail_fn


def measure_async(func):
    async def func_wrapper(*args, **kwargs):
        start = time.time()
        res = await func(*args, **kwargs)
        duration = time.time() - start
        logging.info(f"measure: {func.__name__}, {round(duration, 2)}")
        return res

    return func_wrapper


def measure(func):
    def func_wrapper(*args, **kwargs):
        start = time.time()
        res = func(*args, **kwargs)
        duration = time.time() - start
        logging.info(f"measure: {func.__name__}, {round(duration, 2)}")
        return res

    return func_wrapper


def timeout(timeout_sec=60):
    def timeout_fn(func):
        async def func_wrapper(*args, **kwargs):
            try:
                return await asyncio.wait_for(func(*args, **kwargs), timeout=timeout_sec)
            except Exception as e:
                if e.__class__.__name__ == 'TimeoutError':
                    logging.warning(
                        f"Timeout {timeout_sec} for function {func.__name__}, *args {args}, kwargs {kwargs}")
                raise e

        return func_wrapper

    return timeout_fn


def read_prop(obj, *args, fallback=None):
    if obj is None:
        return fallback
    elif not args:
        return obj
    elif len(args) == 1:
        if args[0] not in obj:
            logging.debug(f"property {args[0]} not in object {obj}")
            return fallback
        return obj.get(args[0])
    else:
        return read_prop(read_prop(obj, args[0]), *args[1:], fallback=fallback)


def get_tasks_results(bulk_await_result, is_json=False):
    return [i.result().body.decode() if not is_json else json.loads(i.result().body.decode()) for i in
            bulk_await_result[0]]


def randomify_url(url) -> str:
    rand_url = url + "?gqe=" + str(random.randint(0, 10 ** 20))
    return rand_url


class AsyncScheduler:

    def __init__(self, eloop) -> None:
        super().__init__()
        self.eloop = eloop

    def run(self, func, *args):
        self.task = partial(func, args) if len(args) else func
        return self

    def every(self, delay):
        async def loop():
            while True:
                await asyncio.sleep(delay)
                self.eloop.create_task(self.task())

        self.eloop.create_task(loop())


if __name__ == '__main__':
    demo = {'a': {'b': {'c': 123}}}
    # print(1, read_prop(demo))
    # print(2, read_prop(demo, 'a'))
    # print(3, read_prop(demo, 'a', 'b123', 'c'))
    print(3, read_prop(demo, 'a', 'b123', 'c', fallback='ABSENT'))
