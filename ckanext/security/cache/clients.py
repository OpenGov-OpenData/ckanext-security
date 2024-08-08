from builtins import object
import redis
from ckan.common import config


class RedisClient(object):
    prefix = ''

    def __init__(self):
        self.host = config.get('ckanext.security.redis.host', 'localhost')
        self.port = config.get('ckanext.security.redis.port', 6379)
        self.db = config.get('ckanext.security.redis.db', 0)
        self.pwd = config.get('ckanext.security.redis.password', None)
        self._client = None

    @property
    def client(self):
        if not self._client:
            self._client = redis.StrictRedis(host=self.host, port=self.port, db=self.db, password=self.pwd)
        return self._client

    def get(self, key):
        return self.client.get(self.prefix + key)

    def set(self, key, value):
        return self.client.set(self.prefix + key, value)

    def delete(self, key):
        return self.client.delete(self.prefix + key)


class ThrottleClient(RedisClient):
    prefix = 'security_throttle_'
