from pytacacs_plus.accounting_plugins.base import BaseAccountingPlugin
from pytacacs_plus.packet import AcctPacket

try:
    import aioredis

    HAS_AIOREDIS = True
except ImportError:
    HAS_AIOREDIS = False

if HAS_AIOREDIS:
    # Cheap hack

    class RedisPubSubAccountingPlugin(BaseAccountingPlugin):
        NAME = 'RedisPubSub'

        def __init__(self, *args, **kwargs):
            super(RedisPubSubAccountingPlugin, self).__init__(*args, **kwargs)

            self.redis_conn = None

            self._host = None
            self._port = None
            self._channel = None
            self._redis_url = None

            self._parse_config()

        def _parse_config(self):
            # Parse redis config
            self._host = self.config.parser.get('accounting:RedisPubSub', 'host', fallback='localhost')
            self._port = self.config.parser.getint('accounting:RedisPubSub', 'port', fallback=6379)
            self._channel = self.config.parser.get('accounting:RedisPubSub', 'channel', fallback='tacacs_accounting:1')

            self._redis_url = 'redis://{0}:{1}'.format(self._host, self._port)

        def __del__(self):
            if self.redis_conn:
                try:
                    self.redis_conn.close()
                except:
                    pass

        async def process(self, pkt: AcctPacket) -> bool:
            """
            Return True to reply with a TAC_PLUS_ACCT_STATUS_SUCCESS
            False will reply with TAC_PLUS_ACCT_STATUS_ERROR
            """
            if not self.redis_conn:
                self.redis_conn = await aioredis.create_redis(self._redis_url)

            data = pkt.to_dict()

            res = await self.redis_conn.publish_json(self._channel, data)

            self._logger.debug('Accounting: Published to Redis {0} {1}'.format(self._redis_url, self._channel))

            return res == 1
