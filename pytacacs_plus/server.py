import asyncio
import binascii
import logging
from typing import Optional

from pytacacs_plus.packet import PacketDecoder, DecodeError
from pytacacs_plus.session import SessionFactory
from pytacacs_plus.config import read_config, Config


class TACACSPlusProtocol(asyncio.Protocol):
    def __init__(self, *args, config: Config, **kwargs):
        super(TACACSPlusProtocol, self).__init__(*args, **kwargs)

        self.config = config
        self.transport = None
        self.logger = logging.getLogger('tacacs.network')
        self.pkt_decoder = None
        self.source_addr = None
        self.source_name = None

        self._sessions = {}

    def connection_made(self, transport):
        peername = transport.get_extra_info('peername')
        self.source_addr = peername[0]

        # Terminate connection if not authorised and required that
        if self.config.use_whitelist and self.source_addr not in self.config:
            self.logger.warning('{0} attempted connection but not in the whitelist'.format(self.source_addr))
            transport.close()
            return

        # Determine friendly name
        if self.source_addr in self.config:
            self.source_name = self.config[self.source_addr].name
        else:
            self.source_name = self.source_addr

        self.pkt_decoder = PacketDecoder(parent=self)
        self.logger.debug('Connection from {0}'.format(self.source_name))
        self.transport = transport

    def data_received(self, data):
        self.logger.debug('Data received: {0}, decoding...'.format(binascii.hexlify(data)))

        packet = self.pkt_decoder.decode(data)

        # Error during packet decoding
        if not packet:
            self.transport.close()
            return

        if packet.session_id not in self._sessions:
            # New connection, create session
            sesh = SessionFactory.get_session(packet)(self.config, self.source_addr)
            self._sessions[packet.session_id] = sesh

        sesh = self._sessions[packet.session_id]

        # Session.process is a coroutine, so call_soon. Once done, so some crappy logic to reply to sender
        response_future = asyncio.ensure_future(sesh.process(packet))
        response_future.add_done_callback(self._process_response)

    def _process_response(self, response_future):
        if response_future.exception():
            response = None
            self.logger.error('Application Error: {0}'.format(response_future.exception()))
        else:
            response = response_future.result()

        if not response:
            self.transport.close()
        else:
            self.transport.write(response)


def configure_logging(config: Optional[Config]=None):
    log_level = logging.DEBUG
    if config:
        log_level = config.logging['tacacs']

    formatter = logging.Formatter('[%(asctime)s %(name)s %(levelname)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    logger = logging.getLogger('tacacs')
    logger.setLevel(log_level)
    if not logger.handlers:
        h = logging.StreamHandler()
        h.setFormatter(formatter)
        logger.addHandler(h)

    for logger_name in ('tacacs.network', 'tacacs.packet', 'tacacs.config', 'tacacs.session'):
        l = logging.getLogger(logger_name)

        if config:
            log_level = config.logging.get(logger_name, log_level)

        l.setLevel(log_level)


async def main(loop: asyncio.AbstractEventLoop):
    # Configure Logging
    configure_logging()
    logger = logging.getLogger('tacacs')

    # Read config file
    config = read_config('../resources/config.ini')
    configure_logging(config)

    server_obj = lambda: TACACSPlusProtocol(config=config)
    server = await loop.create_server(server_obj, '0.0.0.0', 8888)
    logger.info('Serving on {0[0]}:{0[1]}'.format(server.sockets[0].getsockname()))

    return server


if __name__ == '__main__':
    event_loop = asyncio.get_event_loop()
    server_handler = event_loop.run_until_complete(main(event_loop))

    try:
        event_loop.run_forever()
    except KeyboardInterrupt:
        pass

    # Close the server
    server_handler.close()
    event_loop.run_until_complete(server_handler.wait_closed())
    event_loop.close()
