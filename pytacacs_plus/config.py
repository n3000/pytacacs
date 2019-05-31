import os
import configparser
import logging
import socket
import crypt
import hmac

from typing import Union, Optional, List

from pytacacs_plus.accounting_plugins import get_accounting_plugins
from pytacacs_plus.accounting_plugins.base import BaseAccountingPlugin
from pytacacs_plus.authentication_plugins import get_authentication_plugins
from pytacacs_plus.authentication_plugins.base import BaseAuthenticationPlugin


logger = logging.getLogger('tacacs.config')

ACCOUNTING_PLUGINS = get_accounting_plugins()
AUTHENTICATION_PLUGINS = get_authentication_plugins()


class Client(object):
    def __init__(self, name: str, ip: str, shared_key: Optional[str] = None) -> None:
        self.name = name
        self.ip = ip
        self.shared_key = shared_key


class User(object):
    def __init__(self, name: str, password: str, priv: str) -> None:
        self.name = name
        self.password = password
        self.priv = priv

    def authenticate(self, password: str) -> bool:
        return hmac.compare_digest(crypt.crypt(password, self.password), self.password)


class Config(object):
    def __init__(self, file: str) -> None:

        self.parser = configparser.ConfigParser()
        if os.path.exists(file):
            self.parser.read(file)

        self._clients = {}
        self._users = {}

        self._default_key = self.parser.get('defaults', 'shared_key', fallback=None)
        self.use_whitelist = self.parser.getboolean('defaults', 'require_clients_whitelisted', fallback=False)

        self.logging = {
            'tacacs': 'INFO',
            'tacacs.network': 'INFO',
            'tacacs.packet': 'INFO',
            'tacacs.config': 'INFO',
            'tacacs.session': 'INFO'
        }

        self.accounting = {}
        self.authentication = {}

        self._deal_with_logging()
        self._deal_with_accounting()
        self._deal_with_authentication()

        for section in self.parser.sections():
            if section.startswith('client:'):
                self._add_client(section)
            elif section.startswith('user:'):
                self._add_user(section)

    def _add_client(self, section: str) -> None:
        name = section.split(':', 1)[-1]
        ip = self.parser.get(section, 'ip', fallback=None)
        host = self.parser.get(section, 'host', fallback=None)
        shared_secret = self.parser.get(section, 'shared_key', fallback=None)

        if ip:
            pass
        elif host:
            try:
                ip = socket.gethostbyname(host)
            except socket.gaierror:
                logger.warning('Could not resolve {0}, ignoring section'.format(host))
        else:
            logger.warning('Client section {0} is missing a host or ip declaration, ignoring section'.format(section))

        # By now either we have an IP or one has been resolved, else skip
        if ip:
            self._clients[ip] = Client(name, ip, shared_secret)
            logger.info('Registered client {0}'.format(name))

    def _add_user(self, section: str) -> None:
        name = section.split(':', 1)[-1]
        password = self.parser.get(section, 'password', fallback=None)
        priv = self.parser.get(section, 'privilege', fallback=None)

        self._users[name] = User(name, password, priv)
        logger.info('Registered user {0}'.format(name))

    def __contains__(self, item) -> bool:
        return self._clients.__contains__(item)

    def __getitem__(self, item) -> Client:
        return self._clients.__getitem__(item)

    def _parse_log_level(self, level: str) -> str:
        if level.upper() not in ('CRITICAL', 'WARNING', 'INFO', 'DEBUG'):
            return 'INFO'
        return level.upper()

    def _deal_with_logging(self) -> None:
        if self.parser.has_section('logging'):
            current_level = self._parse_log_level(self.parser.get('logging', 'log_level', fallback='INFO'))

            self.logging = {
                'tacacs': current_level,
                'tacacs.network': self._parse_log_level(self.parser.get('logging', 'network_log_level', fallback=current_level)),
                'tacacs.packet': self._parse_log_level(self.parser.get('logging', 'packet_log_level', fallback=current_level)),
                'tacacs.config': current_level,
                'tacacs.session': self._parse_log_level(self.parser.get('logging', 'session_log_level', fallback=current_level))
            }

    def _deal_with_accounting(self) -> None:
        self.accounting['ignore_task_id_0'] = self.parser.getboolean('accounting', 'ignore_task_id_0', fallback=False)
        self.accounting['plugins'] = []

        plugins = self.parser.get('accounting', 'plugins', fallback='Dummy').split(',')

        for plugin in plugins:
            if plugin in ACCOUNTING_PLUGINS:
                plugin_class = ACCOUNTING_PLUGINS[plugin]

                try:
                    plugin_obj = plugin_class(self)
                    logger.info('Registered accounting plugin {0}'.format(plugin))
                except Exception as err:
                    logger.exception('Failed to initialise accounting plugin {0}'.format(plugin), exc_info=err)
                    continue

                self.accounting['plugins'].append(plugin_obj)
            else:
                logger.warning('Accounting plugin {0} doesnt exist'.format(plugin))

    def _deal_with_authentication(self) -> None:
        self.authentication['plugins'] = []

        plugins = self.parser.get('authentication', 'plugins', fallback='Dummy').split(',')

        for plugin in plugins:
            if plugin in AUTHENTICATION_PLUGINS:
                plugin_class = AUTHENTICATION_PLUGINS[plugin]

                try:
                    plugin_obj = plugin_class(self)
                    logger.info('Registered authentication plugin {0}'.format(plugin))
                except Exception as err:
                    logger.exception('Failed to initialise accounting plugin {0}'.format(plugin), exc_info=err)
                    continue

                self.authentication['plugins'].append(plugin_obj)
            else:
                logger.warning('Authentication plugin {0} doesnt exist'.format(plugin))

    def get_shared_key(self, client_addr: Optional[str] = None) -> Union[str, None]:
        if client_addr in self and self[client_addr].shared_key:
            return self[client_addr].shared_key

        return self._default_key

    def get_user(self, user: str) -> Union[User, None]:
        return self._users.get(user, None)

    def get_accounting_plugins(self) -> List[BaseAccountingPlugin]:
        return self.accounting['plugins']

    def get_authentication_plugins(self) -> List[BaseAuthenticationPlugin]:
        return self.authentication['plugins']


def read_config(file: str) -> Config:
    config = Config(file)

    return config

