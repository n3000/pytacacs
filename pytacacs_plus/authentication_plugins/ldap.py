import ssl
from typing import Union, Tuple, List

from async_timeout import timeout

from pytacacs_plus.authentication_plugins.base import BaseAuthenticationPlugin
from pytacacs_plus.packet import AuthenPacket, TACACSAuthenticationStatus, TACACSAuthenticationReplyFlags

import aioldap
import aioldap.exceptions


class LDAPAuthenticationPlugin(BaseAuthenticationPlugin):
    NAME = 'LDAPAuth'

    def __init__(self, *args, **kwargs):
        super(LDAPAuthenticationPlugin, self).__init__(*args, **kwargs)

        self.ldap_conn = None

        self._host: str = None
        self._port: int = None
        self._start_tls = True
        self._ignore_cert = False
        self._strategy: str = None

        self._search_filter = None

        # BINDASUSER
        self._bind_dn_template = None

        # SEARCHTHENBIND
        self._bind_dn = None
        self._bind_pw = None
        self._search_base = None

        self._parse_config()

        self.ldap_conn: aioldap.LDAPConnection = None

        ctx = None
        if self._start_tls:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS)
            if self._ignore_cert:
                ctx = ssl._create_unverified_context()

        self._server = aioldap.Server(self._host,  self._port, ssl_context=ctx)

    def _parse_config(self) -> None:
        # Parse redis config
        self._host = self.config.parser.get('authentication:LDAP', 'host', fallback='localhost')
        self._port = self.config.parser.getint('authentication:LDAP', 'port', fallback=389)
        self._start_tls = self.config.parser.getboolean('authentication:LDAP', 'start_tls', fallback=True)
        self._ignore_cert = self.config.parser.getboolean('authentication:LDAP', 'ignore_cert', fallback=False)

        self._strategy = self.config.parser.get('authentication:LDAP', 'strategy', fallback='BINDASUSER')
        self._search_filter = self.config.parser.get('authentication:LDAP', 'search_filter', fallback=None)

        if self._strategy not in ('BINDASUSER', 'SEARCHTHENBIND'):
            raise RuntimeError('strategy not in [BINDASUSER, SEARCHTHENBIND]')
        elif self._strategy == 'BINDASUSER':
            self._bind_dn_template = self.config.parser.get('authentication:LDAP', 'bind_dn_template', fallback='cn={username},ou=users,dc=exmaple,dc=org')
        else:  # SEARCHTHENBIND
            self._bind_dn = self.config.parser.get('authentication:LDAP', 'bind_dn', fallback=None)
            self._bind_pw = self.config.parser.get('authentication:LDAP', 'bind_pw', fallback=None)
            if not self._bind_dn or not self._bind_pw:
                raise RuntimeError('bind_dn and bind_pw must be provided')

            self._search_base = self.config.parser.get('authentication:LDAP', 'search_base', fallback=None)
            if not self._bind_dn or not self._bind_pw:
                raise RuntimeError('search_base must be provided')

            if not self._search_filter:
                raise RuntimeError('search_filter must be provided')

    def __del__(self) -> None:
        if self.ldap_conn:
            try:
                self.ldap_conn.close()
            except:
                pass

    async def _bindasuser(self, user: str, password: str) -> bool:
        dn = self._bind_dn_template.format(username=user)

        success = False

        try:
            await self.ldap_conn.bind(bind_dn=dn, bind_pw=password)
            # Passed

            if self._search_filter:
                results = await self.ldap_conn.search(dn, search_filter=self._search_filter, search_scope='BASE')
                # If we found 0 matches, we clearly dont meet the requirements
                if results['entries']:
                    success = True

            else:
                success = True

        except aioldap.exceptions.LDAPBindException:
            self._logger.warning('Failed to bind as {0}'.format(dn))

        except Exception as err:
            self._logger.exception('Caught exception whilst running _bindasuser', exc_info=err)

        return success

    async def _searchthenbind(self, user: str, password: str) -> bool:
        success = False

        bind_dn = self._bind_dn

        try:
            await self.ldap_conn.bind(bind_dn=self._bind_dn, bind_pw=self._bind_pw)

            ldap_filter = self._search_filter.format(username=user)
            results = await self.ldap_conn.search(self._search_base, ldap_filter, search_scope='SUBTREE', attributes=['*'])

            if len(results['entries']) == 0:
                self._logger.warning('Found no ldap entries when looking for {0}'.format(user))
            elif len(results['entries']) > 1:
                self._logger.warning('Multiple ldap entries when looking for {0}'.format(user))
            else:
                bind_dn = results['entries'][0]['dn']

                await self.ldap_conn.bind(bind_dn=bind_dn, bind_pw=password)
                success = True

        except aioldap.exceptions.LDAPBindException:
            self._logger.warning('Failed to bind as {0}'.format(bind_dn))

        except Exception as err:
            self._logger.exception('Caught exception whilst running _bindasuser', exc_info=err)

        return success

    async def process_start(self, pkt: AuthenPacket) -> Tuple[Union[TACACSAuthenticationStatus, None], Union[TACACSAuthenticationReplyFlags, int]]:
        return TACACSAuthenticationStatus.TAC_PLUS_AUTHEN_STATUS_GETPASS, TACACSAuthenticationReplyFlags.TAC_PLUS_REPLY_FLAG_NOECHO

    async def process_continue(self, packets: List[AuthenPacket]) -> Tuple[Union[TACACSAuthenticationStatus, None], Union[TACACSAuthenticationReplyFlags, int]]:
        # As we could have a start packet and a few continue packets (not normal though)

        # By this point packet 0 will be start, 1 will be first continue
        start_packet = packets[0]
        continue_packet = packets[1]

        remote_address = start_packet.start_data['rem_addr']
        user = start_packet.start_data['user']
        password = continue_packet.continue_data['user_msg']

        if not self.ldap_conn:
            self.ldap_conn = aioldap.LDAPConnection(self._server)

            try:
                if self._start_tls:
                    async with timeout(4):  # Needed till start_tls works properly
                        await self.ldap_conn.start_tls()
            except Exception as err:
                self._logger.critical('Failed to negotiate STARTTLS with LDAP server')

        result = None
        if self._strategy == 'BINDASUSER':
            result = await self._bindasuser(user, password)
        elif self._strategy == 'SEARCHTHENBIND':
            result = await self._searchthenbind(user, password)

        if result:
            self._logger.info('Authentication success for {0} from {1}'.format(user, remote_address))
            return TACACSAuthenticationStatus.TAC_PLUS_AUTHEN_STATUS_PASS, 0

        # Return None so we fall back to next plugin
        self._logger.info('Authentication failure for {0} from {1}'.format(user, remote_address))
        return None, 0
