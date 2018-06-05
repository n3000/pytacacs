import asyncio
import logging

from typing import Union, Type

import pytacacs_plus.packet


logger = logging.getLogger('tacacs.session')


class Session(object):
    def __init__(self, config, source_addr):
        self.config = config
        self.source_addr = source_addr

    async def process(self, packet: pytacacs_plus.packet.Packet) -> Union[bytes, None]:
        """
        Can return a packet or None to drop connection
        """
        raise NotImplementedError()

    # Stock functions
    def auth_user(self, user, password):
        user = self.config.get_user(user)

        if not user:
            return False

        # If user has no password, then yolo
        return not user.password or user.password == password


class AuthenticationSession(Session):
    def __init__(self, *args, **kwargs):
        super(AuthenticationSession, self).__init__(*args, **kwargs)

        self.user = None
        self.pw = None
        self.remote_address = None

        # First pkt from client is a START packet
        self._seen_start_pkt = False

    async def process(self, packet: pytacacs_plus.packet.AuthenPacket) -> Union[bytes, None]:
        res = None

        if not self._seen_start_pkt:
            self._seen_start_pkt = True
            res = self._handle_start_pkt(packet)
        elif self.pw is None:  # So if they've given us a dud password, it'll close connection next time they try anytihng
            # Handle continue packet
            res = self._handle_continue_pkt(packet)
        else:
            logger.warning('Got additional TACACS CONTINUE packet after receiving user password, not accounted for, so abort')

        return res

    def _handle_start_pkt(self, packet: pytacacs_plus.packet.AuthenPacket) -> Union[bytes, None]:
        packet.decode_start()

        self.user = packet.start_data['user']
        self.remote_address = packet.start_data['rem_addr']

        # Create reply, we need a password
        pkt = packet.create_reply(
            status=pytacacs_plus.packet.TACACSAuthenticationStatus.TAC_PLUS_AUTHEN_STATUS_GETPASS,
            flags=pytacacs_plus.packet.TACACSAuthenticationReplyFlags.TAC_PLUS_REPLY_FLAG_NOECHO,  # Hide password when its typed in
        )

        logger.debug('Sending reply packet to {0} requesting password'.format(self.source_addr))
        return pkt

    def _handle_continue_pkt(self, packet: pytacacs_plus.packet.AuthenPacket) -> Union[bytes, None]:
        packet.decode_continue()

        if pytacacs_plus.packet.TACACSAuthenticationContinueFlags.TAC_PLUS_CONTINUE_FLAG_ABORT in packet.continue_data['flags']:
            return None

        self.pw = packet.continue_data['user_msg']
        # Herewe decide on auth,
        if self.auth_user(self.user, self.pw):
            status = pytacacs_plus.packet.TACACSAuthenticationStatus.TAC_PLUS_AUTHEN_STATUS_PASS
            logger.info('{0} is trying to authenticate user {1}. Success'.format(self.remote_address, self.user))
        else:
            status = pytacacs_plus.packet.TACACSAuthenticationStatus.TAC_PLUS_AUTHEN_STATUS_FAIL
            logger.info('{0} is trying to authenticate user {1}. Password failure'.format(self.remote_address, self.user))

        pkt = packet.create_reply(status=status)
        logger.debug('Sending success packet to {0} requesting auth'.format(self.source_addr))
        return pkt


class AuthorisationSession(Session):
    async def process(self, packet: pytacacs_plus.packet.AuthorPacket) -> Union[bytes, None]:
        """
        Can return a packet or None to drop connection
        """
        packet.decode_request()

        logger.info('Got Authorisation request: user: {0}, {1}'.format(packet.request_data['user'], packet.request_data['args']))

        # Shell with no cmd is autologon
        if packet.request_data['args'].get('service') == 'shell' and packet.request_data['args'].get('cmd') == '':
            #logger.info('Sending privilege level 1')
            pkt = packet.create_reply(
                status=pytacacs_plus.packet.TACACSAuthorisationStatus.TAC_PLUS_AUTHOR_STATUS_PASS_ADD,
                # args=['priv-lvl=1']
            )
        else:
            pkt = packet.create_reply(status=pytacacs_plus.packet.TACACSAuthorisationStatus.TAC_PLUS_AUTHOR_STATUS_PASS_ADD)
        return pkt


class AccountingSession(Session):
    async def process(self, packet: pytacacs_plus.packet.AcctPacket) -> Union[bytes, None]:
        """
        Can return a packet or None to drop connection
        """
        packet.decode_request()

        # # service=shell
        # # start signies login, save taskid
        # # end specifies logout, matches start taskid, has elapsed time

        result = True

        # task_id 0 is odd, gives negative seconds
        if not (packet.request_data['args'].get('task_id', -1) == 0 and self.config.accounting['ignore_task_id_0']):
            for plugin in self.config.get_accounting_plugins():
                if not result:
                    break

                try:
                    result &= await plugin.process(packet)
                except Exception as err:
                    logger.exception('Plugin {0} caused exception'.format(plugin.NAME), exc_info=err)
                    result = False
                    break

        if result:
            status = pytacacs_plus.packet.TACACSAccountingStatus.TAC_PLUS_ACCT_STATUS_SUCCESS
        else:
            status = pytacacs_plus.packet.TACACSAccountingStatus.TAC_PLUS_ACCT_STATUS_ERROR

        pkt = packet.create_reply(status=status)
        return pkt


class SessionFactory(object):
    @staticmethod
    def get_session(packet) -> Type[Session]:
        if isinstance(packet, pytacacs_plus.packet.AuthenPacket):
            return AuthenticationSession
        elif isinstance(packet, pytacacs_plus.packet.AuthorPacket):
            return AuthorisationSession
        else:
            return AccountingSession
