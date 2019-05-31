import logging
from typing import Union, Tuple, List, TYPE_CHECKING

from pytacacs_plus.packet import AuthenPacket, TACACSAuthenticationStatus, TACACSAuthenticationReplyFlags

if TYPE_CHECKING:
    from pytacacs_plus.config import Config


class BaseAuthenticationPlugin(object):
    NAME = 'DummyAuth'

    def __init__(self, config: "Config") -> None:
        self.config = config

        self._logger = logging.getLogger('tacacs.auth.' + self.NAME.lower())

    async def process_start(self, pkt: AuthenPacket) -> Tuple[Union[TACACSAuthenticationStatus, None], Union[TACACSAuthenticationReplyFlags, int]]:
        """
        Returning None will skip this plugin
        """
        return TACACSAuthenticationStatus.TAC_PLUS_AUTHEN_STATUS_PASS, 0

    async def process_continue(self, pkt: List[AuthenPacket]) -> Tuple[Union[TACACSAuthenticationStatus, None], Union[TACACSAuthenticationReplyFlags, int]]:
        """
        Returning None will skip this plugin
        """
        return TACACSAuthenticationStatus.TAC_PLUS_AUTHEN_STATUS_PASS, 0


class LocalAuthPlugin(BaseAuthenticationPlugin):
    NAME = 'LocalAuth'

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

        user_obj = self.config.get_user(user)
        if user_obj and user_obj.authenticate(password):
            self._logger.info('Authentication success for {0} from {1}'.format(user, remote_address))
            return TACACSAuthenticationStatus.TAC_PLUS_AUTHEN_STATUS_PASS, 0

        # Return None so we fall back to next plugin
        self._logger.info('Authentication failure for {0} from {1}'.format(user, remote_address))
        return None, 0
