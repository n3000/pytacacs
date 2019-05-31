import logging
from pytacacs_plus.packet import AcctPacket
from pytacacs_plus.config import Config


class BaseAccountingPlugin(object):
    NAME = 'Dummy'

    def __init__(self, config: Config) -> None:
        self.config = config

        self._logger = logging.getLogger('tacacs')

    async def process(self, pkt: AcctPacket) -> bool:
        """
        Return True to reply with a TAC_PLUS_ACCT_STATUS_SUCCESS
        False will reply with TAC_PLUS_ACCT_STATUS_ERROR
        """
        return True


class StdoutLoggerPlugin(BaseAccountingPlugin):
    NAME = 'StdoutLogger'

    async def process(self, pkt: AcctPacket) -> bool:
        """
        Return True to reply with a TAC_PLUS_ACCT_STATUS_SUCCESS
        False will reply with TAC_PLUS_ACCT_STATUS_ERROR
        """
        self._logger.info('Accounting: User {0}, SrcIP {1}, Flag {2}, Args {3}'.format(pkt.request_data['user'], pkt.request_data['rem_addr'], pkt.accounting_type, pkt.request_data['args']))

        return True
