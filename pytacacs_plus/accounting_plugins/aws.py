from pytacacs_plus.accounting_plugins.base import BaseAccountingPlugin
from pytacacs_plus.packet import AcctPacket

try:
    import aioboto3
    HAS_AIOBOTO3 = True
except ImportError:
    HAS_AIOBOTO3 = False

if HAS_AIOBOTO3:
    # Cheap hack

    class AWSKinesisAccountingPlugin(BaseAccountingPlugin):
        NAME = 'AWSKinesis'

        def __init__(self, *args, **kwargs):
            super(AWSKinesisAccountingPlugin, self).__init__(*args, **kwargs)

        async def process(self, pkt: AcctPacket) -> bool:
            """
            Return True to reply with a TAC_PLUS_ACCT_STATUS_SUCCESS
            False will reply with TAC_PLUS_ACCT_STATUS_ERROR
            """
            self._logger.info('Accounting: User {0}, SrcIP {1}, Flag {2}, Args {3}'.format(pkt.request_data['user'], pkt.request_data['rem_addr'], pkt.accounting_type, pkt.request_data['args']))

            return True


    class AWSDynamoDBAccountingPlugin(BaseAccountingPlugin):
        NAME = 'AWSDynamoDB'

        def __init__(self, *args, **kwargs):
            super(AWSDynamoDBAccountingPlugin, self).__init__(*args, **kwargs)

        async def process(self, pkt: AcctPacket) -> bool:
            """
            Return True to reply with a TAC_PLUS_ACCT_STATUS_SUCCESS
            False will reply with TAC_PLUS_ACCT_STATUS_ERROR
            """
            self._logger.info('Accounting: User {0}, SrcIP {1}, Flag {2}, Args {3}'.format(pkt.request_data['user'], pkt.request_data['rem_addr'], pkt.accounting_type, pkt.request_data['args']))

            return True