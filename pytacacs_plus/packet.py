import struct
import hashlib
import logging
from enum import IntFlag, IntEnum
from typing import Tuple, Union, Optional, Any, Dict, List


logger = logging.getLogger('tacacs.packet')


class TACACSPacketType(IntEnum):
    TAC_PLUS_AUTHEN = 0x01
    TAC_PLUS_AUTHOR = 0x02
    TAC_PLUS_ACCT = 0x03
    UNKNOWN = 0xff


class TACACSFlags(IntFlag):
    TAC_PLUS_UNENCRYPTED_FLAG = 0x01
    TAC_PLUS_SINGLE_CONNECT_FLAG = 0x04


class TACACSAuthenticationPacketType(IntEnum):
    START = 1
    REPLY = 2
    CONTINUE = 3


class TACACSAuthenticationAction(IntEnum):
    TAC_PLUS_AUTHEN_LOGIN = 0x01
    TAC_PLUS_AUTHEN_CHPASS = 0x02
    TAC_PLUS_AUTHEN_SENDAUTH = 0x04


class TACACSAuthenticationType(IntEnum):
    TAC_PLUS_AUTHEN_TYPE_ASCII = 0x01
    TAC_PLUS_AUTHEN_TYPE_PAP = 0x02
    TAC_PLUS_AUTHEN_TYPE_CHAP = 0x03
    TAC_PLUS_AUTHEN_TYPE_ARAP = 0x04
    TAC_PLUS_AUTHEN_TYPE_MSCHAP = 0x05
    TAC_PLUS_AUTHEN_TYPE_MSCHAPV2 = 0x06


class TACACSAuthenticationService(IntEnum):
    TAC_PLUS_AUTHEN_SVC_NONE = 0x00
    TAC_PLUS_AUTHEN_SVC_LOGIN = 0x01
    TAC_PLUS_AUTHEN_SVC_ENABLE = 0x02
    TAC_PLUS_AUTHEN_SVC_PPP = 0x03
    TAC_PLUS_AUTHEN_SVC_ARAP = 0x04
    TAC_PLUS_AUTHEN_SVC_PT = 0x05
    TAC_PLUS_AUTHEN_SVC_RCMD = 0x06
    TAC_PLUS_AUTHEN_SVC_X25 = 0x07
    TAC_PLUS_AUTHEN_SVC_NASI = 0x08
    TAC_PLUS_AUTHEN_SVC_FWPROXY = 0x09


class TACACSAuthenticationStatus(IntEnum):
    TAC_PLUS_AUTHEN_STATUS_PASS = 0x01
    TAC_PLUS_AUTHEN_STATUS_FAIL = 0x02
    TAC_PLUS_AUTHEN_STATUS_GETDATA = 0x03
    TAC_PLUS_AUTHEN_STATUS_GETUSER = 0x04
    TAC_PLUS_AUTHEN_STATUS_GETPASS = 0x05
    TAC_PLUS_AUTHEN_STATUS_RESTART = 0x06
    TAC_PLUS_AUTHEN_STATUS_ERROR = 0x07
    TAC_PLUS_AUTHEN_STATUS_FOLLOW = 0x21
    

class TACACSAuthenticationReplyFlags(IntFlag):
    TAC_PLUS_REPLY_FLAG_NOECHO = 0x01


class TACACSAuthenticationContinueFlags(IntFlag):
    TAC_PLUS_CONTINUE_FLAG_ABORT = 0x01


class TACACSAccountingFlags(IntFlag):
    TAC_PLUS_ACCT_FLAG_START = 0x02
    TAC_PLUS_ACCT_FLAG_STOP = 0x04
    TAC_PLUS_ACCT_FLAG_WATCHDOG = 0x08


class TACACSAccountingStatus(IntEnum):
    TAC_PLUS_ACCT_STATUS_SUCCESS = 0x01
    TAC_PLUS_ACCT_STATUS_ERROR = 0x02
    TAC_PLUS_ACCT_STATUS_FOLLOW = 0x21


class TACACSAuthenticationMethod(IntEnum):
    TAC_PLUS_AUTHEN_METH_NOT_SET = 0x00
    TAC_PLUS_AUTHEN_METH_NONE = 0x01
    TAC_PLUS_AUTHEN_METH_KRB5 = 0x02
    TAC_PLUS_AUTHEN_METH_LINE = 0x03
    TAC_PLUS_AUTHEN_METH_ENABLE = 0x04
    TAC_PLUS_AUTHEN_METH_LOCAL = 0x05
    TAC_PLUS_AUTHEN_METH_TACACSPLUS = 0x06
    TAC_PLUS_AUTHEN_METH_GUEST = 0x08
    TAC_PLUS_AUTHEN_METH_RADIUS = 0x10
    TAC_PLUS_AUTHEN_METH_KRB4 = 0x11
    TAC_PLUS_AUTHEN_METH_RCMD = 0x20


class TACACSAuthorisationStatus(IntEnum):
    TAC_PLUS_AUTHOR_STATUS_PASS_ADD = 0x01
    TAC_PLUS_AUTHOR_STATUS_PASS_REPL = 0x02
    TAC_PLUS_AUTHOR_STATUS_FAIL = 0x10
    TAC_PLUS_AUTHOR_STATUS_ERROR = 0x11
    TAC_PLUS_AUTHOR_STATUS_FOLLOW = 0x21


class DecodeError(Exception):
    pass


class Packet(object):
    _type = TACACSPacketType.UNKNOWN
    HEADER_STRUCT = '>BBBBII'
    HEADER_SIZE = 12

    def __init__(self, config, source_addr: str, source_name: str, data: bytes) -> None:
        self._config = config
        self._source_addr = source_addr
        self._source_name = source_name
        self._packet = data

        if len(data) < 12:
            raise DecodeError('Not enough bytes for TACACS+ header')

        self._index = 0
        self._header = struct.unpack_from(self.HEADER_STRUCT, data, self._index)
        self._index += 12

        self._payload = data[12:]

        if len(self._payload) != self.length:
            raise DecodeError('Packet body doesnt match length in header')

        # Parse out flags
        self.flags = TACACSFlags(self._header[3])

        # Will decrypt if needed
        self._payload = self._do_crypto(self._payload)  # Encryption routine is same as decryption

    def _encode_header(self, version, _type, seq_no, flags, session_id, length):
        return struct.pack(self.HEADER_STRUCT, version, _type, seq_no, flags, session_id, length)

    def _get_key(self):
        secret_key = self._config.get_shared_key(self._source_addr)
        if not secret_key:
            raise DecodeError('Could not find a secret key to use for {0}'.format(self._source_name))

        return secret_key

    def _do_crypto(self, data: bytes, seq_no: int = None) -> bytes:
        if TACACSFlags.TAC_PLUS_UNENCRYPTED_FLAG not in self.flags:
            seq_no = seq_no if seq_no else self.sequence_number

            secret_key = self._get_key()

            crypto_pad = self._encrypted_pad(secret_key, seq_no, len(data))

            plaintext = []
            for i in range(0, len(data)):
                plaintext.append(crypto_pad[i] ^ data[i])

            plaintext = bytes(plaintext)

            data = plaintext
        return data

    def _encrypted_pad(self, secret_key: str, seq_no, length: int) -> bytes:
        result = b''
        last_hash = b''

        secret_key = secret_key.encode()
        hash_data = struct.pack('>I{0}sBB'.format(len(secret_key)), self.session_id, secret_key, self.raw_version, seq_no)

        while True:
            last_hash = hashlib.md5(hash_data + last_hash).digest()
            result += last_hash

            if len(result) >= length:
                break

        result = result[:length]  # Trim to size if needed

        return result

    @property
    def raw_version(self) -> int:
        return self._header[0]

    @property
    def version(self) -> Tuple[int, int]:
        return self._header[0] >> 4, self._header[0] & 0b00001111

    @property
    def type(self) -> TACACSPacketType:
        return self._type

    @property
    def sequence_number(self) -> int:
        return self._header[2]

    @property
    def session_id(self) -> int:
        return self._header[4]

    @property
    def length(self) -> int:
        return self._header[5]

    @staticmethod
    def _arg_value_to_type(key: str, value: str) -> Tuple[str, Any]:
        try:
            if key == 'task_id':
                value = int(value, 16)
            elif key == 'elapsed_time':
                value = float(value)

        except Exception:
            pass

        return key, value

    @classmethod
    def _arg_to_key_value(cls, data: str) -> Tuple[Union[str, None], Union[str, None]]:
        if '=' in data:
            key, value = data.split('=', 1)
        elif '*' in data:
            key, value = data.split('*', 1)
        else:
            logger.warning('Invalid attribute-value field "{0}"'.format(data))
            return None, None

        return cls._arg_value_to_type(key, value)

    def __bytes__(self) -> bytes:
        return b''

    def to_bytes(self) -> bytes:
        return self.__bytes__()


class AuthenPacket(Packet):
    _type = TACACSPacketType.TAC_PLUS_AUTHEN
    REPLY_STRUCT = '>BBHH'

    def __init__(self, *args, **kwargs) -> None:
        super(AuthenPacket, self).__init__(*args, **kwargs)

        self.packet_type = None
        self.start_data = {}
        self.continue_data = {}

    def decode_start(self) -> None:
        """
         1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
        +----------------+----------------+----------------+----------------+
        |    action      |    priv_lvl    |  authen_type   | authen_service |
        +----------------+----------------+----------------+----------------+
        |    user_len    |    port_len    |  rem_addr_len  |    data_len    |
        +----------------+----------------+----------------+----------------+
        |    user ...
        +----------------+----------------+----------------+----------------+
        |    port ...
        +----------------+----------------+----------------+----------------+
        |    rem_addr ...
        +----------------+----------------+----------------+----------------+
        |    data...
        +----------------+----------------+----------------+----------------+
        """
        # No need to length check as thats done during header parsing
        index = 0
        data = struct.unpack_from('>BBBBBBBB', self._payload, index)
        index += 8

        result_data = {
            'action': TACACSAuthenticationAction(data[0]),
            'priv_lvl': data[1],
            'authen_type': TACACSAuthenticationType(data[2]),
            'authen_service': TACACSAuthenticationService(data[3]),
            'user_len': data[4],
            'port_len': data[5],
            'rem_addr_len': data[6],
            'data_len': data[7],
        }
        result_data['user'] = self._payload[index:index+result_data['user_len']].decode()

        index += result_data['user_len']
        result_data['port'] = self._payload[index:index + result_data['port_len']].decode()

        index += result_data['port_len']
        result_data['rem_addr'] = self._payload[index:index + result_data['rem_addr_len']].decode()

        index += result_data['rem_addr_len']
        result_data['data'] = self._payload[index:index + result_data['data_len']].decode()

        self.start_data = result_data

    def decode_continue(self) -> None:
        """
         1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
        +----------------+----------------+----------------+----------------+
        |          user_msg len           |            data_len             |
        +----------------+----------------+----------------+----------------+
        |     flags      |  user_msg ...
        +----------------+----------------+----------------+----------------+
        |    data ...
        +----------------+
        """
        # No need to length check as thats done during header parsing
        index = 0
        data = struct.unpack_from('>HHB', self._payload, index)
        index += 5

        result_data = {
            'user_msg_len': data[0],
            'data_len': data[1],
            'flags': TACACSAuthenticationContinueFlags(data[2]),
        }
        result_data['user_msg'] = self._payload[index:index+result_data['user_msg_len']].decode()

        index += result_data['user_msg_len']
        result_data['data'] = self._payload[index:index + result_data['data_len']].decode()

        self.continue_data = result_data

    def create_reply(self, status: TACACSAuthenticationStatus,
                     flags: Union[TACACSAuthenticationReplyFlags, int] = 0,
                     server_msg: Optional[str] = None,
                     data: Optional[bytes] = None) -> bytes:

        if server_msg:
            server_msg = server_msg.encode()
        else:
            server_msg = b''

        if not data:
            data = b''

        server_msg_len = len(server_msg)
        data_len = len(data)

        payload = struct.pack(self.REPLY_STRUCT, status, flags, server_msg_len, data_len) + server_msg + data
        payload = self._do_crypto(payload, self.sequence_number + 1)

        header = self._encode_header(self.raw_version, self.type, self.sequence_number + 1, self.flags, self.session_id, len(payload))

        return header + payload


class AuthorPacket(Packet):
    _type = TACACSPacketType.TAC_PLUS_AUTHOR
    REPLY_STRUCT = '>BBHH'

    # noinspection PyDictCreation
    def decode_request(self) -> None:
        """
         1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
        +----------------+----------------+----------------+----------------+
        |    action      |    priv_lvl    |  authen_type   | authen_service |
        +----------------+----------------+----------------+----------------+
        |    user_len    |    port_len    |  rem_addr_len  |    data_len    |
        +----------------+----------------+----------------+----------------+
        |    user ...
        +----------------+----------------+----------------+----------------+
        |    port ...
        +----------------+----------------+----------------+----------------+
        |    rem_addr ...
        +----------------+----------------+----------------+----------------+
        |    data...
        +----------------+----------------+----------------+----------------+
        """
        # No need to length check as thats done during header parsing
        index = 0
        data = struct.unpack_from('>BBBBBBBB', self._payload, index)
        index += 8

        user_len = data[4]
        port_len = data[5]
        rem_addr_len = data[6]
        arg_count = data[7]
        arg_sizes = []
        for _ in range(0, arg_count):
            arg_sizes.append(self._payload[index])  # Size is 1 byte
            index += 1

        result_data = {
            'authen_method': TACACSAuthenticationMethod(data[0]),
            'priv_lvl': data[1],
            'authen_type': TACACSAuthenticationType(data[2]),
            'authen_service': TACACSAuthenticationService(data[3]),
            'args': {}
        }

        result_data['user'] = self._payload[index:index + user_len].decode()
        index += user_len

        result_data['port'] = self._payload[index:index + port_len].decode()
        index += port_len

        result_data['rem_addr'] = self._payload[index:index + rem_addr_len].decode()
        index += rem_addr_len

        for size in arg_sizes:
            data = self._payload[index:index + size].decode()
            key, value = self._arg_to_key_value(data)
            if not key:  # Key is bad, skip
                continue

            result_data['args'][key] = value
            index += size

        self.request_data = result_data

    def create_reply(self, status: TACACSAuthorisationStatus,
                     server_msg: Optional[str] = None,
                     data: Optional[bytes] = None,
                     args: Optional[List[str]] = None) -> bytes:

        if server_msg:
            server_msg = server_msg.encode()
        else:
            server_msg = b''

        if not data:
            data = b''

        if args is None:
            args = []

        server_msg_len = len(server_msg)
        data_len = len(data)

        payload = struct.pack(self.REPLY_STRUCT, status, len(args), server_msg_len, data_len)
        payload += bytes([len(arg) for arg in args])  # each Arg length
        payload += server_msg + data
        for arg in args:
            payload += arg.encode()

        payload = self._do_crypto(payload, self.sequence_number + 1)

        header = self._encode_header(self.raw_version, self.type, self.sequence_number + 1, self.flags, self.session_id, len(payload))

        return header + payload


class AcctPacket(Packet):
    _type = TACACSPacketType.TAC_PLUS_ACCT
    REPLY_STRUCT = '>HHB'

    def __init__(self, *args, **kwargs) -> None:
        super(AcctPacket, self).__init__(*args, **kwargs)

        self.packet_type = None
        self.request_data = {}

    # noinspection PyDictCreation
    def decode_request(self) -> None:
        """
         1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
        +----------------+----------------+----------------+----------------+
        |    action      |    priv_lvl    |  authen_type   | authen_service |
        +----------------+----------------+----------------+----------------+
        |    user_len    |    port_len    |  rem_addr_len  |    data_len    |
        +----------------+----------------+----------------+----------------+
        |    user ...
        +----------------+----------------+----------------+----------------+
        |    port ...
        +----------------+----------------+----------------+----------------+
        |    rem_addr ...
        +----------------+----------------+----------------+----------------+
        |    data...
        +----------------+----------------+----------------+----------------+
        """
        # No need to length check as thats done during header parsing
        index = 0
        data = struct.unpack_from('>BBBBBBBBB', self._payload, index)
        index += 9

        user_len = data[5]
        port_len = data[6]
        rem_addr_len = data[7]
        arg_count = data[8]
        arg_sizes = []
        for _ in range(0, arg_count):
            arg_sizes.append(self._payload[index])  # Size is 1 byte
            index += 1

        result_data = {
            'flags': TACACSAccountingFlags(data[0]),
            'authen_method': TACACSAuthenticationMethod(data[1]),
            'priv_lvl': data[2],
            'authen_type': TACACSAuthenticationType(data[3]),
            'authen_service': TACACSAuthenticationService(data[4]),
            'args': {}
        }

        result_data['user'] = self._payload[index:index + user_len].decode()
        index += user_len

        result_data['port'] = self._payload[index:index + port_len].decode()
        index += port_len

        result_data['rem_addr'] = self._payload[index:index + rem_addr_len].decode()
        index += rem_addr_len

        for size in arg_sizes:
            data = self._payload[index:index + size].decode()
            key, value = self._arg_to_key_value(data)
            if not key:  # Key is bad, skip
                continue

            result_data['args'][key] = value
            index += size

        self.request_data = result_data

    def to_dict(self) -> Dict[str, Any]:
        return {
            'source_addr': self._source_addr,
            'source_name': self._source_name,
            'user': self.request_data['user'],
            'port': self.request_data['port'],
            'remote_address': self.request_data['rem_addr'],
            'args': self.request_data['args'],
            'flags': self.accounting_flags_to_string_list,
            'authen_method': self.request_data['authen_method'].name,
            'authen_type': self.request_data['authen_type'].name,
            'authen_service': self.request_data['authen_service'].name,
        }

    def create_reply(self, status: TACACSAccountingStatus,
                     server_msg: Optional[str] = None,
                     data: Optional[bytes] = None) -> bytes:

        if server_msg:
            server_msg = server_msg.encode()
        else:
            server_msg = b''

        if not data:
            data = b''

        server_msg_len = len(server_msg)
        data_len = len(data)

        payload = struct.pack(self.REPLY_STRUCT, server_msg_len, data_len, status) + server_msg + data
        payload = self._do_crypto(payload, self.sequence_number + 1)

        header = self._encode_header(self.raw_version, self.type, self.sequence_number + 1, self.flags, self.session_id, len(payload))

        return header + payload

    @property
    def accounting_flags_to_string_list(self) -> List[str]:
        result = []
        if TACACSAccountingFlags.TAC_PLUS_ACCT_FLAG_START in self.request_data.get('flags', -1):
            result.append('TAC_PLUS_ACCT_FLAG_START')
        if TACACSAccountingFlags.TAC_PLUS_ACCT_FLAG_STOP in self.request_data.get('flags', -1):
            result.append('TAC_PLUS_ACCT_FLAG_STOP')
        if TACACSAccountingFlags.TAC_PLUS_ACCT_FLAG_WATCHDOG in self.request_data.get('flags', -1):
            result.append('TAC_PLUS_ACCT_FLAG_WATCHDOG')

        return result

    @property
    def accounting_type(self) -> str:
        if TACACSAccountingFlags.TAC_PLUS_ACCT_FLAG_START in self.request_data.get('flags', -1):
            flag = 'start'
        elif TACACSAccountingFlags.TAC_PLUS_ACCT_FLAG_STOP in self.request_data.get('flags', -1):
            flag = 'end'
        elif TACACSAccountingFlags.TAC_PLUS_ACCT_FLAG_WATCHDOG in self.request_data.get('flags', -1):
            flag = 'update'
        else:
            flag = 'unknown'

        return flag


class PacketDecoder(object):
    def __init__(self, parent):
        self.config = parent.config
        self.source_addr = parent.source_addr
        self.source_name = parent.source_name

    def decode(self, packet_bytes: bytes) -> Union[Packet, None]:
        if len(packet_bytes) < 2:
            logger.warning('Not enough bytes to decode, skipping')

        version, _type, = struct.unpack_from('>BB', packet_bytes, 0)

        if version >> 4 != 0x0C:
            logger.warning('Got packet that doesnt contain TACACS Major version number, dropping')
            return None
        elif version & 0b00001111 not in (0x00, 0x01):
            logger.warning('Got packet that doesnt contain TACACS Major version number, dropping')
            return None

        if _type == 0x01:
            # Authentication
            logger.debug('Decoding authentication packet')
            packet_class = AuthenPacket
        elif _type == 0x02:
            # Authorisation
            logger.debug('Decoding authorisation packet')
            packet_class = AuthorPacket
        elif _type == 0x03:
            # Accounting
            logger.debug('Decoding accounting packet')
            packet_class = AcctPacket
        else:
            logger.warning('Got packet with unknown type {0}, dropping'.format(_type))
            return None

        try:
            packet = packet_class(self.config, self.source_addr, self.source_name, packet_bytes)
        except DecodeError as err:
            logger.error('Failed to decode packet. Error {0}'.format(err))
            packet = None
        except Exception as err:
            logger.error('Application error. Error {0}'.format(err))
            packet = None

        return packet


