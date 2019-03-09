import base58
import base64
import os

import idna
from netaddr import IPAddress
import six
import struct
import varint

from .protocols import P_DNS
from .protocols import P_DNS4
from .protocols import P_DNS6
from .protocols import P_DCCP
from .protocols import P_IP4
from .protocols import P_IP6
from .protocols import P_P2P
from .protocols import P_ONION
from .protocols import protocol_with_code
from .protocols import protocol_with_name
from .protocols import P_SCTP
from .protocols import P_TCP
from .protocols import P_UDP
from .protocols import P_UNIX
from .protocols import read_varint_code


if hasattr(os, "fsencode") and hasattr(os, "fsdecode"):
    fsencode = os.fsencode
    fsdecode = os.fsdecode
else:  # PY2
    import sys

    def fsencode(path):
        if not isinstance(path, six.binary_type):
            path = path.encode(sys.getfilesystemencoding())
        return path

    def fsdecode(path):
        if not isinstance(path, six.text_type):
            path = path.decode(sys.getfilesystemencoding())
        return path


def string_to_bytes(string):
    if not string:
        return b''
    # consume trailing slashes
    if not string.startswith('/'):
        raise ValueError("invalid multiaddr, must begin with /")
    string = string.rstrip('/')
    sp = string.split('/')

    # skip the first element, since it starts with /
    sp.pop(0)
    bs = []
    while sp:
        element = sp.pop(0)
        proto = protocol_with_name(element)
        bs.append(varint.encode(proto.code))
        if proto.size == 0:
            continue
        if len(sp) < 1:
            raise ValueError(
                "protocol requires address, none given: %s" % proto.name)
        if proto.path:
            sp = ["/" + "/".join(sp)]
        bs.append(address_string_to_bytes(proto, sp.pop(0)))
    return b''.join(bs)


def bytes_to_string(buf):
    st = ['']  # start with empty string so we get a leading slash on join()
    while buf:
        maddr_component = ""
        code, num_bytes_read = read_varint_code(buf)
        buf = buf[num_bytes_read:]
        proto = protocol_with_code(code)
        maddr_component += proto.name
        size = size_for_addr(proto, buf)
        if size > 0:
            addr = address_bytes_to_string(proto, buf[:size])
            if not (proto.path and addr[0] == '/'):
                maddr_component += '/'
            maddr_component += addr
        st.append(maddr_component)
        buf = buf[size:]
    return '/'.join(st)


def address_string_to_bytes(proto, addr_string):
    if proto.code == P_IP4:  # ipv4
        try:
            return IPAddress(addr_string, version=4).packed
        except Exception:
            raise ValueError("failed to parse ip4 addr: %s" % addr_string)
    elif proto.code == P_IP6:  # ipv6
        try:
            return IPAddress(addr_string, version=6).packed
        except Exception:
            raise ValueError("failed to parse ip6 addr: %s" % addr_string)
    # tcp udp dccp sctp
    elif proto.code in [P_TCP, P_UDP, P_DCCP, P_SCTP]:
        try:
            return struct.pack('>H', int(addr_string, 10))
        except ValueError as ex:
            raise ValueError("failed to parse %s addr: %s"
                             % (proto.name, str(ex)))
        except struct.error:
            raise ValueError("failed to parse %s addr: %s" %
                             (proto.name, "greater than 65536"))
    elif proto.code == P_ONION:
        addr = addr_string.split(":")
        if len(addr) != 2:
            raise ValueError(
                "failed to parse %s addr: %s does not contain a port number."
                % (proto.name, addr_string))

        # onion address without the ".onion" substring
        if len(addr[0]) != 16:
            raise ValueError(
                "failed to parse %s addr: %s not a Tor onion address."
                % (proto.name, addr_string))
        try:
            onion_host_bytes = base64.b32decode(addr[0].upper())
        except Exception as ex:
            raise ValueError(
                "failed to decode base32 %s addr: %s %s"
                % (proto.name, addr_string, str(ex)))

        # onion port number
        try:
            port = int(addr[1])
        except Exception as ex:
            raise ValueError("failed to parse %s addr: %s"
                             % (proto.name, str(ex)))
        if port >= 65536:
            raise ValueError("failed to parse %s addr: %s"
                             % (proto.name, "port greater than 65536"))
        if port < 1:
            raise ValueError("failed to parse %s addr: %s"
                             % (proto.name, "port less than 1"))

        return b''.join([onion_host_bytes, struct.pack('>H', port)])
    elif proto.code == P_P2P:  # ipfs
        # the address is a varint prefixed multihash string representation
        try:
            if six.PY2 and isinstance(addr_string, unicode):
                addr_string = addr_string.encode("ascii")
            mm = base58.b58decode(addr_string)
        except Exception as ex:
            raise ValueError("failed to parse p2p addr: %s %s"
                             % (addr_string, str(ex)))
        size = varint.encode(len(mm))
        if len(mm) < 5:
            # TODO - port go-multihash so we can do this correctly
            raise ValueError("invalid P2P multihash: %s" % mm)
        return b''.join([size, mm])
    elif proto.code == P_UNIX:
        addr_string_bytes = fsencode(addr_string)
        size = varint.encode(len(addr_string_bytes))
        return b''.join([size, addr_string_bytes])
    elif proto.code in (P_DNS, P_DNS4, P_DNS6):
        addr_string_bytes = idna.encode(addr_string, uts46=True)
        size = varint.encode(len(addr_string_bytes))
        return b''.join([size, addr_string_bytes])
    else:
        raise ValueError("failed to parse %s addr: unknown" % proto.name)


packed_net_bytes_to_int = None


def address_bytes_to_string(proto, buf):
    global packed_net_bytes_to_int
    if packed_net_bytes_to_int is None:
        from .util import packed_net_bytes_to_int

    if proto.code == P_IP4:
        return six.text_type(IPAddress(packed_net_bytes_to_int(buf), 4))
    elif proto.code == P_IP6:
        return six.text_type(IPAddress(packed_net_bytes_to_int(buf), 6))
    elif proto.code in [P_TCP, P_UDP, P_DCCP, P_SCTP]:
        if len(buf) != 2:
            raise ValueError("Not a uint16")
        return six.text_type(struct.unpack('>H', buf)[0])
    elif proto.code == P_ONION:
        addr_bytes, port_bytes = (buf[:-2], buf[-2:])
        addr = base64.b32encode(addr_bytes).decode('ascii').lower()
        port = six.text_type(struct.unpack('>H', port_bytes)[0])
        return u':'.join([addr, port])
    elif proto.code == P_P2P:
        size, num_bytes_read = read_varint_code(buf)
        buf = buf[num_bytes_read:]
        if len(buf) != size:
            raise ValueError("inconsistent lengths")
        return base58.b58encode(buf).decode('ascii')
    elif proto.code == P_UNIX:
        size, num_bytes_read = read_varint_code(buf)
        return fsdecode(buf[num_bytes_read:])
    elif proto.code in (P_DNS, P_DNS4, P_DNS6):
        size, num_bytes_read = read_varint_code(buf)
        return idna.decode(buf[num_bytes_read:])
    raise ValueError("unknown protocol")


def size_for_addr(proto, buf):
    if proto.size >= 0:
        return proto.size // 8
    else:
        size, num_bytes_read = read_varint_code(buf)
        return size + num_bytes_read


def bytes_split(buf):
    ret = []
    while buf:
        code, num_bytes_read = read_varint_code(buf)
        proto = protocol_with_code(code)
        size = size_for_addr(proto, buf[num_bytes_read:])
        length = size + num_bytes_read
        ret.append(buf[:length])
        buf = buf[length:]
    return ret
