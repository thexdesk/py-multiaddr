from __future__ import absolute_import

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
        from .codecs import ip4
        return ip4.to_bytes(proto, addr_string)
    elif proto.code == P_IP6:  # ipv6
        from .codecs import ip6
        return ip6.to_bytes(proto, addr_string)
    # tcp udp dccp sctp
    elif proto.code in [P_TCP, P_UDP, P_DCCP, P_SCTP]:
        from .codecs import uint16be
        return uint16be.to_bytes(proto, addr_string)
    elif proto.code == P_ONION:
        from .codecs import onion
        return onion.to_bytes(proto, addr_string)
    elif proto.code == P_P2P:  # ipfs
        from .codecs import multihash
        return multihash.to_bytes(proto, addr_string)
    elif proto.code == P_UNIX:
        from .codecs import fspath
        return fspath.to_bytes(proto, addr_string)
    elif proto.code in (P_DNS, P_DNS4, P_DNS6):
        from .codecs import idna
        return idna.to_bytes(proto, addr_string)
    else:
        raise ValueError("failed to parse %s addr: unknown" % proto.name)


def address_bytes_to_string(proto, buf):
    if proto.code == P_IP4:
        from .codecs import ip4
        return ip4.to_string(proto, buf)
    elif proto.code == P_IP6:
        from .codecs import ip6
        return ip6.to_string(proto, buf)
    elif proto.code in [P_TCP, P_UDP, P_DCCP, P_SCTP]:
        from .codecs import uint16be
        return uint16be.to_string(proto, buf)
    elif proto.code == P_ONION:
        from .codecs import onion
        return onion.to_string(proto, buf)
    elif proto.code == P_P2P:
        from .codecs import multihash
        return multihash.to_string(proto, buf)
    elif proto.code == P_UNIX:
        from .codecs import fspath
        return fspath.to_string(proto, buf)
    elif proto.code in (P_DNS, P_DNS4, P_DNS6):
        from .codecs import idna
        return idna.to_string(proto, buf)
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
