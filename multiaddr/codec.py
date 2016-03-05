import base58
import base64
import binascii
import struct

from netaddr import IPAddress

from .protocols import code_to_varint
from .protocols import P_DCCP
from .protocols import P_IP4
from .protocols import P_IP6
from .protocols import P_IPFS
from .protocols import P_ONION
from .protocols import protocol_with_code
from .protocols import protocol_with_name
from .protocols import P_SCTP
from .protocols import P_TCP
from .protocols import P_UDP
from .protocols import read_varint_code


def string_to_bytes(string):
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
        bs.append(code_to_varint(proto.code))
        if proto.size == 0:
            continue
        if len(sp) < 1:
            raise ValueError(
                "protocol requires address, none given: %s" % proto.name)
        addr_string = sp.pop(0)
        addr_bytes = address_string_to_bytes(proto, addr_string)
        bs.append(bytes(addr_bytes))
    return b''.join(bs)


def bytes_to_string(buf):
    st = ['']  # start with empty string so we get a leading slash on join()
    while buf:
        code, num_bytes_read = read_varint_code(buf)
        buf = buf[num_bytes_read:]
        proto = protocol_with_code(code)
        st.append(proto.name)
        size = size_for_addr(proto, buf) * 2
        if size > 0:
            addr = address_bytes_to_string(proto, buf[:size])
            st.append(addr)
        buf = buf[size:]
    return '/'.join(st)


def address_string_to_bytes(proto, addr_string):
    if proto.code == P_IP4:  # ipv4
        try:
            ip = IPAddress(addr_string)
            if ip.version != 4:
                raise ValueError("failed to parse ip4 addr: %s" % addr_string)
            return '%x' % int(ip)
        except Exception:
            raise ValueError("failed to parse ip4 addr: %s" % addr_string)
    elif proto.code == P_IP6:  # ipv6
        try:
            ip = IPAddress(addr_string)
            if ip.version != 6:
                raise ValueError("failed to parse ip6 addr: %s" % addr_string)
            return '%x' % int(ip)
        except Exception:
            raise ValueError("failed to parse ip6 addr: %s" % addr_string)
    # tcp udp dccp sctp
    elif proto.code in [P_TCP, P_UDP, P_DCCP, P_SCTP]:
        try:
            ip = int(addr_string)
        except ValueError as ex:
            raise ValueError("failed to parse %s addr: %s"
                             % (proto.name, str(ex)))

        if ip >= 65536:
            raise ValueError("failed to parse %s addr: %s" %
                             (proto.name, "greater than 65536"))
        # b := make([]byte, 2)
        # binary.BigEndian.PutUint16(b, uint16(i))
        # return b, nil
        return binascii.hexlify(struct.pack('>I', ip)[-2:])
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

        return b''.join([onion_host_bytes, bytes(port)])
    elif proto.code == P_IPFS:  # ipfs
        # the address is a varint prefixed multihash string representation
        try:
            mm = binascii.hexlify(base58.b58decode(addr_string))
        except Exception as ex:
            raise ValueError("failed to parse ipfs addr: %s %s"
                             % (addr_string, str(ex)))
        size = code_to_varint(len(mm))
        if len(mm) < 10:
            # TODO - port go-multihash so we can do this correctly
            raise ValueError("invalid IPFS multihash: %s" % mm)
        return b''.join([size, mm])
    else:
        raise ValueError("failed to parse %s addr: unknown" % proto.name)


def address_bytes_to_string(proto, buf):
    if proto.code in [P_IP4, P_IP6]:
        return str(IPAddress(int(buf, 16)))
    elif proto.code in [P_TCP, P_UDP, P_DCCP, P_SCTP]:
        return struct.unpack('>I', binascii.unhexlify(buf))
    elif proto.code == P_IPFS:
        size, num_bytes_read = read_varint_code(buf)
        buf = buf[num_bytes_read:]
        if len(buf) != size:
            raise ValueError("inconsistent lengths")
        return base58.b58encode(binascii.unhexlify(buf))
    raise ValueError("unknown protocol")


def size_for_addr(proto, buf):
    if proto.size > 0:
        return proto.size / 8
    elif proto.size == 0:
        return 0
    else:
        size, num_bytes_read = read_varint_code(buf)
        return size + num_bytes_read


def bytes_split(buf):
    ret = []
    while buf:
        code, num_bytes_read = read_varint_code(buf)
        proto = protocol_with_code(code)
        size = size_for_addr(proto, buf[num_bytes_read:]) * 2
        length = size + num_bytes_read
        ret.append(buf[:length])
        buf = buf[length:]
    return ret
