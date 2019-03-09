import six
import struct

from .codec import bytes_split
from .multiaddr import Multiaddr


def split(ma):
    """Return the sub-address portions of a multiaddr"""
    addrs = []
    bb = bytes_split(ma.to_bytes())
    for addr in bb:
        addrs.append(Multiaddr(addr))
    return addrs


def join(multiaddrs):
    bs = []
    for ma in multiaddrs:
        bs.append(ma.to_bytes())
    return Multiaddr(b''.join(bs))


if hasattr(int, 'from_bytes'):
    def packed_net_bytes_to_int(b):
        """Convert the given big-endian byte-string to an int."""
        return int.from_bytes(b, byteorder='big')
else:  # PY2
    def packed_net_bytes_to_int(b):
        """Convert the given big-endian byte-string to an int."""
        return int(b.encode('hex'), 16)


def decode_big_endian_16(b):
	return struct.unpack_from('>H', b.rjust(2, b'\0'))[0]
