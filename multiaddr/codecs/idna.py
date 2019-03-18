from __future__ import absolute_import

import idna
import varint

from ..codec import LENGTH_PREFIXED_VAR_SIZE
from ..protocols import read_varint_code


SIZE = LENGTH_PREFIXED_VAR_SIZE
IS_PATH = False


def to_bytes(proto, string):
	bytes = idna.encode(string, uts46=True)
	size = varint.encode(len(bytes))
	return b''.join([size, bytes])


def to_string(proto, buf):
	size, num_bytes_read = read_varint_code(buf)
	return idna.decode(buf[num_bytes_read:])