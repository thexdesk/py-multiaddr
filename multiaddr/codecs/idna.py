from __future__ import absolute_import

import idna
import varint

from ..protocols import read_varint_code


def to_bytes(proto, string):
	bytes = idna.encode(string, uts46=True)
	size = varint.encode(len(bytes))
	return b''.join([size, bytes])


def to_string(proto, buf):
	size, num_bytes_read = read_varint_code(buf)
	return idna.decode(buf[num_bytes_read:])