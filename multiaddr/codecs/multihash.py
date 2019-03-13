from __future__ import absolute_import

import base58
import six
import varint

from ..protocols import read_varint_code


def to_bytes(proto, string):
	# the address is a varint prefixed multihash string representation
	try:
		if six.PY2 and isinstance(string, unicode):
			string = string.encode("ascii")
		mm = base58.b58decode(string)
	except Exception as ex:
		raise ValueError("failed to parse p2p addr: %s %s" % (string, str(ex)))
	size = varint.encode(len(mm))
	if len(mm) < 5:
		# TODO - port go-multihash so we can do this correctly
		raise ValueError("invalid P2P multihash: %s" % mm)
	return b''.join([size, mm])


def to_string(proto, buf):
	size, num_bytes_read = read_varint_code(buf)
	buf = buf[num_bytes_read:]
	if len(buf) != size:
		raise ValueError("inconsistent lengths")
	return base58.b58encode(buf).decode('ascii')