from __future__ import absolute_import
import struct

import six


def to_bytes(proto, string):
	try:
		return struct.pack('>H', int(string, 10))
	except ValueError as ex:
		raise ValueError("failed to parse %s addr: %s"
		                 % (proto.name, str(ex)))
	except struct.error:
		raise ValueError("failed to parse %s addr: %s" %
		                 (proto.name, "greater than 65536"))


def to_string(proto, buf):
	if len(buf) != 2:
		raise ValueError("Not a uint16")
	return six.text_type(struct.unpack('>H', buf)[0])