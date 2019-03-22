from __future__ import absolute_import

import base58
import six

from ..codec import LENGTH_PREFIXED_VAR_SIZE


SIZE = LENGTH_PREFIXED_VAR_SIZE
IS_PATH = False


def to_bytes(proto, string):
	# the address is a base58-encoded string
	try:
		if six.PY2 and isinstance(string, unicode):
			string = string.encode("ascii")
		mm = base58.b58decode(string)
	except Exception as ex:
		raise ValueError("failed to parse p2p addr: %s %s" % (string, str(ex)))
	if len(mm) < 5:
		raise ValueError("invalid P2P multihash: %s" % mm)
	return mm


def to_string(proto, buf):
	return base58.b58encode(buf).decode('ascii')