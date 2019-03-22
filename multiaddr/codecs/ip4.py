from __future__ import absolute_import

import netaddr
import six

from ._util import packed_net_bytes_to_int


SIZE = 32
IS_PATH = False


def to_bytes(proto, string):
	try:
		return netaddr.IPAddress(string, version=4).packed
	except Exception:
		raise ValueError("failed to parse ip4 addr: %s" % string)


def to_string(proto, buf):
	ip_addr = netaddr.IPAddress(packed_net_bytes_to_int(buf), version=4)
	return six.text_type(ip_addr)