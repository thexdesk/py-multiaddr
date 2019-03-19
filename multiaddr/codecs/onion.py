from __future__ import absolute_import
import base64
import struct

import six


def to_bytes(proto, string):
	addr = string.split(":")
	if len(addr) != 2:
		raise ValueError(
		    "failed to parse %s addr: %s does not contain a port number."
		    % (proto.name, string))

	# onion address without the ".onion" substring
	if len(addr[0]) != 16:
		raise ValueError(
		    "failed to parse %s addr: %s not a Tor onion address."
		    % (proto.name, string))
	try:
		onion_host_bytes = base64.b32decode(addr[0].upper())
	except Exception as ex:
		raise ValueError(
		    "failed to decode base32 %s addr: %s %s"
		    % (proto.name, string, str(ex)))

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

	return b''.join((onion_host_bytes, struct.pack('>H', port)))


def to_string(proto, buf):
	addr_bytes, port_bytes = (buf[:-2], buf[-2:])
	addr = base64.b32encode(addr_bytes).decode('ascii').lower()
	port = six.text_type(struct.unpack('>H', port_bytes)[0])
	return u':'.join([addr, port])