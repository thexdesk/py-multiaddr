# -*- encoding: utf-8 -*-
from __future__ import absolute_import
import importlib

import six
import varint

from .protocols import protocol_with_code
from .protocols import protocol_with_name
from .protocols import read_varint_code


# These are special sizes
LENGTH_PREFIXED_VAR_SIZE = -1


class NoneCodec:
	SIZE = 0
	IS_PATH = False


CODEC_CACHE = {}
def find_codec_by_name(name):
    if name is None:  # Special “do nothing – expect nothing” pseudo-codec
        return NoneCodec
    codec = CODEC_CACHE.get(name)
    if not codec:
        codec = CODEC_CACHE[name] = importlib.import_module(".codecs.{0}".format(name), __package__)
    return codec


def string_to_bytes(string):
    if not string:
        return b''

    bs = []
    for proto, codec, value in string_iter(string):
        bs.append(varint.encode(proto.code))
        if value is not None:
            buf = codec.to_bytes(proto, value)
            if codec.SIZE == LENGTH_PREFIXED_VAR_SIZE:
                bs.append(varint.encode(len(buf)))
            bs.append(buf)
    return b''.join(bs)


def bytes_to_string(buf):
	st = [u'']  # start with empty string so we get a leading slash on join()
	for proto, codec, part in bytes_iter(buf):
		st.append(proto.name)
		if codec.SIZE != 0:
			value = codec.to_string(proto, part)
			if codec.IS_PATH and value[0] == u'/':
				st.append(value[1:])
			else:
				st.append(value)
	return u'/'.join(st)


def size_for_addr(codec, buf):
    if codec.SIZE >= 0:
        return codec.SIZE // 8, 0
    else:
        return read_varint_code(buf)


def string_iter(string):
	if not string.startswith(u'/'):
		raise ValueError("invalid multiaddr, must begin with /")
	# consume trailing slashes
	string = string.rstrip(u'/')
	sp = string.split(u'/')

	# skip the first element, since it starts with /
	sp.pop(0)
	while sp:
		element = sp.pop(0)
		proto = protocol_with_name(element)
		try:
			codec = find_codec_by_name(proto.codec)
		except ImportError as exc:
			six.raise_from(ValueError("failed to parse %s addr: unknown" % proto.name), exc)
		value = None
		if codec.SIZE != 0:
			if len(sp) < 1:
				raise ValueError(
					"protocol requires address, none given: %s" % proto.name)
			if codec.IS_PATH:
				value = "/" + "/".join(sp)
				if not six.PY2:
					sp.clear()
				else:
					sp = []
			else:
				value = sp.pop(0)
		yield proto, codec, value


def bytes_iter(buf):
	while buf:
		code, num_bytes_read = read_varint_code(buf)
		proto = protocol_with_code(code)
		try:
			codec = find_codec_by_name(proto.codec)
		except ImportError as exc:
			six.raise_from(ValueError("failed to parse %s addr: unknown" % proto.name), exc)
		size, num_bytes_read2 = size_for_addr(codec, buf[num_bytes_read:])
		length = size + num_bytes_read2 + num_bytes_read
		yield proto, codec, buf[(length - size):length]
		buf = buf[length:]
