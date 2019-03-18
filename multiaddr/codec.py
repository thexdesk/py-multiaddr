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
        bs.append(varint.encode(proto.code))
        try:
            codec = find_codec_by_name(proto.codec)
        except ImportError as exc:
            six.raise_from(ValueError("failed to parse %s addr: unknown" % proto.name), exc)
        if codec.SIZE == 0:
            continue
        if len(sp) < 1:
            raise ValueError(
                "protocol requires address, none given: %s" % proto.name)
        if codec.IS_PATH:
            sp = ["/" + "/".join(sp)]
        bs.append(codec.to_bytes(proto, sp.pop(0)))
    return b''.join(bs)


def bytes_to_string(buf):
    st = ['']  # start with empty string so we get a leading slash on join()
    while buf:
        maddr_component = ""
        code, num_bytes_read = read_varint_code(buf)
        buf = buf[num_bytes_read:]
        proto = protocol_with_code(code)
        maddr_component += proto.name
        try:
            codec = find_codec_by_name(proto.codec)
        except ImportError as exc:
            six.raise_from(ValueError("failed to parse %s addr: unknown" % proto.name), exc)
        size = size_for_addr(codec, buf)
        if size > 0:
            addr = codec.to_string(proto, buf[:size])
            if not (codec.IS_PATH and addr[0] == '/'):
                maddr_component += '/'
            maddr_component += addr
        st.append(maddr_component)
        buf = buf[size:]
    return '/'.join(st)


def size_for_addr(codec, buf):
    if codec.SIZE >= 0:
        return codec.SIZE // 8
    else:
        size, num_bytes_read = read_varint_code(buf)
        return size + num_bytes_read


def bytes_split(buf):
    ret = []
    while buf:
        code, num_bytes_read = read_varint_code(buf)
        proto = protocol_with_code(code)
        try:
            codec = find_codec_by_name(proto.codec)
        except ImportError as exc:
            six.raise_from(ValueError("failed to parse %s addr: unknown" % proto.name), exc)
        size = size_for_addr(codec, buf[num_bytes_read:])
        length = size + num_bytes_read
        ret.append(buf[:length])
        buf = buf[length:]
    return ret
