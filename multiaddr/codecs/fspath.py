from __future__ import absolute_import
import os

import six
import varint

from ..protocols import read_varint_code


if hasattr(os, "fsencode") and hasattr(os, "fsdecode"):
    fsencode = os.fsencode
    fsdecode = os.fsdecode
else:  # PY2
    import sys

    def fsencode(path):
        if not isinstance(path, six.binary_type):
            path = path.encode(sys.getfilesystemencoding())
        return path

    def fsdecode(path):
        if not isinstance(path, six.text_type):
            path = path.decode(sys.getfilesystemencoding())
        return path


def to_bytes(proto, string):
	bytes = fsencode(string)
	size = varint.encode(len(bytes))
	return b''.join([size, bytes])


def to_string(proto, buf):
	size, num_bytes_read = read_varint_code(buf)
	return fsdecode(buf[num_bytes_read:])