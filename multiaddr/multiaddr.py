# -*- coding: utf-8 -*-
import binascii
from copy import copy

from .codec import size_for_addr
from .codec import string_to_bytes
from .codec import bytes_to_string
from .protocols import protocol_with_code
from .protocols import read_varint_code


class ProtocolNotFoundException(Exception):
    pass


class Multiaddr(object):
    """Multiaddr is a representation of multiple nested internet addresses.

    Multiaddr is a cross-protocol, cross-platform format for representing
    internet addresses. It emphasizes explicitness and self-description.

    Learn more here: https://github.com/jbenet/multiaddr

    Multiaddrs have both a binary and string representation.

        >>> from multiaddr import Multiaddr
        >>> addr = Multiaddr("/ip4/1.2.3.4/tcp/80")

    Multiaddr objects are immutable, so `encapsulate` and `decapsulate`
    return new objects rather than modify internal state.
    """
    def __init__(self, string_addr=None, bytes_addr=None):
        """Instantiate a new Multiaddr.

        Args:
            string_addr (optional): A string-encoded Multiaddr
            bytes_addr (optional): A byte-encoded Multiaddr

        Only one of string_addr or bytes_addr may be set
        """
        if string_addr is not None and bytes_addr is None:
            self._bytes = string_to_bytes(string_addr)
        elif bytes_addr is not None and string_addr is None:
            self._bytes = bytes_addr
        else:
            raise ValueError("Invalid address type, must be bytes or str")

    def __eq__(self, other):
        """Checks if two Multiaddr objects are exactly equal."""
        return self._bytes == other._bytes

    def __ne__(self, other):
        return not (self == other)

    def __str__(self):
        """Return the string representation of this Multiaddr.

        May raise an exception if the internal state of the Multiaddr is
        corrupted."""
        try:
            return bytes_to_string(self._bytes)
        except Exception:
            raise ValueError(
                "multiaddr failed to convert back to string. corrupted?")

    def __repr__(self):
        return "<Multiaddr %s>" % str(self)

    def to_bytes(self):
        """Returns the byte array representation of this Multiaddr."""
        return self._bytes

    def protocols(self):
        """Returns a list of Protocols this Multiaddr includes."""
        buf = binascii.unhexlify(self.to_bytes())
        protos = []
        while buf:
            code, num_bytes_read = read_varint_code(buf)
            proto = protocol_with_code(code)
            protos.append(proto)
            buf = buf[num_bytes_read:]
            size = size_for_addr(proto, buf)
            buf = buf[size:]
        return protos

    def encapsulate(self, other):
        """Wrap this Multiaddr around another.

        For example:
            /ip4/1.2.3.4 encapsulate /tcp/80 = /ip4/1.2.3.4/tcp/80
        """
        mb = self.to_bytes()
        ob = other.to_bytes()
        return Multiaddr(bytes_addr=b''.join([mb, ob]))

    def decapsulate(self, other):
        """Remove a Multiaddr wrapping.

        For example:
            /ip4/1.2.3.4/tcp/80 decapsulate /ip4/1.2.3.4 = /tcp/80
        """
        s1 = str(self)
        s2 = str(other)
        try:
            idx = s1.rindex(s2)
        except ValueError:
            # if multiaddr not contained, returns a copy
            return copy(self)
        try:
            return Multiaddr(s1[:idx])
        except Exception as ex:
            raise ValueError(
                "Multiaddr.decapsulate incorrect byte boundaries: %s"
                % str(ex))

    def value_for_protocol(self, code):
        """Return the value (if any) following the specified protocol."""
        from .util import split
        for sub_addr in split(self):
            if sub_addr.protocols()[0].code == code:
                addr_parts = str(sub_addr).split("/")
                if len(addr_parts) > 3:
                    raise ValueError("Unknown Protocol format")
                elif len(addr_parts) == 3:
                    # If we have an address, return it
                    return addr_parts[2]
                elif len(addr_parts) == 2:
                    # We were given something like '/utp', which doesn't have
                    # an address, so return ''
                    return ''
        raise ProtocolNotFoundException()
