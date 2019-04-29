# -*- coding: utf-8 -*-
from copy import copy

import six

from . import exceptions, protocols

from .transforms import bytes_iter
from .transforms import string_to_bytes
from .transforms import bytes_to_string


class Multiaddr(object):
    """Multiaddr is a representation of multiple nested internet addresses.

    Multiaddr is a cross-protocol, cross-platform format for representing
    internet addresses. It emphasizes explicitness and self-description.

    Learn more here: https://multiformats.io/multiaddr/

    Multiaddrs have both a binary and string representation.

        >>> from multiaddr import Multiaddr
        >>> addr = Multiaddr("/ip4/1.2.3.4/tcp/80")

    Multiaddr objects are immutable, so `encapsulate` and `decapsulate`
    return new objects rather than modify internal state.
    """

    __slots__ = ("_bytes",)

    def __init__(self, addr):
        """Instantiate a new Multiaddr.

        Args:
            addr : A string-encoded or a byte-encoded Multiaddr

        """
        # On Python 2 text string will often be binary anyways so detect the
        # obvious case of a “binary-encoded” multiaddr starting with a slash
        # and decode it into text
        if six.PY2 and isinstance(addr, str) and addr.startswith("/"):
            addr = addr.decode("utf-8")

        if isinstance(addr, six.text_type):
            self._bytes = string_to_bytes(addr)
        elif isinstance(addr, six.binary_type):
            self._bytes = addr
        else:
            raise TypeError("MultiAddr must be bytes or str")

    def __eq__(self, other):
        """Checks if two Multiaddr objects are exactly equal."""
        return self._bytes == other._bytes

    def __ne__(self, other):
        return not (self == other)

    def __str__(self):
        """Return the string representation of this Multiaddr.

        May raise a :class:`~multiaddr.exceptions.BinaryParseError` if the
        stored MultiAddr binary representation is invalid."""
        return bytes_to_string(self._bytes)

    # On Python 2 __str__ needs to return binary text, so expose the original
    # function as __unicode__ and transparently encode its returned text based
    # on the current locale
    if six.PY2:
        __unicode__ = __str__

        def __str__(self):
            import locale
            return self.__unicode__().encode(locale.getpreferredencoding())

    def __repr__(self):
        return "<Multiaddr %s>" % str(self)

    def to_bytes(self):
        """Returns the byte array representation of this Multiaddr."""
        return self._bytes

    def protocols(self):
        """Returns a list of Protocols this Multiaddr includes."""
        return list(proto for proto, _, _ in bytes_iter(self.to_bytes()))

    def encapsulate(self, other):
        """Wrap this Multiaddr around another.

        For example:
            /ip4/1.2.3.4 encapsulate /tcp/80 = /ip4/1.2.3.4/tcp/80
        """
        mb = self.to_bytes()
        ob = other.to_bytes()
        return Multiaddr(b''.join([mb, ob]))

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
        return Multiaddr(s1[:idx])

    def value_for_protocol(self, proto):
        """Return the value (if any) following the specified protocol
        
        Returns
        -------
        union[object, NoneType]
            The parsed protocol value for the given protocol code or ``None``
            if the given protocol does not require any value
        
        Raises
        ------
        ~multiaddr.exceptions.BinaryParseError
            The stored MultiAddr binary representation is invalid
        ~multiaddr.exceptions.ProtocolLookupError
            MultiAddr does not contain any instance of this protocol
        """
        if not isinstance(proto, protocols.Protocol):
            if isinstance(proto, int):
                proto = protocols.protocol_with_code(proto)
            elif isinstance(proto, six.string_types):
                proto = protocols.protocol_with_name(proto)
            else:
                raise TypeError("Protocol object, name or code expected, got {0!r}".format(proto))

        for proto2, codec, part in bytes_iter(self.to_bytes()):
            if proto2 == proto:
                if codec.SIZE != 0:
                    try:
                        # If we have an address, return it
                        return codec.to_string(proto2, part)
                    except Exception as exc:
                        six.raise_from(exceptions.BinaryParseError(str(exc), self.to_bytes(), proto2.name, exc), exc)
                else:
                    # We were given something like '/utp', which doesn't have
                    # an address, so return None
                    return None
        raise exceptions.ProtocolLookupError(proto, str(self))
