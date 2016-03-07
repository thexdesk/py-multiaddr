===============================
Multiaddr
===============================

.. image:: https://img.shields.io/pypi/v/multiaddr.svg
        :target: https://pypi.python.org/pypi/multiaddr

.. image:: https://travis-ci.org/sbuss/py-multiaddr.svg?branch=master
        :target: https://travis-ci.org/sbuss/py-multiaddr

.. image:: https://codecov.io/github/sbuss/py-multiaddr/coverage.svg?branch=master
        :target: https://codecov.io/github/sbuss/py-multiaddr?branch=master

.. image:: https://readthedocs.org/projects/multiaddr/badge/?version=latest
        :target: https://readthedocs.org/projects/multiaddr/?badge=latest
        :alt: Documentation Status


Python implementation of jbenet_'s multiaddr_

.. _jbenet: https://github.com/jbenet
.. _multiaddr: https://github.com/jbenet/multiaddr

* Free software: MIT License
* Documentation: https://multiaddr.readthedocs.org.

Usage
=====

Simple
------

.. code-block:: python

    from multiaddr import Multiaddr

    # construct from a string
    m1 = Multiaddr("/ip4/127.0.0.1/udp/1234")

    # construct from bytes
    m2 = Multiaddr(bytes_addr=m1.to_bytes())

    assert str(m1) == "/ip4/127.0.0.1/udp/1234"
    assert str(m1) == str(m2)
    assert m1.to_bytes() == m2.to_bytes()
    assert m1 == m2
    assert m2 == m1
    assert not (m1 != m2)
    assert not (m2 != m1)


Protocols
---------

.. code-block:: python

    from multiaddr import Multiaddr

    m1 = Multiaddr("/ip4/127.0.0.1/udp/1234")

    # get the multiaddr protocol description objects
    m1.protocols()
    # [Protocol(code=4, name='ip4', size=32), Protocol(code=17, name='udp', size=16)]


En/decapsulate
--------------

.. code-block:: python

    from multiaddr import Multiaddr

    m1 = Multiaddr("/ip4/127.0.0.1/udp/1234")
    m1.encapsulate(Multiaddr("/sctp/5678"))
    # <Multiaddr /ip4/127.0.0.1/udp/1234/sctp/5678>
    m1.decapsulate(Multiaddr("/udp"))
    # <Multiaddr /ip4/127.0.0.1>


Tunneling
---------

Multiaddr allows expressing tunnels very nicely.


.. code-block:: python

    printer = Multiaddr("/ip4/192.168.0.13/tcp/80")
    proxy = Multiaddr("/ip4/10.20.30.40/tcp/443")
    printerOverProxy = proxy.encapsulate(printer)
    print(printerOverProxy)
    # /ip4/10.20.30.40/tcp/443/ip4/192.168.0.13/tcp/80

    proxyAgain = printerOverProxy.decapsulate(printer)
    print(proxyAgain)
    # /ip4/10.20.30.40/tcp/443
