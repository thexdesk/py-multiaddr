=======
History
=======

0.0.2 (2016-5-4)
----------------

* Fix a bug in decapsulate that threw an IndexError instead of a copy of the
  Multiaddr when the original multiaddr does not contain the multiaddr to
  decapsulate. [via fredthomsen_ `#9`_]
* Increase test coverage [via fredthomsen_ `#9`_]

.. _fredthomsen: https://github.com/fredthomsen
.. _`#9`: https://github.com/sbuss/py-multiaddr/pull/9

0.0.1 (2016-1-22)
------------------

* First release on PyPI.
