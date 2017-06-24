SQRL Server Library
=======================

This module supports Python-based web servers in processing SQRL_ requests. It only does the verification work. It leaves data representation, storage, and other platform-specific actions to the user.

.. _SQRL: https://www.grc.com/sqrl/sqrl.htm

Currently Implemented
---------------------

* ``nut_generate``: Generates a base64-encoded nut with embedded sanity checking data
* ``nut_validate``: Analyzes a base64-encoded nut and returns a dictionary of validity checks
* ``url_generate``: Generates the URL that directs the SQRL client where to authenticate

Todo
----

* Lots of signature validation code. Still digesting the spec.
