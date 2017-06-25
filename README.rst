SQRL Server Library
=======================

This module supports Python-based web servers in processing SQRL_ requests. It only does the verification work. It leaves data representation, storage, and other platform-specific actions to the user.

.. _SQRL: https://www.grc.com/sqrl/sqrl.htm

Currently Implemented
---------------------

* ``Nut`` class: Used for generating, inspecting, and validating nuts
* ``url_generate``: Generates the URL that directs the SQRL client where to authenticate

Todo
----

* Working on the base Request class
