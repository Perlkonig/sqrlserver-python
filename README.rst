SQRL Server Library
=======================

ALPHA STATE! CODE MAY NOT BUILD, LET ALONE WORK AS EXPECTED!

This module supports Python-based web servers in processing SQRL_ requests. It only does the verification work. It leaves data representation, storage, and other platform-specific actions to the user.

.. _SQRL: https://www.grc.com/sqrl/sqrl.htm

Currently Implemented
---------------------

* ``url_generate``: Generates the URL that directs the SQRL client where to authenticate.
* ``Nut`` class: Used for generating, inspecting, and validating nuts.
* ``Request`` class: Used for receiving and processing client requests. Still being expanded to include all the required commands.
* ``Response`` class: Used by the ``Request`` class to build the response you will need to return to the client.

