SQRL Server Library
=======================

ALPHA STATE! CODE MAY NOT BUILD, LET ALONE WORK AS EXPECTED!

This module supports Python-based web servers in processing SQRL_ requests. It only does the core protocol work. It leaves data representation, storage, and other platform-specific actions to the server.

.. _SQRL: https://www.grc.com/sqrl/sqrl.htm

Currently Implemented
---------------------

- ``url_generate``: Generates the URL that directs the SQRL client where to authenticate.

- ``Nut`` class: Used for generating, inspecting, and validating nuts.

- ``Request`` class: Used for receiving and processing client requests. Currently supports the following commands:
  
  - ``query``
	
- ``Response`` class: Used by the ``Request`` class to build the response you will need to return to the client.

Divergences
-----------

- Status code 0x100 is not currently used. If IDs ever get rolled into the nut, then this could change.

- There is confusion in the spec about what exactly the server should be doing about the ``opt`` parameter. Right now this library ignores it until it's time to actually execute a non-query command. It does not ensure that the field remains constant over some set of requests.

- The spec is unclear about how to handle unsupported options. For now, the library leaves it up to the server to decide whether to hard or soft fail an option request. Hard fail will result in setting TIF codes 0x10 and 0x80 and aborting any requested actions. A soft fail will result in the command being successfully concluded without any notice to the user, unless the server chooses to use the ASK feature.

