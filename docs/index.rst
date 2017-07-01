.. SQRL Server documentation master file, created by
   sphinx-quickstart on Wed Jun 28 05:29:34 2017.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

#######################################
SQRL Server
#######################################

.. toctree::
   :maxdepth: 2
   :hidden:

   usage
   examples
   divergences
   API <modules>

This module supports Python-based web servers in processing `SQRL <https://www.grc.com/sqrl/sqrl.htm>`_ requests. It only does the core protocol work (signature validation, etc.). It leaves data representation, storage, and other platform-specific actions to the server.

The following terms are used throughout the documentation:

user
    The human actor interacting with the system

client
    The client software the user is using to interact

server
    The web service that is wanting to support SQRL interaction

library
    This code that supports the server in understanding SQRL interactions

Installation
============

Eventually it will be available via PyPi::

    pip install sqrlserver

For now, download and install manually::

    python setup.py test
    python setup.py install

Requirements
============

This library only works with Python3. It requires the following external libraries to run:

- bitstring
- PyNaCl

Contribute
==========

- Issue Tracker: <https://github.com/Perlkonig/sqrlserver-python/issues>
- Source Code: <https://github.com/Perlkonig/sqrlserver-python>

Licence
=======

The project is licensed under the MIT licence.

Changelog
=========

01 Jul 2017
  * Initial release (v0.1.0)

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

