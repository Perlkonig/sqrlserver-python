del modules.rst
del sqrlserver.rst
del sqrlserver.*.rst
sphinx-apidoc -e -o . ../sqrlserver
call make clean
call make html _build
