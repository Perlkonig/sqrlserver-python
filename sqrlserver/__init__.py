from .nut import Nut
from .utils import pad, depad

import urllib.parse
from base64 import urlsafe_b64encode, urlsafe_b64decode

def url_generate(authority, path, nut, sfn, query=[], ext=0, secure=True):
	"""Produces a valid SQRL link (LINK TO SPEC)

	Parameters
	----------
	authority : string
		The authority part of the url the SQRL client will contact to authenticate.
		Includes the username, password, domain, and port.
		See RFC 3986, Jan 2005, section 3.2 (https://tools.ietf.org/html/rfc3986#section-3.2)
	path : string
		The path the SQRL client will contact to authenticate.
	nut : string
		Base64-encoded URL-safe string that is 
		  - opaque,
		  - reasonably unique, and
		  - cryptographically unpredictable.
	sfn : string
		The "server friendly name" the SQRL client will use to identify you to the user.
	query : array of tuples
		Each tuple represents additional name-value pairs the SQRL client will need to 
		return when it tries to authenticate.
	ext : int
		If greater than zero, it signals to the SQRL client how much of the path should
		be considered as part of the site's official identifier (LINK TO SPEC).
		Defaults to 0.
	secure : boolean
		If True, uses the ``sqrl`` scheme, otherwise it uses ``qrl``.
		Defaults to True.

	Returns
	-------
	string representing a valid SQRL URL
		Query parameters will always appear in the following order:
		  - nut
		  - sfn
		  - x (if present)
		  - user-provided parameters in the order provided
	"""
	parts = []
	#scheme
	if secure:
		parts.append('sqrl')
	else:
		parts.append('qrl')

	#authority
	parts.append(authority)

	#path
	parts.append(path)

	#params
	parts.append(None)

	#query (insert at front in reverse order)
	if query is None:
		query = []
	if ( (ext is not None) and (ext > 0) ):
		query.insert(0, ('x', ext))
	query.insert(0, ('sfn', depad(urlsafe_b64encode(sfn.encode('utf-8')).decode('utf-8'))))
	query.insert(0, ('nut', nut))
	parts.append(urllib.parse.urlencode(query, True))

	#fragment
	parts.append(None)

	return urllib.parse.urlunparse(parts)

def _extract_client(s):
	"""Decodes and processes client parameter from auth request"""
	s = urlsafe_b64decode(pad(s)).decode('utf-8').strip()

	'''
	While it would be great to be able to do the following, I can't
	because the spec currently does not require that the values be
	escaped, so on the back burner for now.

	s = s.replace('\r\n', '&')
	return urllib.parse.parse_qs(s)
	'''
	client = {}
	for line in s.split('\r\n'):
		name, value = line.split('=', 1)

		client[name] = value
	return client


def _extract_server(s):
	"""Decodes and processes server parameter from auth request"""
	s = urlsafe_b64decode(pad(s)).decode('utf-8').strip()
	
	#if it's a valid s/qrl URL, then return it
	u = urllib.parse.urlparse(s)
	if ( (u.scheme == 'sqrl') or (u.scheme == 'qrl') ):
		return s

	#Otherwise it's name/value pairs
	server = {}
	for line in s.split('\r\n'):
		name, value = line.split('=', 1)
		server[name] = value
	return server

def request_validate(params, key, nonce, ipaddr, ttl, maxcounter=None, mincounter=0):
	"""Checks for basic completeness (it doesn't know the CMD yet) and packages
	everything for the request handler, or it throws an error.

	Parameters
	----------
	params : dictionary
		Dictionary of name/value pairs received from the POST to the SQRL endpoint.
		It is assumed that all initial URL escaping has been reversed.
		The params must contain at least the following keys:
		  - nut
		  - client
		  - server
		  - ids

  	The remaining parameters are passed directly to ``nut_validate``.

  	Returns
  	-------
  	(boolean, response)
  		If the request is well formed, then the first element of the tuple will be True.
  		In which case, the second element will be a dictionary containing the information
  		needed by the request handler.

  		If the request is not well formed, then the first element will be True.
  		In which case, the second element will contain the body of the reply that 
  		should be returned to the requester.
	"""

	for key in []:
		if key not in params:
			pass

def request_handle(request):
	"""Handles an incoming request based on the CMD embedded in the "client" parameter.
	Expects data in the form created by ``request_validate``.

	Parameters
	----------
	request : dictionary
		Expects the format produced by ``request_validate``.

	Returns
	-------
	Tuple of boolean and response body
		The first element is a simple boolean that signals whether things validated OK.
		If True, the server should return a 200 HTTP status code.
		If False, the server should return some sort of 400 HTTP status code.

		The second element should be returned in the body of the response regardless of
		how things validated.
	"""

	r = [('ver', '1')]
	tif = 0x00

	#validate the nut
	nut = nut_validate()

	if 'client' not in params:
		return (False, AUTH_ERROR_CLIENT_MISSING)
	client = _extract_client(params['client'])

	if ( ('ver' not in client) or (client['ver'][0] != '1') ):
		return (False, AUTH_ERROR_VERSION_UNKNOWN)

	if 'server' not in params:
		return (False, AUTH_ERROR_SERVER_MISSING)
	server = _extract_server(params['server'])
