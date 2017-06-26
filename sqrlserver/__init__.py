from .nut import Nut
from .request import Request
from .response import Response
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
