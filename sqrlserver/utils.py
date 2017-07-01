from urllib.parse import urlparse, urlunparse, parse_qs, urlencode

def pad(data):
    """Pads a string so the length is a multiple of 4"""

    data += '=' * (len(data) % 4)
    return data

def depad(data):
    """Removes padding characters from the end of b64u encoded strings"""

    return data.rstrip('=')

def stripurl(url):
    """Strips scheme and netloc from urls"""
    
    u = urlparse(url)
    return urlunparse(('', '', u.path, u.params, u.query, u.fragment))

def addquery(url, params):
    """Adds/replaces query paramters to a url

    For predictability and testing, they are sorted alphabetically.
    """

    u = urlparse(url)
    q = parse_qs(u.query)
    for name in params:
        q[name] = params[name]
    q = sorted([(name,value) for name,value in q.items()], key=lambda x: x[0])
    q = urlencode(q, doseq=True)
    return urlunparse((u.scheme, u.netloc, u.path, u.params, q, u.fragment))

def delquery(url, *args):
    """Removes requested query paramters from a url

    For predictability and testing, they are sorted alphabetically.
    """

    u = urlparse(url)
    q = parse_qs(u.query)
    for name in args:
        del q[name]
    q = sorted([(name,value) for name,value in q.items()], key=lambda x: x[0])
    q = urlencode(q, doseq=True)
    return urlunparse((u.scheme, u.netloc, u.path, u.params, q, u.fragment))
