from urllib.parse import urlparse, urlunparse

def pad(data):
    data += '=' * (len(data) % 4)
    return data

def depad(data):
    return data.rstrip('=')

def stripurl(url):
    u = urlparse(url)
    return urlunparse(('', '', u.path, u.params, u.query, u.fragment))
