"""tools for OAuth2 from the command line

modified from
https://github.com/googleapis/oauth2client/blob/master/oauth2client/tools.py
https://github.com/googleapis/oauth2client/blob/master/oauth2client/_helpers.py
under Apache license
https://github.com/googleapis/oauth2client/blob/master/LICENSE

"""
import http.server
import urllib.parse

TIMEOUT = 60 * 5  # timeout for SocketServer that waits for request


# adapted from
# https://github.com/googleapis/oauth2client/blob/master/oauth2client/_helpers.py
def parse_unique_urlencoded(content):
    """Parses unique key-value parameters from urlencoded content.

    Parameters
    ----------
    content: str
        URL-encoded key-value pairs.

    Returns
    -------
    params : dict
    Parameters key-value pairs from ``content``.

    Notes
    ------
    Raises ValueError if one of the keys is repeated.
    """
    urlencoded_params = urllib.parse.parse_qs(content)
    params = {}
    for key, value in urlencoded_params.iteritems():
        if len(value) != 1:
            msg = ('URL-encoded content contains a repeated value:'
                   '%s -> %s' % (key, ', '.join(value)))
            raise ValueError(msg)
        params[key] = value[0]
    return params


# adapted from
# https://github.com/googleapis/oauth2client/blob/master/oauth2client/tools.py
class RedirectServer(http.server.HTTPServer):
    """A server to handle OAuth 2.0 redirects back to localhost.

    Waits for a single request and parses the query parameters
    into query_params and then stops serving.
    """
    query_params = {}
    timeout = TIMEOUT


# adapted fromm
# https://github.com/googleapis/oauth2client/blob/master/oauth2client/tools.py
class RedirectHandler(http.server.SimpleHTTPRequestHandler):
    """A handler for OAuth 2.0 redirects back to localhost.

    Waits for a single request and parses the query parameters
    into the servers query_params and then stops serving.
    """
    def __init__(self, request, client_address, server):
        super().__init__(request, client_address, server)
        self.params_from_get = None

    def do_GET(self):
        """Handle a GET request.
        Parses the query parameters and prints a message
        if the flow has completed. Note that we can't detect
        if an error occurred.
        """
        self.send_response(http_client.OK)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        parts = urllib.parse.urlparse(self.path)
        query = parse_unique_urlencoded(parts.query)
        self.server.query_params = query
        self.wfile.write(
            b'<html><head><title>Authentication Status</title></head>')
        self.wfile.write(
            b'<body><p>The authentication flow has completed.</p>')
        self.wfile.write(b'</body></html>')