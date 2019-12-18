"""Figshare authentication

based on ideas from:
https://github.com/ropensci/rfigshare/blob/master/R/fs_auth.R
https://github.com/NickleDave/figshare/blob/master/figshare/oauth_dance.py
https://developer.okta.com/blog/2018/07/16/oauth-2-command-line

some functions/classes modified from
https://github.com/googleapis/oauth2client/blob/master/oauth2client/tools.py
https://github.com/googleapis/oauth2client/blob/master/oauth2client/_helpers.py
under Apache license
https://github.com/googleapis/oauth2client/blob/master/LICENSE
"""
from configparser import ConfigParser
import http.server
import os
from pathlib import Path
import ssl
import sys
import urllib.parse
import webbrowser

from requests_oauthlib import OAuth2Session

HERE = Path(__file__).parent

# consumer ID and consumer secret are stored in a config.ini file
CONSUMER_INI = HERE.joinpath('consumer.ini')
CONFIG = ConfigParser()
CONFIG.read(CONSUMER_INI)
# FigShare uses the term 'consumer' ID and secret, instead of 'client'
CONSUMER_ID = CONFIG['CONSUMER']['ID']
CONSUMER_SECRET = CONFIG['CONSUMER']['SECRET']
REDIRECT_URI = CONFIG['CONSUMER']['REDIRECT_URI']
PORT = CONFIG['CONSUMER']['PORT']

FIGSHARE_AUTHORIZATION_ENDPOINT = 'https://figshare.com/account/applications/authorize'
FIGSHARE_TOKEN_ENDPOINT = 'https://api.figshare.com/v2/token'

TIMEOUT = 60 * 5  # timeout for SocketServer that waits for request

CERTFILE = './server.pem'


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


def auth(client_id=None,
         client_secret=None,
         token=None,
         token_secret=None,
         scope='ALL',
         redirect_uri=None,
         port=None,
         timeout=TIMEOUT):
    """authenticate Figshare access

    Parameters
    ----------
    client_id : str
        ID provided by Figshare for applications, optional.
        Default is None, in which case a consumer ID created
        for this package is used.
    client_secret : str
    token : str
    token_secret : str

    Other Parameters
    ----------------
    scope : str
        scope to use when requesting authorization.
        Default is 'ALL'. Currently, 'ALL' is the only scope
        implemented for the Figshare 2.0 API.
    redirect_uri : str
        redirect uri specified by app.
    port
    timeout

    Returns
    -------
    token :
    """
    if ((client_id is None and client_secret is not None) or
            (client_id is not None and client_secret is None)):
        raise ValueError(
            'must provide both consumer key and consumer secret'
        )

    if client_id is None and client_secret is None:
        client_id = CONSUMER_ID
        client_secret = CONSUMER_SECRET

    if port is None:
        port = int(PORT)

    if redirect_uri is None:
        redirect_uri = REDIRECT_URI + PORT

    oauth = OAuth2Session(client_id,
                          redirect_uri=redirect_uri,
                          scope=scope)

    authorization_url, state = oauth.authorization_url(
        FIGSHARE_AUTHORIZATION_ENDPOINT
    )

    try:
        if 'DISPLAY' not in os.environ:
            raise ValueError(
                'unable to open webbrowser, DISPLAY not in os.environ'
            )
        with RedirectServer(("", port),
                            RedirectHandler) as httpd:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(CERTFILE)
            httpd.socket = ssl.wrap_socket(httpd.socket,
                                           certfile=CERTFILE,
                                           server_side=True)
            # open webbrowser inside socketserver context
            # so we can wait for the request *after* opening the browser
            r = webbrowser.open(authorization_url)
            if not r:
                raise ValueError(
                    'was not able to open webbrowser'
                )
            httpd.handle_request()
            if 'error' in httpd.query_params:
                sys.exit('Authentication request was rejected.')
            if 'code' in httpd.query_params:
                code = httpd.query_params['code']

    except ValueError:
        print("Unable to open browser. "
              "Please paste this url into a browser to authorize:" + authorization_url)

    auth_token = oauth.fetch_token(
        token_url=FIGSHARE_TOKEN_ENDPOINT,
        code=code,
        client_secret=client_secret)

    return auth_token