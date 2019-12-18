"""Figshare authentication

based on ideas from:
https://github.com/ropensci/rfigshare/blob/master/R/fs_auth.R
https://gist.github.com/burnash/6771295
https://github.com/rmcgibbo/figshare/blob/master/figshare/oauth_dance.py
https://developer.okta.com/blog/2018/07/16/oauth-2-command-line/
"""
import os

import ssl
import sys

import webbrowser

from requests_oauthlib import OAuth2Session

from .constants import CONSUMER_ID, CONSUMER_SECRET,
from .constants import REDIRECT_URI, PORT
from .constants import FIGSHARE_AUTHORIZATION_ENDPOINT, FIGSHARE_TOKEN_ENDPOINT
from .oauth import ClientRedirectHandler, ClientRedirectServer


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