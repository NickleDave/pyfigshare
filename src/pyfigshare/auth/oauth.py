# Copyright 2014 Google Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Command-line tools for authenticating via OAuth 2.0

Do the OAuth 2.0 Web Server dance for a command line application. Stores the
generated credentials in a common file that is used by other example apps in
the same directory.

modified from
https://github.com/googleapis/oauth2client/blob/master/oauth2client/tools.py
https://github.com/googleapis/oauth2client/blob/master/oauth2client/_helpers.py
under Apache license
https://github.com/googleapis/oauth2client/blob/master/LICENSE
"""
import http.server
from http import HTTPStatus
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
        parameters key-value pairs from ``content``.

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
class ClientRedirectServer(http.server.HTTPServer):
    """A server to handle OAuth 2.0 redirects back to localhost.

    Waits for a single request and parses the query parameters
    into query_params and then stops serving.
    """
    query_params = {}
    timeout = TIMEOUT


# adapted fromm
# https://github.com/googleapis/oauth2client/blob/master/oauth2client/tools.py
class ClientRedirectHandler(http.server.BaseHTTPRequestHandler):
    """A handler for OAuth 2.0 redirects back to localhost.

    Waits for a single request and parses the query parameters
    into the servers query_params and then stops serving.
    """
    def do_GET(self):
        """Handle a GET request.
        Parses the query parameters and prints a message
        if the flow has completed. Note that we can't detect
        if an error occurred.
        """
        self.send_response(HTTPStatus.OK)
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
