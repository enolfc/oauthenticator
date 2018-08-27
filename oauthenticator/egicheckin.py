"""
EGI Check-in authenticator for JupyterHub

Uses OpenID Connect with aai.egi.eu
"""


import json
import os
import base64
import urllib
import pprint

from tornado.auth import OAuth2Mixin
from tornado import gen, web

from tornado.httputil import url_concat
from tornado.httpclient import HTTPRequest, AsyncHTTPClient

from jupyterhub.auth import LocalAuthenticator

from traitlets import Unicode, List, Bool, validate

from .generic import GenericOAuthenticator
from .oauth2 import OAuthLoginHandler

EGICHECKIN_HOST = os.environ.get('EGICHECKIN_HOST') or 'aai.egi.eu'


class EGICheckinMixin(OAuth2Mixin):
    _OAUTH_ACCESS_TOKEN_URL = 'https://%s/oidc/token' % EGICHECKIN_HOST
    _OAUTH_AUTHORIZE_URL = 'https://%s/oidc/authorize' % EGICHECKIN_HOST


class EGICheckinLoginHandler(OAuthLoginHandler, EGICheckinMixin):
    pass


class EGICheckinAuthenticator(GenericOAuthenticator):
    login_service = "EGI Check-in"

    client_id_env = 'EGICHECKIN_CLIENT_ID'
    client_secret_env = 'EGICHECKIN_CLIENT_SECRET'
    login_handler = EGICheckinLoginHandler

    scope = List(Unicode(), default_value=['openid', 'email', 'refeds_edu',
                                           'offline_access'],
                 config=True,
                 help="""The OAuth scopes to request.

        See https://wiki.egi.eu/wiki/AAI_guide_for_SPs#OpenID_Connect_Service_Provider for details.
        At least 'openid' is required.
        """,
                 )

    @validate('scope')
    def _validate_scope(self, proposal):
        """ensure openid is requested"""
        if 'openid' not in proposal.value:
            return ['openid'] + proposal.value
        return proposal.value

    claims_key = Unicode(
        'edu_person_entitlements',
        config=True,
        help="Claim name used to whitelist users",
    )

    claims_whitelist = List(
        config=True,
        help="""A list of user claims that are authorized to login.""",
    )

    # User name in Check-in comes in sub
    # From Check-in docs: An identifier for the user, unique among all
    # EGI accounts and never reused. Use sub within your application as the
    # unique-identifier key for the user.
    username_key = 'sub'

    # getting these from .well-known?
    token_url = 'https://%s/oidc/token' % EGICHECKIN_HOST
    userdata_url = 'https://%s/oidc/userinfo' % EGICHECKIN_HOST

    @gen.coroutine
    def authenticate(self, handler, data=None):
        user_data = yield super(EGICheckinAuthenticator,
                                self).authenticate(handler, data)
        if self.claims_whitelist:
            oauth_user = user_data['auth_state']['oauth_user']
            gotten_claims = oauth_user.get(self.claims_key, '')
            if not any(x in gotten_claims for x in self.claims_whitelist):
                self.log.debug(
                        'User does not have any of the white listed claims')
                raise web.HTTPError(
                        401, 'Trying to login without the authorized claims')
        self.log.debug('USER DATA: %s', pprint.pformat(user_data))
        return user_data


class LocalEGICheckinAuthenticator(LocalAuthenticator, EGICheckinAuthenticator):
    """A version that mixes in local system user creation"""
    pass
