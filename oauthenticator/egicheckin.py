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
from jupyterhub.handlers import BaseHandler

from traitlets import Unicode, List, Bool, validate

from .generic import GenericOAuthenticator
from .oauth2 import OAuthLoginHandler

EGICHECKIN_HOST = os.environ.get('EGICHECKIN_HOST') or 'aai.egi.eu'


class EGICheckinMixin(OAuth2Mixin):
    _OAUTH_ACCESS_TOKEN_URL = 'https://%s/oidc/token' % EGICHECKIN_HOST
    _OAUTH_AUTHORIZE_URL = 'https://%s/oidc/authorize' % EGICHECKIN_HOST


class EGICheckinLoginHandler(OAuthLoginHandler, EGICheckinMixin):
    pass


class EGICheckinRefreshHandler(BaseHandler):
    @web.authenticated
    @gen.coroutine
    def get(self):
        user = self.get_current_user()
        auth_state = yield user.get_auth_state()
        if not auth_state or 'refresh_token' not in auth_state:
            # auth_state not enabled
            raise web.HTTPError(500, 'No auth state available')

        # performing the refresh token call
        http_client = AsyncHTTPClient()
        headers = {
            "Accept": "application/json",
            "User-Agent": "JupyterHub",
        }
        params = dict(
            client_id=self.authenticator.client_id,
            client_secret=self.authenticator.client_secret,
            grant_type='refresh_token',
            refresh_token=auth_state['refresh_token'],
            scope=' '.join(self.authenticator.scope),
        )
        url = url_concat(self.authenticator.token_url, params)
        req = HTTPRequest(url,
                          auth_username=self.authenticator.client_id,
                          auth_password=self.authenticator.client_secret,
                          headers=headers,
                          method='POST',
                          body=''
                          )
        resp = yield http_client.fetch(req)
        refresh_response = json.loads(resp.body.decode('utf8', 'replace'))
        self.log.debug("Got response with new access token")
        result = {'access_token': refresh_response['access_token']}
        self.write(json.dumps(result))
        # Missing here:
        # 1. Update the access token in the auto_state
        # 2. Store the expiry date of access token
        # 3. Do not try to get an access token every time, as they last for ~1 hour


class EGICheckinAuthenticator(GenericOAuthenticator):
    login_service = "EGI Check-in"

    client_id_env = 'EGICHECKIN_CLIENT_ID'
    client_secret_env = 'EGICHECKIN_CLIENT_SECRET'
    login_handler = EGICheckinLoginHandler
    refresh_handler = EGICheckinRefreshHandler

    scope = List(Unicode(), default_value=['openid', 'profile', 'eduperson_scoped_affiliation',
                                           'eduperson_entitlement', 'offline_access'],
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

    entitlements_key = Unicode(
        'edu_person_entitlements',
        config=True,
        help="Claim name used to whitelist users",
    )

    entitlements_whitelist = List(
        config=True,
        help="""A list of user claims that are authorized to login.""",
    )

    affiliations_key = Unicode(
        'edu_person_scoped_affiliations',
        config=True,
        help="Claim name used to whitelist affiliations",
     )

    affiliations_whitelist = List(
        config=True,
        help="""A list of user affiliations that are authorized to login.""",
    )


    # User name in Check-in comes in sub, but we are defaulting to
    # preferred_username as sub is too long to be used as id for
    # volumes
    username_key = Unicode(
        'preferred_username',
        config=True,
        help="""
        Claim name to use for getting the user name. 'sub' is unique but it's
        too long.
        """
    )

    # getting these from .well-known?
    token_url = 'https://%s/oidc/token' % EGICHECKIN_HOST
    userdata_url = 'https://%s/oidc/userinfo' % EGICHECKIN_HOST

    @gen.coroutine
    def authenticate(self, handler, data=None):
        user_data = yield super(EGICheckinAuthenticator,
                                self).authenticate(handler, data)

        #self.log.info('USER DATA: %s', user_data)
        # probably we shouldn't store everything here
        oauth_user = user_data['auth_state']['oauth_user']
        if self.affiliations_whitelist:
            gotten_claims = oauth_user.get(self.affiliations_key, '')
            if any(x in gotten_claims for x in self.affiliations_whitelist):
                # no need to further check!
                self.log.info('USER allowed as member of %s', self.affiliations_whitelist)
                return user_data

        if self.entitlements_whitelist:
            gotten_claims = oauth_user.get(self.entitlements_key, '')
            if not any(x in gotten_claims for x in self.entitlements_whitelist):
                self.log.debug('User does not belong to white listed claims')
                if not self.whitelist:
                    raise web.HTTPError(
                        401, 'Trying to login without the authorized claims')
        user_data['name'] = user_data['name'].split('@')[0]
        return user_data

    def get_handlers(self, app):
        base = super(EGICheckinAuthenticator, self).get_handlers(app)
        base.append((r'/api/refresh', self.refresh_handler))
        return base


class LocalEGICheckinAuthenticator(LocalAuthenticator, EGICheckinAuthenticator):
    """A version that mixes in local system user creation"""
    pass
