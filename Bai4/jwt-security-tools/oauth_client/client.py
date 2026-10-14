"""
Module OAuthClient.

Trien khai client OAuth 2.0 theo Authorization Code Flow: tao URL uy quyen
va doi ma (code) lay access token.
"""

import requests
from urllib.parse import urlencode


class OAuthClient:
    """Client OAuth 2.0 toi gian, tuan thu luong Authorization Code."""

    def __init__(self, client_id, client_secret, auth_url, token_url, redirect_uri):
        self.client_id = client_id
        self.client_secret = client_secret
        self.auth_url = auth_url
        self.token_url = token_url
        self.redirect_uri = redirect_uri

    def get_auth_url(self, scope="openid"):
        """Tao URL dieu huong nguoi dung toi trang uy quyen."""
        params = {
            "response_type": "code",
            "client_id":     self.client_id,
            "redirect_uri":  self.redirect_uri,
            "scope":         scope,
        }
        return f"{self.auth_url}?{urlencode(params)}"

    def get_token(self, code):
        """Doi authorization code lay access token tu token endpoint."""
        data = {
            "grant_type":    "authorization_code",
            "code":          code,
            "redirect_uri":  self.redirect_uri,
            "client_id":     self.client_id,
            "client_secret": self.client_secret,
        }
        response = requests.post(self.token_url, data=data)
        return response.json()
