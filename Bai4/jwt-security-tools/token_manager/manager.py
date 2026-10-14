"""
Module TokenManager.

Quan ly vong doi JWT: phat hanh cap access/refresh token, va cap moi
access token tu refresh token con hieu luc.
"""

import jwt
import datetime


class TokenManager:
    """Bo quan ly phat hanh va lam moi JWT."""

    def __init__(self, secret, algorithm="HS256", access_exp=15, refresh_exp=60 * 24):
        self.secret = secret
        self.algorithm = algorithm
        self.access_exp = access_exp        # han access token (phut)
        self.refresh_exp = refresh_exp      # han refresh token (phut)

    def _generate(self, payload, exp_minutes):
        """Gan truong exp va ky token."""
        payload["exp"] = (
            datetime.datetime.utcnow()
            + datetime.timedelta(minutes=exp_minutes)
        )
        return jwt.encode(payload, self.secret, algorithm=self.algorithm)

    def generate_tokens(self, user_id):
        access_token = self._generate(
            {"sub": user_id, "type": "access"}, self.access_exp)
        refresh_token = self._generate(
            {"sub": user_id, "type": "refresh"}, self.refresh_exp)
        return access_token, refresh_token

    def refresh_access_token(self, refresh_token):
        try:
            payload = jwt.decode(
                refresh_token, self.secret, algorithms=[self.algorithm])

            # Chi cap access token moi khi dung la refresh token.
            if payload.get("type") == "refresh":
                return self._generate(
                    {"sub": payload["sub"], "type": "access"}, self.access_exp)

        except jwt.ExpiredSignatureError:
            # Refresh token da het han.
            return None
