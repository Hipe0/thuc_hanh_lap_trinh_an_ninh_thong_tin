"""
Module JWTValidator.

Kiem tra tinh hop le cua mot JWT: xac minh chu ky, han su dung (exp) va
cac loi dinh dang token. Tra ve dict mo ta ket qua kiem tra.
"""

import jwt
from jwt.exceptions import (
    InvalidTokenError,
    ExpiredSignatureError,
    InvalidSignatureError,
)


class JWTValidator:
    """Bo kiem tra tinh hop le va an toan cua JWT."""

    def __init__(self, secret, algorithms=["HS256"]):
        self.secret = secret
        self.algorithms = algorithms

    def validate(self, token: str):
        try:
            payload = jwt.decode(
                token,
                self.secret,
                algorithms=self.algorithms,
            )
            return {"valid": True, "payload": payload}

        except ExpiredSignatureError:
            # Token da het han su dung.
            return {"valid": False, "reason": "Token expired"}

        except InvalidSignatureError:
            # Chu ky khong khop -> token bi gia mao hoac sai khoa.
            return {"valid": False, "reason": "Invalid signature"}

        except InvalidTokenError as e:
            # Cac loi token khac (dinh dang sai, thieu phan, ...).
            return {"valid": False, "reason": str(e)}
