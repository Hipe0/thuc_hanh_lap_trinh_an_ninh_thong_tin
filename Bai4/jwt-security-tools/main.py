"""
Chuong trinh chinh cua bo cong cu JWTSecure.

Phat hanh cap access/refresh token cho mot nguoi dung mau, in ra man hinh,
sau do khoi dong API Gateway de kiem thu endpoint /protected.
"""

from api_gateway.gateway import APIGateway
from token_manager.manager import TokenManager


if __name__ == "__main__":
    secret = "supersecret"

    # Phat hanh token cho nguoi dung "phuoc".
    manager = TokenManager(secret)
    access_token, refresh_token = manager.generate_tokens("phuoc")

    print("Access Token:", access_token)
    print("Refresh Token:", refresh_token)

    # Khoi dong cong API co xac thuc JWT.
    gateway = APIGateway(secret)
    gateway.run()
