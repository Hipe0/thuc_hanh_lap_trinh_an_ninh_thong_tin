"""
Module APIGateway.

Cong API don gian (Flask) co tich hop xac thuc bang JWT. Endpoint
/protected chi cho phep truy cap khi Authorization header mang token hop le.
"""

from flask import Flask, request, jsonify
import jwt


class APIGateway:
    """Cong API bao ve bang JWT."""

    def __init__(self, secret, algorithm="HS256"):
        self.secret = secret
        self.algorithm = algorithm
        self.app = Flask(__name__)
        self.routes()

    def routes(self):
        @self.app.route("/protected")
        def protected():
            # Lay token tu header "Authorization: Bearer <token>".
            token = request.headers.get("Authorization", "").replace("Bearer ", "")

            try:
                payload = jwt.decode(
                    token, self.secret, algorithms=[self.algorithm])
                return jsonify({
                    "message": "Access granted",
                    "user": payload["sub"],
                })

            except jwt.InvalidTokenError:
                # Token khong hop le -> tu choi truy cap.
                return jsonify({"message": "Access denied"}), 401

    def run(self):
        self.app.run(port=5000)
