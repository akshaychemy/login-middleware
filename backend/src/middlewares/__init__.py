from flask import Blueprint, request, Response, g, session
from functools import wraps
import jwt
import os
import logging

def decode_jwt(token):
    """
    Decode the JWT token using the secret key.
    """
    try:
        token = token.split(" ")[1]  # Split the token in 'Bearer <token>' format
        return jwt.decode(token, str(os.getenv('SECRET_KEY')), algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        logging.error("Token has expired")
        return {'error': 'Token has expired'}
    except jwt.InvalidTokenError:
        logging.error("Invalid token")
        return {'error': 'Invalid token'}


def authenticate_admin(func):
    """
    Middleware to authenticate the user as an admin. Verifies the JWT token
    and ensures that the user has 'Admin' role in the token payload.
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get('Authorization')

        print("auth_header==>",auth_header.split()[1])

        if not auth_header:
            logging.warning("Missing Authorization header")
            return Response(
                response='{"message": "Unauthorized - Missing Authorization header"}',
                status=401,
                mimetype='application/json'
            )

        user_info = decode_jwt(auth_header)
        print("user_info--->",user_info)

        if 'error' in user_info:
            return Response(
                response=f'{{"message": "Unauthorized - {user_info["error"]}"}}',
                status=401,
                mimetype='application/json'
            )

        if 'role' not in user_info or 'admin' not in user_info['role']:
            logging.warning("User is not authorized")
            return Response(
                response='{"message": "Unauthorized - User is not authorized"}',
                status=403,
                mimetype='application/json'
            )

        # Set user information in global `g` and session
        g.user_info = user_info
        session['user_info'] = user_info

        # Proceed to the actual function
        return func(*args, **kwargs)

    return wrapper
