from src.models.all_models import User, db
from flask_jwt_extended import create_access_token
from src.config.config import bcrypt
import uuid

import jwt
import os

def signup(data, user_info):
    try:
        if "username" in data and "email" in data and "password" in data:
            username = data["username"]
            email = data["email"]
            password = data["password"]
            role= data["role"]

            # Hash the password using bcrypt
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

            # Create a new user object
            new_user = User(
                id=str(uuid.uuid4()),  # Assuming UUID as a string
                username=username,
                email=email,
                password=hashed_password , 
                role=role
            )
            db.session.add(new_user)
            db.session.commit()
            return {'status': "success", "statusCode": 201, "message": "User created successfully!"}, 201
        else:
            return {'status': "failed", "statusCode": 400, "message": "Username, email, and password are required"}, 400
    except Exception as e:
        db.session.rollback()
        return {'status': "failed", "statusCode": 500, "message": "Error occurred", "error": str(e)}, 500



def login(data):
    try:
        if "email" in data and "password" in data:
            user = User.query.filter_by(email=data["email"]).first()
            if user and bcrypt.check_password_hash(user.password, data["password"]):
                # Include role and username in the token
                token_data = {
                    'role': user.role,
                    'username': user.username,
                    'id': str(user.id)
                }
                print("id===>",user.id)
                
                # Encode the token using JWT
                token = jwt.encode(token_data,str(os.getenv('SECRET_KEY')), algorithm='HS256')

                print("token===>",token)
                
                return {'status': "success", "statusCode": 200, "token": token}, 200
            else:
                return {'status': "failed", "statusCode": 401, "message": "Invalid credentials!"}, 401
        else:
            return {'status': "failed", "statusCode": 400, "message": "Email and password are required"}, 400
    except Exception as e:
        return {'status': "failed", "statusCode": 500, "message": "Error occurred", "error": str(e)}, 500

def get_profile(user_id):
    try:
        user = User.query.get(user_id)
        if user:
            user_data = {
                "username": user.username,
                "email": user.email
            }
            return {'status': "success", "statusCode": 200, "message": "User profile found", "data": user_data}, 200
        else:
            return {'status': "failed", "statusCode": 404, "message": "User not found"}, 404
    except Exception as e:
        return {'status': "failed", "statusCode": 500, "message": "Error occurred", "error": str(e)}, 500

# @log_function_execution
def logout(user_info):
    try:
        # Normally, the frontend will handle removing the JWT token.
        return {'status': "success", "statusCode": 200, "message": "Logged out successfully!"}, 200
    except Exception as e:
        return {'status': "failed", "statusCode": 500, "message": "Error occurred", "error": str(e)}, 500
    

def get_all_users():
    try:
        users = User.query.all()
        if users:
            users_data = []
            for user in users:
                user_data = {
                    "id": user.id,
                    "username": user.username,
                    "email": user.email,
                    "role": user.role  
                }
                users_data.append(user_data)
            
            return {'status': "success", "statusCode": 200, "message": "Users found", "data": users_data}, 200
        else:
            return {'status': "success", "statusCode": 200, "message": "No users found", "data": []}, 200
    except Exception as e:
        return {'status': "failed", "statusCode": 500, "message": "Error occurred", "error": str(e)}, 500

