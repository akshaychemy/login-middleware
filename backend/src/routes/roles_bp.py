from flask import Blueprint
from src.controllers.user_controller import signup, login, profile, logout

# Blueprint for user authentication routes
roles_bp = Blueprint('user_bp', __name__)

# Define routes
roles_bp.route('/create-role', methods=['POST'])(signup)
roles_bp.route('/update-role', methods=['POST'])(login)
