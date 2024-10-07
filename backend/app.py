# /Users/krishnamayekar/Desktop/login/backend/app.py
from src.config.config import create_app, db  # Import 'db' from config.py
from src.routes.user_bp import user_bp  # Import blueprint from the routes folder

from flask_migrate import Migrate

app = create_app()
migrate = Migrate(app, db)

# Register Blueprints
app.register_blueprint(user_bp, url_prefix="/users")
# app.register_blueprint(roles_bp, url_prefix="/roles")

# Main entry point of the application
if __name__ == "__main__":
    # Create all database tables (if they do not exist) within the app context
    # with app.app_context():
    #     db.drop_all()
    #     db.create_all()  

    app.run(debug=True)
