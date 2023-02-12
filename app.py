from flask import Flask
from flask_jwt_extended import JWTManager
from flask_restful import Api

from resources.role import RoleList
from resources.user import UserList, UserRegister, UserLogin, UserIdentity, UserRefreshToken, UserAddRole, \
    UserRemoveRole
from db import db

app = Flask(__name__)
app.config.from_pyfile('settings.py')
api = Api(app)  # Flask REST Api code

jwt = JWTManager(app)

api.add_resource(UserList, '/auth/users')
api.add_resource(UserRegister, '/auth/register')
api.add_resource(UserLogin, '/auth/login')
api.add_resource(UserIdentity, '/auth/whoiam')
api.add_resource(UserRefreshToken, '/auth/refresh')
api.add_resource(RoleList, '/roles')
api.add_resource(UserAddRole, '/role/user')
api.add_resource(UserRemoveRole, '/role/user')

db.init_app(app)

with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(host="0.0.0.0")
