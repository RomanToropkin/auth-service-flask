import json

import flask
from flask import jsonify
from flask_restful import Resource, reqparse

from common.role_required import admin_required
from model.user import UserModel
from model.role import RoleModel
from werkzeug.security import check_password_hash, generate_password_hash
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    set_access_cookies, set_refresh_cookies, jwt_required, get_jwt_identity, get_jwt
)

_user_login_parser = reqparse.RequestParser()
_user_login_parser.add_argument('username', type=str, required=True, help="Параметр username не может быть пустым")
_user_login_parser.add_argument('password', type=str, required=True, help="Параметр password не может быть пустым")

_user_register_parser = _user_login_parser.copy()
_user_register_parser.add_argument('email', type=str, required=True, help="Параметр email не может быть пустым")

_user_role_link_parse = _user_login_parser.copy()
_user_role_link_parse.remove_argument('username')
_user_role_link_parse.remove_argument('password')
_user_role_link_parse.add_argument('id_user', type=str, required=True, help="Параметр id_user не может быть пустым")
_user_role_link_parse.add_argument('id_role', type=int, required=True, help="Параметр id_role не может быть пустым")


class User(Resource):
    @classmethod
    def get(cls, user_id):
        user = UserModel.find_by_id(user_id)
        if not user:
            return {'message': 'User not found'}, 404
        return user.json()


class UserList(Resource):

    def get(self):
        users = [user.json() for user in UserModel.find_all()]
        return {'users': users}, 200


class UserLogin(Resource):
    @classmethod
    def post(cls):
        data = _user_login_parser.parse_args()
        response = flask.make_response()
        response.content_type = 'application/json'

        user = UserModel.find_by_username(data['username'])

        # check password
        if user and check_password_hash(user.password, data['password']):
            # flask_jwt_extended, it allow user to send token back to us to tell us who they are
            additional_claims = {"roles": user.get_roles()}
            access_token = create_access_token(identity=user.id, fresh=True,
                                               additional_claims=additional_claims)  # entering password so fresh is True
            refresh_token = create_refresh_token(user.id)
            # when user login, give user access/refresh token
            response.data = json.dumps({'access_token': access_token, 'refresh_token': refresh_token})
            response.status_code = 200
            set_access_cookies(response, access_token)
            set_refresh_cookies(response, refresh_token)
        else:
            response.data = json.dumps({'message': 'Invalid credentials'})
            response.status_code = 401
        return response


class UserRegister(Resource):
    def post(self):
        data = _user_register_parser.parse_args()
        if UserModel.find_by_username(data['username']):
            return {"message": "A user with that username already exists"}, 400
        data['password'] = generate_password_hash(data['password'])
        user = UserModel(**data)  # data is dict
        role = RoleModel.find_by_id(2)
        user.save_to_db()
        user.add_role(role)

        return {"message": "User created successfully."}, 201


class UserAddRole(Resource):
    @admin_required
    def put(self):
        data = _user_role_link_parse.parse_args()
        user = UserModel.find_by_id(data['id_user'])
        if user:
            role = RoleModel.find_by_id(data['id_role'])
            if role:
                user.add_role(role)
                return {'message': 'Add new role'}, 201
            else:
                return {'message': 'Role not found'}, 404
        else:
            return {'message': 'User not found'}, 404


class UserRemoveRole(Resource):
    @admin_required
    def delete(self):
        data = _user_role_link_parse.parse_args()
        user = UserModel.find_by_id(data['id_user'])
        if user:
            role = RoleModel.find_by_id(data['id_role'])
            if role:
                user.delete_role(role)
                return {'message': 'Delete role on user'}, 200
            else:
                return {'message': 'Role not found'}, 404
        else:
            return {'message': 'User not found'}, 404


class UserIdentity(Resource):
    @jwt_required()
    def get(self):
        current_identity = get_jwt()
        user = UserModel.find_by_id(current_identity['sub'])
        if not user:
            return {'message': 'User not found'}, 404
        return user.json()


class UserRefreshToken(Resource):
    @jwt_required(refresh=True)
    def post(self):
        identity = get_jwt_identity()
        access_token = create_access_token(identity=identity)
        return jsonify(access_token=access_token)
