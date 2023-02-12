from flask_restful import Resource, reqparse
from model.role import RoleModel
from common.role_required import admin_required


class RoleList(Resource):
    @admin_required
    def get(self):
        roles = [role.json() for role in RoleModel.find_all()]
        return {'roles': roles}, 200
