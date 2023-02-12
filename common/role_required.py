from functools import wraps

from flask_jwt_extended import verify_jwt_in_request, get_jwt
from model.user import UserModel


def contains_role(list, id_role):
    for x in list:
        if x['id'] == id_role:
            return True
    return False


def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        verify_jwt_in_request()
        jwt = get_jwt()
        id_user = jwt['sub']
        user = UserModel.find_by_id(id_user)
        if not contains_role(user.get_roles(), 1):
            return {'error': 'Admins Only'}, 403
        else:
            return fn(*args, **kwargs)

    return wrapper
