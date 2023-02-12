from db import db


class RoleModel(db.Model):
    __tablename__ = 'role'
    __table_args__ = {"schema": "auth"}

    id = db.Column(db.Integer, db.Sequence('role_id_seq'),
                   primary_key=True)
    role_name = db.Column(db.String(80))

    def __init__(self, role_name):
        self.role_name = role_name

    def json(self):
        return {
            'id': self.id,
            'role_name': self.role_name
        }

    @classmethod
    def find_all(cls):
        return cls.query.all()

    @classmethod
    def find_by_id(cls, id):
        return cls.query.filter_by(id=id).first()