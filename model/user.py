import uuid

from db import db

association_table = db.Table(
    "user_role",
    db.Model.metadata,
    db.Column("id_user", db.ForeignKey("auth.user.id")),
    db.Column("id_role", db.ForeignKey("auth.role.id")),
    schema="auth"
)


class UserModel(db.Model):
    __tablename__ = 'user'
    __table_args__ = {"schema": "auth"}

    id = db.Column(db.String(255), primary_key=True)
    username = db.Column(db.String(80))
    email = db.Column(db.String(80))
    password = db.Column(db.String(255))
    roles = db.relationship("RoleModel", secondary=association_table)

    def __init__(self, username, email, password):
        self.username = username
        self.email = email
        self.password = password

    def get_roles(self):
        return [role.json() for role in self.roles]

    def json(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'roles': self.get_roles()
        }

    def save_to_db(self):
        self.id = str(uuid.uuid4())
        db.session.add(self)
        db.session.commit()

    @classmethod
    def find_all(cls):
        return cls.query.all()

    @classmethod
    def find_by_email(cls, email):
        return cls.query.filter_by(email=email).first()

    @classmethod
    def find_by_username(cls, username):
        return cls.query.filter_by(username=username).first()

    @classmethod
    def find_by_id(cls, id):
        return cls.query.filter_by(id=id).first()

    def add_role(self, role):
        self.roles.append(role)
        db.session.commit()

    def delete_role(self, role):
        if role in self.roles:
            self.roles.remove(role)
            db.session.commit()