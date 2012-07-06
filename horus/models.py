from pyramid.i18n               import TranslationStringFactory
from pyramid.security           import Allow
from datetime                   import datetime
from datetime                   import timedelta
from datetime                   import date
from sqlalchemy.ext.declarative import declared_attr
from sqlalchemy                 import or_
from sqlalchemy                 import func
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy.orm import backref
from sqlalchemy.schema import UniqueConstraint
from sqlalchemy.sql.expression import and_

from horus.lib                  import generate_random_string
from horus.lib                  import get_session
from horus.lib                  import pluralize

import cryptacular.bcrypt
import re
import urllib
import hashlib
import sqlalchemy as sa


_ = TranslationStringFactory('horus')

crypt = cryptacular.bcrypt.BCRYPTPasswordManager()

class BaseModel(object):
    """Base class which auto-generates tablename, and surrogate
    primary key column.
    """
    __table_args__ = {
        'sqlite_autoincrement': True,
        'mysql_engine': 'InnoDB',
        'mysql_charset': 'utf8'
    }

    @declared_attr
    def __tablename__(cls):
        """Convert CamelCase class name to underscores_between_words 
        table name."""
        name = cls.__name__.replace('Mixin', '')

        return pluralize((
            name[0].lower() + 
            re.sub(r'([A-Z])', lambda m:"_" + m.group(0).lower(), name[1:])
        ))

    id =  sa.Column(sa.Integer, autoincrement=True, primary_key=True)

    def __json__(self):
        """Converts all the properties of the object into a dict
        for use in json
        """
        props = {}

        for key in self.__dict__:
            if not key.startswith('__') and not key.startswith('_sa_'):
                obj = getattr(self, key)

                if isinstance(obj, datetime) or isinstance(obj, date):
                        props[key] = obj.isoformat()
                else:
                    props[key] = getattr(self, key)

        return props

    @classmethod
    def get_all(cls, request):
        session = get_session(request)

        return session.query(cls).all()

    @classmethod
    def get_by_id(cls, request, id):
        """Gets an object by its primary key"""
        session = get_session(request)

        return session.query(cls).filter(cls.id == id).first()


class ActivationMixin(BaseModel):
    """
    Handle activations/password reset items for users

    The code should be a random hash that is valid only one time
    After that hash is used to access the site it'll be removed

    The created by is a system: new user registration, password reset, forgot
    password, etc.

    """
    @declared_attr
    def code(self):
        """ Unique user name """
        return sa.Column(sa.Unicode(30), nullable=False, unique=True)

    @declared_attr
    def valid_until(self):
        """ How long will the activation key last """
        return sa.Column(sa.DateTime, nullable=False)

    @declared_attr
    def created_by(self):
        """ The system that generated the activation key """
        return sa.Column(sa.Unicode(30), nullable=False)

    @classmethod
    def get_by_code(cls, request, code):
        session = get_session(request)
        return session.query(cls).filter(cls.code == code).first()

    def __init__(self, created_by='web', valid_until=None):
        """ Create a new activation, valid_until is a datetime, 
        defaults to 3 days from current day
        """
        self.code =  generate_random_string(12)
        self.created_by = created_by

        if valid_until:
            self.valid_until = valid_until
        else:
             self.valid_until = datetime.utcnow() + timedelta(days=3)

class UserMixin(BaseModel):
    @declared_attr
    def display_name(self):
        """ Display name """
        return sa.Column(sa.Unicode(80), default=u'')

    @declared_attr
    def active(self):
        """ Is active """
        return sa.Column(sa.Boolean, default=True)

    @declared_attr
    def accounts(self):
        """ Relationship for accounts belonging to this user """
        return sa.orm.relationship(
            'UserAccount',
            cascade="all,delete-orphan",
            passive_deletes=True,
            passive_updates=True,
            backref=backref(UserMixin.__tablename__.rstrip('s'), lazy="joined")
        )

    def get_account(self, request, provider=None):
        """ Return an account of the user """
        session = get_session(request)

        if provider is None:
            """ Return the first one found """
            return session.query(UserAccountMixin).filter(
                and_(
                    UserAccountMixin.user_id == self.id,
                )
            ).first()

        else:
            """ Return a specified one """
            return session.query(UserAccountMixin).filter(
                and_(
                    UserAccountMixin.user_id == self.id,
                    func.lower(UserAccountMixin.provider) == provider.lower(),
                )
            ).first()

class UserAccountMixin(BaseModel):

    __table_args__ = (
        UniqueConstraint('username', 'provider'),
        UniqueConstraint('openid', 'provider'),
        BaseModel.__table_args__
    )

    @declared_attr
    def user_id(self):
        return sa.Column(
            sa.Integer,
            sa.ForeignKey('%s.id' % UserMixin.__tablename__)
        )

    @declared_attr
    def username(self):
        """ Username, unique constraint with `provider` """
        return sa.Column(sa.Unicode(30), nullable=False, index=True)

    @declared_attr
    def openid(self):
        """ Openid, unique constraint with `provider` """
        return sa.Column(sa.Integer, nullable=True, index=True)

    @declared_attr
    def provider(self):
        """ Account provider ('local' or eg. 'facebook')"""
        return sa.Column(sa.Unicode(80), default=u'local', nullable=False, index=True)

    @declared_attr
    def email(self):
        """ E-mail for user """
        return sa.Column(sa.Unicode(100), nullable=True, unique=True)

    @declared_attr
    def status(self):
        """ Status of user """
        return sa.Column(sa.Integer())

    @declared_attr
    def security_code(self):
        """ Security code user, can be used for API calls or password reset """
        return sa.Column(sa.Unicode(256), nullable=True)

    @declared_attr
    def last_login_date(self):
        """ Date of user's last login """
        return sa.Column(
            sa.TIMESTAMP(timezone=False)
            , default=sa.func.now()
            , server_default=sa.func.now()
            , nullable=False
        )

    @declared_attr
    def registered_date(self):
        """ Date of user's registration """
        return sa.Column(
            sa.TIMESTAMP(timezone=False)
            , default=sa.sql.func.now()
            , server_default=sa.func.now()
            , nullable=False
        )

    @declared_attr
    def salt(self):
        """ Password salt for user """
        return sa.Column(sa.Unicode(256), nullable=True)

    @declared_attr
    def _password(self):
        """ Password hash for user object """
        return sa.Column('password', sa.Unicode(256), nullable=True)

    @hybrid_property
    def password(self):
        return self._password

    @password.setter
    def password(self, value):
        self._set_password(value)

    @declared_attr
    def activation_id(self):
        return sa.Column(
            sa.Integer,
            sa.ForeignKey('%s.id' % ActivationMixin.__tablename__)
        )

    @declared_attr
    def activation(self):
        return sa.orm.relationship(
            'Activation',
            backref='user'
        )

    @property
    def is_activated(self):
        return self.activation_id == None

    def _set_password(self, raw_password):
        self._password = self._hash_password(raw_password)

    def _hash_password(self, password):
        if not self.salt:
            self.salt = generate_random_string(24)

        return unicode(crypt.encode(password + self.salt))

    def gravatar_url(self, default='mm'):
        """ returns user gravatar url """
        # construct the url
        h = hashlib.md5(self.email.encode('utf8').lower()).hexdigest()
        base_url = "https://secure.gravatar.com/avatar/%s?%s"
        gravatar_url = base_url % (h, urllib.urlencode({'d': default}))

        return gravatar_url

    @classmethod
    def generate_random_password(cls, chars=12):
        """ generates random string of fixed length"""
        return generate_random_string(chars)


    @classmethod
    def get_by_email(cls, request, email):
        session = get_session(request)

        return session.query(cls).filter(
            and_(
                func.lower(cls.email) == email.lower(),
                cls.provider == u'local',
            )
        ).first()

    @classmethod
    def get_by_username(cls, request, username):
        session = get_session(request)

        return session.query(cls).filter(
            and_(
                func.lower(cls.username) == username.lower(),
                cls.provider == u'local',
            )
        ).first()

    @classmethod
    def get_by_openid(cls, request, openid, provider):
        session = get_session(request)

        return session.query(cls).filter(
            and_(
                cls.openid == openid,
                cls.provider == provider,
            )
        ).first()

    @classmethod
    def get_by_username_or_email(cls, request, username, email):
        session = get_session(request)

        return session.query(cls).filter(
            and_(
                or_(
                    func.lower(cls.username) == username.lower(),
                    cls.email == email
                ),
                cls.provider == u'local',
            )
        ).first()

    @classmethod
    def get_by_email_password(cls, request, email, password):
        user = cls.get_by_email(request, email)

        if user:
            valid = cls.validate_user(request, user, password)

            if valid:
                return user

    @classmethod
    def get_by_activation(cls, request, activation):
        session = get_session(request)
        user = session.query(cls).filter(cls.activation_id == activation.id).first()
        return user

    @classmethod
    def get_account(cls, request, username, password):
        user = cls.get_by_username(request, username)

        valid = cls.validate_user(user, password)

        if valid:
            return user

    @classmethod
    def validate_user(cls, user, password):
        if not user:
            return None

        if user.password == None:
            valid = False
        else:
            valid = crypt.check(user.password, password + user.salt)

        return valid

    def __repr__(self):
        display_name = self.openid and '%s:%i' % (self.provider, self.openid) \
                            or self.username
        return '<UserAccount: %s>' % display_name

    @property
    def __acl__(self):
        return [
                (Allow, 'useraccount:%s' % self.id, 'access_user')
        ]

class GroupMixin(BaseModel):
    """ base mixin for group object"""

    @declared_attr
    def name(self):
        return sa.Column(sa.Unicode(50), unique=True)

    @declared_attr
    def description(self):
        return sa.Column(sa.UnicodeText())

    @declared_attr
    def users(self):
        """ relationship for users belonging to this group"""
        return sa.orm.relationship(
            'User'
            , secondary=UserGroupMixin.__tablename__
#            , order_by='%s.user.user_name' % UserMixin.__tablename__
            , passive_deletes=True
            , passive_updates=True
            , backref=GroupMixin.__tablename__
        )

#    @declared_attr
#    def permissions(self):
#        """ permissions assigned to this group"""
#        return sa.orm.relationship('GroupPermission'
#            , backref='groups'
#            , cascade="all, delete-orphan"
#            , passive_deletes=True
#            , passive_updates=True
#        )

    def __repr__(self):
        return '<Group: %s>' % self.name

class UserGroupMixin(BaseModel):
    @declared_attr
    def group_id(self):
        return sa.Column(sa.Integer,
            sa.ForeignKey('%s.id' % GroupMixin.__tablename__)
        )

    @declared_attr
    def user_id(self):
        return sa.Column(
            sa.Integer
            , sa.ForeignKey('%s.id' % UserMixin.__tablename__,
                onupdate='CASCADE',
                ondelete='CASCADE'
            )
            , primary_key=True
        )

    def __repr__(self):
        return '<UserGroup: %s, %s>' % (self.group_name, self.user_id,)
