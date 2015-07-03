import logging

from flask import Flask, jsonify, redirect, render_template, request, url_for
from flask.ext.login import LoginManager, current_user, login_user, login_required, logout_user
from flask.ext.sqlalchemy import SQLAlchemy
from flask_oauthlib.provider import OAuth2Provider
from sqlalchemy import Column, DateTime, Integer, String, Boolean
from sqlalchemy.orm import relationship, synonym
from werkzeug.security import generate_password_hash, check_password_hash

"""Forms to render HTML input & validate request data."""
from wtforms import Form, PasswordField, StringField
from wtforms.validators import required
from datetime import datetime, timedelta

app = Flask(__name__)
oauth = OAuth2Provider(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///op.db'
app.config['SECRET_KEY'] = 'enydM2ANhdcoKwdVa0jWvEsbPFuQpMjf'

db = SQLAlchemy(app)

logger1 = logging.getLogger('flask_oauthlib')
logger2 = logging.getLogger('oauthlib')
logger1.setLevel(logging.DEBUG)
logger2.setLevel(logging.DEBUG)
file_handler1 = logging.FileHandler('flask_oauthlib.log')
file_handler2 = logging.FileHandler('oauthlib.log')
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s = %(message)s')
file_handler1.setFormatter(formatter)
file_handler2.setFormatter(formatter)

logger1.addHandler(file_handler1)
logger2.addHandler(file_handler2)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to see your appointments.'


@login_manager.user_loader
def load_user(user_id):
    """Hook for Flask-Login to load a User instance from a user ID."""
    return User.query.get(user_id)


class LoginForm(Form):
    """Render HTML input for user login form.

    Authentication (i.e. password verification) happens in the view function.
    """
    username = StringField('Username', [required()])
    password = PasswordField('Password', [required()])


class Client(db.Model):
    __tablename__ = 'client'
    # human readable name, not required
    name = db.Column(db.Unicode(40))

    # human readable description, not required
    description = db.Column(db.Unicode(400))

    # creator of the client, not required
    user_id = db.Column(db.ForeignKey('user.id'))
    # required if you need to support client credential
    user = relationship('User')

    client_id = db.Column(db.Unicode(40), primary_key=True)
    client_secret = db.Column(db.Unicode(55), unique=True, index=True, nullable=False)

    # public or confidential
    is_confidential = db.Column(db.Boolean)

    _redirect_uris = db.Column(db.UnicodeText)
    _default_scopes = db.Column(db.UnicodeText)

    @property
    def client_type(self):
        if self.is_confidential:
            return 'confidential'
        return 'public'

    @property
    def redirect_uris(self):
        if self._redirect_uris:
            return self._redirect_uris.split()
        return []

    @property
    def default_redirect_uri(self):
        return self.redirect_uris[0]

    @property
    def default_scopes(self):
        if self._default_scopes:
            return self._default_scopes.split()
        return []


class User(db.Model):
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True)
    name = Column('name', String(200))
    email = Column(String(100), unique=True, nullable=False)
    active = Column(Boolean, default=True)
    _password = Column('password', String(100))

    created = Column(DateTime, default=datetime.now)
    modified = Column(DateTime, default=datetime.now, onupdate=datetime.now)

    def _get_password(self):
        return self._password

    def _set_password(self, password):
        if password:
            password = password.strip()
        self._password = generate_password_hash(password)

    password_descriptor = property(_get_password, _set_password)
    password = synonym('_password', descriptor=password_descriptor)

    def check_password(self, password):
        if self.password is None:
            return False
        password = password.strip()
        if not password:
            return False
        return check_password_hash(self.password, password)

    @classmethod
    def authenticate(cls, query, email, password):
        email = email.strip().lower()
        user = query(cls).filter(cls.email == email).first()
        if user is None:
            return None, False
        if not user.active:
            return user, False
        return user, user.check_password(password)

    def get_id(self):
        return str(self.id)

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def is_authenticated(self):
        return True

    def __repr__(self):
        return u'<{self.__class__.__name__}: {self.id}>'.format(self=self)


class Grant(db.Model):
    __tablename__ = 'grant'

    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'))
    user = relationship('User')

    client_id = db.Column(db.Unicode(40), db.ForeignKey('client.client_id'), nullable=False, )
    client = relationship('Client')

    code = db.Column(db.Unicode(255), index=True, nullable=False)

    redirect_uri = db.Column(db.Unicode(255))
    expires = db.Column(db.DateTime)

    _scopes = db.Column(db.UnicodeText)

    def delete(self):
        db.session.delete(self)
        db.session.commit()
        return self

    @property
    def scopes(self):
        if self._scopes:
            return self._scopes.split()
        return []


class Token(db.Model):
    __tablename__ = 'token'

    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(
        db.Unicode(40), db.ForeignKey('client.client_id'),
        nullable=False,
    )
    client = relationship('Client')

    user_id = db.Column(
        db.Integer, db.ForeignKey('user.id')
    )
    user = relationship('User')

    # currently only bearer is supported
    token_type = db.Column(db.Unicode(40))

    access_token = db.Column(db.Unicode(255), unique=True)
    refresh_token = db.Column(db.Unicode(255), unique=True)
    expires = db.Column(db.DateTime)
    _scopes = db.Column(db.UnicodeText)

    @property
    def scopes(self):
        if self._scopes:
            return self._scopes.split()
        return []

    def _get_scope(self):
        if self._scopes:
            return self._scopes.split()
        return []

    def _set_scope(self, scope):
        if scope:
            scope = scope
        self._scopes = scope

    scope_descriptor = property(_get_scope, _set_scope)
    scope = synonym('_scopes', descriptor=scope_descriptor)


@oauth.clientgetter
def load_client(client_id):
    # return Client.query.filter_by(client_id=client_id).first()
    return Client.query.filter_by(client_id=client_id).first()


@oauth.grantgetter
def load_grant(client_id, code):
    return Grant.query.filter_by(client_id=client_id, code=code).first()


def get_current_user():
    return User.query.get(current_user.id)


@oauth.grantsetter
def save_grant(client_id, code, request, *args, **kwargs):
    # decide the expires time yourself
    expires = datetime.utcnow() + timedelta(seconds=100)
    grant = Grant(
        client_id=client_id,
        code=code['code'],
        redirect_uri=request.redirect_uri,
        _scopes=' '.join(request.scopes),
        user=get_current_user(),
        expires=expires
    )
    db.session.add(grant)
    db.session.commit()
    return grant


@oauth.tokengetter
def load_token(access_token=None, refresh_token=None):
    if access_token:
        return Token.query.filter_by(access_token=access_token).first()
    elif refresh_token:
        return Token.query.filter_by(refresh_token=refresh_token).first()


@oauth.tokensetter
def save_token(token, request, *args, **kwargs):
    # toks = Token.query.filter_by(client_id=request.client.client_id, user_id=request.user.id).all()
    # make sure that every client has only one token connected to a user
    # for tok in toks:
    #     db.session.delete(tok)

    expires_in = token.pop('expires_in')
    expires = datetime.utcnow() + timedelta(seconds=expires_in)

    tok = Token(**token)
    tok.expires = expires
    tok.client_id = request.client.client_id

    if not request.user:
        tok.user_id = current_user.id
    else:
        tok.user_id = request.user.id

    db.session.add(tok)
    db.session.commit()
    return tok


@oauth.usergetter
def get_user(username, password, *args, **kwargs):
    user = User.query.filter_by(email=username).first()
    if user.check_password(password):
        return user
    return None


@app.route('/oauth/authorize', methods=['GET', 'POST'])
@login_required
@oauth.authorize_handler
def authorize(*args, **kwargs):
    if request.method == 'GET':
        client_id = kwargs.get('client_id')
        client = Client.query.filter_by(client_id=client_id).first()
        kwargs['client'] = client
        return render_template('oauthorize.html', **kwargs)

    confirm = request.form.get('confirm', 'no')
    return confirm == 'yes'


@app.route('/oauth/token', methods=['GET', 'POST'])
@oauth.token_handler
def access_token():
    return None


@app.route('/api/me')
@oauth.require_oauth('email')
def me():
    user = request.oauth.user
    return jsonify(email=user.email, username=user.name)


@app.route('/api/user/<email>')
@oauth.require_oauth('email')
def user(email):
    user = User.query.filter_by(email=email).first()
    return jsonify(email=user.email, username=user.name)


@app.route('/api/sample')
@oauth.require_oauth('email')
def sample():
    email = request.oauth.user.email
    return jsonify({'hello': email})


@app.route('/login/', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated():
        return redirect(url_for('index'))
    form = LoginForm(request.form)
    error = None
    if request.method == 'POST' and form.validate():
        email = form.username.data.lower().strip()
        password = form.password.data.lower().strip()
        user, authenticated = User.authenticate(db.session.query, email, password)
        if authenticated:
            login_user(user)
            return redirect(request.args.get("next") or url_for("authorize"))
        else:
            error = 'Incorrect username or password. Try again.'
    return render_template('user/login.html', form=form, error=error)


@app.route('/logout/')
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/')
def index():
    return 'Hello, %s' % (current_user.name if current_user else 'world')


if __name__ == '__main__':
    # from datetime import timedelta

    from sqlalchemy import create_engine
    # from sqlalchemy.orm import sessionmaker

    engine = create_engine('sqlite:///op.db', echo=True)
    db.Model.metadata.create_all(engine)

    user = User(name='Pyunghyuk Yoo', email='yoophi@gmail.com', password='secret')
    db.session.add(user)
    db.session.commit()
