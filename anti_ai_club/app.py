from flask import Flask, render_template, redirect, url_for, request, session, flash, get_flashed_messages
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from authlib.integrations.flask_client import OAuth
from config import Config
import requests
import logging
import os
import base64
from authlib.integrations.base_client.errors import OAuthError
from flask_migrate import Migrate

app = Flask(__name__)
app.config.from_object(Config)
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
oauth = OAuth(app)


@app.route('/admin/management', methods=['GET', 'POST'])
@login_required
def admin_management():
    #if not current_user.is_admin:
     #   flash('You do not have permission to view this page.')
      #  return redirect(url_for('home'))

    if request.method == 'POST':
        if 'email' in request.form:
            email = request.form['email']
            user = User.query.filter_by(email=email).first()
            if user:
                user.is_admin = True
                db.session.commit()
                flash('Admin privileges granted.')
            else:
                flash('User not found.')
        elif 'user_id' in request.form:
            user_id = request.form.get('user_id')
            user = User.query.get(user_id)
            if user:
                user.is_admin = False
                db.session.commit()
                flash('Admin privileges revoked.')
            else:
                flash('User not found.')

    admins = User.query.filter_by(is_admin=True).all()
    app.logger.debug(f'Admins: {admins}')  # Debugging line
    return render_template('admin_management.html', admins=admins)

@app.route('/admin/add', methods=['POST'])
@login_required
def add_admin():
    if not current_user.is_admin:
        flash('You do not have permission to perform this action.')
        return redirect(url_for('home'))

    email = request.form.get('email')
    user = User.query.filter_by(email=email).first()
    
    if user:
        user.is_admin = True
        db.session.commit()
        flash('Admin privileges granted.')
        app.logger.debug(f'User {email} is now an admin.')
    else:
        flash('User not found.')
        app.logger.debug(f'User {email} not found in database.')
    
    return redirect(url_for('admin_management'))



@app.route('/admin/remove/<int:user_id>', methods=['POST'])
@login_required
def remove_admin(user_id):
    if not current_user.is_admin:
        flash('You do not have permission to perform this action.')
        return redirect(url_for('home'))

    user = User.query.get(user_id)
    if user:
        user.is_admin = False
        db.session.commit()
        flash('Admin privileges revoked.')
    else:
        flash('User not found.')

    return redirect(url_for('admin_management'))

# Database models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    name = db.Column(db.String(150))
    picture = db.Column(db.String(255))
    is_admin = db.Column(db.Boolean, default=False)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Float, nullable=False)
    description = db.Column(db.String(255), nullable=True)

# Google OAuth setup
google = oauth.register(
    name='google',
    client_id=Config.GOOGLE_CLIENT_ID,
    client_secret=Config.GOOGLE_CLIENT_SECRET,
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    access_token_url='https://oauth2.googleapis.com/token',
    access_token_params=None,
    refresh_token_url=None,
    redirect_uri='http://localhost:5000/login/authorized',
    client_kwargs={'scope': 'openid profile email'},
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration'
)

@app.route('/print-config')
def print_openid_config():
    try:
        response = requests.get('https://accounts.google.com/.well-known/openid-configuration')
        response.raise_for_status()
        return response.text
    except requests.RequestException as e:
        return f'Error fetching OpenID configuration: {e}'

@app.route('/print-jwks')
def print_jwks():
    try:
        response = requests.get('https://www.googleapis.com/oauth2/v3/certs')
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        return f'Error fetching JWKS: {e}'

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

@app.route('/users')
@login_required
def list_users():
    users = User.query.all()
    return render_template('list_users.html', users=users)

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login')
def login():
    nonce = base64.urlsafe_b64encode(os.urandom(16)).decode('utf-8')
    session['nonce'] = nonce
    redirect_uri = url_for('authorized', _external=True)
    return oauth.google.authorize_redirect(redirect_uri, nonce=nonce)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/login/authorized')
def authorized():
    try:
        token = google.authorize_access_token()
        if not token:
            error_reason = request.args.get('error')
            if error_reason == 'access_denied':
                return redirect(url_for('home'))

            return 'Access denied: reason={}'.format(error_reason or 'Unknown reason'), 400

        nonce = session.pop('nonce', None)
        if not nonce:
            return 'Nonce is missing or has expired', 400

        try:
            user_info = google.parse_id_token(token, nonce=nonce)
        except Exception as e:
            app.logger.error(f'Error parsing ID token: {e}')
            return f'Error parsing ID token: {e}', 400

        email = user_info.get('email')
        user = User.query.filter_by(email=email).first()
        if not user:
            user = User(
                email=email,
                name=user_info.get('name'),
                picture=user_info.get('picture')
            )
            db.session.add(user)
            db.session.commit()
        else:
            user.name = user_info.get('name')
            user.picture = user_info.get('picture')
            db.session.commit()

        login_user(user)
        return redirect(url_for('home'))

    except OAuthError as e:
        app.logger.error(f'OAuthError: {e}')
        return 'Login failed: {}'.format(e.error_description or e.error), 400

@app.route('/product/<int:product_id>')
@login_required
def product(product_id):
    product = Product.query.get(product_id)
    return render_template('product.html', product=product)

@app.route('/add_product', methods=['GET', 'POST'])
@login_required
def add_product():
    if request.method == 'POST':
        name = request.form.get('name')
        price = request.form.get('price')
        description = request.form.get('description')
        product = Product(name=name, price=float(price), description=description)
        db.session.add(product)
        db.session.commit()
        return redirect(url_for('home'))
    return render_template('add_product.html')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
