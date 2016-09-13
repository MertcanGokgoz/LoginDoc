import os.path
import flask
import sqlite3
import flask_login
import zipfile
from uuid import uuid4
from flask import session
from flask_wtf import RecaptchaField, Form, CsrfProtect
from werkzeug.utils import secure_filename

db = sqlite3.connect('/home/mertcan/PycharmProjects/Login/logindoc.db', check_same_thread=False)
c = db.cursor()

# Main App Conf
application = flask.Flask(__name__)
application.config.from_object(__name__)
os.path.dirname(os.path.abspath(__file__))
application.view_functions['docs'] = flask_login.login_required(application.send_static_file)
application.jinja_env.autoescape = True | False

CsrfProtect(application)

application.config.update(
    SECRET_KEY=os.urandom(32),
    SEND_FILE_MAX_AGE_DEFAULT=43200,
    SESSION_COOKIE_NAME="LoginDoc",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=False,
    SESSION_KEY_PREFIX="login_doc:",
    RECAPTCHA_OPTIONS={'theme': 'dark'},
    RECAPTCHA_PUBLIC_KEY="6Le61ykTAAAAACmvsDyHdzYHei_xkS4fNjEYFgmO",
    RECAPTCHA_PRIVATE_KEY="",
    UPLOAD_FOLDER='/tmp/'
)

# Flask Login Method
login_manager = flask_login.LoginManager()
login_manager.init_app(application)
login_manager.session_protection = "strong"

# Users
users = {'Admin': {'login_password': '1234'}}


class LoginForm(Form):
    recap = RecaptchaField()


class User(flask_login.UserMixin):
    pass


@login_manager.user_loader
def user_loader(email):
    if email not in users:
        return

    user = User()
    user.id = email
    return user


# User request for base system
@login_manager.request_loader
def request_loader(request):
    email = request.form.get('login_username')
    if email not in users:
        return

    user = User()
    user.id = email
    users.is_authenticated = request.form['login_password'] == users[email]['login_password']

    return user


# not found page handle
@application.errorhandler(404)
def page_not_found(e):
    return flask.render_template('404.html'), 404


# main page to panel
@application.route('/', methods=['GET'])
def main_page():
    if not session.get('logged_in'):
        return flask.redirect(flask.url_for('login'))
    else:
        return flask.redirect(flask.url_for('panel'))


# main page template def for dashboard
@application.route('/Main_page', methods=['GET'])
@flask_login.login_required
def panel():
    return flask.render_template('panel.html')


# login area handle
@application.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm(flask.request.form)
    if flask.request.method == 'GET':
        return flask.render_template('login.html', form=form)

    if flask.request.method == 'POST':
        if form.validate_on_submit():
            token = session.pop('auth_token', None)
            if not token or token != flask.request.form.get('auth_token'):
                return flask.redirect(flask.url_for('page_not_found'))

            email = flask.request.form['login_username']
            if flask.request.form['login_password'] == users[email]['login_password']:
                user = User()
                user.id = email
                flask_login.login_user(user)
                session['logged_in'] = True
                return flask.redirect(flask.url_for('panel'))
            else:
                return flask.redirect(flask.url_for('login'))
        else:
            return 'ERROR'  # document viewer handle for files and other


@application.route('/docs/<path:filename>')
@flask_login.login_required
def protected(filename):
    try:
        filename = flask.safe_join('docs', filename)

        with open(filename, 'rb') as fd:
            content = fd.read()
        extension = os.path.splitext(filename)[1][1:]
        if extension == "css":
            response = flask.make_response(content)
            response.headers['Content-Type'] = 'text/css; charset=utf-8'
            return response
        elif extension == "js":
            response = flask.make_response(content)
            response.headers['Content-Type'] = 'application/javascript; charset=utf-8'
            return response
        else:
            response = flask.make_response(content)
            response.headers['Content-Type'] = 'text/html; charset=utf-8'
            return response
    except Exception as e:
        return flask.render_template('404.html', error=str(e))


@application.route('/list/', methods=['GET'])
@flask_login.login_required
def list():
    if not session.get('logged_in'):
        return flask.redirect(flask.url_for('login'))
    else:
        c.execute("SELECT * FROM logindoc")
        doclist = c.fetchall()
        return flask.render_template('documentlist.html', doclist=doclist)


@application.route('/list/delete/<id>/', methods=['GET'])
@flask_login.login_required
def delete_post_item(id):
    c.execute("DELETE FROM logindoc WHERE id=?", id)
    db.commit()
    return "Deleted Item"


@application.route('/document/add', methods=['GET', 'POST'])
@flask_login.login_required
def upload():
    if flask.request.method == 'GET':
        return flask.render_template('upload.html')

    allowed_ext = set(['zip', 'rar'])
    if flask.request.method == 'POST':
        file = flask.request.files['file']
        file_path = os.path.splitext(file.filename)[0]
        filename = secure_filename(file.filename)
        title = flask.request.form['title']
        description = flask.request.form['description']
        if filename.rsplit('.', 1)[1] in allowed_ext:
            if os.path.isfile("/tmp/" + filename):
                return "Not Allowed", 500
            else:
                file.save(os.path.join(application.config['UPLOAD_FOLDER'], filename))
                c.execute("INSERT INTO logindoc VALUES (NULL,?,?,?)",
                          (title, description, '/docs/' + file_path + '/index.html'))
                db.commit()
                unzip(file, os.getcwd() + '/docs/')
                return flask.redirect(flask.url_for('list', filename=filename))
        else:
            return '<script type="text/javascript">alert(Fatal ERROR)</script>'


@application.route('/tmp/<filename>')
def uploaded_files(filename):
    return flask.send_from_directory(application.config['UPLOAD_FOLDER'], filename)


@application.route('/logout', methods=['GET'])
@flask_login.login_required
def logout():
    if session.get('logged_in') is False:
        return flask.redirect(flask.url_for('main_page'))
    else:
        session['logged_in'] = False
        flask_login.logout_user()
        return flask.redirect(flask.url_for('main_page'))


@login_manager.unauthorized_handler
def unauthorized_handler():
    return flask.render_template('blocked.html')


# generate session csrf token
def generate_auth_token():
    if 'auth_token' not in session:
        session['auth_token'] = str(uuid4())
    return session['auth_token']


# unzip document file
def unzip(source_filename, dest_dir):
    with zipfile.ZipFile(source_filename) as zf:
        zf.extractall(dest_dir)


# page template for csrf token
application.jinja_env.globals['auth_token'] = generate_auth_token

if __name__ == '__main__':
    application.run(host='127.0.0.1', debug=True)
