import os.path
import flask
import flask_login
from uuid import uuid4
from flask import session
from flask_wtf import RecaptchaField, Form

# Main App Conf
application = flask.Flask(__name__)
application.config.from_object(__name__)
application.view_functions['docs'] = flask_login.login_required(application.send_static_file)
application.jinja_env.autoescape = True | False

application.config.update(
    SEND_FILE_MAX_AGE_DEFAULT=43200,
    SESSION_COOKIE_NAME="LoginDoc",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=False,
    SECRET_KEY=os.urandom(32),
    RECAPTCHA_OPTIONS={'theme': 'dark'},
    RECAPTCHA_PUBLIC_KEY="6Le61ykTAAAAACmvsDyHdzYHei_xkS4fNjEYFgmO",
    RECAPTCHA_PRIVATE_KEY=""
)

# Flask Login Method
login_manager = flask_login.LoginManager()
login_manager.init_app(application)
login_manager.session_protection = "strong"

# Users
users = {'Admin': {'login_password': 'pa$$word'}}


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


@login_manager.request_loader
def request_loader(request):
    email = request.form.get('login_username')
    if email not in users:
        return

    user = User()
    user.id = email
    users.is_authenticated = request.form['login_password'] == users[email]['login_password']

    return user


@application.errorhandler(404)
def page_not_found(e):
    return flask.render_template('404.html'), 404


@application.route('/', methods=['GET'])
def mainpage():
    if not session.get('logged_in'):
        return flask.redirect(flask.url_for('login'))
    else:
        return flask.redirect(flask.url_for('protected', filename="index.html"))


@application.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm(flask.request.form)
    if flask.request.method == 'GET':
        return flask.render_template('login.html', form=form)

    if flask.request.method == 'POST':
        if form.validate_on_submit():
            token = session.pop('_csrf_token', None)
            if not token or token != flask.request.form.get('_csrf_token'):
                flask.abort(403)
        email = flask.request.form['login_username']
        if flask.request.form['login_password'] == users[email]['login_password']:
            user = User()
            user.id = email
            flask_login.login_user(user)
            session['logged_in'] = True
            return flask.redirect(flask.url_for('protected', filename="index.html"))
        else:
            return flask.redirect(flask.url_for('mainpage'))
    else:
        return "Need Captcha."


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


@application.route('/logout')
def logout():
    if session.get('logged_in') is False:
        return flask.redirect(flask.url_for('mainpage'))
    else:
        session['logged_in'] = False
        flask_login.logout_user()
        return flask.redirect(flask.url_for('mainpage'))


@login_manager.unauthorized_handler
def unauthorized_handler():
    return flask.render_template('blocked.html')


def generate_csrf_token():
    if '_csrf_token' not in session:
        session['_csrf_token'] = str(uuid4())
    return session['_csrf_token']


application.jinja_env.globals['csrf_token'] = generate_csrf_token

if __name__ == '__main__':
    application.run(host='127.0.0.1')
