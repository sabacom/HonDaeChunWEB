from flask import Flask, render_template, redirect, url_for, request, make_response, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user 
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import create_engine, text
import re

app = Flask(__name__)

app.config['SECRET_KEY'] = 'SECRET_KEY'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///user.db' 

db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_message = None 

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, index=True)
    password = db.Column(db.String(80))
    is_admin = db.Column(db.Boolean, default=False)
    is_approved = db.Column(db.Boolean, default=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

login_manager.login_view = 'login'  


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main'))

    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username'].lower()).first()
        if user:
            if not user.is_approved:
                flash('계정이 아직 승인되지 않았습니다.', 'danger')
            elif check_password_hash(user.password, request.form['password']):
                remember = 'rememberMe' in request.form
                login_user(user, remember=remember)
                return redirect(url_for('main'))
            else:
                flash('아이디 또는 비밀번호가 올바르지 않습니다.', 'danger')
        else:
            flash('아이디 또는 비밀번호가 올바르지 않습니다.', 'danger')

    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('main'))

    if request.method == 'POST':
        username = request.form['username']
        
        if not re.match("^[a-z0-9]{5,20}$", username):
            flash('5~20자의 영문 소문자, 숫자만 사용 가능합니다.')
            return render_template('signup.html')

        if User.query.filter_by(username=username.lower()).first():
            flash('사용할 수 없는 아이디입니다.')
            return render_template('signup.html')
        
        hashed_password = generate_password_hash(request.form['password'], method='sha256')
        new_user = User(
            username=username,
            password=hashed_password,
        )
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('login'))

    return render_template('signup.html')

@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin():
    if not current_user.is_admin:
        return redirect(url_for('main'))
    
    if request.method == 'POST':
        user_id = request.form.get('user_id')
        action = request.form.get('action')
        user = User.query.get(user_id)
        if user:
            if action == 'approve':
                user.is_approved = True
            elif action == 'delete':
                db.session.delete(user)
            db.session.commit()

    users = User.query.all()
    return render_template('admin.html', users=users)

@app.route('/', methods=['GET', 'POST'])
@login_required
def main():
    username = current_user.username
    if request.method == 'POST':
        query = request.form.get('query')  
    else:
        query = request.args.get('query', '')  

    dark_mode = request.cookies.get('dark_mode', 'off')

    results = []
    db_creation_date = None

    engine = create_engine('sqlite:///DB.db')
    with engine.connect() as connection:
        stmt = text("SELECT created_at FROM db_info WHERE id = 1")
        db_creation_date = connection.execute(stmt).fetchone()[0]

        if query:
            stmt = text(
                "SELECT * FROM music_data WHERE "
                "유형 LIKE :query OR "
                "제목 LIKE :query OR "
                "채널명 LIKE :query OR "
                "전송자 LIKE :query OR "
                "유튜브id LIKE :query "
                "ORDER BY 최초전송일 ASC"
            )
            results = connection.execute(stmt, {"query": f"%{query}%"}).fetchall()

    response = make_response(render_template('index.html', username=username, results=results, db_creation_date=db_creation_date, dark_mode=dark_mode))
    response.set_cookie('dark_mode', dark_mode)
    return response

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)
