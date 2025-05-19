from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime

app = Flask(__name__)

# Use secret key from environment variable or fallback to this fixed one
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', '5cbcc28a9f9b3c1b30025c107be06486')

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///instance/quicktask.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(150), nullable=False)
    tasks = db.relationship('Task', backref='owner', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.String(255), nullable=False)
    due_date = db.Column(db.Date, nullable=True)
    priority = db.Column(db.String(10), nullable=False, default='Normal')
    done = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
@login_required
def index():
    search_query = request.args.get('search', '')
    filter_status = request.args.get('filter', 'all')
    sort_by = request.args.get('sort', 'due')

    tasks_query = Task.query.filter_by(user_id=current_user.id)

    if search_query:
        tasks_query = tasks_query.filter(Task.description.ilike(f'%{search_query}%'))

    if filter_status == 'pending':
        tasks_query = tasks_query.filter_by(done=False)
    elif filter_status == 'completed':
        tasks_query = tasks_query.filter_by(done=True)

    if sort_by == 'priority':
        priority_order = {'High': 1, 'Normal': 2, 'Low': 3}
        tasks = sorted(tasks_query.all(), key=lambda t: priority_order.get(t.priority, 4))
    else:
        # Sort by due date
        tasks = tasks_query.order_by(Task.due_date.asc().nulls_last()).all()

    return render_template('index.html', tasks=tasks, search_query=search_query, filter_status=filter_status, sort_by=sort_by)

@app.route('/add', methods=['POST'])
@login_required
def add():
    description = request.form.get('description')
    due_date_str = request.form.get('due_date')
    priority = request.form.get('priority', 'Normal')

    due_date = None
    if due_date_str:
        try:
            due_date = datetime.strptime(due_date_str, '%Y-%m-%d').date()
        except ValueError:
            flash('Invalid due date format', 'danger')
            return redirect(url_for('index'))

    new_task = Task(description=description, due_date=due_date, priority=priority, user_id=current_user.id)
    db.session.add(new_task)
    db.session.commit()
    flash('Task added successfully.', 'success')
    return redirect(url_for('index'))

@app.route('/toggle/<int:task_id>', methods=['POST'])
@login_required
def toggle(task_id):
    task = Task.query.filter_by(id=task_id, user_id=current_user.id).first_or_404()
    task.done = not task.done
    db.session.commit()
    return jsonify({'success': True, 'done': task.done})

@app.route('/delete/<int:task_id>', methods=['POST'])
@login_required
def delete(task_id):
    task = Task.query.filter_by(id=task_id, user_id=current_user.id).first_or_404()
    db.session.delete(task)
    db.session.commit()
    flash('Task deleted successfully.', 'success')
    return jsonify({'success': True})

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            flash('Logged in successfully.', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password.', 'danger')

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('register'))

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists.', 'danger')
            return redirect(url_for('register'))

        new_user = User(username=username)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful. Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully.', 'success')
    return redirect(url_for('login'))

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
