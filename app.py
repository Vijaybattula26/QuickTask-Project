from flask import Flask, render_template, redirect, request, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from flask_bcrypt import Bcrypt
from datetime import datetime, date
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'  # Change this before production!
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///quicktask.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
bcrypt = Bcrypt(app)

# --- Models ---
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    tasks = db.relationship('Task', backref='owner', lazy=True)

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.String(200), nullable=False)
    due_date = db.Column(db.Date, nullable=True)
    priority = db.Column(db.String(10), nullable=False, default='Normal')  # High, Normal, Low
    done = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Routes ---

@app.route('/')
@login_required
def index():
    sort_by = request.args.get('sort', 'due')
    filter_status = request.args.get('filter', 'all')
    search_query = request.args.get('search', '')

    tasks_query = Task.query.filter_by(owner=current_user)

    if filter_status == 'completed':
        tasks_query = tasks_query.filter_by(done=True)
    elif filter_status == 'pending':
        tasks_query = tasks_query.filter_by(done=False)

    if search_query:
        tasks_query = tasks_query.filter(Task.description.ilike(f'%{search_query}%'))

    if sort_by == 'priority':
        priority_order = {'High': 1, 'Normal': 2, 'Low': 3}
        tasks = sorted(tasks_query.all(), key=lambda t: priority_order.get(t.priority, 2))
    else:
        tasks = sorted(tasks_query.all(), key=lambda t: (t.due_date or datetime.max.date()))

    # Analytics
    completed_tasks = Task.query.filter_by(owner=current_user, done=True).count()
    overdue_tasks = Task.query.filter(
        Task.user_id == current_user.id,
        Task.due_date < date.today(),
        Task.done == False
    ).count()
    daily_completed = Task.query.filter(
        Task.user_id == current_user.id,
        Task.done == True,
        Task.due_date == date.today()
    ).count()

    return render_template(
        'index.html', tasks=tasks, sort_by=sort_by, filter_status=filter_status,
        search_query=search_query,
        completed_tasks=completed_tasks,
        overdue_tasks=overdue_tasks,
        daily_completed=daily_completed
    )

@app.route('/add', methods=['POST'])
@login_required
def add():
    description = request.form.get('description')
    due_date = request.form.get('due_date')
    priority = request.form.get('priority') or 'Normal'

    if not description:
        flash('Task description cannot be empty.', 'danger')
        return redirect(url_for('index'))

    due = None
    if due_date:
        try:
            due = datetime.strptime(due_date, '%Y-%m-%d').date()
        except ValueError:
            flash('Invalid date format.', 'warning')
            return redirect(url_for('index'))

    new_task = Task(description=description, due_date=due, priority=priority, owner=current_user)
    db.session.add(new_task)
    db.session.commit()
    flash('Task added successfully!', 'success')
    return redirect(url_for('index'))

@app.route('/complete/<int:task_id>', methods=['POST'])
@login_required
def complete(task_id):
    task = Task.query.get_or_404(task_id)
    if task.owner != current_user:
        return jsonify({'success': False, 'message': 'Unauthorized action.'}), 403
    task.done = not task.done
    db.session.commit()
    return jsonify({'success': True, 'completed': task.done})

@app.route('/delete/<int:task_id>', methods=['POST'])
@login_required
def delete(task_id):
    task = Task.query.get_or_404(task_id)
    if task.owner != current_user:
        return jsonify({'success': False, 'message': 'Unauthorized action.'}), 403
    db.session.delete(task)
    db.session.commit()
    return jsonify({'success': True})

@app.route('/edit/<int:task_id>', methods=['GET', 'POST'])
@login_required
def edit(task_id):
    task = Task.query.get_or_404(task_id)
    if task.owner != current_user:
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('index'))

    if request.method == 'POST':
        description = request.form.get('description')
        due_date = request.form.get('due_date')
        priority = request.form.get('priority') or 'Normal'

        if not description:
            flash('Task description cannot be empty.', 'danger')
            return redirect(url_for('edit', task_id=task_id))

        due = None
        if due_date:
            try:
                due = datetime.strptime(due_date, '%Y-%m-%d').date()
            except ValueError:
                flash('Invalid date format.', 'warning')
                return redirect(url_for('edit', task_id=task_id))

        task.description = description
        task.due_date = due
        task.priority = priority

        db.session.commit()
        flash('Task updated successfully!', 'success')
        return redirect(url_for('index'))

    return render_template('edit_task.html', task=task)

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
            flash('Invalid credentials.', 'danger')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'warning')
            return redirect(url_for('register'))
        user = User(username=username)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully.', 'info')
    return redirect(url_for('login'))

# --- Run app ---
if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # create tables if they don't exist
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
