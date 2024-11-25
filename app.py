from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
import os
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime  # Import necessário

app = Flask(__name__)
app.secret_key = 'sua_chave_secreta_aqui'  # Necessário para mensagens flash, altere para algo seguro

# Configurações do Banco de Dados
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///betteryou.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Inicializar o Banco de Dados
db = SQLAlchemy(app)

# Modelo de Usuário
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)  # Guardaremos as senhas com hash
    date_of_birth = db.Column(db.Date, nullable=False)
    tasks = db.relationship('Task', backref='user', lazy=True)

# Modelo de Tarefa
class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    creation_date = db.Column(db.DateTime, default=datetime.utcnow)
    due_date = db.Column(db.DateTime, nullable=True)
    is_completed = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# Rota para processar a criação de conta
@app.route('/register', methods=['POST'])
def register():
    name = request.form.get('name')
    email = request.form.get('email')
    password = request.form.get('password')
    dob_str = request.form.get('dob')  # Data de nascimento como string

    # Converte a data de nascimento para um objeto date
    try:
        dob = datetime.strptime(dob_str, '%Y-%m-%d').date()
    except ValueError:
        flash('Invalid date format. Please use YYYY-MM-DD.', 'danger')
        return redirect(url_for('index'))

    # Verifica se o e-mail já está cadastrado
    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        flash('Email already registered. Please login instead.', 'warning')
        return redirect(url_for('index'))

    # Cria um novo usuário
    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
    new_user = User(name=name, email=email, password=hashed_password, date_of_birth=dob)

    # Adiciona ao banco de dados
    db.session.add(new_user)
    db.session.commit()
    flash('Account created successfully! Please login.', 'success')
    return redirect(url_for('login'))

# Rota para a página de criação de conta
@app.route('/')
def index():
    return render_template('index.html')

# Rota para a página de login
@app.route('/login')
def login():
    return render_template('login.html')

# Rota para a página de recuperação de senha
@app.route('/forgot-password')
def forgot_password():
    return render_template('forgot-password.html')

# Rota para processar o login
@app.route('/do-login', methods=['POST'])
def do_login():
    email = request.form.get('email')
    password = request.form.get('password')
    user = User.query.filter_by(email=email).first()
    if user and check_password_hash(user.password, password):
        flash('Login successful!', 'success')
        return redirect(url_for('list_tasks'))
    else:
        flash('Invalid email or password.', 'danger')
        return redirect(url_for('login'))

# Rota para processar o envio de recuperação de senha
@app.route('/send-recovery', methods=['POST'])
def send_recovery():
    email = request.form.get('email')
    flash('Password reset instructions sent!', 'info')
    return redirect(url_for('forgot_password'))

# Rotas para Gerenciamento de Tarefas
@app.route('/tasks', methods=['GET'])
def list_tasks():
    user_id = 1  # Substituir com o ID do usuário autenticado (mockado por enquanto)
    tasks = Task.query.filter_by(user_id=user_id).all()
    return render_template('list-tasks.html', tasks=tasks)

@app.route('/tasks/create', methods=['GET', 'POST'])
def create_task():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        due_date = request.form.get('due_date')
        if due_date:
            due_date = datetime.strptime(due_date, '%Y-%m-%d')
        user_id = 1  # Substituir com o ID do usuário autenticado
        new_task = Task(title=title, description=description, due_date=due_date, user_id=user_id)
        db.session.add(new_task)
        db.session.commit()
        flash('Task created successfully!', 'success')
        return redirect(url_for('list_tasks'))

    return render_template('create-task.html')

@app.route('/tasks/edit/<int:task_id>', methods=['GET', 'POST'])
def edit_task(task_id):
    task = Task.query.get_or_404(task_id)
    if request.method == 'POST':
        task.title = request.form['title']
        task.description = request.form['description']
        due_date = request.form.get('due_date')
        if due_date:
            task.due_date = datetime.strptime(due_date, '%Y-%m-%d')
        task.is_completed = 'is_completed' in request.form
        db.session.commit()
        flash('Task updated successfully!', 'success')
        return redirect(url_for('list_tasks'))

    return render_template('edit-task.html', task=task)

@app.route('/tasks/delete/<int:task_id>', methods=['POST'])
def delete_task(task_id):
    task = Task.query.get_or_404(task_id)
    db.session.delete(task)
    db.session.commit()
    flash('Task deleted successfully!', 'success')
    return redirect(url_for('list_tasks'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Cria as tabelas no banco de dados, caso não existam
    app.run(debug=True)
