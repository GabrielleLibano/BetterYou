 
deve ter: Flask==2.0.1
para instalar: pip install -r requirements.md
executar: python app.py

pip install Flask-SQLAlchemy
pip install werkzeug





from app import db
db.create_all()

- Implementar o Registro de Usuário com Armazenamento no Banco de Dados

Atualize a rota `/register` para salvar os dados do usuário no banco de dados. Para a segurança das senhas, usaremos a biblioteca `werkzeug` para criar hashes de senha.