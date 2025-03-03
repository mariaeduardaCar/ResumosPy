from transformers import pipeline
import sqlite3
from datetime import datetime
from flask import Flask, request, jsonify, render_template, redirect, url_for, session
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
import os
from werkzeug.security import generate_password_hash, check_password_hash
from config import SECRET_KEY

# Carrega as variáveis do arquivo .env
load_dotenv()

app = Flask(__name__)

app.config["SECRET_KEY"] = SECRET_KEY

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")

# Configuração do Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)

# Configuração do OAuth
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    authorize_url='https://accounts.google.com/o/oauth2/v2/auth',
    access_token_url='https://oauth2.googleapis.com/token',
    client_kwargs={
        'scope': 'openid email profile',
        'token_endpoint_auth_method': 'client_secret_post',
        'userinfo_endpoint': 'https://openidconnect.googleapis.com/v1/userinfo',
    },
    jwks_uri='https://www.googleapis.com/oauth2/v3/certs'
)

# Banco de dados SQLite
def init_db():
    conn = sqlite3.connect('resumos.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS usuario (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            senha_hash TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS resumos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario_id INTEGER,
            texto_original TEXT NOT NULL,
            resumo TEXT NOT NULL,
            data TEXT NOT NULL,
            FOREIGN KEY(usuario_id) REFERENCES usuario(id)
        )
    ''')
    conn.commit()
    conn.close()

# Modelo de usuário
class Usuario(UserMixin):
    def __init__(self, id, nome, email):
        self.id = id
        self.nome = nome
        self.email = email

@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect('resumos.db')
    cursor = conn.cursor()
    cursor.execute("SELECT id, nome, email FROM usuario WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    conn.close()
    if user:
        print(f"Carregando usuário: {user}")  # Para debug
    return Usuario(*user) if user else None


@app.route('/cadastro', methods=['POST'])
def cadastro():
    dados = request.get_json() or request.form
    nome = dados.get('nome')
    email = dados.get('email')
    senha_hash = dados.get('senha_hash')

    if not nome or not email or not senha_hash:
        return jsonify({"erro": "Todos os campos são obrigatórios"}), 400

    senha_hash = generate_password_hash(senha_hash)
    conn = sqlite3.connect('resumos.db')
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM usuario WHERE email = ?", (email,))
    if cursor.fetchone():
        conn.close()
        return jsonify({"erro": "E-mail já cadastrado"}), 400

    cursor.execute("INSERT INTO usuario (nome, email, senha_hash) VALUES (?, ?, ?)", (nome, email, senha_hash))
    conn.commit()
    conn.close()

    return jsonify({"mensagem": "Usuário cadastrado com sucesso!"}), 201

@app.route('/login', methods=['POST'])
def login():
    dados = request.json
    email = dados.get('email')
    senha_hash = dados.get('senha_hash')

    conn = sqlite3.connect('resumos.db')
    cursor = conn.cursor()
    cursor.execute("SELECT id, nome, senha_hash FROM usuario WHERE email = ?", (email,))
    usuario = cursor.fetchone()
    conn.close()

    if usuario and check_password_hash(usuario[2], senha_hash):
        login_user(Usuario(usuario[0], usuario[1], email))
        return jsonify({"mensagem": f"Bem-vindo, {usuario[1]}!"})

    return jsonify({"erro": "Credenciais inválidas"}), 401

@app.route('/perfil')
@login_required
def perfil():
    return jsonify({"nome": current_user.nome, "email": current_user.email})



@app.route('/login/google')
def login_google():
    return google.authorize_redirect(url_for('google_authorized', _external=True))

@app.route('/login/google/callback')
def google_authorized():
    token = google.authorize_access_token()
    if not token:
        return jsonify({"erro": "Falha no login com o Google."}), 400

    user_info = google.get('https://www.googleapis.com/oauth2/v1/userinfo').json()

    conn = sqlite3.connect('resumos.db')
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM usuario WHERE email = ?", (user_info['email'],))
    usuario = cursor.fetchone()

    if not usuario:
        cursor.execute("INSERT INTO usuario (nome, email) VALUES (?, ?)", (user_info['name'], user_info['email']))
        conn.commit()
        usuario_id = cursor.lastrowid
    else:
        usuario_id = usuario[0]

    conn.close()
    login_user(Usuario(usuario_id, user_info['name'], user_info['email']))
    return redirect(url_for('ia'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return jsonify({"mensagem": "Logout realizado com sucesso!"})

# Pipeline de resumo
summarizer = pipeline("summarization", model="sshleifer/distilbart-cnn-12-6", device=-1)


@app.route('/')
def home():
    return render_template('index.html')

@app.route('/ia', methods=['GET', 'POST'])
@login_required
def ia():
    if request.method == 'POST':
        texto_original = request.form['texto']
        resumo = summarizer(texto_original, max_length=130, min_length=30, do_sample=False)[0]['summary_text']

        conn = sqlite3.connect('resumos.db')
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO resumos (usuario_id, texto_original, resumo, data) 
            VALUES (?, ?, ?, ?)
        ''', (current_user.id, texto_original, resumo, datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
        conn.commit()
        conn.close()

        return redirect(url_for('historico'))
    return render_template('ia.html')

@app.route('/historico')
@login_required
def historico():
    print(f"Usuário logado: {current_user.id}")  # Exibe o ID do usuário no terminal
    conn = sqlite3.connect('resumos.db')
    cursor = conn.cursor()
    cursor.execute('''
        SELECT texto_original, resumo, data 
        FROM resumos 
        WHERE usuario_id = ? 
        ORDER BY data DESC
    ''', (current_user.id,))
    resumos = cursor.fetchall()
    conn.close()
    return render_template('historico.html', resumos=resumos)


if __name__ == '__main__':
    init_db()
    app.run(debug=True)
