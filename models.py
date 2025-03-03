import psycopg2
from flask_bcrypt import Bcrypt
from flask_login import UserMixin
import os
from config import DATABASE_URL

bcrypt = Bcrypt()

# Conexão com o Banco de Dados
conn = psycopg2.connect(DATABASE_URL)
cursor = conn.cursor()

class Usuario(UserMixin):
    def __init__(self, id, nome, email, senha_hash=None):
        self.id = id
        self.nome = nome
        self.email = email
        self.senha_hash = senha_hash
