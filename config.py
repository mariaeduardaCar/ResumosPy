import os
from dotenv import load_dotenv
import psycopg2
load_dotenv()  # Carrega variáveis do .env

DATABASE_URL = "postgres://postgres:Fe151206@localhost:5432/filmes"
SECRET_KEY = "12345"

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")


