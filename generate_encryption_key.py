"""Run once. Paste output into .env as DATA_ENCRYPTION_KEY=..."""
from cryptography.fernet import Fernet
print('DATA_ENCRYPTION_KEY=' + Fernet.generate_key().decode())
