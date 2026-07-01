# Intentionally vulnerable for testing
import os

OPENAI_API_KEY = "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJK"
STRIPE_SECRET = "sk_live_abcdefghijklmnopqrstuvwxyz1234"
DATABASE_URL = "postgresql://admin:password123@db.example.com/mydb"
JWT_SECRET = "mysecret"
GITHUB_TOKEN = "ghp_abcdefghijklmnopqrstuvwxyz123456"

# This should be safe — env var reference
SAFE_KEY = os.environ.get("OPENAI_KEY")
