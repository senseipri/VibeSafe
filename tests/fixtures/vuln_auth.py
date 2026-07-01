from fastapi import FastAPI
app = FastAPI()

@app.get("/api/admin/users")      # CRITICAL — no auth
def list_all_users(): return []

@app.delete("/api/admin/user/{id}")  # CRITICAL — no auth
def delete_user(id: int): pass

@app.get("/api/public/info")     # OK — public
def public_info(): return {}
