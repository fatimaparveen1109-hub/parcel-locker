import os, hmac, hashlib, secrets, time
import jwt
from fastapi import FastAPI, HTTPException, Request, Response, Depends
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from supabase import create_client

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sb = create_client(os.environ["SUPABASE_URL"], os.environ["SUPABASE_SERVICE_KEY"])
JWT_SECRET = os.environ["JWT_SECRET"]
app = FastAPI()

def hash_pw(pw, salt=None):
    salt = salt or secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 200000).hex()
    return f"{salt}${h}"

def check_pw(pw, stored):
    salt, _ = stored.split("$")
    return hmac.compare_digest(hash_pw(pw, salt), stored)

def audit(action, actor_id=None, role=None, ref=None, details=None):
    sb.table("audit_log").insert({"action": action, "actor_id": actor_id,
        "actor_role": role, "ref_id": ref, "details": details}).execute()

@app.on_event("startup")
def seed_demo_users():
    pw = os.environ.get("DEMO_PASSWORD")
    if not pw:
        return
    demo = [("admin", "Admin", "admin@demo.pk"), ("seller", "Seller One", "seller1@demo.pk"),
            ("seller", "Seller Two", "seller2@demo.pk"), ("rider", "Rider One", "rider1@demo.pk"),
            ("rider", "Rider Two", "rider2@demo.pk"), ("rider", "Rider Three", "rider3@demo.pk")]
    for role, name, email in demo:
        if not sb.table("users").select("id").eq("email", email).execute().data:
            sb.table("users").insert({"role": role, "full_name": name, "email": email,
                                      "password_hash": hash_pw(pw)}).execute()

class Reg(BaseModel):
    full_name: str
    email: str
    password: str
    phone: str = ""

class Login(BaseModel):
    email: str
    password: str

def set_cookie(resp, user):
    token = jwt.encode({"sub": user["id"], "role": user["role"], "exp": int(time.time()) + 8 * 3600},
                       JWT_SECRET, algorithm="HS256")
    resp.set_cookie("session", token, httponly=True, samesite="lax",
                    secure=os.environ.get("COOKIE_SECURE", "1") == "1", max_age=8 * 3600)

def current_user(request: Request):
    token = request.cookies.get("session")
    if not token:
        raise HTTPException(401, "Login required")
    try:
        data = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except Exception:
        raise HTTPException(401, "Session expired")
    rows = sb.table("users").select("id,role,full_name,email,status").eq("id", data["sub"]).execute().data
    if not rows or rows[0]["status"] != "active":
        raise HTTPException(403, "Account not active")
    return rows[0]

def need_role(role):
    def dep(user=Depends(current_user)):
        if user["role"] != role:
            audit("access_denied", user["id"], user["role"], details=f"tried {role} area")
            raise HTTPException(403, "Not allowed")
        return user
    return dep

@app.post("/api/register")
def register(body: Reg, response: Response):
    email = body.email.strip().lower()
    if "@" not in email or len(body.password) < 8 or not body.full_name.strip():
        raise HTTPException(400, "Valid name, email and 8+ character password required")
    if sb.table("users").select("id").eq("email", email).execute().data:
        raise HTTPException(400, "Email already registered")
    # Public registration can ONLY create customers. Never admin/seller/rider.
    user = sb.table("users").insert({"role": "customer", "full_name": body.full_name.strip(),
        "email": email, "password_hash": hash_pw(body.password)}).execute().data[0]
    sb.table("customer_private").insert({"user_id": user["id"], "phone": body.phone}).execute()
    audit("register", user["id"], "customer")
    set_cookie(response, user)
    return {"role": "customer"}

@app.post("/api/login")
def login(body: Login, response: Response):
    rows = sb.table("users").select("*").eq("email", body.email.strip().lower()).execute().data
    if not rows or not check_pw(body.password, rows[0]["password_hash"]):
        audit("login_failed", details="bad credentials")
        raise HTTPException(401, "Wrong email or password")
    u = rows[0]
    if u["status"] != "active":
        raise HTTPException(403, "Account suspended")
    audit("login", u["id"], u["role"])
    set_cookie(response, u)
    return {"role": u["role"]}

@app.post("/api/logout")
def logout(response: Response):
    response.delete_cookie("session")
    return {"ok": True}

@app.get("/api/me")
def me(user=Depends(current_user)):
    return {"full_name": user["full_name"], "role": user["role"]}

def count(table, **eq):
    q = sb.table(table).select("id", count="exact")
    for k, v in eq.items():
        q = q.eq(k, v)
    return q.execute().count or 0

# Har role ka apna protected endpoint. Sab numbers database se aate hain.
@app.get("/api/dashboard/customer")
def d_customer(u=Depends(need_role("customer"))):
    return {"cards": {"My orders": count("orders", customer_id=u["id"])}}

@app.get("/api/dashboard/seller")
def d_seller(u=Depends(need_role("seller"))):
    return {"cards": {"My orders": count("orders", seller_id=u["id"]),
                      "My products": count("products", seller_id=u["id"])}}

@app.get("/api/dashboard/rider")
def d_rider(u=Depends(need_role("rider"))):
    return {"cards": {"My tasks": count("deliveries", rider_id=u["id"])}}

@app.get("/api/dashboard/admin")
def d_admin(u=Depends(need_role("admin"))):
    return {"cards": {"Total orders": count("orders"), "Users": count("users"),
                      "Available compartments": count("compartments", status="available"),
                      "Open tickets": count("tickets", status="open")}}

@app.get("/dashboard")
def dash_page():
    return FileResponse(os.path.join(BASE, "static", "dashboard.html"))

app.mount("/", StaticFiles(directory=os.path.join(BASE, "static"), html=True), name="static")
