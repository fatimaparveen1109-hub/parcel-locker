import hashlib, hmac, secrets
import streamlit as st
from supabase import create_client

st.set_page_config(page_title="SafeLocker", page_icon="📦", layout="wide")
st.markdown("""<style>
.stApp{background:#f5f7ff}
h1,h2,h3{color:#1e1b4b}
div.stButton>button{background:linear-gradient(90deg,#2563eb,#7c3aed);color:#fff;border:0;border-radius:10px;font-weight:700}
[data-testid="stMetric"]{background:#fff;border-radius:16px;padding:16px;box-shadow:0 4px 16px #4f46e514}
[data-testid="stMetricValue"]{color:#0d9488}
</style>""", unsafe_allow_html=True)

@st.cache_resource
def db():
    return create_client(st.secrets["SUPABASE_URL"], st.secrets["SUPABASE_SERVICE_KEY"])

def hash_pw(pw, salt=None):
    salt = salt or secrets.token_hex(16)
    return salt + "$" + hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 200000).hex()

def check_pw(pw, stored):
    return hmac.compare_digest(hash_pw(pw, stored.split("$")[0]), stored)

def audit(action, uid=None, role=None, details=None):
    db().table("audit_log").insert({"action": action, "actor_id": uid, "actor_role": role, "details": details}).execute()

@st.cache_resource
def seed():
    demo = [("admin","Admin","admin@demo.pk"),("seller","Seller One","seller1@demo.pk"),
            ("seller","Seller Two","seller2@demo.pk"),("rider","Rider One","rider1@demo.pk"),
            ("rider","Rider Two","rider2@demo.pk"),("rider","Rider Three","rider3@demo.pk")]
    for role, name, email in demo:
        if not db().table("users").select("id").eq("email", email).execute().data:
            db().table("users").insert({"role": role, "full_name": name, "email": email,
                "password_hash": hash_pw(st.secrets["DEMO_PASSWORD"])}).execute()
    return True
seed()

def count(table, **eq):
    q = db().table(table).select("id", count="exact")
    for k, v in eq.items():
        q = q.eq(k, v)
    return q.execute().count or 0

def dashboard(u):
    top = st.columns([6, 2, 1])
    top[0].markdown("## 📦 SafeLocker")
    top[1].write(f"**{u['full_name']}** ({u['role']})")
    if top[2].button("Logout"):
        audit("logout", u["id"], u["role"])
        st.session_state.clear(); st.rerun()
    st.subheader(u["role"].capitalize() + " Dashboard")
    r = u["role"]
    cards = {"customer": {"My orders": count("orders", customer_id=u["id"])},
             "seller": {"My orders": count("orders", seller_id=u["id"]), "My products": count("products", seller_id=u["id"])},
             "rider": {"My tasks": count("deliveries", rider_id=u["id"])},
             "admin": {"Total orders": count("orders"), "Users": count("users"),
                       "Available compartments": count("compartments", status="available"),
                       "Open tickets": count("tickets", status="open")}}[r]
    cols = st.columns(len(cards))
    for c, (k, v) in zip(cols, cards.items()):
        c.metric(k, v)
    st.info("Shop, orders, lockers aur payments agle stages mein aayenge.")

if "user" in st.session_state:
    dashboard(st.session_state["user"]); st.stop()

st.markdown("# 📦 SafeLocker")
t1, t2, t3, t4 = st.tabs(["Home", "How It Works", "Privacy Policy", "Login / Sign Up"])
with t1:
    st.markdown("## Your parcel. Your privacy.")
    st.write("Get orders delivered to a secure smart locker. Sellers and riders never see your home address or phone number.")
with t2:
    a, b, c = st.columns(3)
    a.markdown("### 1. Order\nPick products and choose your preferred locker hub.")
    b.markdown("### 2. Deliver\nA rider takes your parcel to the hub and drops it in a locker.")
    c.markdown("### 3. Collect\nScan your private QR code and collect within 48 hours.")
with t3:
    st.write("We share only what each person needs. Sellers see your name and order items. Riders see only the delivery ID, parcel size and hub. Your phone and address stay private. Payments in this demo are simulated; no real money moves.")
with t4:
    mode = st.radio("Choose", ["Login", "Sign Up (customer)"], horizontal=True)
    email = st.text_input("Email").strip().lower()
    pw = st.text_input("Password", type="password")
    if mode.startswith("Sign"):
        name = st.text_input("Full name"); phone = st.text_input("Phone (kept private)")
        if st.button("Create account"):
            if "@" not in email or len(pw) < 8 or not name.strip():
                st.error("Valid name, email and 8+ character password required")
            elif db().table("users").select("id").eq("email", email).execute().data:
                st.error("Email already registered")
            else:
                u = db().table("users").insert({"role": "customer", "full_name": name.strip(), "email": email,
                    "password_hash": hash_pw(pw)}).execute().data[0]
                db().table("customer_private").insert({"user_id": u["id"], "phone": phone}).execute()
                audit("register", u["id"], "customer")
                st.session_state["user"] = u; st.rerun()
    else:
        if st.button("Login"):
            rows = db().table("users").select("*").eq("email", email).execute().data
            if not rows or not check_pw(pw, rows[0]["password_hash"]):
                audit("login_failed"); st.error("Wrong email or password")
            elif rows[0]["status"] != "active":
                st.error("Account suspended")
            else:
                audit("login", rows[0]["id"], rows[0]["role"])
                st.session_state["user"] = rows[0]; st.rerun()
