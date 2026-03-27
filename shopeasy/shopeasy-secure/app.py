"""
=============================================================
  ShopEasy SECURE — Fixed E-Commerce App
  Purpose: Demonstrate what a secure API looks like
  Compare with: ShopEasy (vulnerable version) on port 5000

  FIXES APPLIED:
  [1] JWT secret: strong random secret, never hardcoded
  [2] JWT role: always verified from database, never trusted from token
  [3] BOLA orders: ownership check enforced
  [4] BOLA messages: user_id always taken from verified token
  [5] Admin endpoints: require authentication + admin role from DB
  [6] Debug/backup/metrics endpoints: removed entirely
  [7] Passwords: hashed, never returned in responses
  [8] Rate limiting on login endpoint
=============================================================
"""

from flask import Flask, request, jsonify, render_template
import jwt, datetime, sqlite3, os, secrets, hashlib, time
from functools import wraps

app = Flask(__name__)

JWT_SECRET    = os.environ.get("JWT_SECRET", secrets.token_hex(32))
JWT_ALGORITHM = "HS256"
DB_PATH       = "/tmp/shopeasy_secure.db"

_login_attempts = {}
RATE_LIMIT_WINDOW = 60
RATE_LIMIT_MAX    = 10

def _hash_pw(pw):
    return hashlib.sha256(("shopeasy_salt_" + pw).encode()).hexdigest()

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY, username TEXT UNIQUE,
        password_hash TEXT, email TEXT, full_name TEXT,
        address TEXT, role TEXT DEFAULT 'user')""")
    c.execute("""CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY, name TEXT, description TEXT,
        price REAL, category TEXT, stock INTEGER, image_emoji TEXT)""")
    c.execute("""CREATE TABLE IF NOT EXISTS orders (
        id INTEGER PRIMARY KEY, user_id INTEGER, product_id INTEGER,
        quantity INTEGER, total REAL, status TEXT,
        shipping_address TEXT, card_last4 TEXT, created_at TEXT)""")
    c.execute("""CREATE TABLE IF NOT EXISTS reviews (
        id INTEGER PRIMARY KEY, product_id INTEGER, user_id INTEGER,
        rating INTEGER, comment TEXT, created_at TEXT)""")
    c.execute("""CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY, user_id INTEGER, subject TEXT,
        body TEXT, is_read INTEGER DEFAULT 0, created_at TEXT)""")

    users = [
        (1,"alice",  _hash_pw("alice123"),  "alice@shopeasy.com",  "Alice Johnson","12 Elm St, Springfield","user"),
        (2,"bob",    _hash_pw("bob456"),    "bob@shopeasy.com",    "Bob Smith",    "88 Oak Ave, Portland",  "user"),
        (3,"charlie",_hash_pw("charlie789"),"charlie@shopeasy.com","Charlie Brown","5 Maple Rd, Austin",    "user"),
        (4,"admin",  _hash_pw("adminpass"), "admin@shopeasy.com",  "Admin User",   "HQ, San Francisco",     "admin"),
    ]
    c.executemany("INSERT OR IGNORE INTO users VALUES (?,?,?,?,?,?,?)", users)

    products = [
        (1,"Wireless Headphones","Premium noise-cancelling over-ear headphones with 40hr battery",89.99,"Electronics",45,"🎧"),
        (2,"Running Shoes","Lightweight mesh trainers with responsive foam sole",64.99,"Footwear",120,"👟"),
        (3,"Coffee Maker","12-cup programmable drip coffee maker with thermal carafe",49.99,"Kitchen",60,"☕"),
        (4,"Yoga Mat","Non-slip eco-friendly 6mm thick exercise mat",29.99,"Sports",200,"🧘"),
        (5,"Backpack","30L waterproof hiking backpack with laptop sleeve",79.99,"Bags",85,"🎒"),
        (6,"Sunglasses","Polarised UV400 aviator sunglasses",34.99,"Accessories",150,"🕶️"),
        (7,"Smart Watch","Fitness tracker with heart rate, GPS and 7-day battery",129.99,"Electronics",30,"⌚"),
        (8,"Water Bottle","1L insulated stainless steel bottle, keeps cold 24hrs",24.99,"Sports",300,"💧"),
    ]
    c.executemany("INSERT OR IGNORE INTO products VALUES (?,?,?,?,?,?,?)", products)

    orders = [
        (1,1,1,1,89.99,"delivered","12 Elm St, Springfield","4242","2024-01-10"),
        (2,1,3,2,99.98,"shipped",  "12 Elm St, Springfield","4242","2024-02-14"),
        (3,2,2,1,64.99,"delivered","88 Oak Ave, Portland",  "5678","2024-01-20"),
        (4,3,7,1,129.99,"processing","5 Maple Rd, Austin",  "9999","2024-03-01"),
        (5,4,5,3,239.97,"delivered","HQ, San Francisco",    "1111","2024-02-28"),
    ]
    c.executemany("INSERT OR IGNORE INTO orders VALUES (?,?,?,?,?,?,?,?,?)", orders)

    reviews = [
        (1,1,2,5,"Absolutely love these headphones! Crystal clear sound.","2024-01-25"),
        (2,1,3,4,"Great headphones, very comfortable for long sessions.",  "2024-02-01"),
        (3,2,1,5,"Best running shoes I have ever owned. Super lightweight!","2024-01-22"),
        (4,7,3,4,"Smart watch works great, battery life is impressive.",   "2024-03-05"),
    ]
    c.executemany("INSERT OR IGNORE INTO reviews VALUES (?,?,?,?,?,?)", reviews)

    msgs = [
        (1,1,"Your order has been shipped!","Order #1 is on its way. Track: SE-20240110.","0","2024-01-11"),
        (2,2,"Welcome to ShopEasy!","Thanks for joining. Use code WELCOME10 for 10% off.","0","2024-01-15"),
        (3,4,"ADMIN: Stripe secret key","sk_live_REDACTED_KEY","0","2024-01-01"),
        (4,4,"ADMIN: DB backup creds","Host: db.internal, user: root, pass: Sup3rS3cr3t!","0","2024-01-01"),
    ]
    c.executemany("INSERT OR IGNORE INTO messages VALUES (?,?,?,?,?,?)", msgs)

    conn.commit(); conn.close()

def get_db():
    return sqlite3.connect(DB_PATH)

def decode_token(token):
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except Exception:
        return None

def get_db_user(user_id):
    conn = get_db()
    row = conn.execute("SELECT id,username,role FROM users WHERE id=?", (user_id,)).fetchone()
    conn.close()
    return {"id":row[0],"username":row[1],"role":row[2]} if row else None

def auth_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization","").replace("Bearer ","") or request.cookies.get("token","")
        if not token: return jsonify({"error":"Authentication required"}), 401
        payload = decode_token(token)
        if not payload: return jsonify({"error":"Invalid or expired token"}), 401
        db_user = get_db_user(payload.get("user_id"))
        if not db_user: return jsonify({"error":"User not found"}), 401
        request.user = db_user
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.user.get("role") != "admin":
            return jsonify({"error":"Admin access required","your_role":request.user.get("role")}), 403
        return f(*args, **kwargs)
    return decorated

# ── PAGE ROUTES ───────────────────────────────────────────
@app.route("/")
def index():         return render_template("index.html")
@app.route("/login")
def login_page():    return render_template("login.html")
@app.route("/register")
def register_page(): return render_template("register.html")
@app.route("/shop")
def shop_page():     return render_template("shop.html")
@app.route("/product/<int:pid>")
def product_page(pid): return render_template("product.html", pid=pid)
@app.route("/cart")
def cart_page():     return render_template("cart.html")
@app.route("/orders")
def orders_page():   return render_template("orders.html")
@app.route("/profile")
def profile_page():  return render_template("profile.html")
@app.route("/messages")
def messages_page(): return render_template("messages.html")

# ── API: AUTH ─────────────────────────────────────────────
@app.route("/api/register", methods=["POST"])
def api_register():
    d = request.get_json()
    if not d or not d.get("username") or not d.get("password"):
        return jsonify({"error":"username and password required"}), 400
    conn = get_db()
    try:
        conn.execute("INSERT INTO users (username,password_hash,email,full_name,address,role) VALUES (?,?,?,?,?,?)",
            (d["username"],_hash_pw(d["password"]),d.get("email",""),d.get("full_name",""),d.get("address",""),"user"))
        conn.commit()
        return jsonify({"message":"Account created successfully"}), 201
    except sqlite3.IntegrityError:
        return jsonify({"error":"Username already taken"}), 409
    finally:
        conn.close()

@app.route("/api/login", methods=["POST"])
def api_login():
    ip = request.remote_addr; now = time.time()
    _login_attempts[ip] = [t for t in _login_attempts.get(ip,[]) if now-t < RATE_LIMIT_WINDOW]
    if len(_login_attempts[ip]) >= RATE_LIMIT_MAX:
        return jsonify({"error":"Too many login attempts. Try again later."}), 429
    _login_attempts[ip].append(now)

    d = request.get_json()
    if not d: return jsonify({"error":"JSON required"}), 400
    conn = get_db()
    u = conn.execute("SELECT id,username,role,full_name FROM users WHERE username=? AND password_hash=?",
        (d.get("username",""), _hash_pw(d.get("password","")))).fetchone()
    conn.close()
    if not u: return jsonify({"error":"Invalid username or password"}), 401

    token = jwt.encode({"user_id":u[0],"exp":datetime.datetime.utcnow()+datetime.timedelta(hours=24)},
        JWT_SECRET, algorithm=JWT_ALGORITHM)
    return jsonify({"token":token,"user_id":u[0],"username":u[1],"role":u[2],"full_name":u[3]})

# ── API: PRODUCTS ─────────────────────────────────────────
@app.route("/api/products", methods=["GET"])
def api_products():
    cat = request.args.get("category","")
    conn = get_db()
    rows = conn.execute("SELECT * FROM products WHERE category=?" if cat else "SELECT * FROM products",
        (cat,) if cat else ()).fetchall()
    conn.close()
    return jsonify([{"id":r[0],"name":r[1],"description":r[2],"price":r[3],"category":r[4],"stock":r[5],"image_emoji":r[6]} for r in rows])

@app.route("/api/products/<int:pid>", methods=["GET"])
def api_product(pid):
    conn = get_db()
    p = conn.execute("SELECT * FROM products WHERE id=?", (pid,)).fetchone()
    revs = conn.execute("SELECT r.rating,r.comment,r.created_at,u.username FROM reviews r JOIN users u ON r.user_id=u.id WHERE r.product_id=?", (pid,)).fetchall()
    conn.close()
    if not p: return jsonify({"error":"Product not found"}), 404
    return jsonify({"id":p[0],"name":p[1],"description":p[2],"price":p[3],"category":p[4],"stock":p[5],"image_emoji":p[6],
        "reviews":[{"rating":r[0],"comment":r[1],"date":r[2],"user":r[3]} for r in revs]})

# ── API: ORDERS ───────────────────────────────────────────
@app.route("/api/orders", methods=["GET"])
@auth_required
def api_my_orders():
    conn = get_db()
    rows = conn.execute("SELECT o.id,p.name,p.image_emoji,o.quantity,o.total,o.status,o.shipping_address,o.card_last4,o.created_at FROM orders o JOIN products p ON o.product_id=p.id WHERE o.user_id=?", (request.user["id"],)).fetchall()
    conn.close()
    return jsonify([{"order_id":r[0],"product":r[1],"emoji":r[2],"qty":r[3],"total":r[4],"status":r[5],"address":r[6],"card_last4":r[7],"date":r[8]} for r in rows])

@app.route("/api/orders/<int:oid>", methods=["GET"])
@auth_required
def api_order_detail(oid):
    conn = get_db()
    row = conn.execute("""SELECT o.id,o.user_id,p.name,p.image_emoji,o.quantity,o.total,o.status,o.shipping_address,o.card_last4,o.created_at
        FROM orders o JOIN products p ON o.product_id=p.id WHERE o.id=?""", (oid,)).fetchone()
    conn.close()
    if not row: return jsonify({"error":"Order not found"}), 404
    # [FIX 3] Ownership check
    if row[1] != request.user["id"] and request.user["role"] != "admin":
        return jsonify({"error":"You are not authorised to view this order"}), 403
    return jsonify({"order_id":row[0],"product":row[2],"emoji":row[3],"quantity":row[4],"total":row[5],"status":row[6],"shipping_address":row[7],"card_last4":row[8],"date":row[9]})

@app.route("/api/orders", methods=["POST"])
@auth_required
def api_place_order():
    d = request.get_json()
    if not d: return jsonify({"error":"JSON required"}), 400
    conn = get_db()
    p = conn.execute("SELECT price FROM products WHERE id=?", (d.get("product_id"),)).fetchone()
    if not p: return jsonify({"error":"Product not found"}), 404
    qty = int(d.get("quantity",1)); total = round(p[0]*qty, 2)
    conn.execute("INSERT INTO orders (user_id,product_id,quantity,total,status,shipping_address,card_last4,created_at) VALUES (?,?,?,?,?,?,?,?)",
        (request.user["id"],d["product_id"],qty,total,"processing",d.get("address",""),d.get("card_last4","****"),datetime.date.today().isoformat()))
    conn.commit(); conn.close()
    return jsonify({"message":"Order placed successfully","total":total}), 201

# ── API: MESSAGES ─────────────────────────────────────────
@app.route("/api/messages", methods=["GET"])
@auth_required
def api_messages():
    # [FIX 4] user_id from verified token only — query param ignored
    conn = get_db()
    rows = conn.execute("SELECT id,subject,body,is_read,created_at FROM messages WHERE user_id=?", (request.user["id"],)).fetchall()
    conn.close()
    return jsonify([{"id":r[0],"subject":r[1],"body":r[2],"read":r[3],"date":r[4]} for r in rows])

# ── API: PROFILE ──────────────────────────────────────────
@app.route("/api/profile", methods=["GET"])
@auth_required
def api_profile():
    conn = get_db()
    u = conn.execute("SELECT id,username,email,full_name,address,role FROM users WHERE id=?", (request.user["id"],)).fetchone()
    conn.close()
    if not u: return jsonify({"error":"User not found"}), 404
    return jsonify({"id":u[0],"username":u[1],"email":u[2],"full_name":u[3],"address":u[4],"role":u[5]})

# ── API: ADMIN ────────────────────────────────────────────
@app.route("/api/admin/users", methods=["GET"])
@auth_required
@admin_required
def api_admin_users():
    conn = get_db()
    rows = conn.execute("SELECT id,username,email,full_name,address,role FROM users").fetchall()
    conn.close()
    return jsonify([{"id":r[0],"username":r[1],"email":r[2],"full_name":r[3],"address":r[4],"role":r[5]} for r in rows])

@app.route("/api/admin/orders", methods=["GET"])
@auth_required
@admin_required
def api_admin_orders():
    conn = get_db()
    rows = conn.execute("SELECT o.id,u.username,p.name,o.total,o.status FROM orders o JOIN users u ON o.user_id=u.id JOIN products p ON o.product_id=p.id").fetchall()
    conn.close()
    return jsonify([{"order_id":r[0],"user":r[1],"product":r[2],"total":r[3],"status":r[4]} for r in rows])

@app.route("/api/admin/secret", methods=["GET"])
@auth_required
@admin_required
def api_admin_secret():
    return jsonify({
        "message": "Authenticated as admin via database-verified role.",
        "note":    "JWT role forgery does not work here — role is checked against the DB on every request."
    })

# [FIX 6] /api/debug/config, /api/backup, /api/internal/metrics — NOT REGISTERED

@app.route("/api/jwt/decode", methods=["POST"])
def api_jwt_decode():
    d = request.get_json()
    token = d.get("token","") if d else ""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return jsonify({"payload":payload,"note":"Signature verified ✓"})
    except jwt.ExpiredSignatureError:
        return jsonify({"error":"Token has expired"}), 401
    except jwt.InvalidSignatureError:
        return jsonify({"error":"Invalid signature — token has been tampered with"}), 401
    except Exception as e:
        return jsonify({"error":str(e)}), 400

if __name__ == "__main__":
    init_db()
    print("\n" + "="*55)
    print("  ShopEasy SECURE — Fixed E-Commerce Lab")
    print("  http://localhost:5001")
    print("  Compare with vulnerable version on :5000")
    print("="*55 + "\n")
    app.run(host="0.0.0.0", port=5001, debug=False)
