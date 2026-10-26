"""
Rochar Gelato — backend v2 (FastAPI + Postgres on Render)

Lean, single-operator design:
  • Master Products (gelato, raw materials, packaging)
  • Messenger-style open orders → completed sales (or voided, kept for audit)
  • Purchases and Expenses, with proof photos
  • Production log (record only)
  • Monthly inventory count → periodic COGS:
        COGS = Beginning Inventory + Purchases − Ending Inventory
  • Customers / resellers (custom price lists), receivables for credit
    sales, daily reconciliation with day locking, liabilities (Gino / card)

Everything except the health checks and login needs a logged-in session.
"""

import base64
import hashlib
import json
import os
import secrets
import threading
import time
from contextlib import asynccontextmanager
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path
from typing import List, Optional

import psycopg
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool
from fastapi import APIRouter, Body, Depends, FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import Response
from pydantic import BaseModel, Field


# ----------------------------------------------------------------------------
# Setup
# ----------------------------------------------------------------------------

DATABASE_URL = os.environ["DATABASE_URL"]   # injected by Render
MANILA_TZ = timezone(timedelta(hours=8))
SESSION_DAYS = 90
SCHEMA_FILE = Path(__file__).with_name("schema.sql")

SELL_CATEGORIES = ("Mini", "Pint", "Cake")               # finished goods — on the POS
MATERIAL_CATEGORIES = ("Raw Material", "Packaging")      # bought materials — count only
CATEGORIES = SELL_CATEGORIES + MATERIAL_CATEGORIES
PAYMENT_METHODS = ("Cash", "GCash", "Gino", "Credit Card", "Check")   # purchases / expenses
LIABILITY_METHODS = ("Gino", "Credit Card")                            # paid with money the business owes back
SALE_METHODS = ("Cash", "GCash", "Bank")                               # where customer money lands
TIERS = ("Retail", "Reseller")
MAX_ATTACHMENT_BYTES = 6 * 1024 * 1024
LOCAL_DAY = "(({col}) AT TIME ZONE 'Asia/Manila')::date"   # timestamp → Manila calendar day


def today_manila() -> date:
    return datetime.now(MANILA_TZ).date()


POOL = ConnectionPool(DATABASE_URL, min_size=1, max_size=10, open=False,
                      kwargs={"row_factory": dict_row}, check=ConnectionPool.check_connection)


def db():
    """`with db() as conn:` — commits if everything succeeds, rolls back on error.
    Connections come from a pool, so requests don't pay to open a new one each time."""
    return POOL.connection()


def clean(v):
    return float(v) if isinstance(v, Decimal) else v


def rows(cur):
    return [{k: clean(v) for k, v in r.items()} for r in cur.fetchall()]


def one(cur):
    r = cur.fetchone()
    return None if r is None else {k: clean(v) for k, v in r.items()}


def day_range(date_from: Optional[date], date_to: Optional[date]):
    """Inclusive Manila dates. Default: the last 31 days."""
    end = date_to or today_manila()
    start = date_from or (end - timedelta(days=30))
    return start, end


@asynccontextmanager
async def lifespan(app: FastAPI):
    with psycopg.connect(DATABASE_URL, autocommit=True) as conn:
        conn.execute(SCHEMA_FILE.read_text())
        conn.execute("DELETE FROM sessions WHERE expires_at < now();")
    POOL.open(wait=True, timeout=30)
    worker = threading.Thread(target=background_loop, daemon=True, name="rochar-jobs")
    worker.start()
    yield
    STOP_JOBS.set()
    POOL.close()


app = FastAPI(title="Rochar Gelato API", lifespan=lifespan)
app.add_middleware(GZipMiddleware, minimum_size=1000)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    allow_headers=["*"],
)


@app.get("/")
def health_check():
    return {"ok": True, "message": "Rochar Gelato backend is running.", "version": 2}


@app.get("/db-check")
def db_check():
    try:
        with db() as conn:
            v = conn.execute("SELECT version() AS v;").fetchone()["v"]
        return {"connected": True, "postgres_version": v}
    except Exception as error:
        return {"connected": False, "error": str(error)}


# ----------------------------------------------------------------------------
# Login — one shared PIN. Send the token back as  Authorization: Bearer <token>
# ----------------------------------------------------------------------------

class PinPayload(BaseModel):
    pin: str


class ChangePinPayload(BaseModel):
    current_pin: str
    new_pin: str


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def check_pin_format(pin: str):
    if not pin.isdigit() or not 4 <= len(pin) <= 12:
        raise HTTPException(400, "PIN must be 4–12 digits.")


_failed_logins: List[float] = []


def _locked_out() -> bool:
    cutoff = time.time() - 15 * 60
    while _failed_logins and _failed_logins[0] < cutoff:
        _failed_logins.pop(0)
    return len(_failed_logins) >= 10


def new_session(cur) -> str:
    token = secrets.token_urlsafe(32)
    cur.execute("INSERT INTO sessions (token_hash, expires_at) VALUES (%s, now() + %s * interval '1 day');",
                (token_hash(token), SESSION_DAYS))
    return token


def session_valid(token: str) -> bool:
    if not token:
        return False
    with db() as conn:
        return bool(conn.execute("SELECT 1 FROM sessions WHERE token_hash = %s AND expires_at > now();",
                                 (token_hash(token),)).fetchone())


@app.get("/auth/status")
def auth_status():
    with db() as conn:
        return {"pin_set": bool(conn.execute("SELECT 1 FROM admin_auth WHERE id = 1;").fetchone())}


@app.post("/auth/setup")
def auth_setup(p: PinPayload):
    check_pin_format(p.pin)
    with db() as conn, conn.cursor() as cur:
        cur.execute("SELECT 1 FROM admin_auth WHERE id = 1 FOR UPDATE;")
        if cur.fetchone():
            raise HTTPException(409, "A PIN has already been set. Log in instead.")
        cur.execute("INSERT INTO admin_auth (id, pin_hash) VALUES (1, crypt(%s, gen_salt('bf')));", (p.pin,))
        return {"token": new_session(cur)}


@app.post("/auth/login")
def auth_login(p: PinPayload):
    if _locked_out():
        raise HTTPException(429, "Too many wrong PINs. Try again in 15 minutes.")
    with db() as conn, conn.cursor() as cur:
        cur.execute("SELECT 1 FROM admin_auth WHERE id = 1 AND pin_hash = crypt(%s, pin_hash);", (p.pin,))
        if not cur.fetchone():
            _failed_logins.append(time.time())
            raise HTTPException(401, "Wrong PIN.")
        return {"token": new_session(cur)}


def require_login(authorization: str = Header(default="")):
    token = authorization.removeprefix("Bearer ").strip()
    if not token:
        raise HTTPException(401, "Not logged in.")
    if not session_valid(token):
        raise HTTPException(401, "Session expired. Please log in again.")
    return token


api = APIRouter(dependencies=[Depends(require_login)])


@api.post("/auth/logout")
def auth_logout(token: str = Depends(require_login)):
    with db() as conn:
        conn.execute("DELETE FROM sessions WHERE token_hash = %s;", (token_hash(token),))
    return {"ok": True}


@api.post("/auth/change-pin")
def auth_change_pin(p: ChangePinPayload):
    check_pin_format(p.new_pin)
    with db() as conn, conn.cursor() as cur:
        cur.execute("SELECT 1 FROM admin_auth WHERE id = 1 AND pin_hash = crypt(%s, pin_hash);", (p.current_pin,))
        if not cur.fetchone():
            raise HTTPException(401, "Current PIN is wrong.")
        cur.execute("UPDATE admin_auth SET pin_hash = crypt(%s, gen_salt('bf')), updated_at = now() WHERE id = 1;",
                    (p.new_pin,))
        cur.execute("DELETE FROM sessions;")
        return {"token": new_session(cur)}


# ----------------------------------------------------------------------------
# Field cleaners + partial updates (inline editing sends one field at a time)
# ----------------------------------------------------------------------------

def as_text(v):
    return ("" if v is None else str(v)).strip()


def as_money(v):
    try:
        x = round(float(v or 0), 2)
    except (TypeError, ValueError):
        raise HTTPException(400, f"“{v}” isn't a number.")
    if x < 0:
        raise HTTPException(400, "Amounts can't be negative.")
    return x


def as_qty(v):
    try:
        x = float(v)
    except (TypeError, ValueError):
        raise HTTPException(400, f"“{v}” isn't a number.")
    if x < 0:
        raise HTTPException(400, "Quantities can't be negative.")
    return x


def as_bool(v):
    return v in (True, "true", "1", 1, "on")


def as_int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        raise HTTPException(400, f"“{v}” isn't a whole number.")


def as_category(v):
    if v not in CATEGORIES:
        raise HTTPException(400, "Category must be one of: " + ", ".join(CATEGORIES))
    return v


def as_payment(v):
    v = as_text(v)
    if v not in PAYMENT_METHODS:
        raise HTTPException(400, "Payment method must be one of: " + ", ".join(PAYMENT_METHODS))
    return v


def as_sale_method(v):
    v = as_text(v)
    if v not in SALE_METHODS:
        raise HTTPException(400, "Must be Cash, GCash, or Bank.")
    return v


def as_pay_status(v):
    if v not in ("paid", "credit"):
        raise HTTPException(400, "Payment status must be paid or credit.")
    return v


def as_tier(v):
    if v not in TIERS:
        raise HTTPException(400, "Type must be Retail or Reseller.")
    return v


def manila_day(ts) -> Optional[date]:
    return ts.astimezone(MANILA_TZ).date() if ts else None


def day_locked(cur, d: Optional[date]) -> bool:
    if d is None:
        return False
    cur.execute("SELECT 1 FROM reconciliations WHERE recon_date = %s AND locked;", (d,))
    return bool(cur.fetchone())


def assert_unlocked(cur, d: Optional[date], what: str = "this"):
    if day_locked(cur, d):
        raise HTTPException(423, f"{d:%b %d, %Y} is already reconciled and locked — unlock it in Reconciliation to change {what}.")


def as_timestamp(v):
    if isinstance(v, datetime):
        return v
    try:
        dt = datetime.fromisoformat(str(v).replace("Z", "+00:00"))
    except ValueError:
        raise HTTPException(400, f"“{v}” isn't a valid date/time.")
    return dt if dt.tzinfo else dt.replace(tzinfo=MANILA_TZ)


def as_date(v):
    try:
        return date.fromisoformat(str(v)[:10])
    except ValueError:
        raise HTTPException(400, f"“{v}” isn't a valid date.")


def apply_patch(cur, table: str, row_id: int, changes: dict, allowed: dict, extra_sql: str = ""):
    """UPDATE only the fields that were sent. `allowed` maps field → cleaner."""
    sets, params = [], []
    for key, value in changes.items():
        if key in allowed:
            sets.append(f"{key} = %s")
            params.append(allowed[key](value))
    if not sets:
        raise HTTPException(400, "Nothing to update.")
    cur.execute(f"UPDATE {table} SET {', '.join(sets)}{extra_sql} WHERE id = %s RETURNING id;",
                params + [row_id])
    if not cur.fetchone():
        raise HTTPException(404, "Not found.")


# ----------------------------------------------------------------------------
# Master Products
# ----------------------------------------------------------------------------

class ItemPayload(BaseModel):
    name: str
    category: str = "Pint"
    variant: str = ""
    unit_cost: float = 0
    selling_price: float = 0
    active: bool = True
    base_unit: str = ""
    content_qty: float = 1


def as_content(v):
    x = as_qty(v)
    if x <= 0:
        raise HTTPException(400, "The recipe-unit conversion must be more than 0.")
    return x


ITEM_FIELDS = {"name": as_text, "category": as_category, "variant": as_text, "unit_cost": as_money,
               "selling_price": as_money, "active": as_bool, "sort_order": as_int,
               "base_unit": as_text, "content_qty": as_content}
CATEGORY_ORDER = "CASE category WHEN 'Mini' THEN 0 WHEN 'Pint' THEN 1 WHEN 'Cake' THEN 2 WHEN 'Raw Material' THEN 3 ELSE 4 END"
ITEM_ORDER = CATEGORY_ORDER + ", sort_order, name, variant"


ITEM_LIST_SQL = f"""
    SELECT i.*,
           img.updated_at AS image_updated_at,
           lp.unit_price AS latest_price, lp.purchased_at AS latest_price_at,
           (r.product_id IS NOT NULL) AS has_recipe
    FROM items i
    LEFT JOIN item_images img ON img.item_id = i.id
    LEFT JOIN recipes r ON r.product_id = i.id
    LEFT JOIN LATERAL (
        SELECT ROUND(l.amount / l.qty, 4) AS unit_price, p.purchased_at
        FROM purchase_lines l JOIN purchases p ON p.id = l.purchase_id
        WHERE l.item_id = i.id AND l.qty > 0
        ORDER BY p.purchased_at DESC, l.id DESC LIMIT 1) lp ON true
"""


@api.get("/items")
def list_items(include_inactive: bool = False):
    with db() as conn, conn.cursor() as cur:
        cur.execute(ITEM_LIST_SQL + f" WHERE i.active OR %s ORDER BY {ITEM_ORDER.replace('category', 'i.category').replace('sort_order', 'i.sort_order').replace(', name, variant', ', i.name, i.variant')};",
                    (include_inactive,))
        return rows(cur)


# ---- automatic costing ------------------------------------------------------

def refresh_costs(cur):
    """Materials take their unit cost from their latest purchase; products
    with a recipe take theirs from the recipe. Runs after anything that can
    change a price (purchases, recipes, material units)."""
    cur.execute("""
        UPDATE items i SET unit_cost = lp.unit_price
        FROM (SELECT DISTINCT ON (l.item_id) l.item_id, ROUND(l.amount / l.qty, 2) AS unit_price
                FROM purchase_lines l JOIN purchases p ON p.id = l.purchase_id
               WHERE l.item_id IS NOT NULL AND l.qty > 0
               ORDER BY l.item_id, p.purchased_at DESC, l.id DESC) lp
        WHERE i.id = lp.item_id AND i.category IN ('Raw Material', 'Packaging') AND i.unit_cost <> lp.unit_price;
    """)
    cur.execute("""
        UPDATE items i SET unit_cost = c.cost
        FROM (SELECT r.product_id,
                     ROUND(COALESCE(SUM(rl.qty * m.unit_cost / NULLIF(m.content_qty, 0)), 0) / r.yield_qty, 2) AS cost
                FROM recipes r
                LEFT JOIN recipe_lines rl ON rl.product_id = r.product_id
                LEFT JOIN items m ON m.id = rl.material_id
               GROUP BY r.product_id, r.yield_qty) c
        WHERE i.id = c.product_id AND i.unit_cost <> c.cost;
    """)


def require_material(cur, name: str, item_id: Optional[int] = None) -> int:
    """Stock In lines must be an item from the Materials list (Raw Material / Packaging)."""
    if item_id:
        cur.execute("SELECT id FROM items WHERE id = %s AND category IN ('Raw Material', 'Packaging');", (item_id,))
        r = cur.fetchone()
        if r:
            return r["id"]
    mid = match_item(cur, name)
    if mid:
        cur.execute("SELECT 1 FROM items WHERE id = %s AND category IN ('Raw Material', 'Packaging');", (mid,))
        if cur.fetchone():
            return mid
    raise HTTPException(400, f"“{(name or '').strip() or 'That item'}” isn't in your Materials list. Add it under Materials first, then pick it here.")


def match_item(cur, name: str) -> Optional[int]:
    """Links a typed purchase line (e.g. "Powdered milk (1 kg)") to its material."""
    n = (name or "").strip().lower()
    if not n:
        return None
    cur.execute("""
        SELECT id FROM items
        WHERE lower(CASE WHEN variant <> '' THEN name || ' (' || variant || ')' ELSE name END) = %s
           OR (lower(name) = %s AND variant = '')
        ORDER BY (category IN ('Raw Material', 'Packaging')) DESC, id LIMIT 1;
    """, (n, n))
    r = cur.fetchone()
    return r["id"] if r else None


@api.post("/items")
def create_item(p: ItemPayload):
    if not p.name.strip():
        raise HTTPException(400, "Product name is required.")
    with db() as conn, conn.cursor() as cur:
        try:
            cur.execute("""
                INSERT INTO items (name, category, variant, unit_cost, selling_price, active, base_unit, content_qty)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s) RETURNING *;
            """, (p.name.strip(), as_category(p.category), p.variant.strip(), as_money(p.unit_cost),
                  as_money(p.selling_price), p.active, p.base_unit.strip(), as_content(p.content_qty or 1)))
        except psycopg.errors.UniqueViolation:
            raise HTTPException(409, "That product + size already exists.")
        return one(cur)


@api.patch("/items/{item_id}")
def patch_item(item_id: int, changes: dict = Body(...)):
    if "name" in changes and not as_text(changes["name"]):
        raise HTTPException(400, "Product name can't be blank.")
    with db() as conn, conn.cursor() as cur:
        try:
            apply_patch(cur, "items", item_id, changes, ITEM_FIELDS)
        except psycopg.errors.UniqueViolation:
            raise HTTPException(409, "That product + size already exists.")
        refresh_costs(cur)
        cur.execute("SELECT * FROM items WHERE id = %s;", (item_id,))
        return one(cur)


@api.delete("/items/{item_id}")
def delete_item(item_id: int):
    """Past orders, purchases and counts keep their own copy of the name,
    so deleting a product never changes history."""
    with db() as conn:
        r = conn.execute("DELETE FROM items WHERE id = %s RETURNING id;", (item_id,)).fetchone()
    if not r:
        raise HTTPException(404, "Product not found.")
    return {"ok": True}


# ----------------------------------------------------------------------------
# Orders (open → completed / voided)
# ----------------------------------------------------------------------------

ORDER_SELECT = """
    SELECT o.*,
           COALESCE((SELECT json_agg(json_build_object(
                        'id', oi.id, 'item_id', oi.item_id, 'name', oi.name, 'variant', oi.variant,
                        'qty', oi.qty, 'unit_price', oi.unit_price, 'amount', oi.qty * oi.unit_price)
                        ORDER BY oi.id)
                     FROM order_items oi WHERE oi.order_id = o.id), '[]') AS items,
           COALESCE((SELECT SUM(oi.qty * oi.unit_price) FROM order_items oi WHERE oi.order_id = o.id), 0) AS subtotal,
           COALESCE((SELECT SUM(p.amount) FROM receivable_payments p WHERE p.order_id = o.id), 0) AS amount_paid,
           (SELECT c.tier FROM customers c WHERE c.id = o.customer_id) AS customer_tier
    FROM orders o
"""
ORDER_FIELDS = {"customer_name": as_text, "phone": as_text, "phone2": as_text, "address": as_text, "delivery_fee": as_money,
                "rider_name": as_text, "notes": as_text, "completed_at": as_timestamp, "delivery_at": as_timestamp,
                "payment_status": as_pay_status, "payment_method": as_sale_method}


def order_out(r):
    r = {k: clean(v) for k, v in r.items()}
    r["total"] = round(r["subtotal"] + r["delivery_fee"], 2)
    if r["payment_status"] == "credit":
        r["balance"] = round(r["total"] - r["amount_paid"], 2)
        r["receivable_status"] = ("cancelled" if r["status"] == "voided" else
                                  "settled" if r["balance"] <= 0 else "partial" if r["amount_paid"] > 0 else "unpaid")
    else:
        r["balance"] = 0
        r["receivable_status"] = None
    return r


def price_for(cur, customer_id: Optional[int], item_id: int):
    """A reseller's custom price if one is set, otherwise the normal price."""
    cur.execute("""
        SELECT i.name, i.variant, COALESCE(cp.price, i.selling_price) AS price
        FROM items i LEFT JOIN customer_prices cp ON cp.item_id = i.id AND cp.customer_id = %s
        WHERE i.id = %s;
    """, (customer_id, item_id))
    return cur.fetchone()


def fetch_order(cur, order_id: int):
    cur.execute(ORDER_SELECT + " WHERE o.id = %s;", (order_id,))
    r = cur.fetchone()
    if not r:
        raise HTTPException(404, "Order not found.")
    return order_out(r)


class OrderLineQty(BaseModel):
    qty: int = Field(ge=0, le=999)


class VoidPayload(BaseModel):
    reason: str = ""


@api.get("/orders/open")
def open_orders():
    with db() as conn, conn.cursor() as cur:
        cur.execute(ORDER_SELECT + " WHERE o.status = 'open' ORDER BY o.created_at;")
        return [order_out(r) for r in cur.fetchall()]


@api.get("/orders/history")
def order_history(date_from: Optional[date] = None, date_to: Optional[date] = None):
    """Completed and voided orders, newest first, dated by when they were
    finished (or voided, for orders cancelled before finishing)."""
    start, end = day_range(date_from, date_to)
    when = LOCAL_DAY.format(col="COALESCE(o.completed_at, o.voided_at)")
    with db() as conn, conn.cursor() as cur:
        cur.execute(ORDER_SELECT + f"""
            WHERE o.status IN ('completed', 'voided') AND {when} BETWEEN %s AND %s
            ORDER BY COALESCE(o.completed_at, o.voided_at) DESC, o.id DESC;
        """, (start, end))
        out = [order_out(r) for r in cur.fetchall()]
    done = [o for o in out if o["status"] == "completed"]
    return {
        "date_from": start, "date_to": end, "orders": out,
        "totals": {
            "orders": len(done),
            "items_subtotal": round(sum(o["subtotal"] for o in done), 2),
            "delivery_fees": round(sum(o["delivery_fee"] for o in done), 2),
            "grand_total": round(sum(o["total"] for o in done), 2),
            "on_credit": round(sum(o["total"] for o in done if o["payment_status"] == "credit"), 2),
            "voided": len(out) - len(done),
        },
    }


@api.get("/orders/schedule")
def order_schedule(date_from: Optional[date] = None, date_to: Optional[date] = None, include_open: bool = False):
    """Live and finished orders (not voided) by delivery day, earliest first.
    include_open=true also returns every open order (one trip instead of two)."""
    start = date_from or today_manila()
    end = date_to or start
    when = LOCAL_DAY.format(col="o.delivery_at")
    with db() as conn, conn.cursor() as cur:
        cur.execute(ORDER_SELECT + f"""
            WHERE o.status IN ('open', 'completed') AND {when} BETWEEN %s AND %s
            ORDER BY o.delivery_at, o.id;
        """, (start, end))
        out = {"date_from": start, "date_to": end, "orders": [order_out(r) for r in cur.fetchall()]}
        if include_open:
            cur.execute(ORDER_SELECT + " WHERE o.status = 'open' ORDER BY o.created_at;")
            out["open"] = [order_out(r) for r in cur.fetchall()]
        return out


@api.get("/orders/days")
def order_days(date_from: date, date_to: date):
    """How many orders each day has (for the dots on the calendar)."""
    when = LOCAL_DAY.format(col="delivery_at")
    with db() as conn, conn.cursor() as cur:
        cur.execute(f"""SELECT {when} AS d, COUNT(*) FILTER (WHERE status = 'open') AS open,
                               COUNT(*) FILTER (WHERE status = 'completed') AS done
                        FROM orders WHERE status IN ('open', 'completed') AND {when} BETWEEN %s AND %s
                        GROUP BY 1 ORDER BY 1;""", (date_from, date_to))
        return {str(r["d"]): {"open": r["open"], "done": r["done"]} for r in cur.fetchall()}


class NewOrderLine(BaseModel):
    item_id: int
    qty: int = Field(gt=0, le=999)


class NewOrderIn(BaseModel):
    items: List[NewOrderLine] = []
    customer_id: Optional[int] = None
    customer_name: str = ""
    phone: str = ""
    phone2: str = ""
    address: str = ""
    notes: str = ""
    rider_name: str = ""
    delivery_fee: float = 0
    delivery_at: Optional[datetime] = None
    payment_status: Optional[str] = None
    payment_method: Optional[str] = None


@api.post("/orders")
def create_order(p: Optional[NewOrderIn] = Body(default=None)):
    """Creates an open order. The POS sends the tapped items plus the details
    from the confirm screen; the order then closes itself at the end of its delivery day."""
    p = p or NewOrderIn()
    with db() as conn, conn.cursor() as cur:
        cust = None
        if p.customer_id:
            cur.execute("SELECT * FROM customers WHERE id = %s;", (p.customer_id,))
            cust = cur.fetchone()
            if not cust:
                raise HTTPException(404, "That client no longer exists — pick again.")
        name = p.customer_name.strip() or (cust["name"] if cust else "")
        pay = as_pay_status(p.payment_status) if p.payment_status else ("credit" if cust and cust["tier"] == "Reseller" else "paid")
        if pay == "credit" and not name:
            raise HTTPException(400, "A credit order needs a customer name so it can be collected later.")
        cur.execute("""INSERT INTO orders (customer_id, customer_name, phone, phone2, address, notes, rider_name,
                                           delivery_fee, delivery_at, payment_status, payment_method)
                       VALUES (%s,%s,%s,%s,%s,%s,%s,%s,COALESCE(%s, now()),%s,COALESCE(%s, 'GCash'))
                       RETURNING id;""",
                    (cust["id"] if cust else None, name,
                     p.phone.strip() or (cust["phone"] if cust else ""), p.phone2.strip() or (cust["phone2"] if cust else ""),
                     p.address.strip() or (cust["address"] if cust else ""), p.notes.strip(),
                     p.rider_name.strip(), as_money(p.delivery_fee or 0), p.delivery_at, pay,
                     as_sale_method(p.payment_method) if p.payment_method else None))
        order_id = cur.fetchone()["id"]
        for line in p.items:
            item = price_for(cur, cust["id"] if cust else None, line.item_id)
            if not item:
                raise HTTPException(404, "A product on the ticket no longer exists — reload and try again.")
            cur.execute("""
                INSERT INTO order_items (order_id, item_id, name, variant, qty, unit_price)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (order_id, item_id) DO UPDATE SET qty = order_items.qty + EXCLUDED.qty;
            """, (order_id, line.item_id, item["name"], item["variant"], line.qty, item["price"]))
        o = fetch_order(cur, order_id)
        if p.items and name:
            remember_customer(cur, o)          # new names become saved clients right away
            o = fetch_order(cur, order_id)
        return o


@api.get("/orders/{order_id}")
def get_order(order_id: int):
    with db() as conn, conn.cursor() as cur:
        return fetch_order(cur, order_id)


@api.patch("/orders/{order_id}")
def patch_order(order_id: int, changes: dict = Body(...)):
    with db() as conn, conn.cursor() as cur:
        o = fetch_order(cur, order_id)
        if o["status"] == "voided":
            raise HTTPException(400, "This order is voided and can't be edited.")
        if "completed_at" in changes and o["status"] != "completed":
            raise HTTPException(400, "Only a finished order has a completed date.")
        if o["status"] == "completed":
            assert_unlocked(cur, manila_day(o["completed_at"]), "this order")
            if "completed_at" in changes:
                assert_unlocked(cur, manila_day(as_timestamp(changes["completed_at"])), "orders on that day")
            if changes.get("payment_status") == "paid" and o["amount_paid"] > 0:
                raise HTTPException(400, "Payments were already logged against this credit sale — remove them in Receivables first.")
        apply_patch(cur, "orders", order_id, changes, ORDER_FIELDS, ", updated_at = now()")
        return fetch_order(cur, order_id)


@api.put("/orders/{order_id}/items/{item_id}")
def set_order_item(order_id: int, item_id: int, p: OrderLineQty):
    """Sets how many of a product are in an open order (0 removes it)."""
    with db() as conn, conn.cursor() as cur:
        o = fetch_order(cur, order_id)
        if o["status"] != "open":
            raise HTTPException(400, "Items can only be changed while the order is open.")
        if p.qty == 0:
            cur.execute("DELETE FROM order_items WHERE order_id = %s AND item_id = %s;", (order_id, item_id))
        else:
            item = price_for(cur, o["customer_id"], item_id)
            if not item:
                raise HTTPException(404, "Product not found.")
            cur.execute("""
                INSERT INTO order_items (order_id, item_id, name, variant, qty, unit_price)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (order_id, item_id) DO UPDATE SET qty = EXCLUDED.qty;
            """, (order_id, item_id, item["name"], item["variant"], p.qty, item["price"]))
        cur.execute("UPDATE orders SET updated_at = now() WHERE id = %s;", (order_id,))
        return fetch_order(cur, order_id)


class OrderCustomerIn(BaseModel):
    customer_id: Optional[int] = None


@api.put("/orders/{order_id}/customer")
def set_order_customer(order_id: int, p: OrderCustomerIn):
    """Links (or unlinks) a saved customer: copies their details onto the
    order and re-prices the items with their price list."""
    with db() as conn, conn.cursor() as cur:
        o = fetch_order(cur, order_id)
        if o["status"] != "open":
            raise HTTPException(400, "The customer can only be changed while the order is open.")
        if p.customer_id is None:
            cur.execute("UPDATE orders SET customer_id = NULL, updated_at = now() WHERE id = %s;", (order_id,))
        else:
            cur.execute("SELECT * FROM customers WHERE id = %s;", (p.customer_id,))
            c = cur.fetchone()
            if not c:
                raise HTTPException(404, "Customer not found.")
            cur.execute("""UPDATE orders SET customer_id=%s, customer_name=%s, phone=%s, phone2=%s, address=%s, notes=%s,
                                  payment_status = CASE WHEN %s = 'Reseller' THEN 'credit' ELSE payment_status END,
                                  updated_at=now() WHERE id=%s;""",
                        (c["id"], c["name"], c["phone"], c["phone2"], c["address"], c["notes"], c["tier"], order_id))
        cur.execute("SELECT item_id FROM order_items WHERE order_id = %s AND item_id IS NOT NULL;", (order_id,))
        for r in cur.fetchall():
            item = price_for(cur, p.customer_id, r["item_id"])
            cur.execute("UPDATE order_items SET unit_price = %s WHERE order_id = %s AND item_id = %s;",
                        (item["price"], order_id, r["item_id"]))
        return fetch_order(cur, order_id)


def remember_customer(cur, o):
    """New names typed on an order become saved customers when the order is
    finished. Saved customers get blank details filled in from the order."""
    if o["customer_id"]:
        cur.execute("""UPDATE customers SET
                         phone   = CASE WHEN phone = ''   THEN %s ELSE phone END,
                         phone2  = CASE WHEN phone2 = ''  THEN %s ELSE phone2 END,
                         address = CASE WHEN address = '' THEN %s ELSE address END
                       WHERE id = %s;""", (o["phone"], o.get("phone2", ""), o["address"], o["customer_id"]))
        return
    name = o["customer_name"].strip()
    if not name:
        return
    cur.execute("""SELECT id FROM customers WHERE lower(name) = lower(%s)
                   AND (phone = %s OR phone = '' OR %s = '') ORDER BY id LIMIT 1;""", (name, o["phone"], o["phone"]))
    found = cur.fetchone()
    if found:
        cid = found["id"]
    else:
        cur.execute("INSERT INTO customers (name, phone, phone2, address) VALUES (%s, %s, %s, %s) RETURNING id;",
                    (name, o["phone"], o.get("phone2", ""), o["address"]))
        cid = cur.fetchone()["id"]
    cur.execute("UPDATE orders SET customer_id = %s WHERE id = %s;", (cid, o["id"]))


@api.post("/orders/{order_id}/finish")
def finish_order(order_id: int):
    with db() as conn, conn.cursor() as cur:
        o = fetch_order(cur, order_id)
        if o["status"] != "open":
            raise HTTPException(400, f"This order is already {o['status']}.")
        if not o["items"]:
            raise HTTPException(400, "Add at least one item before finishing the order.")
        if o["payment_status"] == "credit" and not o["customer_name"].strip():
            raise HTTPException(400, "A credit sale needs a customer name so it can be collected later.")
        assert_unlocked(cur, today_manila(), "sales for today")
        cur.execute("UPDATE orders SET status='completed', completed_at=now(), updated_at=now() WHERE id=%s;",
                    (order_id,))
        remember_customer(cur, o)
        return fetch_order(cur, order_id)


@api.post("/orders/{order_id}/void")
def void_order(order_id: int, p: VoidPayload):
    with db() as conn, conn.cursor() as cur:
        o = fetch_order(cur, order_id)
        if o["status"] == "voided":
            raise HTTPException(400, "This order is already voided.")
        if o["status"] == "completed":
            assert_unlocked(cur, manila_day(o["completed_at"]), "this order")
        cur.execute("""UPDATE orders SET status='voided', voided_at=now(), void_reason=%s, updated_at=now()
                       WHERE id=%s;""", (p.reason.strip() or None, order_id))
        return fetch_order(cur, order_id)


@api.delete("/orders/{order_id}")
def delete_order(order_id: int):
    """Permanently removes an order (open, finished or voided), its items and any
    payments logged against it. Blocked only when it touches a reconciled (locked) day."""
    with db() as conn, conn.cursor() as cur:
        o = fetch_order(cur, order_id)
        if o["status"] == "completed":
            assert_unlocked(cur, manila_day(o["completed_at"]), "this order")
        cur.execute("SELECT paid_at FROM receivable_payments WHERE order_id = %s;", (order_id,))
        for r in cur.fetchall():
            assert_unlocked(cur, manila_day(r["paid_at"]), "payments for this order")
        cur.execute("DELETE FROM orders WHERE id = %s;", (order_id,))
    return {"ok": True}


# ----------------------------------------------------------------------------
# Purchases and Expenses — same shape: a header, several lines, attachments
# ----------------------------------------------------------------------------

class AttachmentIn(BaseModel):
    filename: str = ""
    mime: str
    data_b64: str


class PurchaseLineIn(BaseModel):
    item_id: Optional[int] = None
    item_name: str
    qty: float = 1
    amount: float = 0


class PurchaseIn(BaseModel):
    purchased_at: Optional[datetime] = None
    payment_method: str = "Gino"
    notes: str = ""
    lines: List[PurchaseLineIn]
    attachments: List[AttachmentIn] = []


class ExpenseLineIn(BaseModel):
    particulars: str
    amount: float = 0


class ExpenseIn(BaseModel):
    spent_at: Optional[datetime] = None
    payment_method: str = "Gino"
    notes: str = ""
    lines: List[ExpenseLineIn]
    attachments: List[AttachmentIn] = []


def save_attachments(cur, owner_type: str, owner_id: int, files: List[AttachmentIn]):
    for f in files:
        if not (f.mime.startswith("image/") or f.mime == "application/pdf"):
            raise HTTPException(400, "Only photos and PDFs can be attached.")
        try:
            data = base64.b64decode(f.data_b64.split(",")[-1])
        except Exception:
            raise HTTPException(400, "Couldn't read the attached file.")
        if len(data) > MAX_ATTACHMENT_BYTES:
            raise HTTPException(400, f"“{f.filename or 'Attachment'}” is too large (max 6 MB).")
        cur.execute("INSERT INTO attachments (owner_type, owner_id, filename, mime, data) VALUES (%s,%s,%s,%s,%s);",
                    (owner_type, owner_id, f.filename[:200], f.mime, data))


LEDGERS = {
    "purchase": {
        "path": "purchases", "table": "purchases", "lines": "purchase_lines", "fk": "purchase_id",
        "when": "purchased_at",
        "line_json": "'item_id', l.item_id, 'item_name', l.item_name, 'qty', l.qty, 'amount', l.amount",
        "header_fields": {"purchased_at": as_timestamp, "payment_method": as_payment, "notes": as_text},
        "line_fields": {"item_name": as_text, "qty": as_qty, "amount": as_money},
        "required_line_field": "item_name",
    },
    "expense": {
        "path": "expenses", "table": "expenses", "lines": "expense_lines", "fk": "expense_id",
        "when": "spent_at",
        "line_json": "'particulars', l.particulars, 'amount', l.amount",
        "header_fields": {"spent_at": as_timestamp, "payment_method": as_payment, "notes": as_text},
        "line_fields": {"particulars": as_text, "amount": as_money},
        "required_line_field": "particulars",
    },
}


def ledger_select(kind: str) -> str:
    L = LEDGERS[kind]
    return f"""
        SELECT h.*,
               COALESCE((SELECT json_agg(json_build_object('id', l.id, {L['line_json']}) ORDER BY l.id)
                         FROM {L['lines']} l WHERE l.{L['fk']} = h.id), '[]') AS lines,
               COALESCE((SELECT SUM(l.amount) FROM {L['lines']} l WHERE l.{L['fk']} = h.id), 0) AS total,
               COALESCE((SELECT json_agg(json_build_object('id', a.id, 'filename', a.filename, 'mime', a.mime) ORDER BY a.id)
                         FROM attachments a WHERE a.owner_type = '{kind}' AND a.owner_id = h.id), '[]') AS attachments
        FROM {L['table']} h
    """


def fetch_ledger(cur, kind: str, row_id: int):
    cur.execute(ledger_select(kind) + " WHERE h.id = %s;", (row_id,))
    r = one(cur)
    if not r:
        raise HTTPException(404, "Not found.")
    return r


@api.get("/purchases")
def list_purchases(date_from: Optional[date] = None, date_to: Optional[date] = None):
    return list_ledger("purchase", date_from, date_to)


@api.post("/purchases")
def create_purchase(p: PurchaseIn):
    lines = [l for l in p.lines if l.item_name.strip()]
    if not lines:
        raise HTTPException(400, "Add at least one item.")
    with db() as conn, conn.cursor() as cur:
        cur.execute("""INSERT INTO purchases (purchased_at, payment_method, notes)
                       VALUES (COALESCE(%s, now()), %s, %s) RETURNING id;""",
                    (p.purchased_at, as_payment(p.payment_method), p.notes.strip()))
        pid = cur.fetchone()["id"]
        for l in lines:
            cur.execute("INSERT INTO purchase_lines (purchase_id, item_id, item_name, qty, amount) VALUES (%s,%s,%s,%s,%s);",
                        (pid, require_material(cur, l.item_name, l.item_id), l.item_name.strip(), as_qty(l.qty), as_money(l.amount)))
        save_attachments(cur, "purchase", pid, p.attachments)
        refresh_costs(cur)
        return fetch_ledger(cur, "purchase", pid)


@api.get("/expenses")
def list_expenses(date_from: Optional[date] = None, date_to: Optional[date] = None):
    return list_ledger("expense", date_from, date_to)


@api.post("/expenses")
def create_expense(p: ExpenseIn):
    lines = [l for l in p.lines if l.particulars.strip()]
    if not lines:
        raise HTTPException(400, "Add at least one line.")
    with db() as conn, conn.cursor() as cur:
        cur.execute("""INSERT INTO expenses (spent_at, payment_method, notes)
                       VALUES (COALESCE(%s, now()), %s, %s) RETURNING id;""",
                    (p.spent_at, as_payment(p.payment_method), p.notes.strip()))
        eid = cur.fetchone()["id"]
        for l in lines:
            cur.execute("INSERT INTO expense_lines (expense_id, particulars, amount) VALUES (%s,%s,%s);",
                        (eid, l.particulars.strip(), as_money(l.amount)))
        save_attachments(cur, "expense", eid, p.attachments)
        return fetch_ledger(cur, "expense", eid)


def list_ledger(kind: str, date_from, date_to):
    L = LEDGERS[kind]
    start, end = day_range(date_from, date_to)
    with db() as conn, conn.cursor() as cur:
        cur.execute(ledger_select(kind) + f"""
            WHERE {LOCAL_DAY.format(col='h.' + L['when'])} BETWEEN %s AND %s
            ORDER BY h.{L['when']} DESC, h.id DESC;
        """, (start, end))
        out = rows(cur)
    return {"date_from": start, "date_to": end, "entries": out,
            "total": round(sum(e["total"] for e in out), 2)}


def register_ledger_routes(kind: str):
    """Edit/delete routes shared by purchases and expenses."""
    L = LEDGERS[kind]
    base = "/" + L["path"]

    def patch_header(row_id: int, changes: dict = Body(...)):
        with db() as conn, conn.cursor() as cur:
            apply_patch(cur, L["table"], row_id, changes, L["header_fields"])
            refresh_costs(cur)
            return fetch_ledger(cur, kind, row_id)

    def delete_entry(row_id: int):
        with db() as conn, conn.cursor() as cur:
            cur.execute(f"DELETE FROM {L['table']} WHERE id = %s RETURNING id;", (row_id,))
            if not cur.fetchone():
                raise HTTPException(404, "Not found.")
            cur.execute("DELETE FROM attachments WHERE owner_type = %s AND owner_id = %s;", (kind, row_id))
            refresh_costs(cur)
        return {"ok": True}

    def add_line(row_id: int, line: dict = Body(...)):
        with db() as conn, conn.cursor() as cur:
            fetch_ledger(cur, kind, row_id)
            if kind == "purchase":
                cur.execute("INSERT INTO purchase_lines (purchase_id, item_id, item_name, qty, amount) VALUES (%s,%s,%s,%s,%s);",
                            (row_id, require_material(cur, line.get("item_name"), line.get("item_id")), as_text(line.get("item_name")),
                             as_qty(line.get("qty", 1)), as_money(line.get("amount", 0))))
                refresh_costs(cur)
            else:
                cur.execute("INSERT INTO expense_lines (expense_id, particulars, amount) VALUES (%s,%s,%s);",
                            (row_id, as_text(line.get("particulars")) or "New line", as_money(line.get("amount", 0))))
            return fetch_ledger(cur, kind, row_id)

    def patch_line(row_id: int, line_id: int, changes: dict = Body(...)):
        req = L["required_line_field"]
        if req in changes and not as_text(changes[req]):
            raise HTTPException(400, "That field can't be blank.")
        with db() as conn, conn.cursor() as cur:
            cur.execute(f"SELECT 1 FROM {L['lines']} WHERE id = %s AND {L['fk']} = %s;", (line_id, row_id))
            if not cur.fetchone():
                raise HTTPException(404, "Line not found.")
            apply_patch(cur, L["lines"], line_id, changes, L["line_fields"])
            if kind == "purchase":
                if "item_name" in changes:
                    cur.execute("UPDATE purchase_lines SET item_id = %s WHERE id = %s;", (require_material(cur, changes["item_name"]), line_id))
                refresh_costs(cur)
            return fetch_ledger(cur, kind, row_id)

    def delete_line(row_id: int, line_id: int):
        with db() as conn, conn.cursor() as cur:
            cur.execute(f"SELECT COUNT(*) AS n FROM {L['lines']} WHERE {L['fk']} = %s;", (row_id,))
            if cur.fetchone()["n"] <= 1:
                raise HTTPException(400, "That's the last line — delete the whole entry instead.")
            cur.execute(f"DELETE FROM {L['lines']} WHERE id = %s AND {L['fk']} = %s RETURNING id;", (line_id, row_id))
            if not cur.fetchone():
                raise HTTPException(404, "Line not found.")
            refresh_costs(cur)
            return fetch_ledger(cur, kind, row_id)

    def add_files(row_id: int, files: List[AttachmentIn]):
        with db() as conn, conn.cursor() as cur:
            fetch_ledger(cur, kind, row_id)
            save_attachments(cur, kind, row_id, files)
            return fetch_ledger(cur, kind, row_id)

    api.add_api_route(base + "/{row_id}", patch_header, methods=["PATCH"])
    api.add_api_route(base + "/{row_id}", delete_entry, methods=["DELETE"])
    api.add_api_route(base + "/{row_id}/lines", add_line, methods=["POST"])
    api.add_api_route(base + "/{row_id}/lines/{line_id}", patch_line, methods=["PATCH"])
    api.add_api_route(base + "/{row_id}/lines/{line_id}", delete_line, methods=["DELETE"])
    api.add_api_route(base + "/{row_id}/attachments", add_files, methods=["POST"])


register_ledger_routes("purchase")
register_ledger_routes("expense")


@api.delete("/attachments/{attachment_id}")
def delete_attachment(attachment_id: int):
    with db() as conn:
        r = conn.execute("DELETE FROM attachments WHERE id = %s RETURNING id;", (attachment_id,)).fetchone()
    if not r:
        raise HTTPException(404, "Attachment not found.")
    return {"ok": True}


@app.get("/files/{attachment_id}")
def get_attachment(attachment_id: int, token: str = Query(default="")):
    """Serves a proof photo/PDF. The login token rides in the link because
    an <img> tag can't send a login header."""
    if not session_valid(token):
        raise HTTPException(401, "Not logged in.")
    with db() as conn:
        r = conn.execute("SELECT mime, data, filename FROM attachments WHERE id = %s;", (attachment_id,)).fetchone()
    if not r:
        raise HTTPException(404, "Attachment not found.")
    safe_name = "".join(ch for ch in (r["filename"] or "proof") if ch.isalnum() or ch in "._- ")[:80] or "proof"
    return Response(content=bytes(r["data"]), media_type=r["mime"],
                    headers={"Cache-Control": "private, max-age=86400",
                             "Content-Disposition": f'inline; filename="{safe_name}"'})


# ----------------------------------------------------------------------------
# Production log (record only)
# ----------------------------------------------------------------------------

class ProductionRow(BaseModel):
    item_id: int
    qty: float = Field(gt=0)


class ProductionIn(BaseModel):
    produced_at: Optional[datetime] = None
    notes: str = ""
    rows: List[ProductionRow]


PRODUCTION_FIELDS = {"produced_at": as_timestamp, "qty": as_qty, "notes": as_text}


@api.get("/production")
def list_production(date_from: Optional[date] = None, date_to: Optional[date] = None):
    start, end = day_range(date_from, date_to)
    with db() as conn, conn.cursor() as cur:
        cur.execute(f"""
            SELECT * FROM production WHERE {LOCAL_DAY.format(col='produced_at')} BETWEEN %s AND %s
            ORDER BY produced_at DESC, id DESC;
        """, (start, end))
        entries = rows(cur)
    totals = {}
    for e in entries:
        key = e["item_name"] + (f" ({e['variant']})" if e["variant"] else "")
        totals[key] = totals.get(key, 0) + e["qty"]
    return {"date_from": start, "date_to": end, "entries": entries,
            "totals": [{"product": k, "qty": v} for k, v in sorted(totals.items())]}


@api.post("/production")
def create_production(p: ProductionIn):
    if not p.rows:
        raise HTTPException(400, "Add at least one product.")
    out = []
    with db() as conn, conn.cursor() as cur:
        for r in p.rows:
            cur.execute("SELECT name, variant FROM items WHERE id = %s;", (r.item_id,))
            item = cur.fetchone()
            if not item:
                raise HTTPException(404, "Product not found.")
            cur.execute("""
                INSERT INTO production (produced_at, item_id, item_name, variant, qty, notes)
                VALUES (COALESCE(%s, now()), %s, %s, %s, %s, %s) RETURNING *;
            """, (p.produced_at, r.item_id, item["name"], item["variant"], r.qty, p.notes.strip()))
            out.append(one(cur))
    return out


@api.patch("/production/{row_id}")
def patch_production(row_id: int, changes: dict = Body(...)):
    if "qty" in changes and as_qty(changes["qty"]) <= 0:
        raise HTTPException(400, "Quantity must be more than 0.")
    with db() as conn, conn.cursor() as cur:
        apply_patch(cur, "production", row_id, changes, PRODUCTION_FIELDS)
        cur.execute("SELECT * FROM production WHERE id = %s;", (row_id,))
        return one(cur)


@api.delete("/production/{row_id}")
def delete_production(row_id: int):
    with db() as conn:
        r = conn.execute("DELETE FROM production WHERE id = %s RETURNING id;", (row_id,)).fetchone()
    if not r:
        raise HTTPException(404, "Not found.")
    return {"ok": True}


# ----------------------------------------------------------------------------
# Monthly inventory counts
# ----------------------------------------------------------------------------

class CountLineIn(BaseModel):
    item_id: int
    qty: float = Field(ge=0)


class CountIn(BaseModel):
    count_date: Optional[date] = None
    notes: str = ""
    lines: List[CountLineIn]


COUNT_SELECT = """
    SELECT c.*,
           COALESCE((SELECT SUM(l.qty * l.unit_cost) FROM count_lines l WHERE l.count_id = c.id), 0) AS total_value,
           (SELECT COUNT(*) FROM count_lines l WHERE l.count_id = c.id) AS line_count
    FROM inventory_counts c
"""


def fetch_count(cur, count_id: int):
    cur.execute(COUNT_SELECT + " WHERE c.id = %s;", (count_id,))
    head = one(cur)
    if not head:
        raise HTTPException(404, "Count not found.")
    cur.execute("""
        SELECT id, item_id, name, variant, category, qty, unit_cost, ROUND(qty * unit_cost, 2) AS value
        FROM count_lines WHERE count_id = %s
        ORDER BY """ + CATEGORY_ORDER + """, name, variant;
    """, (count_id,))
    head["lines"] = rows(cur)
    return head


@api.get("/counts")
def list_counts():
    with db() as conn, conn.cursor() as cur:
        cur.execute(COUNT_SELECT + " ORDER BY c.count_date DESC, c.id DESC;")
        return rows(cur)


@api.get("/counts/matrix")
def counts_matrix():
    """Every count as a column, every item as a row — for the Physical Count
    and Physical Count (Value) grids. Oldest count first."""
    with db() as conn, conn.cursor() as cur:
        cur.execute(COUNT_SELECT + " ORDER BY c.count_date, c.id;")
        counts = rows(cur)
        cur.execute(f"""
            SELECT l.count_id, l.item_id, COALESCE(i.name, l.name) AS name, COALESCE(i.variant, l.variant) AS variant,
                   COALESCE(i.category, l.category) AS category, l.qty, l.unit_cost
            FROM count_lines l LEFT JOIN items i ON i.id = l.item_id
            ORDER BY {CATEGORY_ORDER.replace('category', 'COALESCE(i.category, l.category)')}, 3, 4;
        """)
        lines = rows(cur)
    return {"counts": counts, "lines": lines}


@api.get("/counts/checklist")
def count_checklist():
    """Every active product, with what was counted last time (as a hint)."""
    with db() as conn, conn.cursor() as cur:
        cur.execute(f"""
            SELECT i.id AS item_id, i.name, i.variant, i.category, i.unit_cost,
                   (SELECT l.qty FROM count_lines l JOIN inventory_counts c ON c.id = l.count_id
                     WHERE l.item_id = i.id ORDER BY c.count_date DESC, c.id DESC LIMIT 1) AS last_qty
            FROM items i WHERE i.active ORDER BY {ITEM_ORDER.replace('category', 'i.category')};
        """)
        return rows(cur)


@api.post("/counts")
def create_count(p: CountIn):
    if not p.lines:
        raise HTTPException(400, "The count is empty.")
    with db() as conn, conn.cursor() as cur:
        cur.execute("INSERT INTO inventory_counts (count_date, notes) VALUES (%s, %s) RETURNING id;",
                    (p.count_date or today_manila(), p.notes.strip()))
        cid = cur.fetchone()["id"]
        for l in p.lines:
            cur.execute("SELECT name, variant, category, unit_cost FROM items WHERE id = %s;", (l.item_id,))
            item = cur.fetchone()
            if not item:
                raise HTTPException(404, "A product on the checklist no longer exists — reload and try again.")
            cur.execute("""
                INSERT INTO count_lines (count_id, item_id, name, variant, category, qty, unit_cost)
                VALUES (%s, %s, %s, %s, %s, %s, %s);
            """, (cid, l.item_id, item["name"], item["variant"], item["category"], l.qty, item["unit_cost"]))
        return fetch_count(cur, cid)


@api.get("/counts/{count_id}")
def get_count(count_id: int):
    with db() as conn, conn.cursor() as cur:
        return fetch_count(cur, count_id)


@api.patch("/counts/{count_id}")
def patch_count(count_id: int, changes: dict = Body(...)):
    with db() as conn, conn.cursor() as cur:
        apply_patch(cur, "inventory_counts", count_id, changes, {"count_date": as_date, "notes": as_text})
        return fetch_count(cur, count_id)


@api.patch("/counts/{count_id}/lines/{line_id}")
def patch_count_line(count_id: int, line_id: int, changes: dict = Body(...)):
    with db() as conn, conn.cursor() as cur:
        cur.execute("SELECT 1 FROM count_lines WHERE id = %s AND count_id = %s;", (line_id, count_id))
        if not cur.fetchone():
            raise HTTPException(404, "Line not found.")
        apply_patch(cur, "count_lines", line_id, changes, {"qty": as_qty, "unit_cost": as_money})
        return fetch_count(cur, count_id)


@api.delete("/counts/{count_id}")
def delete_count(count_id: int):
    with db() as conn:
        r = conn.execute("DELETE FROM inventory_counts WHERE id = %s RETURNING id;", (count_id,)).fetchone()
    if not r:
        raise HTTPException(404, "Count not found.")
    return {"ok": True}


# ----------------------------------------------------------------------------
# Reports — profit per count period
# ----------------------------------------------------------------------------

def period_numbers(cur, start_excl: Optional[date], end_incl: date):
    """Sales, purchases, expenses and production for Manila days after
    start_excl, up to and including end_incl."""
    q = {"lo": start_excl or date(2000, 1, 1), "hi": end_incl}
    day = lambda col: LOCAL_DAY.format(col=col)
    cur.execute(f"""
        SELECT COUNT(*) AS orders,
               COALESCE(SUM((SELECT SUM(oi.qty * oi.unit_price) FROM order_items oi WHERE oi.order_id = o.id)), 0) AS sales,
               COALESCE(SUM(o.delivery_fee), 0) AS delivery_fees
        FROM orders o
        WHERE o.status = 'completed' AND {day('o.completed_at')} > %(lo)s AND {day('o.completed_at')} <= %(hi)s;
    """, q)
    s = one(cur)
    cur.execute(f"""
        SELECT COALESCE(SUM(l.amount), 0) AS total FROM purchase_lines l JOIN purchases p ON p.id = l.purchase_id
        WHERE {day('p.purchased_at')} > %(lo)s AND {day('p.purchased_at')} <= %(hi)s;
    """, q)
    purchases = one(cur)["total"]
    cur.execute(f"""
        SELECT COALESCE(SUM(l.amount), 0) AS total FROM expense_lines l JOIN expenses e ON e.id = l.expense_id
        WHERE {day('e.spent_at')} > %(lo)s AND {day('e.spent_at')} <= %(hi)s;
    """, q)
    expenses = one(cur)["total"]
    cur.execute(f"""
        SELECT COALESCE(SUM(qty), 0) AS units FROM production
        WHERE {day('produced_at')} > %(lo)s AND {day('produced_at')} <= %(hi)s;
    """, q)
    produced = one(cur)["units"]
    return {"orders": s["orders"], "sales": s["sales"], "delivery_fees": s["delivery_fees"],
            "purchases": purchases, "expenses": expenses, "units_produced": produced}


def build_periods(cur):
    cur.execute(COUNT_SELECT + " ORDER BY c.count_date, c.id;")
    counts = rows(cur)
    periods, prev = [], None
    for c in counts:
        n = period_numbers(cur, prev["count_date"] if prev else None, c["count_date"])
        p = {"count_id": c["id"], "period_start": prev["count_date"] if prev else None,
             "period_end": c["count_date"], "ending_inventory": round(c["total_value"], 2),
             "beginning_inventory": round(prev["total_value"], 2) if prev else None, **n}
        if prev:
            if prev["count_date"] == c["count_date"]:
                p["warning"] = "Two counts on the same day — delete one of them."
            p["cogs"] = round(p["beginning_inventory"] + n["purchases"] - p["ending_inventory"], 2)
            p["gross_profit"] = round(n["sales"] - p["cogs"], 2)
            p["net_profit"] = round(p["gross_profit"] - n["expenses"], 2)
            p["gross_margin_pct"] = round(p["gross_profit"] / n["sales"] * 100, 1) if n["sales"] else None
        else:
            p["opening"] = True
        periods.append(p)
        prev = c
    current = period_numbers(cur, prev["count_date"] if prev else None, today_manila())
    current.update({"period_start": prev["count_date"] if prev else None, "period_end": today_manila(),
                    "beginning_inventory": round(prev["total_value"], 2) if prev else None})
    return {"periods": list(reversed(periods)), "current": current}


@api.get("/reports/periods")
def report_periods():
    """One row per count (the first is the opening balance, so no COGS),
    newest first, plus the running period since the latest count."""
    with db() as conn, conn.cursor() as cur:
        return build_periods(cur)


@api.get("/dashboard")
def dashboard(date_from: Optional[date] = None, date_to: Optional[date] = None):
    """Gross sales and OpEx for any range. COGS and net profit only exist per
    count period (periodic inventory), so they're filled in when the range
    matches a count period exactly."""
    t = today_manila()
    start, end = (date_from or t), (date_to or t)
    with db() as conn, conn.cursor() as cur:
        n = period_numbers(cur, start - timedelta(days=1), end)
        rep = build_periods(cur)
        match = next((p for p in rep["periods"]
                      if not p.get("opening") and p["period_start"] + timedelta(days=1) == start and p["period_end"] == end), None)
        cur.execute("SELECT COUNT(*) AS n FROM orders WHERE status = 'open';")
        open_n = cur.fetchone()["n"]
        receivables = outstanding_receivables(cur)
        cur.execute(f"""
            SELECT COALESCE(SUM(l.amount), 0) AS total FROM (
              SELECT (SELECT SUM(amount) FROM purchase_lines WHERE purchase_id = p.id) AS amount
                FROM purchases p WHERE p.payment_method IN ('Gino', 'Credit Card') AND p.settled_at IS NULL
              UNION ALL
              SELECT (SELECT SUM(amount) FROM expense_lines WHERE expense_id = e.id)
                FROM expenses e WHERE e.payment_method IN ('Gino', 'Credit Card') AND e.settled_at IS NULL) l;
        """)
        liabilities = one(cur)["total"]
        cur.execute(f"""
            SELECT COUNT(DISTINCT d) AS n FROM (
              SELECT {LOCAL_DAY.format(col='completed_at')} AS d FROM orders
               WHERE status = 'completed' AND payment_status = 'paid'
              UNION SELECT {LOCAL_DAY.format(col='paid_at')} FROM receivable_payments) x
            WHERE d < %s AND d NOT IN (SELECT recon_date FROM reconciliations WHERE locked);
        """, (t,))
        unreconciled = cur.fetchone()["n"]
    return {
        "date_from": start, "date_to": end, "today": t,
        "gross_sales": n["sales"], "delivery_fees": n["delivery_fees"], "opex": n["expenses"],
        "purchases": n["purchases"], "orders": n["orders"], "units_produced": n["units_produced"],
        "cogs": match["cogs"] if match else None,
        "net_profit": match["net_profit"] if match else None,
        "gross_profit": match["gross_profit"] if match else None,
        "matched_period": match,
        "open_orders": open_n, "receivables_outstanding": receivables, "liabilities_unpaid": liabilities,
        "unreconciled_days": unreconciled,
        "periods": rep["periods"], "current_period": rep["current"],
    }


# ----------------------------------------------------------------------------
# Customers & resellers
# ----------------------------------------------------------------------------

class CustomerIn(BaseModel):
    name: str
    phone: str = ""
    phone2: str = ""
    address: str = ""
    notes: str = ""
    tier: str = "Retail"


CUSTOMER_FIELDS = {"name": as_text, "phone": as_text, "phone2": as_text, "address": as_text, "notes": as_text,
                   "tier": as_tier, "active": as_bool}
CUSTOMER_STATS = """
    SELECT c.*,
           (SELECT COUNT(*) FROM orders o WHERE o.customer_id = c.id AND o.status = 'completed') AS order_count,
           (SELECT COALESCE(SUM(oi.qty * oi.unit_price), 0)
              FROM orders o JOIN order_items oi ON oi.order_id = o.id
             WHERE o.customer_id = c.id AND o.status = 'completed') AS items_total,
           (SELECT MAX(o.completed_at) FROM orders o WHERE o.customer_id = c.id AND o.status = 'completed') AS last_order_at,
           (SELECT COUNT(*) FROM customer_prices cp WHERE cp.customer_id = c.id) AS custom_prices
    FROM customers c
"""


def customer_balance(cur, customer_id: int) -> float:
    cur.execute("""
        SELECT COALESCE(SUM(
          (SELECT COALESCE(SUM(oi.qty * oi.unit_price), 0) FROM order_items oi WHERE oi.order_id = o.id) + o.delivery_fee
          - (SELECT COALESCE(SUM(p.amount), 0) FROM receivable_payments p WHERE p.order_id = o.id)), 0) AS bal
        FROM orders o WHERE o.customer_id = %s AND o.status = 'completed' AND o.payment_status = 'credit';
    """, (customer_id,))
    return round(float(cur.fetchone()["bal"]), 2)


@api.get("/customers")
def list_customers(tier: Optional[str] = None, include_inactive: bool = False):
    with db() as conn, conn.cursor() as cur:
        cur.execute(CUSTOMER_STATS + " WHERE (%s::text IS NULL OR c.tier = %s) AND (c.active OR %s) ORDER BY lower(c.name);",
                    (tier, tier, include_inactive))
        out = rows(cur)
        cur.execute("""
            SELECT o.customer_id AS cid, COALESCE(SUM(
              (SELECT COALESCE(SUM(oi.qty * oi.unit_price), 0) FROM order_items oi WHERE oi.order_id = o.id) + o.delivery_fee
              - (SELECT COALESCE(SUM(p.amount), 0) FROM receivable_payments p WHERE p.order_id = o.id)), 0) AS bal
            FROM orders o WHERE o.customer_id IS NOT NULL AND o.status = 'completed' AND o.payment_status = 'credit'
            GROUP BY o.customer_id;""")
        bal = {r["cid"]: round(float(r["bal"]), 2) for r in cur.fetchall()}
        for c in out:
            c["balance"] = bal.get(c["id"], 0.0)
        return out


@api.post("/customers")
def create_customer(p: CustomerIn):
    if not p.name.strip():
        raise HTTPException(400, "Name is required.")
    with db() as conn, conn.cursor() as cur:
        cur.execute("""INSERT INTO customers (name, phone, phone2, address, notes, tier) VALUES (%s,%s,%s,%s,%s,%s) RETURNING *;""",
                    (p.name.strip(), p.phone.strip(), p.phone2.strip(), p.address.strip(), p.notes.strip(), as_tier(p.tier)))
        return one(cur)


@api.get("/customers/{customer_id}")
def get_customer(customer_id: int):
    with db() as conn, conn.cursor() as cur:
        cur.execute(CUSTOMER_STATS + " WHERE c.id = %s;", (customer_id,))
        c = one(cur)
        if not c:
            raise HTTPException(404, "Customer not found.")
        c["balance"] = customer_balance(cur, customer_id)
        cur.execute(ORDER_SELECT + " WHERE o.customer_id = %s AND o.status <> 'open' ORDER BY COALESCE(o.completed_at, o.voided_at) DESC LIMIT 200;",
                    (customer_id,))
        c["orders"] = [order_out(r) for r in cur.fetchall()]
        cur.execute("""
            SELECT i.id AS item_id, i.name, i.variant, i.selling_price, cp.price AS custom_price
            FROM items i LEFT JOIN customer_prices cp ON cp.item_id = i.id AND cp.customer_id = %s
            WHERE i.category IN ('Mini', 'Pint', 'Cake') AND (i.active OR cp.price IS NOT NULL)
            ORDER BY i.sort_order, i.name, i.variant;
        """, (customer_id,))
        c["prices"] = rows(cur)
        return c


@api.patch("/customers/{customer_id}")
def patch_customer(customer_id: int, changes: dict = Body(...)):
    if "name" in changes and not as_text(changes["name"]):
        raise HTTPException(400, "Name can't be blank.")
    with db() as conn, conn.cursor() as cur:
        apply_patch(cur, "customers", customer_id, changes, CUSTOMER_FIELDS)
        cur.execute(CUSTOMER_STATS + " WHERE c.id = %s;", (customer_id,))
        return one(cur)


@api.delete("/customers/{customer_id}")
def delete_customer(customer_id: int):
    """Past orders keep the name/phone/address typed on them."""
    with db() as conn, conn.cursor() as cur:
        if customer_balance(cur, customer_id) > 0:
            raise HTTPException(400, "This client still owes money — settle it in Receivables first.")
        cur.execute("DELETE FROM customers WHERE id = %s RETURNING id;", (customer_id,))
        if not cur.fetchone():
            raise HTTPException(404, "Customer not found.")
    return {"ok": True}


class PriceIn(BaseModel):
    price: Optional[float] = None   # null = remove custom price


@api.put("/customers/{customer_id}/prices/{item_id}")
def set_customer_price(customer_id: int, item_id: int, p: PriceIn):
    with db() as conn, conn.cursor() as cur:
        if p.price is None:
            cur.execute("DELETE FROM customer_prices WHERE customer_id = %s AND item_id = %s;", (customer_id, item_id))
        else:
            cur.execute("""INSERT INTO customer_prices (customer_id, item_id, price) VALUES (%s, %s, %s)
                           ON CONFLICT (customer_id, item_id) DO UPDATE SET price = EXCLUDED.price;""",
                        (customer_id, item_id, as_money(p.price)))
    return {"ok": True}


@api.get("/customers-prices")
def all_custom_prices():
    """Every reseller price, so the phone can show the right price on the POS grid."""
    with db() as conn, conn.cursor() as cur:
        cur.execute("SELECT customer_id, item_id, price FROM customer_prices;")
        return rows(cur)


# ----------------------------------------------------------------------------
# Receivables (credit sales)
# ----------------------------------------------------------------------------

def outstanding_receivables(cur) -> float:
    cur.execute("""
        SELECT COALESCE(SUM(
          (SELECT COALESCE(SUM(oi.qty * oi.unit_price), 0) FROM order_items oi WHERE oi.order_id = o.id) + o.delivery_fee
          - (SELECT COALESCE(SUM(p.amount), 0) FROM receivable_payments p WHERE p.order_id = o.id)), 0) AS bal
        FROM orders o WHERE o.status = 'completed' AND o.payment_status = 'credit';
    """)
    return round(float(cur.fetchone()["bal"]), 2)


class PaymentIn(BaseModel):
    amount: float = Field(gt=0)
    method: str = "GCash"
    paid_at: Optional[datetime] = None
    notes: str = ""


@api.get("/receivables")
def list_receivables(show: str = "open"):
    """Credit sales with what's been paid. show=open (still owed) or all."""
    with db() as conn, conn.cursor() as cur:
        cur.execute(ORDER_SELECT + """ WHERE o.payment_status = 'credit' AND o.completed_at IS NOT NULL
                                       AND o.status IN ('completed', 'voided')
                                       ORDER BY o.completed_at DESC NULLS LAST, o.id DESC;""")
        out = [order_out(r) for r in cur.fetchall()]
        cur.execute("SELECT * FROM receivable_payments ORDER BY paid_at, id;")
        pays = {}
        for pmt in rows(cur):
            pays.setdefault(pmt["order_id"], []).append(pmt)
    for o in out:
        o["payments"] = pays.get(o["id"], [])
    if show == "open":
        out = [o for o in out if o["receivable_status"] in ("unpaid", "partial")]
    by_client = {}
    for o in out:
        if o["receivable_status"] in ("unpaid", "partial"):
            key = o["customer_name"] or "(no name)"
            by_client[key] = round(by_client.get(key, 0) + o["balance"], 2)
    return {"entries": out, "outstanding": round(sum(by_client.values()), 2),
            "by_client": [{"customer": k, "balance": v} for k, v in sorted(by_client.items(), key=lambda x: -x[1])]}


@api.post("/orders/{order_id}/payments")
def log_payment(order_id: int, p: PaymentIn):
    with db() as conn, conn.cursor() as cur:
        o = fetch_order(cur, order_id)
        if o["payment_status"] != "credit" or o["status"] != "completed":
            raise HTTPException(400, "Payments can only be logged against a finished credit sale.")
        amount = as_money(p.amount)
        if amount > o["balance"] + 0.001:
            raise HTTPException(400, f"That's more than the {o['balance']:,.2f} still owed.")
        paid_at = p.paid_at or datetime.now(MANILA_TZ)
        assert_unlocked(cur, manila_day(paid_at), "payments on that day")
        cur.execute("INSERT INTO receivable_payments (order_id, amount, method, paid_at, notes) VALUES (%s,%s,%s,%s,%s);",
                    (order_id, amount, as_sale_method(p.method), paid_at, p.notes.strip()))
        return fetch_order(cur, order_id)


@api.delete("/payments/{payment_id}")
def delete_payment(payment_id: int):
    with db() as conn, conn.cursor() as cur:
        cur.execute("SELECT * FROM receivable_payments WHERE id = %s;", (payment_id,))
        pmt = cur.fetchone()
        if not pmt:
            raise HTTPException(404, "Payment not found.")
        assert_unlocked(cur, manila_day(pmt["paid_at"]), "payments on that day")
        cur.execute("DELETE FROM receivable_payments WHERE id = %s;", (payment_id,))
    return {"ok": True}


# ----------------------------------------------------------------------------
# Liabilities (paid by Gino or credit card → owed back until settled)
# ----------------------------------------------------------------------------

class SettleIn(BaseModel):
    method: str = "GCash"
    settled_at: Optional[datetime] = None


@api.get("/liabilities")
def list_liabilities(show: str = "unpaid"):
    out = []
    with db() as conn, conn.cursor() as cur:
        for kind in ("purchase", "expense"):
            L = LEDGERS[kind]
            cur.execute(ledger_select(kind) + f"""
                WHERE h.payment_method IN ('Gino', 'Credit Card') AND (%s = 'all' OR h.settled_at IS NULL)
                ORDER BY h.{L['when']};
            """, (show,))
            for r in rows(cur):
                r["kind"] = kind
                r["when"] = r[L["when"]]
                r["description"] = ", ".join(l.get("item_name") or l.get("particulars") for l in r["lines"])
                out.append(r)
    out.sort(key=lambda r: r["when"], reverse=True)
    unpaid = [r for r in out if not r["settled_at"]]
    return {"entries": out,
            "unpaid_total": round(sum(r["total"] for r in unpaid), 2),
            "unpaid_by_method": {m: round(sum(r["total"] for r in unpaid if r["payment_method"] == m), 2) for m in LIABILITY_METHODS}}


def register_liability_routes(kind: str):
    L = LEDGERS[kind]

    def settle(row_id: int, p: SettleIn):
        with db() as conn, conn.cursor() as cur:
            x = fetch_ledger(cur, kind, row_id)
            if x["payment_method"] not in LIABILITY_METHODS:
                raise HTTPException(400, "Only entries paid by Gino or Credit Card are liabilities.")
            if x["settled_at"]:
                raise HTTPException(400, "Already settled.")
            cur.execute(f"UPDATE {L['table']} SET settled_at = COALESCE(%s, now()), settled_method = %s WHERE id = %s;",
                        (p.settled_at, as_sale_method(p.method), row_id))
            return fetch_ledger(cur, kind, row_id)

    def unsettle(row_id: int):
        with db() as conn, conn.cursor() as cur:
            fetch_ledger(cur, kind, row_id)
            cur.execute(f"UPDATE {L['table']} SET settled_at = NULL, settled_method = NULL WHERE id = %s;", (row_id,))
            return fetch_ledger(cur, kind, row_id)

    api.add_api_route(f"/liabilities/{kind}/{{row_id}}/reimburse", settle, methods=["POST"])
    api.add_api_route(f"/liabilities/{kind}/{{row_id}}/unsettle", unsettle, methods=["POST"])


register_liability_routes("purchase")
register_liability_routes("expense")


# ----------------------------------------------------------------------------
# Daily reconciliation
# ----------------------------------------------------------------------------

class ReconIn(BaseModel):
    actual: dict = {}
    notes: str = ""


def expected_for(cur, d: date):
    """What should have landed in each account on day d: paid sales finished
    that day + credit payments received that day (voided orders excluded)."""
    day = lambda col: LOCAL_DAY.format(col=col)
    cur.execute(ORDER_SELECT + f""" WHERE o.status = 'completed' AND o.payment_status = 'paid'
                                   AND {day('o.completed_at')} = %s ORDER BY o.completed_at;""", (d,))
    sales = [order_out(r) for r in cur.fetchall()]
    cur.execute(f"""
        SELECT p.*, o.customer_name, o.status AS order_status FROM receivable_payments p JOIN orders o ON o.id = p.order_id
        WHERE {day('p.paid_at')} = %s ORDER BY p.paid_at;
    """, (d,))
    pays = rows(cur)
    expected = {m: 0.0 for m in SALE_METHODS}
    lines = []
    for o in sales:
        expected[o["payment_method"]] += o["total"]
        lines.append({"type": "sale", "ref": o["id"], "time": o["completed_at"], "who": o["customer_name"],
                      "method": o["payment_method"], "amount": o["total"]})
    for p in pays:
        expected[p["method"]] += p["amount"]
        lines.append({"type": "payment", "ref": p["order_id"], "time": p["paid_at"], "who": p["customer_name"],
                      "method": p["method"], "amount": p["amount"]})
    return {m: round(v, 2) for m, v in expected.items()}, lines


@api.get("/reconciliation/{d}")
def get_reconciliation(d: date):
    with db() as conn, conn.cursor() as cur:
        cur.execute("SELECT * FROM reconciliations WHERE recon_date = %s;", (d,))
        rec = one(cur)
        live, lines = expected_for(cur, d)
    expected = rec["expected"] if rec and rec["locked"] else live
    actual = (rec or {}).get("actual") or {}
    variance = {m: round(float(actual.get(m) or 0) - expected.get(m, 0), 2) for m in SALE_METHODS if m in actual}
    return {"date": d, "methods": list(SALE_METHODS), "expected": expected, "actual": actual, "variance": variance,
            "total_expected": round(sum(expected.values()), 2),
            "total_actual": round(sum(float(v or 0) for v in actual.values()), 2) if actual else None,
            "notes": (rec or {}).get("notes", ""), "locked": bool(rec and rec["locked"]),
            "locked_at": (rec or {}).get("locked_at"), "lines": lines,
            "changed_since_lock": bool(rec and rec["locked"] and live != rec["expected"])}


@api.put("/reconciliation/{d}")
def save_reconciliation(d: date, p: ReconIn):
    actual = {m: as_money(p.actual[m]) for m in SALE_METHODS if p.actual.get(m) not in (None, "")}
    with db() as conn, conn.cursor() as cur:
        if day_locked(cur, d):
            raise HTTPException(423, "This day is locked. Unlock it first.")
        cur.execute("""INSERT INTO reconciliations (recon_date, actual, notes) VALUES (%s, %s::jsonb, %s)
                       ON CONFLICT (recon_date) DO UPDATE SET actual = EXCLUDED.actual, notes = EXCLUDED.notes, updated_at = now();""",
                    (d, json_dumps(actual), p.notes.strip()))
    return get_reconciliation(d)


@api.post("/reconciliation/{d}/lock")
def lock_reconciliation(d: date, p: ReconIn):
    if d > today_manila():
        raise HTTPException(400, "You can't lock a day that hasn't happened yet.")
    actual = {m: as_money(p.actual.get(m) or 0) for m in SALE_METHODS}
    with db() as conn, conn.cursor() as cur:
        if day_locked(cur, d):
            raise HTTPException(400, "Already locked.")
        expected, _ = expected_for(cur, d)
        cur.execute("""INSERT INTO reconciliations (recon_date, expected, actual, notes, locked, locked_at)
                       VALUES (%s, %s::jsonb, %s::jsonb, %s, true, now())
                       ON CONFLICT (recon_date) DO UPDATE SET expected = EXCLUDED.expected, actual = EXCLUDED.actual,
                         notes = EXCLUDED.notes, locked = true, locked_at = now(), updated_at = now();""",
                    (d, json_dumps(expected), json_dumps(actual), p.notes.strip()))
    return get_reconciliation(d)


@api.post("/reconciliation/{d}/unlock")
def unlock_reconciliation(d: date):
    with db() as conn, conn.cursor() as cur:
        cur.execute("UPDATE reconciliations SET locked = false, locked_at = NULL, updated_at = now() WHERE recon_date = %s RETURNING recon_date;", (d,))
        if not cur.fetchone():
            raise HTTPException(404, "Nothing to unlock.")
    return get_reconciliation(d)


@api.get("/reconciliation-days")
def reconciliation_days(days: int = 21):
    """The recent days that had money coming in, with their status."""
    t = today_manila()
    out = []
    with db() as conn, conn.cursor() as cur:
        cur.execute("SELECT * FROM reconciliations WHERE recon_date >= %s;", (t - timedelta(days=days),))
        recs = {r["recon_date"]: r for r in rows(cur)}
        for i in range(days):
            d = t - timedelta(days=i)
            rec = recs.get(d)
            expected = rec["expected"] if rec and rec["locked"] else expected_for(cur, d)[0]
            total = round(sum(expected.values()), 2)
            if total == 0 and not rec:
                continue
            actual = (rec or {}).get("actual") or {}
            out.append({"date": d, "expected": total,
                        "actual": round(sum(float(v or 0) for v in actual.values()), 2) if actual else None,
                        "variance": round(sum(float(v or 0) for v in actual.values()) - total, 2) if actual else None,
                        "locked": bool(rec and rec["locked"])})
    return out


def json_dumps(v):
    import json
    return json.dumps(v)


# ----------------------------------------------------------------------------
# Recipes — ingredient amounts per batch; cost follows the latest purchases
# ----------------------------------------------------------------------------

class RecipeLineIn(BaseModel):
    material_id: int
    qty: float = Field(gt=0)


class RecipeIn(BaseModel):
    yield_qty: float = Field(gt=0)
    notes: str = ""
    lines: List[RecipeLineIn]


RECIPE_LINES_SQL = """
    SELECT rl.id, rl.material_id, m.name, m.variant, m.category, m.base_unit, m.content_qty, rl.qty,
           m.unit_cost AS material_cost,
           ROUND(m.unit_cost / NULLIF(m.content_qty, 0), 4) AS cost_per_base,
           ROUND(rl.qty * m.unit_cost / NULLIF(m.content_qty, 0), 2) AS line_cost,
           lp.purchased_at AS price_from
    FROM recipe_lines rl JOIN items m ON m.id = rl.material_id
    LEFT JOIN LATERAL (
        SELECT p.purchased_at FROM purchase_lines l JOIN purchases p ON p.id = l.purchase_id
        WHERE l.item_id = m.id AND l.qty > 0 ORDER BY p.purchased_at DESC, l.id DESC LIMIT 1) lp ON true
    WHERE rl.product_id = %s ORDER BY m.category, m.name;
"""


@api.get("/recipes")
def list_recipes():
    """Every finished product, with its recipe cost (if it has a recipe)."""
    with db() as conn, conn.cursor() as cur:
        refresh_costs(cur)
        cur.execute(f"""
            SELECT i.id AS product_id, i.name, i.variant, i.category, i.selling_price, i.unit_cost, i.active,
                   r.yield_qty, r.notes, r.updated_at,
                   (SELECT COUNT(*) FROM recipe_lines rl WHERE rl.product_id = i.id) AS line_count,
                   (SELECT COUNT(*) FROM recipe_lines rl JOIN items m ON m.id = rl.material_id
                     WHERE rl.product_id = i.id AND m.unit_cost = 0) AS missing_prices,
                   (SELECT COALESCE(SUM(rl.qty * m.unit_cost / NULLIF(m.content_qty, 0)), 0)
                      FROM recipe_lines rl JOIN items m ON m.id = rl.material_id WHERE rl.product_id = i.id) AS batch_cost
            FROM items i LEFT JOIN recipes r ON r.product_id = i.id
            WHERE i.category IN ('Mini', 'Pint', 'Cake')
            ORDER BY {CATEGORY_ORDER.replace('category', 'i.category')}, i.name, i.variant;
        """)
        return rows(cur)


@api.get("/recipes/{product_id}")
def get_recipe(product_id: int):
    with db() as conn, conn.cursor() as cur:
        cur.execute("SELECT id, name, variant, category, selling_price, unit_cost FROM items WHERE id = %s;", (product_id,))
        prod = one(cur)
        if not prod:
            raise HTTPException(404, "Product not found.")
        cur.execute("SELECT * FROM recipes WHERE product_id = %s;", (product_id,))
        r = one(cur)
        cur.execute(RECIPE_LINES_SQL, (product_id,))
        lines = rows(cur)
    batch = round(sum(l["line_cost"] or 0 for l in lines), 2)
    y = r["yield_qty"] if r else 1
    return {"product": prod, "exists": bool(r), "yield_qty": y, "notes": (r or {}).get("notes", ""),
            "lines": lines, "batch_cost": batch, "cost_per_unit": round(batch / y, 2) if y else None}


@api.put("/recipes/{product_id}")
def save_recipe(product_id: int, p: RecipeIn):
    ids = [l.material_id for l in p.lines]
    if len(ids) != len(set(ids)):
        raise HTTPException(400, "The same material is listed twice.")
    with db() as conn, conn.cursor() as cur:
        cur.execute("SELECT category FROM items WHERE id = %s;", (product_id,))
        prod = cur.fetchone()
        if not prod or prod["category"] not in SELL_CATEGORIES:
            raise HTTPException(400, "Recipes are for finished products (Mini / Pint / Cake).")
        for mid in ids:
            cur.execute("SELECT category FROM items WHERE id = %s;", (mid,))
            m = cur.fetchone()
            if not m or m["category"] not in MATERIAL_CATEGORIES:
                raise HTTPException(400, "Recipe ingredients must come from Materials.")
        cur.execute("""INSERT INTO recipes (product_id, yield_qty, notes) VALUES (%s, %s, %s)
                       ON CONFLICT (product_id) DO UPDATE SET yield_qty = EXCLUDED.yield_qty, notes = EXCLUDED.notes, updated_at = now();""",
                    (product_id, p.yield_qty, p.notes.strip()))
        cur.execute("DELETE FROM recipe_lines WHERE product_id = %s;", (product_id,))
        for l in p.lines:
            cur.execute("INSERT INTO recipe_lines (product_id, material_id, qty) VALUES (%s, %s, %s);",
                        (product_id, l.material_id, l.qty))
        refresh_costs(cur)
    return get_recipe(product_id)


@api.delete("/recipes/{product_id}")
def delete_recipe(product_id: int):
    """Removes the recipe; the product keeps its last cost (editable by hand again)."""
    with db() as conn:
        r = conn.execute("DELETE FROM recipes WHERE product_id = %s RETURNING product_id;", (product_id,)).fetchone()
    if not r:
        raise HTTPException(404, "No recipe to remove.")
    return {"ok": True}


# ----------------------------------------------------------------------------
# Product photos
# ----------------------------------------------------------------------------

class ImageIn(BaseModel):
    mime: str
    data_b64: str


@api.put("/items/{item_id}/image")
def set_item_image(item_id: int, p: ImageIn):
    if not p.mime.startswith("image/"):
        raise HTTPException(400, "Only photos can be used.")
    try:
        data = base64.b64decode(p.data_b64.split(",")[-1])
    except Exception:
        raise HTTPException(400, "Couldn't read that photo.")
    if len(data) > 2 * 1024 * 1024:
        raise HTTPException(400, "Photo is too large (max 2 MB).")
    with db() as conn:
        if not conn.execute("SELECT 1 FROM items WHERE id = %s;", (item_id,)).fetchone():
            raise HTTPException(404, "Product not found.")
        conn.execute("""INSERT INTO item_images (item_id, mime, data) VALUES (%s, %s, %s)
                        ON CONFLICT (item_id) DO UPDATE SET mime = EXCLUDED.mime, data = EXCLUDED.data, updated_at = now();""",
                     (item_id, p.mime, data))
    return {"ok": True}


@api.delete("/items/{item_id}/image")
def delete_item_image(item_id: int):
    with db() as conn:
        conn.execute("DELETE FROM item_images WHERE item_id = %s;", (item_id,))
    return {"ok": True}


@app.get("/item-images/{item_id}")
def get_item_image(item_id: int):
    """Product photos are public (they're just menu pictures) so they can be cached."""
    with db() as conn:
        r = conn.execute("SELECT mime, data FROM item_images WHERE item_id = %s;", (item_id,)).fetchone()
    if not r:
        raise HTTPException(404, "No photo.")
    return Response(content=bytes(r["data"]), media_type=r["mime"],
                    headers={"Cache-Control": "public, max-age=31536000, immutable"})


# ----------------------------------------------------------------------------
# Settings (copy-paste message texts)
# ----------------------------------------------------------------------------

SETTING_KEYS = ("msg_customer_header", "msg_customer_footer", "msg_rider_location", "msg_rider_df",
                "copy_label_customer", "copy_label_location", "copy_label_df")


@api.get("/settings")
def get_settings():
    with db() as conn:
        s = {r["key"]: r["value"] for r in conn.execute("SELECT key, value FROM settings;").fetchall()}
    s["payment_methods"] = list(PAYMENT_METHODS)
    s["categories"] = list(CATEGORIES)
    s["sell_categories"] = list(SELL_CATEGORIES)
    s["material_categories"] = list(MATERIAL_CATEGORIES)
    return s


@api.patch("/settings")
def patch_settings(changes: dict = Body(...)):
    with db() as conn, conn.cursor() as cur:
        for k, v in changes.items():
            if k in SETTING_KEYS:
                cur.execute("""INSERT INTO settings (key, value) VALUES (%s, %s)
                               ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value;""", (k, as_text(v)))
    return get_settings()


@api.get("/boot")
def boot(day: Optional[date] = None):
    """Everything the app needs to open, in one trip."""
    d = day or today_manila()
    return {"settings": get_settings(), "items": list_items(include_inactive=True), "customers": list_customers(),
            "prices": all_custom_prices(), "schedule": order_schedule(d, d, include_open=True)}


# ----------------------------------------------------------------------------
# End of day: open orders close themselves once their delivery day is over
# ----------------------------------------------------------------------------

def auto_close_orders(cur) -> int:
    when = LOCAL_DAY.format(col="o.delivery_at")
    cur.execute(ORDER_SELECT + f" WHERE o.status = 'open' AND {when} < %s ORDER BY o.id;", (today_manila(),))
    closed = 0
    for o in [order_out(r) for r in cur.fetchall()]:
        if not o["items"]:                       # an empty order that was never filled in
            cur.execute("DELETE FROM orders WHERE id = %s AND status = 'open';", (o["id"],))
            continue
        name = o["customer_name"].strip() or ("No name" if o["payment_status"] == "credit" else "")
        d = manila_day(o["delivery_at"])
        done_at = o["delivery_at"] if not day_locked(cur, d) else datetime.now(timezone.utc)
        cur.execute("""UPDATE orders SET status = 'completed', completed_at = %s, customer_name = %s,
                              auto_closed = true, updated_at = now() WHERE id = %s AND status = 'open';""",
                    (done_at, name, o["id"]))
        o["customer_name"] = name
        remember_customer(cur, o)
        closed += 1
    return closed


# ----------------------------------------------------------------------------
# Phone notifications (web push to the phone app added to the Home Screen)
# ----------------------------------------------------------------------------

DEFAULT_NOTIF_RULES = [
    {"id": "sum1", "type": "summary", "days_before": 1, "time": "20:00", "on": True},
    {"id": "b60", "type": "before", "minutes": 60, "on": True},
    {"id": "b10", "type": "before", "minutes": 10, "on": True},
    {"id": "b0", "type": "before", "minutes": 0, "on": True},
]
GRACE = timedelta(minutes=30)       # a reminder missed by more than this (e.g. during a restart) is skipped


def notif_rules(cur) -> list:
    cur.execute("SELECT value FROM settings WHERE key = 'notif_rules';")
    r = cur.fetchone()
    try:
        return json.loads(r["value"]) if r else [dict(x) for x in DEFAULT_NOTIF_RULES]
    except ValueError:
        return [dict(x) for x in DEFAULT_NOTIF_RULES]


def rule_label(r) -> str:
    if r["type"] == "summary":
        d = int(r.get("days_before", 1))
        when = "Day before" if d == 1 else "Same day" if d == 0 else f"{d} days before"
        hh, mm = map(int, r.get("time", "20:00").split(":"))
        return f"{when} summary at {(hh + 11) % 12 + 1}:{mm:02d} {'AM' if hh < 12 else 'PM'}"
    m = int(r.get("minutes", 0))
    if m == 0:
        return "At delivery time"
    return f"{m // 60} hr before" if m % 60 == 0 else f"{m} min before"


def clean_rules(raw) -> list:
    out, seen = [], set()
    for r in raw if isinstance(raw, list) else []:
        t = r.get("type")
        rid = str(r.get("id") or secrets.token_hex(3))[:20]
        if rid in seen or t not in ("summary", "before"):
            continue
        seen.add(rid)
        if t == "summary":
            tm = str(r.get("time", "20:00"))
            try:
                hh, mm = map(int, tm.split(":"))
                assert 0 <= hh < 24 and 0 <= mm < 60
            except Exception:
                raise HTTPException(400, f"“{tm}” isn't a valid time.")
            days = int(r.get("days_before", 1))
            if not 0 <= days <= 7:
                raise HTTPException(400, "Summary can be 0–7 days before.")
            out.append({"id": rid, "type": t, "days_before": days, "time": f"{hh:02d}:{mm:02d}", "on": bool(r.get("on", True))})
        else:
            mins = int(r.get("minutes", 0))
            if not 0 <= mins <= 7 * 24 * 60:
                raise HTTPException(400, "Reminders can be up to 7 days before.")
            out.append({"id": rid, "type": t, "minutes": mins, "on": bool(r.get("on", True))})
    return out


def vapid_keys(cur):
    """Creates the server's push keys the first time; the private one never leaves the database."""
    cur.execute("SELECT key, value FROM app_secrets WHERE key IN ('vapid_private', 'vapid_public');")
    k = {r["key"]: r["value"] for r in cur.fetchall()}
    if len(k) == 2:
        return k["vapid_private"], k["vapid_public"]
    from py_vapid import Vapid
    from cryptography.hazmat.primitives import serialization
    v = Vapid()
    v.generate_keys()
    priv = v.private_pem().decode()
    raw = v.public_key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    pub = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    cur.execute("""INSERT INTO app_secrets (key, value) VALUES ('vapid_private', %s), ('vapid_public', %s)
                   ON CONFLICT (key) DO NOTHING;""", (priv, pub))
    cur.execute("SELECT key, value FROM app_secrets WHERE key IN ('vapid_private', 'vapid_public');")
    k = {r["key"]: r["value"] for r in cur.fetchall()}
    return k["vapid_private"], k["vapid_public"]


def send_push(subs: list, payload: dict, priv_pem: str):
    """Sends one notification to each phone. Phones that uninstalled are forgotten."""
    from pywebpush import webpush, WebPushException
    from py_vapid import Vapid
    key = Vapid.from_pem(priv_pem.encode())
    dead, ok = [], []
    for sub in subs:
        try:
            webpush({"endpoint": sub["endpoint"], "keys": {"p256dh": sub["p256dh"], "auth": sub["auth"]}},
                    data=json.dumps(payload), vapid_private_key=key,
                    vapid_claims={"sub": "https://rochargelato.com"}, ttl=3600, timeout=10)
            ok.append(sub["id"])
        except WebPushException as e:
            code = getattr(e.response, "status_code", None)
            if code in (404, 410):
                dead.append(sub["id"])
            print(f"push failed ({code}): {e}", flush=True)
        except Exception as e:
            print(f"push failed: {e}", flush=True)
    if dead or ok:
        with db() as conn, conn.cursor() as cur:
            if dead:
                cur.execute("DELETE FROM push_subscriptions WHERE id = ANY(%s);", (dead,))
            if ok:
                cur.execute("UPDATE push_subscriptions SET last_sent_at = now() WHERE id = ANY(%s);", (ok,))
    return len(ok)


def fmt_time12(dt: datetime) -> str:
    t = dt.astimezone(MANILA_TZ)
    return f"{(t.hour + 11) % 12 + 1}:{t.minute:02d} {'AM' if t.hour < 12 else 'PM'}"


def peso(x) -> str:
    x = round(float(x or 0), 2)
    return f"₱{x:,.0f}" if x == int(x) else f"₱{x:,.2f}"


def due_notifications(cur) -> list:
    """Works out which reminders are due right now and marks them sent. Returns [(rule_id, payload)]."""
    now = datetime.now(MANILA_TZ)
    rules = [r for r in notif_rules(cur) if r.get("on")]
    out = []

    def claim(key):
        cur.execute("INSERT INTO notif_log (fire_key) VALUES (%s) ON CONFLICT DO NOTHING RETURNING fire_key;", (key,))
        return cur.fetchone() is not None

    befores = [r for r in rules if r["type"] == "before"]
    if befores:
        horizon = max(r["minutes"] for r in befores)
        cur.execute(ORDER_SELECT + """ WHERE o.status = 'open' AND o.delivery_at BETWEEN %s AND %s ORDER BY o.delivery_at;""",
                    (now - GRACE, now + timedelta(minutes=horizon + 1)))
        for o in [order_out(r) for r in cur.fetchall()]:
            if not o["items"]:
                continue
            for r in befores:
                fire = o["delivery_at"] - timedelta(minutes=r["minutes"])
                # only if it's time, not too late, and the order already existed when the reminder was due
                if not (fire <= now < fire + GRACE) or o["created_at"] > fire:
                    continue
                if not claim(f"{r['id']}:{o['id']}:{o['delivery_at'].isoformat()}"):
                    continue
                left = round((o["delivery_at"] - now).total_seconds() / 60)
                lead = "Now" if left <= 0 else (f"In {left} min" if left < 90 else f"In {round(left / 60)} hr")
                who = o["customer_name"] or "No name"
                body = " · ".join(x for x in [peso(o["total"]), o["address"]] if x)
                out.append((r["id"], {"title": f"⏰ {lead} · {fmt_time12(o['delivery_at'])} · {who}", "body": body,
                                      "url": f"/#schedule", "tag": f"order-{o['id']}"}))

    when = LOCAL_DAY.format(col="o.delivery_at")
    for r in [r for r in rules if r["type"] == "summary"]:
        hh, mm = map(int, r["time"].split(":"))
        fire = now.replace(hour=hh, minute=mm, second=0, microsecond=0)
        if not (fire <= now < fire + GRACE):
            continue
        target = now.date() + timedelta(days=r["days_before"])
        if not claim(f"{r['id']}:{target}"):
            continue
        cur.execute(ORDER_SELECT + f" WHERE o.status IN ('open', 'completed') AND {when} = %s ORDER BY o.delivery_at;", (target,))
        orders = [order_out(x) for x in cur.fetchall()]
        if not orders:
            continue
        day = "Today" if r["days_before"] == 0 else "Tomorrow" if r["days_before"] == 1 else f"{target:%a %b} {target.day}"
        total = sum(o["total"] for o in orders)
        lines = [f"{fmt_time12(o['delivery_at'])} {o['customer_name'] or 'No name'}" for o in orders[:6]]
        if len(orders) > 6:
            lines.append(f"+{len(orders) - 6} more")
        out.append((r["id"], {"title": f"📅 {day}: {len(orders)} order{'s' if len(orders) != 1 else ''} · {peso(total)}",
                              "body": " · ".join(lines), "url": "/#schedule", "tag": f"summary-{target}"}))
    return out


STOP_JOBS = threading.Event()


def run_jobs_once():
    with psycopg.connect(DATABASE_URL, row_factory=dict_row) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT pg_try_advisory_xact_lock(724501) AS ok;")   # only one server copy runs the jobs
            if not cur.fetchone()["ok"]:
                return
            auto_close_orders(cur)
            due = due_notifications(cur)
            priv, _ = vapid_keys(cur)
            cur.execute("SELECT id, endpoint, p256dh, auth, muted FROM push_subscriptions WHERE enabled;")
            subs = cur.fetchall()
        conn.commit()
    for rule_id, payload in due:
        targets = [s for s in subs if rule_id not in (s["muted"] or [])]
        if targets:
            send_push(targets, payload, priv)


def background_loop():
    time.sleep(5)
    while not STOP_JOBS.is_set():
        try:
            run_jobs_once()
        except Exception as e:
            print(f"background job error: {e}", flush=True)
        STOP_JOBS.wait(60)


class PushSubIn(BaseModel):
    endpoint: str
    keys: dict
    label: str = ""


class PushPrefsIn(BaseModel):
    endpoint: str
    enabled: Optional[bool] = None
    muted: Optional[List[str]] = None


class EndpointIn(BaseModel):
    endpoint: str


def sub_out(r):
    return {"id": r["id"], "label": r["label"], "enabled": r["enabled"], "muted": list(r["muted"] or []),
            "created_at": r["created_at"], "last_sent_at": r["last_sent_at"]}


@api.get("/push/key")
def push_key():
    with db() as conn, conn.cursor() as cur:
        return {"public_key": vapid_keys(cur)[1]}


@api.get("/notif-rules")
def get_notif_rules():
    with db() as conn, conn.cursor() as cur:
        return [{**r, "label": rule_label(r)} for r in notif_rules(cur)]


@api.put("/notif-rules")
def put_notif_rules(rules: list = Body(...)):
    clean = clean_rules(rules)
    with db() as conn, conn.cursor() as cur:
        cur.execute("""INSERT INTO settings (key, value) VALUES ('notif_rules', %s)
                       ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value;""", (json.dumps(clean),))
    return [{**r, "label": rule_label(r)} for r in clean]


@api.post("/push/subscribe")
def push_subscribe(p: PushSubIn):
    k = p.keys or {}
    if not p.endpoint.startswith("https://") or not k.get("p256dh") or not k.get("auth"):
        raise HTTPException(400, "That doesn't look like a valid notification subscription.")
    with db() as conn, conn.cursor() as cur:
        cur.execute("""INSERT INTO push_subscriptions (endpoint, p256dh, auth, label) VALUES (%s, %s, %s, %s)
                       ON CONFLICT (endpoint) DO UPDATE SET p256dh = EXCLUDED.p256dh, auth = EXCLUDED.auth,
                         label = CASE WHEN EXCLUDED.label <> '' THEN EXCLUDED.label ELSE push_subscriptions.label END,
                         enabled = true
                       RETURNING *;""", (p.endpoint, k["p256dh"], k["auth"], p.label.strip()[:60]))
        return sub_out(cur.fetchone())


@api.post("/push/me")
def push_me(p: EndpointIn):
    with db() as conn, conn.cursor() as cur:
        cur.execute("SELECT * FROM push_subscriptions WHERE endpoint = %s;", (p.endpoint,))
        r = cur.fetchone()
        return sub_out(r) if r else None


@api.patch("/push/me")
def push_prefs(p: PushPrefsIn):
    with db() as conn, conn.cursor() as cur:
        cur.execute("""UPDATE push_subscriptions SET enabled = COALESCE(%s, enabled), muted = COALESCE(%s, muted)
                       WHERE endpoint = %s RETURNING *;""", (p.enabled, p.muted, p.endpoint))
        r = cur.fetchone()
        if not r:
            raise HTTPException(404, "This phone isn't signed up for notifications — turn them on again.")
        return sub_out(r)


@api.post("/push/unsubscribe")
def push_unsubscribe(p: EndpointIn):
    with db() as conn, conn.cursor() as cur:
        cur.execute("DELETE FROM push_subscriptions WHERE endpoint = %s;", (p.endpoint,))
    return {"ok": True}


@api.post("/push/test")
def push_test(p: EndpointIn):
    with db() as conn, conn.cursor() as cur:
        priv, _ = vapid_keys(cur)
        cur.execute("SELECT id, endpoint, p256dh, auth FROM push_subscriptions WHERE endpoint = %s;", (p.endpoint,))
        subs = cur.fetchall()
    if not subs:
        raise HTTPException(404, "This phone isn't signed up for notifications.")
    sent = send_push(subs, {"title": "🍨 Rochar notifications are on", "body": "This is what an order reminder will look like.",
                            "url": "/#schedule", "tag": "test"}, priv)
    if not sent:
        raise HTTPException(502, "The test couldn't be delivered — try turning notifications off and on again.")
    return {"ok": True}


@api.get("/push/devices")
def push_devices():
    with db() as conn, conn.cursor() as cur:
        cur.execute("SELECT * FROM push_subscriptions ORDER BY created_at;")
        return [sub_out(r) for r in cur.fetchall()]


@api.delete("/push/devices/{sub_id}")
def push_device_delete(sub_id: int):
    with db() as conn, conn.cursor() as cur:
        cur.execute("DELETE FROM push_subscriptions WHERE id = %s;", (sub_id,))
    return {"ok": True}


app.include_router(api)
