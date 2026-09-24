"""
Rochar Gelato — backend v2 (FastAPI + Postgres on Render)

Lean, single-operator design:
  • Master Products (gelato, raw materials, packaging)
  • Messenger-style open orders → completed sales (or voided, kept for audit)
  • Purchases and Expenses, with proof photos
  • Production log (record only)
  • Monthly inventory count → periodic COGS:
        COGS = Beginning Inventory + Purchases − Ending Inventory

Everything except the health checks and login needs a logged-in session.
"""

import base64
import hashlib
import os
import secrets
import time
from contextlib import asynccontextmanager
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path
from typing import List, Optional

import psycopg
from psycopg.rows import dict_row
from fastapi import APIRouter, Body, Depends, FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from pydantic import BaseModel, Field


# ----------------------------------------------------------------------------
# Setup
# ----------------------------------------------------------------------------

DATABASE_URL = os.environ["DATABASE_URL"]   # injected by Render
MANILA_TZ = timezone(timedelta(hours=8))
SESSION_DAYS = 90
SCHEMA_FILE = Path(__file__).with_name("schema.sql")

CATEGORIES = ("Gelato", "Raw Material", "Packaging")
PAYMENT_METHODS = ("Cash", "GCash", "Gino", "Credit Card", "Check")
MAX_ATTACHMENT_BYTES = 6 * 1024 * 1024
LOCAL_DAY = "(({col}) AT TIME ZONE 'Asia/Manila')::date"   # timestamp → Manila calendar day


def today_manila() -> date:
    return datetime.now(MANILA_TZ).date()


def db():
    """`with db() as conn:` — commits if everything succeeds, rolls back on error."""
    return psycopg.connect(DATABASE_URL, row_factory=dict_row)


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
    yield


app = FastAPI(title="Rochar Gelato API", lifespan=lifespan)
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
        raise HTTPException(400, "Category must be Gelato, Raw Material, or Packaging.")
    return v


def as_payment(v):
    v = as_text(v)
    if v not in PAYMENT_METHODS:
        raise HTTPException(400, "Payment method must be one of: " + ", ".join(PAYMENT_METHODS))
    return v


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
    category: str = "Gelato"
    variant: str = ""
    unit_cost: float = 0
    selling_price: float = 0
    active: bool = True


ITEM_FIELDS = {"name": as_text, "category": as_category, "variant": as_text, "unit_cost": as_money,
               "selling_price": as_money, "active": as_bool, "sort_order": as_int}
ITEM_ORDER = "CASE category WHEN 'Gelato' THEN 0 WHEN 'Raw Material' THEN 1 ELSE 2 END, sort_order, name, variant"


@api.get("/items")
def list_items(include_inactive: bool = False):
    with db() as conn, conn.cursor() as cur:
        cur.execute(f"SELECT * FROM items WHERE active OR %s ORDER BY {ITEM_ORDER};", (include_inactive,))
        return rows(cur)


@api.post("/items")
def create_item(p: ItemPayload):
    if not p.name.strip():
        raise HTTPException(400, "Product name is required.")
    with db() as conn, conn.cursor() as cur:
        try:
            cur.execute("""
                INSERT INTO items (name, category, variant, unit_cost, selling_price, active)
                VALUES (%s, %s, %s, %s, %s, %s) RETURNING *;
            """, (p.name.strip(), as_category(p.category), p.variant.strip(), as_money(p.unit_cost),
                  as_money(p.selling_price), p.active))
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
           COALESCE((SELECT SUM(oi.qty * oi.unit_price) FROM order_items oi WHERE oi.order_id = o.id), 0) AS subtotal
    FROM orders o
"""
ORDER_FIELDS = {"customer_name": as_text, "phone": as_text, "address": as_text, "delivery_fee": as_money,
                "rider_name": as_text, "notes": as_text, "completed_at": as_timestamp}


def order_out(r):
    r = {k: clean(v) for k, v in r.items()}
    r["total"] = round(r["subtotal"] + r["delivery_fee"], 2)
    return r


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
            "voided": len(out) - len(done),
        },
    }


@api.post("/orders")
def create_order():
    with db() as conn, conn.cursor() as cur:
        cur.execute("INSERT INTO orders DEFAULT VALUES RETURNING id;")
        return fetch_order(cur, cur.fetchone()["id"])


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
            cur.execute("SELECT name, variant, selling_price FROM items WHERE id = %s;", (item_id,))
            item = cur.fetchone()
            if not item:
                raise HTTPException(404, "Product not found.")
            cur.execute("""
                INSERT INTO order_items (order_id, item_id, name, variant, qty, unit_price)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (order_id, item_id) DO UPDATE SET qty = EXCLUDED.qty;
            """, (order_id, item_id, item["name"], item["variant"], p.qty, item["selling_price"]))
        cur.execute("UPDATE orders SET updated_at = now() WHERE id = %s;", (order_id,))
        return fetch_order(cur, order_id)


@api.post("/orders/{order_id}/finish")
def finish_order(order_id: int):
    with db() as conn, conn.cursor() as cur:
        o = fetch_order(cur, order_id)
        if o["status"] != "open":
            raise HTTPException(400, f"This order is already {o['status']}.")
        if not o["items"]:
            raise HTTPException(400, "Add at least one item before finishing the order.")
        cur.execute("UPDATE orders SET status='completed', completed_at=now(), updated_at=now() WHERE id=%s;",
                    (order_id,))
        return fetch_order(cur, order_id)


@api.post("/orders/{order_id}/void")
def void_order(order_id: int, p: VoidPayload):
    with db() as conn, conn.cursor() as cur:
        o = fetch_order(cur, order_id)
        if o["status"] == "voided":
            raise HTTPException(400, "This order is already voided.")
        cur.execute("""UPDATE orders SET status='voided', voided_at=now(), void_reason=%s, updated_at=now()
                       WHERE id=%s;""", (p.reason.strip() or None, order_id))
        return fetch_order(cur, order_id)


@api.delete("/orders/{order_id}")
def delete_order(order_id: int):
    """Only an empty open order (an accidental 'New order') can be deleted.
    Anything else must be voided so it stays on record."""
    with db() as conn, conn.cursor() as cur:
        o = fetch_order(cur, order_id)
        if o["status"] != "open" or o["items"]:
            raise HTTPException(400, "Only an empty open order can be deleted — void it instead.")
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
                        (pid, l.item_id, l.item_name.strip(), as_qty(l.qty), as_money(l.amount)))
        save_attachments(cur, "purchase", pid, p.attachments)
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
            return fetch_ledger(cur, kind, row_id)

    def delete_entry(row_id: int):
        with db() as conn, conn.cursor() as cur:
            cur.execute(f"DELETE FROM {L['table']} WHERE id = %s RETURNING id;", (row_id,))
            if not cur.fetchone():
                raise HTTPException(404, "Not found.")
            cur.execute("DELETE FROM attachments WHERE owner_type = %s AND owner_id = %s;", (kind, row_id))
        return {"ok": True}

    def add_line(row_id: int, line: dict = Body(...)):
        with db() as conn, conn.cursor() as cur:
            fetch_ledger(cur, kind, row_id)
            if kind == "purchase":
                cur.execute("INSERT INTO purchase_lines (purchase_id, item_id, item_name, qty, amount) VALUES (%s,%s,%s,%s,%s);",
                            (row_id, line.get("item_id"), as_text(line.get("item_name")) or "New item",
                             as_qty(line.get("qty", 1)), as_money(line.get("amount", 0))))
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
            return fetch_ledger(cur, kind, row_id)

    def delete_line(row_id: int, line_id: int):
        with db() as conn, conn.cursor() as cur:
            cur.execute(f"SELECT COUNT(*) AS n FROM {L['lines']} WHERE {L['fk']} = %s;", (row_id,))
            if cur.fetchone()["n"] <= 1:
                raise HTTPException(400, "That's the last line — delete the whole entry instead.")
            cur.execute(f"DELETE FROM {L['lines']} WHERE id = %s AND {L['fk']} = %s RETURNING id;", (line_id, row_id))
            if not cur.fetchone():
                raise HTTPException(404, "Line not found.")
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
        ORDER BY CASE category WHEN 'Gelato' THEN 0 WHEN 'Raw Material' THEN 1 ELSE 2 END, name, variant;
    """, (count_id,))
    head["lines"] = rows(cur)
    return head


@api.get("/counts")
def list_counts():
    with db() as conn, conn.cursor() as cur:
        cur.execute(COUNT_SELECT + " ORDER BY c.count_date DESC, c.id DESC;")
        return rows(cur)


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
def dashboard():
    t = today_manila()
    with db() as conn, conn.cursor() as cur:
        today = period_numbers(cur, t - timedelta(days=1), t)
        cur.execute("SELECT COUNT(*) AS n FROM orders WHERE status = 'open';")
        open_n = cur.fetchone()["n"]
        rep = build_periods(cur)
    return {"today": t, "today_numbers": today, "open_orders": open_n,
            "current_period": rep["current"], "last_period": rep["periods"][0] if rep["periods"] else None}


# ----------------------------------------------------------------------------
# Settings (copy-paste message texts)
# ----------------------------------------------------------------------------

SETTING_KEYS = ("msg_customer_header", "msg_customer_footer", "msg_rider_location", "msg_rider_df")


@api.get("/settings")
def get_settings():
    with db() as conn:
        s = {r["key"]: r["value"] for r in conn.execute("SELECT key, value FROM settings;").fetchall()}
    s["payment_methods"] = list(PAYMENT_METHODS)
    s["categories"] = list(CATEGORIES)
    return s


@api.patch("/settings")
def patch_settings(changes: dict = Body(...)):
    with db() as conn, conn.cursor() as cur:
        for k, v in changes.items():
            if k in SETTING_KEYS:
                cur.execute("""INSERT INTO settings (key, value) VALUES (%s, %s)
                               ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value;""", (k, as_text(v)))
    return get_settings()


app.include_router(api)
