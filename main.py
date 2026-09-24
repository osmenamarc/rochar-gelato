"""
Rochar Gelato — operations backend (FastAPI + Postgres, hosted on Render)

Covers: ingredient + product inventory, production batches, sales,
wastage, expenses, customer orders (with due dates), stock counts,
monthly reporting, and daily email alerts (low stock + orders due).

Everything except the health check, login, and the alert trigger needs
a logged-in session (one shared admin PIN).
"""

import os
import ssl
import time
import hashlib
import secrets
import smtplib
from contextlib import asynccontextmanager
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from html import escape
from pathlib import Path
from typing import List, Optional

import psycopg
import requests
from psycopg.rows import dict_row
from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field


# ----------------------------------------------------------------------------
# Configuration (all set as Environment Variables on Render)
# ----------------------------------------------------------------------------

# Injected automatically by Render once the Postgres database is linked.
DATABASE_URL = os.environ["DATABASE_URL"]

# Secret shared with the scheduled job that triggers the daily alert email.
CRON_SECRET = os.environ.get("CRON_SECRET", "")

# Email — option A: Gmail with an App Password (needs a PAID Render
# instance; Render's free tier blocks outgoing SMTP).
SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")

# Email — option B: Brevo's web API (works on Render's free tier).
BREVO_API_KEY = os.environ.get("BREVO_API_KEY", "")

# The "From" address on alert emails.
ALERT_FROM_EMAIL = os.environ.get("ALERT_FROM_EMAIL", "") or SMTP_USER

MANILA_TZ = timezone(timedelta(hours=8))
SESSION_DAYS = 60
SCHEMA_FILE = Path(__file__).with_name("schema.sql")


def today_manila() -> date:
    return datetime.now(MANILA_TZ).date()


def db():
    """Open a database connection. Used as `with db() as conn:` — commits
    automatically if everything inside succeeds, rolls back if anything fails."""
    return psycopg.connect(DATABASE_URL, row_factory=dict_row)


def clean(value):
    """Postgres NUMERIC comes back as Decimal — turn it into a plain number."""
    if isinstance(value, Decimal):
        return float(value)
    return value


def rows(cur):
    return [{k: clean(v) for k, v in r.items()} for r in cur.fetchall()]


def one(cur):
    r = cur.fetchone()
    return None if r is None else {k: clean(v) for k, v in r.items()}


def month_range(month: Optional[str]):
    """'2026-09' → (2026-09-01, 2026-10-01). Blank → the current month."""
    if not month:
        t = today_manila()
        start = t.replace(day=1)
    else:
        try:
            start = datetime.strptime(month, "%Y-%m").date()
        except ValueError:
            raise HTTPException(400, "Month must look like 2026-09.")
    end = (start.replace(day=28) + timedelta(days=4)).replace(day=1)
    return start, end


def date_range(date_from: Optional[date], date_to: Optional[date]):
    """Default to the current month when no dates are given. Returns an
    inclusive start and an EXCLUSIVE end (end = date_to + 1 day)."""
    if date_from is None and date_to is None:
        return month_range(None)
    start = date_from or date(2000, 1, 1)
    end = (date_to or date(2100, 1, 1)) + timedelta(days=1)
    return start, end


# ----------------------------------------------------------------------------
# App setup — the schema runs automatically on every start (safe to repeat)
# ----------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    with psycopg.connect(DATABASE_URL, autocommit=True) as conn:
        conn.execute(SCHEMA_FILE.read_text())
        conn.execute("DELETE FROM sessions WHERE expires_at < now();")
    yield


app = FastAPI(title="Rochar Gelato API", lifespan=lifespan)

# The admin page is a separate Render Static Site, so the browser needs
# permission to call this API from another address. Access is still
# protected by the PIN login below.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
)


@app.get("/")
def health_check():
    return {"ok": True, "message": "Rochar Gelato backend is running."}


@app.get("/db-check")
def db_check():
    try:
        with db() as conn:
            version = conn.execute("SELECT version() AS v;").fetchone()["v"]
        return {"connected": True, "postgres_version": version}
    except Exception as error:
        return {"connected": False, "error": str(error)}


# ----------------------------------------------------------------------------
# Login (one shared PIN). The frontend sends the token back on every call
# as:  Authorization: Bearer <token>
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
        raise HTTPException(400, "PIN must be 4–12 digits (6 or more recommended).")


# Simple brute-force protection: too many wrong PINs → locked for a while.
_failed_logins: List[float] = []
MAX_FAILED = 10
LOCK_WINDOW_SECONDS = 15 * 60


def _too_many_failures() -> bool:
    cutoff = time.time() - LOCK_WINDOW_SECONDS
    while _failed_logins and _failed_logins[0] < cutoff:
        _failed_logins.pop(0)
    return len(_failed_logins) >= MAX_FAILED


def new_session(cur) -> str:
    token = secrets.token_urlsafe(32)
    cur.execute(
        "INSERT INTO sessions (token_hash, expires_at) VALUES (%s, now() + %s * interval '1 day');",
        (token_hash(token), SESSION_DAYS),
    )
    return token


@app.get("/auth/status")
def auth_status():
    """Tells the login screen whether a PIN has been created yet."""
    with db() as conn:
        exists = conn.execute("SELECT 1 FROM admin_auth WHERE id = 1;").fetchone()
    return {"pin_set": bool(exists)}


@app.post("/auth/setup")
def auth_setup(payload: PinPayload):
    """First-time only: create the admin PIN. Refused once a PIN exists."""
    check_pin_format(payload.pin)
    with db() as conn, conn.cursor() as cur:
        cur.execute("SELECT 1 FROM admin_auth WHERE id = 1 FOR UPDATE;")
        if cur.fetchone():
            raise HTTPException(409, "A PIN has already been set. Log in instead.")
        cur.execute(
            "INSERT INTO admin_auth (id, pin_hash) VALUES (1, crypt(%s, gen_salt('bf')));",
            (payload.pin,),
        )
        token = new_session(cur)
    return {"token": token}


@app.post("/auth/login")
def auth_login(payload: PinPayload):
    if _too_many_failures():
        raise HTTPException(429, "Too many wrong PINs. Try again in 15 minutes.")
    with db() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT 1 FROM admin_auth WHERE id = 1 AND pin_hash = crypt(%s, pin_hash);",
            (payload.pin,),
        )
        if not cur.fetchone():
            _failed_logins.append(time.time())
            raise HTTPException(401, "Wrong PIN.")
        token = new_session(cur)
    return {"token": token}


def require_login(authorization: str = Header(default="")):
    token = authorization.removeprefix("Bearer ").strip()
    if not token:
        raise HTTPException(401, "Not logged in.")
    with db() as conn:
        ok = conn.execute(
            "SELECT 1 FROM sessions WHERE token_hash = %s AND expires_at > now();",
            (token_hash(token),),
        ).fetchone()
    if not ok:
        raise HTTPException(401, "Session expired. Please log in again.")
    return token


# Every route registered on `api` requires a logged-in session.
api = APIRouter(dependencies=[Depends(require_login)])


@api.post("/auth/logout")
def auth_logout(token: str = Depends(require_login)):
    with db() as conn:
        conn.execute("DELETE FROM sessions WHERE token_hash = %s;", (token_hash(token),))
    return {"ok": True}


@api.post("/auth/change-pin")
def auth_change_pin(payload: ChangePinPayload):
    check_pin_format(payload.new_pin)
    with db() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT 1 FROM admin_auth WHERE id = 1 AND pin_hash = crypt(%s, pin_hash);",
            (payload.current_pin,),
        )
        if not cur.fetchone():
            raise HTTPException(401, "Current PIN is wrong.")
        cur.execute(
            "UPDATE admin_auth SET pin_hash = crypt(%s, gen_salt('bf')), updated_at = now() WHERE id = 1;",
            (payload.new_pin,),
        )
        # Log out every device, then give this one a fresh session.
        cur.execute("DELETE FROM sessions;")
        token = new_session(cur)
    return {"token": token}


# ----------------------------------------------------------------------------
# Stock helpers — every stock change goes through these
# ----------------------------------------------------------------------------

def get_ingredient(cur, ingredient_id: int, lock=False):
    cur.execute(
        "SELECT * FROM ingredients WHERE id = %s" + (" FOR UPDATE" if lock else "") + ";",
        (ingredient_id,),
    )
    r = one(cur)
    if not r:
        raise HTTPException(404, f"Ingredient #{ingredient_id} not found.")
    return r


def get_product(cur, product_id: int, lock=False):
    cur.execute(
        "SELECT * FROM products WHERE id = %s" + (" FOR UPDATE" if lock else "") + ";",
        (product_id,),
    )
    r = one(cur)
    if not r:
        raise HTTPException(404, f"Product #{product_id} not found.")
    return r


def move_ingredient(cur, ingredient_id: int, delta):
    cur.execute(
        "UPDATE ingredients SET current_stock = current_stock + %s::numeric WHERE id = %s;",
        (delta, ingredient_id),
    )


def move_product(cur, product_id: int, delta):
    cur.execute(
        "UPDATE products SET current_stock = current_stock + %s::numeric WHERE id = %s;",
        (delta, product_id),
    )


def weighted_average(old_stock, old_cost, add_qty, add_total):
    """New average cost after adding stock. If there was no (or negative)
    stock before, the new batch's own cost becomes the average."""
    old_stock, old_cost = float(old_stock), float(old_cost)
    add_qty, add_total = float(add_qty), float(add_total)
    if old_stock <= 0:
        return add_total / add_qty
    return (old_stock * old_cost + add_total) / (old_stock + add_qty)


def undo_weighted_average(stock, cost, remove_qty, remove_total):
    """Best-effort reverse of weighted_average when an entry is deleted,
    so a mistaken entry doesn't permanently skew the average cost."""
    stock, cost = float(stock), float(cost)
    remaining = stock - float(remove_qty)
    if remaining <= 0:
        return cost
    return max((stock * cost - float(remove_total)) / remaining, 0)


# ----------------------------------------------------------------------------
# Ingredients (includes packaging)
# ----------------------------------------------------------------------------

class IngredientPayload(BaseModel):
    name: str
    kind: str = "ingredient"
    unit: str = "g"
    reorder_level: float = 0
    cost_per_unit: Optional[float] = None
    supplier: Optional[str] = None
    notes: Optional[str] = None
    active: bool = True
    opening_stock: Optional[float] = None   # only used when creating


LOW_STOCK_SQL = "(active AND current_stock <= reorder_level)"


@api.get("/ingredients")
def list_ingredients(include_inactive: bool = False):
    with db() as conn, conn.cursor() as cur:
        cur.execute(f"""
            SELECT *, {LOW_STOCK_SQL} AS low_stock,
                   ROUND(current_stock * cost_per_unit, 2) AS stock_value
            FROM ingredients
            WHERE active OR %s
            ORDER BY kind, name;
        """, (include_inactive,))
        return rows(cur)


@api.post("/ingredients")
def create_ingredient(p: IngredientPayload):
    if p.kind not in ("ingredient", "packaging", "other"):
        raise HTTPException(400, "Kind must be ingredient, packaging, or other.")
    with db() as conn, conn.cursor() as cur:
        try:
            cur.execute("""
                INSERT INTO ingredients (name, kind, unit, current_stock, reorder_level,
                                         cost_per_unit, supplier, notes, active)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING *;
            """, (p.name.strip(), p.kind, p.unit.strip(), p.opening_stock or 0,
                  p.reorder_level, p.cost_per_unit or 0, p.supplier, p.notes, p.active))
        except psycopg.errors.UniqueViolation:
            raise HTTPException(409, f"An ingredient called “{p.name}” already exists.")
        return one(cur)


@api.put("/ingredients/{ingredient_id}")
def update_ingredient(ingredient_id: int, p: IngredientPayload):
    """Edits details only. Stock changes go through purchases, production,
    wastage, or a stock count — never by typing a new number here."""
    if p.kind not in ("ingredient", "packaging", "other"):
        raise HTTPException(400, "Kind must be ingredient, packaging, or other.")
    with db() as conn, conn.cursor() as cur:
        current = get_ingredient(cur, ingredient_id)
        try:
            cur.execute("""
                UPDATE ingredients SET name=%s, kind=%s, unit=%s, reorder_level=%s,
                       cost_per_unit=%s, supplier=%s, notes=%s, active=%s
                WHERE id=%s RETURNING *;
            """, (p.name.strip(), p.kind, p.unit.strip(), p.reorder_level,
                  current["cost_per_unit"] if p.cost_per_unit is None else p.cost_per_unit,
                  p.supplier, p.notes, p.active, ingredient_id))
        except psycopg.errors.UniqueViolation:
            raise HTTPException(409, f"An ingredient called “{p.name}” already exists.")
        return one(cur)


# ----------------------------------------------------------------------------
# Products (finished gelato — one per flavor + size) and their recipes
# ----------------------------------------------------------------------------

class ProductPayload(BaseModel):
    name: str
    flavor: Optional[str] = None
    size: Optional[str] = None
    selling_price: float = 0
    reorder_level: float = 0
    cost_per_unit: Optional[float] = None
    notes: Optional[str] = None
    active: bool = True
    opening_stock: Optional[float] = None   # only used when creating


class RecipeLine(BaseModel):
    ingredient_id: int
    qty_per_unit: float = Field(gt=0)


class RecipePayload(BaseModel):
    items: List[RecipeLine]


@api.get("/products")
def list_products(include_inactive: bool = False):
    with db() as conn, conn.cursor() as cur:
        cur.execute(f"""
            SELECT p.*, {LOW_STOCK_SQL} AS low_stock,
                   ROUND(p.current_stock * p.cost_per_unit, 2) AS stock_value,
                   (SELECT COALESCE(SUM(ri.qty_per_unit * i.cost_per_unit), 0)
                      FROM recipe_items ri JOIN ingredients i ON i.id = ri.ingredient_id
                     WHERE ri.product_id = p.id) AS recipe_cost_per_unit,
                   (SELECT COUNT(*) FROM recipe_items ri WHERE ri.product_id = p.id) AS recipe_lines
            FROM products p
            WHERE p.active OR %s
            ORDER BY p.name;
        """, (include_inactive,))
        return rows(cur)


@api.post("/products")
def create_product(p: ProductPayload):
    with db() as conn, conn.cursor() as cur:
        try:
            cur.execute("""
                INSERT INTO products (name, flavor, size, selling_price, current_stock,
                                      reorder_level, cost_per_unit, notes, active)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING *;
            """, (p.name.strip(), p.flavor, p.size, p.selling_price, p.opening_stock or 0,
                  p.reorder_level, p.cost_per_unit or 0, p.notes, p.active))
        except psycopg.errors.UniqueViolation:
            raise HTTPException(409, f"A product called “{p.name}” already exists.")
        return one(cur)


@api.put("/products/{product_id}")
def update_product(product_id: int, p: ProductPayload):
    with db() as conn, conn.cursor() as cur:
        current = get_product(cur, product_id)
        try:
            cur.execute("""
                UPDATE products SET name=%s, flavor=%s, size=%s, selling_price=%s,
                       reorder_level=%s, cost_per_unit=%s, notes=%s, active=%s
                WHERE id=%s RETURNING *;
            """, (p.name.strip(), p.flavor, p.size, p.selling_price, p.reorder_level,
                  current["cost_per_unit"] if p.cost_per_unit is None else p.cost_per_unit,
                  p.notes, p.active, product_id))
        except psycopg.errors.UniqueViolation:
            raise HTTPException(409, f"A product called “{p.name}” already exists.")
        return one(cur)


@api.get("/products/{product_id}/recipe")
def get_recipe(product_id: int):
    with db() as conn, conn.cursor() as cur:
        get_product(cur, product_id)
        cur.execute("""
            SELECT ri.ingredient_id, i.name, i.unit, ri.qty_per_unit, i.cost_per_unit,
                   ROUND(ri.qty_per_unit * i.cost_per_unit, 4) AS line_cost
            FROM recipe_items ri JOIN ingredients i ON i.id = ri.ingredient_id
            WHERE ri.product_id = %s ORDER BY i.name;
        """, (product_id,))
        return rows(cur)


@api.put("/products/{product_id}/recipe")
def set_recipe(product_id: int, p: RecipePayload):
    """Replaces the whole recipe for this product (per ONE unit)."""
    ids = [line.ingredient_id for line in p.items]
    if len(ids) != len(set(ids)):
        raise HTTPException(400, "The same ingredient is listed twice in the recipe.")
    with db() as conn, conn.cursor() as cur:
        get_product(cur, product_id)
        for line in p.items:
            get_ingredient(cur, line.ingredient_id)
        cur.execute("DELETE FROM recipe_items WHERE product_id = %s;", (product_id,))
        for line in p.items:
            cur.execute(
                "INSERT INTO recipe_items (product_id, ingredient_id, qty_per_unit) VALUES (%s, %s, %s);",
                (product_id, line.ingredient_id, line.qty_per_unit),
            )
    return get_recipe(product_id)


# ----------------------------------------------------------------------------
# Purchases (ingredient stock in)
# ----------------------------------------------------------------------------

class PurchasePayload(BaseModel):
    purchase_date: date
    ingredient_id: int
    qty: float = Field(gt=0)
    total_cost: float = Field(ge=0)
    supplier: Optional[str] = None
    payment_method: Optional[str] = None
    notes: Optional[str] = None


@api.get("/purchases")
def list_purchases(date_from: Optional[date] = None, date_to: Optional[date] = None):
    start, end = date_range(date_from, date_to)
    with db() as conn, conn.cursor() as cur:
        cur.execute("""
            SELECT pu.*, i.name AS ingredient_name, i.unit, i.kind,
                   ROUND(pu.total_cost / pu.qty, 4) AS unit_cost
            FROM purchases pu JOIN ingredients i ON i.id = pu.ingredient_id
            WHERE pu.purchase_date >= %s AND pu.purchase_date < %s
            ORDER BY pu.purchase_date DESC, pu.id DESC;
        """, (start, end))
        return rows(cur)


@api.post("/purchases")
def create_purchase(p: PurchasePayload):
    with db() as conn, conn.cursor() as cur:
        ing = get_ingredient(cur, p.ingredient_id, lock=True)
        new_cost = weighted_average(ing["current_stock"], ing["cost_per_unit"], p.qty, p.total_cost)
        cur.execute("""
            UPDATE ingredients SET current_stock = current_stock + %s::numeric, cost_per_unit = %s,
                   supplier = COALESCE(NULLIF(%s, ''), supplier)
            WHERE id = %s;
        """, (p.qty, new_cost, p.supplier or "", p.ingredient_id))
        cur.execute("""
            INSERT INTO purchases (purchase_date, ingredient_id, qty, total_cost,
                                   supplier, payment_method, notes)
            VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING *;
        """, (p.purchase_date, p.ingredient_id, p.qty, p.total_cost,
              p.supplier, p.payment_method, p.notes))
        return one(cur)


@api.delete("/purchases/{purchase_id}")
def delete_purchase(purchase_id: int):
    """Removes the purchase, takes its quantity back out of stock, and
    backs its price out of the average cost."""
    with db() as conn, conn.cursor() as cur:
        cur.execute("DELETE FROM purchases WHERE id = %s RETURNING *;", (purchase_id,))
        r = one(cur)
        if not r:
            raise HTTPException(404, "Purchase not found.")
        ing = get_ingredient(cur, r["ingredient_id"], lock=True)
        new_cost = undo_weighted_average(ing["current_stock"], ing["cost_per_unit"],
                                         r["qty"], r["total_cost"])
        cur.execute(
            "UPDATE ingredients SET current_stock = current_stock - %s::numeric, cost_per_unit = %s WHERE id = %s;",
            (r["qty"], new_cost, r["ingredient_id"]),
        )
    return {"ok": True}


# ----------------------------------------------------------------------------
# Production batches
# ----------------------------------------------------------------------------

class ProductionIngredient(BaseModel):
    ingredient_id: int
    qty_used: float = Field(gt=0)


class ProductionPayload(BaseModel):
    batch_date: date
    product_id: int
    units_produced: float = Field(gt=0)
    batch_code: Optional[str] = None
    notes: Optional[str] = None
    # Leave out (null) to use the product's saved recipe × units produced.
    ingredients: Optional[List[ProductionIngredient]] = None


@api.get("/production/recipe-preview")
def production_recipe_preview(product_id: int, units: float):
    """What a batch of N units would use, from the saved recipe — used to
    pre-fill the production form so it can be adjusted before saving."""
    with db() as conn, conn.cursor() as cur:
        get_product(cur, product_id)
        cur.execute("""
            SELECT ri.ingredient_id, i.name, i.unit, i.current_stock,
                   ROUND(ri.qty_per_unit * %s::numeric, 3) AS qty_used,
                   ROUND(ri.qty_per_unit * %s::numeric * i.cost_per_unit, 2) AS cost
            FROM recipe_items ri JOIN ingredients i ON i.id = ri.ingredient_id
            WHERE ri.product_id = %s ORDER BY i.name;
        """, (units, units, product_id))
        return rows(cur)


@api.get("/production")
def list_production(date_from: Optional[date] = None, date_to: Optional[date] = None):
    start, end = date_range(date_from, date_to)
    with db() as conn, conn.cursor() as cur:
        cur.execute("""
            SELECT b.*, p.name AS product_name,
                   ROUND(b.total_cost / b.units_produced, 2) AS cost_per_unit,
                   COALESCE((
                     SELECT json_agg(json_build_object(
                              'ingredient_id', pi.ingredient_id, 'name', i.name, 'unit', i.unit,
                              'qty_used', pi.qty_used, 'unit_cost', pi.unit_cost) ORDER BY i.name)
                     FROM production_ingredients pi JOIN ingredients i ON i.id = pi.ingredient_id
                     WHERE pi.batch_id = b.id), '[]') AS ingredients
            FROM production_batches b JOIN products p ON p.id = b.product_id
            WHERE b.batch_date >= %s AND b.batch_date < %s
            ORDER BY b.batch_date DESC, b.id DESC;
        """, (start, end))
        return rows(cur)


@api.post("/production")
def create_production(p: ProductionPayload):
    with db() as conn, conn.cursor() as cur:
        product = get_product(cur, p.product_id, lock=True)

        if p.ingredients is None:
            cur.execute("""
                SELECT ingredient_id, qty_per_unit * %s::numeric AS qty_used
                FROM recipe_items WHERE product_id = %s;
            """, (p.units_produced, p.product_id))
            lines = [(r["ingredient_id"], float(r["qty_used"])) for r in cur.fetchall()]
        else:
            lines = [(x.ingredient_id, x.qty_used) for x in p.ingredients]

        ids = [i for i, _ in lines]
        if len(ids) != len(set(ids)):
            raise HTTPException(400, "The same ingredient is listed twice.")

        cur.execute("""
            INSERT INTO production_batches (batch_date, product_id, units_produced, batch_code, notes)
            VALUES (%s, %s, %s, %s, %s) RETURNING id;
        """, (p.batch_date, p.product_id, p.units_produced, p.batch_code, p.notes))
        batch_id = cur.fetchone()["id"]

        total_cost = 0.0
        for ingredient_id, qty in lines:
            ing = get_ingredient(cur, ingredient_id, lock=True)
            unit_cost = float(ing["cost_per_unit"])
            total_cost += qty * unit_cost
            cur.execute("""
                INSERT INTO production_ingredients (batch_id, ingredient_id, qty_used, unit_cost)
                VALUES (%s, %s, %s, %s);
            """, (batch_id, ingredient_id, qty, unit_cost))
            move_ingredient(cur, ingredient_id, -qty)

        new_cost = weighted_average(product["current_stock"], product["cost_per_unit"],
                                    p.units_produced, total_cost)
        cur.execute(
            "UPDATE products SET current_stock = current_stock + %s::numeric, cost_per_unit = %s WHERE id = %s;",
            (p.units_produced, new_cost, p.product_id),
        )
        cur.execute("UPDATE production_batches SET total_cost = %s WHERE id = %s RETURNING *;",
                    (round(total_cost, 2), batch_id))
        batch = one(cur)
        batch["ingredient_lines"] = len(lines)
        return batch


@api.delete("/production/{batch_id}")
def delete_production(batch_id: int):
    """Undoes a batch: ingredients go back into stock, the units come back
    out of product stock."""
    with db() as conn, conn.cursor() as cur:
        cur.execute("SELECT * FROM production_batches WHERE id = %s;", (batch_id,))
        batch = one(cur)
        if not batch:
            raise HTTPException(404, "Batch not found.")
        cur.execute("SELECT ingredient_id, qty_used FROM production_ingredients WHERE batch_id = %s;",
                    (batch_id,))
        for r in cur.fetchall():
            move_ingredient(cur, r["ingredient_id"], r["qty_used"])
        product = get_product(cur, batch["product_id"], lock=True)
        new_cost = undo_weighted_average(product["current_stock"], product["cost_per_unit"],
                                         batch["units_produced"], batch["total_cost"])
        cur.execute(
            "UPDATE products SET current_stock = current_stock - %s::numeric, cost_per_unit = %s WHERE id = %s;",
            (batch["units_produced"], new_cost, batch["product_id"]),
        )
        cur.execute("DELETE FROM production_batches WHERE id = %s;", (batch_id,))
    return {"ok": True}


# ----------------------------------------------------------------------------
# Sales
# ----------------------------------------------------------------------------

class SaleItem(BaseModel):
    product_id: int
    qty: float = Field(gt=0)
    unit_price: Optional[float] = None   # blank = product's selling price


class SalePayload(BaseModel):
    sale_date: date
    customer_name: Optional[str] = None
    channel: Optional[str] = None
    payment_method: Optional[str] = None
    discount: float = 0
    delivery_fee: float = 0
    notes: Optional[str] = None
    items: List[SaleItem]


def insert_sale(cur, p: SalePayload, order_id: Optional[int] = None):
    if not p.items:
        raise HTTPException(400, "A sale needs at least one item.")
    items_total = 0.0
    prepared = []
    for item in p.items:
        product = get_product(cur, item.product_id, lock=True)
        price = float(product["selling_price"]) if item.unit_price is None else item.unit_price
        items_total += price * item.qty
        prepared.append((item.product_id, item.qty, price, float(product["cost_per_unit"])))
    total = round(items_total - p.discount + p.delivery_fee, 2)
    cur.execute("""
        INSERT INTO sales (sale_date, customer_name, channel, payment_method, discount,
                           delivery_fee, total, order_id, notes)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING id;
    """, (p.sale_date, p.customer_name, p.channel, p.payment_method, p.discount,
          p.delivery_fee, total, order_id, p.notes))
    sale_id = cur.fetchone()["id"]
    for product_id, qty, price, cost in prepared:
        cur.execute("""
            INSERT INTO sale_items (sale_id, product_id, qty, unit_price, unit_cost)
            VALUES (%s, %s, %s, %s, %s);
        """, (sale_id, product_id, qty, price, cost))
        move_product(cur, product_id, -qty)
    return sale_id


SALE_SELECT = """
    SELECT s.*,
           COALESCE((SELECT json_agg(json_build_object(
                      'product_id', si.product_id, 'name', p.name, 'qty', si.qty,
                      'unit_price', si.unit_price, 'unit_cost', si.unit_cost) ORDER BY si.id)
                     FROM sale_items si JOIN products p ON p.id = si.product_id
                     WHERE si.sale_id = s.id), '[]') AS items
    FROM sales s
"""


@api.get("/sales")
def list_sales(date_from: Optional[date] = None, date_to: Optional[date] = None):
    start, end = date_range(date_from, date_to)
    with db() as conn, conn.cursor() as cur:
        cur.execute(SALE_SELECT + """
            WHERE s.sale_date >= %s AND s.sale_date < %s
            ORDER BY s.sale_date DESC, s.id DESC;
        """, (start, end))
        return rows(cur)


@api.post("/sales")
def create_sale(p: SalePayload):
    with db() as conn, conn.cursor() as cur:
        sale_id = insert_sale(cur, p)
        cur.execute(SALE_SELECT + " WHERE s.id = %s;", (sale_id,))
        return one(cur)


@api.delete("/sales/{sale_id}")
def delete_sale(sale_id: int):
    """Removes a sale and puts the products back in stock. If it came from
    a completed order, that order goes back to 'ready'."""
    with db() as conn, conn.cursor() as cur:
        cur.execute("SELECT * FROM sales WHERE id = %s;", (sale_id,))
        sale = one(cur)
        if not sale:
            raise HTTPException(404, "Sale not found.")
        cur.execute("SELECT product_id, qty FROM sale_items WHERE sale_id = %s;", (sale_id,))
        for r in cur.fetchall():
            move_product(cur, r["product_id"], r["qty"])
        cur.execute("""
            UPDATE orders SET status = 'ready', sale_id = NULL, updated_at = now()
            WHERE sale_id = %s;
        """, (sale_id,))
        cur.execute("DELETE FROM sales WHERE id = %s;", (sale_id,))
    return {"ok": True}


# ----------------------------------------------------------------------------
# Wastage
# ----------------------------------------------------------------------------

class WastagePayload(BaseModel):
    waste_date: date
    item_type: str                  # 'ingredient' or 'product'
    item_id: int
    qty: float = Field(gt=0)
    reason: str = "other"           # melted, expired, damaged, sample, quality, other
    notes: Optional[str] = None


@api.get("/wastage")
def list_wastage(date_from: Optional[date] = None, date_to: Optional[date] = None):
    start, end = date_range(date_from, date_to)
    with db() as conn, conn.cursor() as cur:
        cur.execute("""
            SELECT w.*, COALESCE(i.name, p.name) AS item_name, COALESCE(i.unit, 'pc') AS unit
            FROM wastage w
            LEFT JOIN ingredients i ON i.id = w.ingredient_id
            LEFT JOIN products p ON p.id = w.product_id
            WHERE w.waste_date >= %s AND w.waste_date < %s
            ORDER BY w.waste_date DESC, w.id DESC;
        """, (start, end))
        return rows(cur)


@api.post("/wastage")
def create_wastage(p: WastagePayload):
    if p.item_type not in ("ingredient", "product"):
        raise HTTPException(400, "item_type must be 'ingredient' or 'product'.")
    with db() as conn, conn.cursor() as cur:
        if p.item_type == "ingredient":
            item = get_ingredient(cur, p.item_id, lock=True)
            move_ingredient(cur, p.item_id, -p.qty)
            ids = (p.item_id, None)
        else:
            item = get_product(cur, p.item_id, lock=True)
            move_product(cur, p.item_id, -p.qty)
            ids = (None, p.item_id)
        cost_value = round(p.qty * float(item["cost_per_unit"]), 2)
        cur.execute("""
            INSERT INTO wastage (waste_date, item_type, ingredient_id, product_id, qty,
                                 reason, cost_value, notes)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s) RETURNING *;
        """, (p.waste_date, p.item_type, ids[0], ids[1], p.qty, p.reason.strip() or "other",
              cost_value, p.notes))
        return one(cur)


@api.delete("/wastage/{wastage_id}")
def delete_wastage(wastage_id: int):
    with db() as conn, conn.cursor() as cur:
        cur.execute("DELETE FROM wastage WHERE id = %s RETURNING *;", (wastage_id,))
        w = one(cur)
        if not w:
            raise HTTPException(404, "Wastage entry not found.")
        if w["item_type"] == "ingredient":
            move_ingredient(cur, w["ingredient_id"], w["qty"])
        else:
            move_product(cur, w["product_id"], w["qty"])
    return {"ok": True}


# ----------------------------------------------------------------------------
# Expenses
# ----------------------------------------------------------------------------

class ExpensePayload(BaseModel):
    expense_date: date
    category: str = "Other"
    description: str
    amount: float = Field(ge=0)
    payment_method: Optional[str] = None
    vendor: Optional[str] = None
    notes: Optional[str] = None


@api.get("/expenses")
def list_expenses(date_from: Optional[date] = None, date_to: Optional[date] = None):
    start, end = date_range(date_from, date_to)
    with db() as conn, conn.cursor() as cur:
        cur.execute("""
            SELECT * FROM expenses
            WHERE expense_date >= %s AND expense_date < %s
            ORDER BY expense_date DESC, id DESC;
        """, (start, end))
        return rows(cur)


@api.get("/expenses/categories")
def expense_categories():
    """Categories already used, so the form can suggest them."""
    defaults = ["Utilities", "Rent", "Delivery", "Marketing", "Equipment",
                "Repairs", "Fees & Permits", "Supplies", "Salaries", "Other"]
    with db() as conn:
        used = [r["category"] for r in conn.execute(
            "SELECT DISTINCT category FROM expenses ORDER BY category;").fetchall()]
    return sorted(set(defaults) | set(used))


@api.post("/expenses")
def create_expense(p: ExpensePayload):
    with db() as conn, conn.cursor() as cur:
        cur.execute("""
            INSERT INTO expenses (expense_date, category, description, amount,
                                  payment_method, vendor, notes)
            VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING *;
        """, (p.expense_date, p.category.strip() or "Other", p.description, p.amount,
              p.payment_method, p.vendor, p.notes))
        return one(cur)


@api.put("/expenses/{expense_id}")
def update_expense(expense_id: int, p: ExpensePayload):
    with db() as conn, conn.cursor() as cur:
        cur.execute("""
            UPDATE expenses SET expense_date=%s, category=%s, description=%s, amount=%s,
                   payment_method=%s, vendor=%s, notes=%s
            WHERE id=%s RETURNING *;
        """, (p.expense_date, p.category.strip() or "Other", p.description, p.amount,
              p.payment_method, p.vendor, p.notes, expense_id))
        r = one(cur)
        if not r:
            raise HTTPException(404, "Expense not found.")
        return r


@api.delete("/expenses/{expense_id}")
def delete_expense(expense_id: int):
    with db() as conn:
        r = conn.execute("DELETE FROM expenses WHERE id = %s RETURNING id;", (expense_id,)).fetchone()
    if not r:
        raise HTTPException(404, "Expense not found.")
    return {"ok": True}


# ----------------------------------------------------------------------------
# Stock counts (physical count corrections)
# ----------------------------------------------------------------------------

class StockCountPayload(BaseModel):
    adjust_date: date
    item_type: str
    item_id: int
    counted_qty: float = Field(ge=0)
    notes: Optional[str] = None


@api.get("/stock-counts")
def list_stock_counts(date_from: Optional[date] = None, date_to: Optional[date] = None):
    start, end = date_range(date_from, date_to)
    with db() as conn, conn.cursor() as cur:
        cur.execute("""
            SELECT a.*, COALESCE(i.name, p.name) AS item_name, COALESCE(i.unit, 'pc') AS unit
            FROM stock_adjustments a
            LEFT JOIN ingredients i ON i.id = a.ingredient_id
            LEFT JOIN products p ON p.id = a.product_id
            WHERE a.adjust_date >= %s AND a.adjust_date < %s
            ORDER BY a.adjust_date DESC, a.id DESC;
        """, (start, end))
        return rows(cur)


@api.post("/stock-counts")
def create_stock_count(p: StockCountPayload):
    if p.item_type not in ("ingredient", "product"):
        raise HTTPException(400, "item_type must be 'ingredient' or 'product'.")
    with db() as conn, conn.cursor() as cur:
        if p.item_type == "ingredient":
            item = get_ingredient(cur, p.item_id, lock=True)
            table, ids = "ingredients", (p.item_id, None)
        else:
            item = get_product(cur, p.item_id, lock=True)
            table, ids = "products", (None, p.item_id)
        system_qty = float(item["current_stock"])
        diff = p.counted_qty - system_qty
        cur.execute(f"UPDATE {table} SET current_stock = %s WHERE id = %s;", (p.counted_qty, p.item_id))
        cur.execute("""
            INSERT INTO stock_adjustments (adjust_date, item_type, ingredient_id, product_id,
                                           system_qty, counted_qty, difference, notes)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s) RETURNING *;
        """, (p.adjust_date, p.item_type, ids[0], ids[1], system_qty, p.counted_qty, diff, p.notes))
        return one(cur)


# ----------------------------------------------------------------------------
# Orders (customer orders + due dates)
# ----------------------------------------------------------------------------

ORDER_STATUSES = ("pending", "confirmed", "in_production", "ready", "completed", "cancelled")
OPEN_STATUSES = ("pending", "confirmed", "in_production", "ready")


class OrderItem(BaseModel):
    product_id: int
    qty: float = Field(gt=0)
    unit_price: Optional[float] = None


class OrderPayload(BaseModel):
    customer_name: str
    contact: Optional[str] = None
    due_date: date
    due_time: Optional[str] = None
    fulfillment: str = "pickup"
    address: Optional[str] = None
    status: str = "pending"
    deposit_paid: float = 0
    delivery_fee: float = 0
    discount: float = 0
    notes: Optional[str] = None
    items: List[OrderItem]


class OrderStatusPayload(BaseModel):
    status: str


class OrderCompletePayload(BaseModel):
    sale_date: Optional[date] = None
    payment_method: Optional[str] = None
    channel: Optional[str] = "order"


ORDER_SELECT = """
    SELECT o.*,
           COALESCE((SELECT json_agg(json_build_object(
                      'product_id', oi.product_id, 'name', p.name, 'qty', oi.qty,
                      'unit_price', oi.unit_price) ORDER BY oi.id)
                     FROM order_items oi JOIN products p ON p.id = oi.product_id
                     WHERE oi.order_id = o.id), '[]') AS items,
           COALESCE((SELECT SUM(oi.qty * oi.unit_price) FROM order_items oi
                     WHERE oi.order_id = o.id), 0) - o.discount + o.delivery_fee AS total,
           (o.due_date - %s) AS days_until_due
    FROM orders o
"""


def validate_order(p: OrderPayload):
    if p.fulfillment not in ("pickup", "delivery"):
        raise HTTPException(400, "Fulfillment must be pickup or delivery.")
    if p.status not in OPEN_STATUSES + ("cancelled",):
        raise HTTPException(400, "Use the Complete button to complete an order.")
    if not p.items:
        raise HTTPException(400, "An order needs at least one item.")


def write_order_items(cur, order_id: int, items: List[OrderItem]):
    cur.execute("DELETE FROM order_items WHERE order_id = %s;", (order_id,))
    for item in items:
        product = get_product(cur, item.product_id)
        price = float(product["selling_price"]) if item.unit_price is None else item.unit_price
        cur.execute("""
            INSERT INTO order_items (order_id, product_id, qty, unit_price)
            VALUES (%s, %s, %s, %s);
        """, (order_id, item.product_id, item.qty, price))


def fetch_order(cur, order_id: int):
    cur.execute(ORDER_SELECT + " WHERE o.id = %s;", (today_manila(), order_id))
    r = one(cur)
    if not r:
        raise HTTPException(404, "Order not found.")
    return r


@api.get("/orders")
def list_orders(date_from: Optional[date] = None, date_to: Optional[date] = None,
                status: Optional[str] = None, open_only: bool = False):
    """Orders by due date. `open_only=true` shows everything not yet
    completed/cancelled regardless of date (including overdue)."""
    where, params = [], [today_manila()]
    if open_only:
        where.append("o.status = ANY(%s)")
        params.append(list(OPEN_STATUSES))
    else:
        start, end = date_range(date_from, date_to)
        where.append("o.due_date >= %s AND o.due_date < %s")
        params += [start, end]
    if status:
        where.append("o.status = %s")
        params.append(status)
    with db() as conn, conn.cursor() as cur:
        cur.execute(ORDER_SELECT + " WHERE " + " AND ".join(where) +
                    " ORDER BY o.due_date, o.id;", params)
        return rows(cur)


@api.get("/orders/{order_id}")
def get_order(order_id: int):
    with db() as conn, conn.cursor() as cur:
        return fetch_order(cur, order_id)


@api.post("/orders")
def create_order(p: OrderPayload):
    validate_order(p)
    with db() as conn, conn.cursor() as cur:
        cur.execute("""
            INSERT INTO orders (customer_name, contact, due_date, due_time, fulfillment, address,
                                status, deposit_paid, delivery_fee, discount, notes)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING id;
        """, (p.customer_name, p.contact, p.due_date, p.due_time, p.fulfillment, p.address,
              p.status, p.deposit_paid, p.delivery_fee, p.discount, p.notes))
        order_id = cur.fetchone()["id"]
        write_order_items(cur, order_id, p.items)
        return fetch_order(cur, order_id)


@api.put("/orders/{order_id}")
def update_order(order_id: int, p: OrderPayload):
    validate_order(p)
    with db() as conn, conn.cursor() as cur:
        current = fetch_order(cur, order_id)
        if current["status"] == "completed":
            raise HTTPException(400, "This order is already completed. Delete its sale first to edit it.")
        cur.execute("""
            UPDATE orders SET customer_name=%s, contact=%s, due_date=%s, due_time=%s,
                   fulfillment=%s, address=%s, status=%s, deposit_paid=%s, delivery_fee=%s,
                   discount=%s, notes=%s, updated_at=now()
            WHERE id=%s;
        """, (p.customer_name, p.contact, p.due_date, p.due_time, p.fulfillment, p.address,
              p.status, p.deposit_paid, p.delivery_fee, p.discount, p.notes, order_id))
        write_order_items(cur, order_id, p.items)
        return fetch_order(cur, order_id)


@api.post("/orders/{order_id}/status")
def set_order_status(order_id: int, p: OrderStatusPayload):
    if p.status not in OPEN_STATUSES + ("cancelled",):
        raise HTTPException(400, "Use the Complete button to complete an order.")
    with db() as conn, conn.cursor() as cur:
        current = fetch_order(cur, order_id)
        if current["status"] == "completed":
            raise HTTPException(400, "This order is already completed. Delete its sale first to change it.")
        cur.execute("UPDATE orders SET status = %s, updated_at = now() WHERE id = %s;",
                    (p.status, order_id))
        return fetch_order(cur, order_id)


@api.post("/orders/{order_id}/complete")
def complete_order(order_id: int, p: OrderCompletePayload):
    """Hands the order over: records it as a sale (which takes the products
    out of stock) and marks the order completed."""
    with db() as conn, conn.cursor() as cur:
        cur.execute("SELECT * FROM orders WHERE id = %s FOR UPDATE;", (order_id,))
        order = one(cur)
        if not order:
            raise HTTPException(404, "Order not found.")
        if order["status"] in ("completed", "cancelled"):
            raise HTTPException(400, f"This order is already {order['status']}.")
        cur.execute("SELECT product_id, qty, unit_price FROM order_items WHERE order_id = %s ORDER BY id;",
                    (order_id,))
        items = [SaleItem(product_id=r["product_id"], qty=float(r["qty"]),
                          unit_price=float(r["unit_price"])) for r in cur.fetchall()]
        sale = SalePayload(
            sale_date=p.sale_date or today_manila(),
            customer_name=order["customer_name"],
            channel=p.channel,
            payment_method=p.payment_method,
            discount=order["discount"],
            delivery_fee=order["delivery_fee"],
            notes=f"Order #{order_id}",
            items=items,
        )
        sale_id = insert_sale(cur, sale, order_id=order_id)
        cur.execute("UPDATE orders SET status='completed', sale_id=%s, updated_at=now() WHERE id=%s;",
                    (sale_id, order_id))
        return fetch_order(cur, order_id)


@api.delete("/orders/{order_id}")
def delete_order(order_id: int):
    with db() as conn, conn.cursor() as cur:
        order = fetch_order(cur, order_id)
        if order["status"] == "completed":
            raise HTTPException(400, "This order is completed. Delete its sale first, then the order.")
        cur.execute("DELETE FROM orders WHERE id = %s;", (order_id,))
    return {"ok": True}


# ----------------------------------------------------------------------------
# Dashboard + monthly report
# ----------------------------------------------------------------------------

def low_stock_items(cur):
    cur.execute(f"""
        SELECT 'ingredient' AS item_type, id, name, kind, unit, current_stock, reorder_level
        FROM ingredients WHERE {LOW_STOCK_SQL}
        UNION ALL
        SELECT 'product', id, name, 'product', 'pc', current_stock, reorder_level
        FROM products WHERE {LOW_STOCK_SQL}
        ORDER BY 1, 3;
    """)
    return rows(cur)


def orders_due_within(cur, days: int):
    t = today_manila()
    cur.execute(ORDER_SELECT + " WHERE o.status = ANY(%s) AND o.due_date <= %s ORDER BY o.due_date, o.id;",
                (t, list(OPEN_STATUSES), t + timedelta(days=days)))
    return rows(cur)


@api.get("/dashboard")
def dashboard():
    t = today_manila()
    start, end = month_range(None)
    with db() as conn, conn.cursor() as cur:
        low = low_stock_items(cur)
        upcoming = orders_due_within(cur, 7)
        cur.execute("""
            SELECT
              (SELECT COALESCE(SUM(total), 0) FROM sales WHERE sale_date = %(t)s) AS sales_today,
              (SELECT COALESCE(SUM(total), 0) FROM sales WHERE sale_date >= %(s)s AND sale_date < %(e)s) AS sales_mtd,
              (SELECT COALESCE(SUM(amount), 0) FROM expenses WHERE expense_date >= %(s)s AND expense_date < %(e)s) AS expenses_mtd,
              (SELECT COALESCE(SUM(cost_value), 0) FROM wastage WHERE waste_date >= %(s)s AND waste_date < %(e)s) AS wastage_mtd,
              (SELECT COALESCE(SUM(units_produced), 0) FROM production_batches WHERE batch_date >= %(s)s AND batch_date < %(e)s) AS units_produced_mtd,
              (SELECT COALESCE(SUM(current_stock * cost_per_unit), 0) FROM ingredients WHERE active) AS ingredient_stock_value,
              (SELECT COALESCE(SUM(current_stock * cost_per_unit), 0) FROM products WHERE active) AS product_stock_value;
        """, {"t": t, "s": start, "e": end})
        totals = one(cur)
    return {"today": t, "month": start.strftime("%Y-%m"), "totals": totals,
            "low_stock": low, "upcoming_orders": upcoming}


@api.get("/reports/monthly")
def monthly_report(month: Optional[str] = None):
    """One month's numbers.

    Profit logic: ingredient purchases are stock (inventory), not an expense.
    Their cost reaches profit through COGS (cost of the gelato actually sold)
    and wastage (cost of what was thrown away).
      Gross profit    = sales − COGS
      Net profit      = gross profit − wastage − operating expenses
    """
    start, end = month_range(month)
    q = {"s": start, "e": end}
    with db() as conn, conn.cursor() as cur:
        cur.execute("""
            SELECT COUNT(*) AS sale_count,
                   COALESCE(SUM(total), 0) AS revenue,
                   COALESCE(SUM(discount), 0) AS discounts,
                   COALESCE(SUM(delivery_fee), 0) AS delivery_fees
            FROM sales WHERE sale_date >= %(s)s AND sale_date < %(e)s;
        """, q)
        sales = one(cur)

        cur.execute("""
            SELECT p.id, p.name,
                   SUM(si.qty) AS qty,
                   ROUND(SUM(si.qty * si.unit_price), 2) AS gross_sales,
                   ROUND(SUM(si.qty * si.unit_cost), 2) AS cogs
            FROM sale_items si JOIN sales s ON s.id = si.sale_id
            JOIN products p ON p.id = si.product_id
            WHERE s.sale_date >= %(s)s AND s.sale_date < %(e)s
            GROUP BY p.id, p.name ORDER BY gross_sales DESC;
        """, q)
        by_product = rows(cur)
        cogs = round(sum(r["cogs"] for r in by_product), 2)

        cur.execute("""
            SELECT COALESCE(NULLIF(channel, ''), '(none)') AS channel,
                   COUNT(*) AS sale_count, COALESCE(SUM(total), 0) AS revenue
            FROM sales WHERE sale_date >= %(s)s AND sale_date < %(e)s
            GROUP BY 1 ORDER BY revenue DESC;
        """, q)
        by_channel = rows(cur)

        cur.execute("""
            SELECT COALESCE(NULLIF(payment_method, ''), '(none)') AS payment_method,
                   COALESCE(SUM(total), 0) AS revenue
            FROM sales WHERE sale_date >= %(s)s AND sale_date < %(e)s
            GROUP BY 1 ORDER BY revenue DESC;
        """, q)
        by_payment = rows(cur)

        cur.execute("""
            SELECT sale_date AS day, COALESCE(SUM(total), 0) AS revenue
            FROM sales WHERE sale_date >= %(s)s AND sale_date < %(e)s
            GROUP BY sale_date ORDER BY sale_date;
        """, q)
        daily_sales = rows(cur)

        cur.execute("""
            SELECT category, COUNT(*) AS entries, SUM(amount) AS amount
            FROM expenses WHERE expense_date >= %(s)s AND expense_date < %(e)s
            GROUP BY category ORDER BY amount DESC;
        """, q)
        expenses_by_category = rows(cur)
        expenses_total = round(sum(r["amount"] for r in expenses_by_category), 2)

        cur.execute("""
            SELECT item_type, reason, SUM(cost_value) AS cost_value, COUNT(*) AS entries
            FROM wastage WHERE waste_date >= %(s)s AND waste_date < %(e)s
            GROUP BY item_type, reason ORDER BY cost_value DESC;
        """, q)
        wastage_breakdown = rows(cur)
        wastage_total = round(sum(r["cost_value"] for r in wastage_breakdown), 2)

        cur.execute("""
            SELECT i.kind, SUM(pu.total_cost) AS amount, COUNT(*) AS entries
            FROM purchases pu JOIN ingredients i ON i.id = pu.ingredient_id
            WHERE pu.purchase_date >= %(s)s AND pu.purchase_date < %(e)s
            GROUP BY i.kind ORDER BY amount DESC;
        """, q)
        purchases_by_kind = rows(cur)
        purchases_total = round(sum(r["amount"] for r in purchases_by_kind), 2)

        cur.execute("""
            SELECT p.name, COUNT(*) AS batches, SUM(b.units_produced) AS units,
                   SUM(b.total_cost) AS cost,
                   ROUND(SUM(b.total_cost) / NULLIF(SUM(b.units_produced), 0), 2) AS cost_per_unit
            FROM production_batches b JOIN products p ON p.id = b.product_id
            WHERE b.batch_date >= %(s)s AND b.batch_date < %(e)s
            GROUP BY p.name ORDER BY units DESC;
        """, q)
        production = rows(cur)

        cur.execute("""
            SELECT status, COUNT(*) AS count FROM orders
            WHERE due_date >= %(s)s AND due_date < %(e)s GROUP BY status;
        """, q)
        orders_by_status = {r["status"]: r["count"] for r in cur.fetchall()}

    revenue = float(sales["revenue"])
    gross_profit = round(revenue - cogs, 2)
    net_profit = round(gross_profit - wastage_total - expenses_total, 2)
    return {
        "month": start.strftime("%Y-%m"),
        "summary": {
            "revenue": revenue,
            "sale_count": sales["sale_count"],
            "discounts": sales["discounts"],
            "delivery_fees": sales["delivery_fees"],
            "cogs": cogs,
            "gross_profit": gross_profit,
            "gross_margin_pct": round(gross_profit / revenue * 100, 1) if revenue else None,
            "wastage": wastage_total,
            "expenses": expenses_total,
            "net_profit": net_profit,
            "ingredient_purchases": purchases_total,
        },
        "sales_by_product": by_product,
        "sales_by_channel": by_channel,
        "sales_by_payment_method": by_payment,
        "daily_sales": daily_sales,
        "expenses_by_category": expenses_by_category,
        "wastage_breakdown": wastage_breakdown,
        "purchases_by_kind": purchases_by_kind,
        "production": production,
        "orders_by_status": orders_by_status,
    }


# ----------------------------------------------------------------------------
# Settings
# ----------------------------------------------------------------------------

class SettingsPayload(BaseModel):
    alert_emails: Optional[str] = None
    order_alert_days: Optional[int] = None
    alerts_enabled: Optional[bool] = None


def read_settings(cur):
    cur.execute("SELECT key, value FROM settings;")
    return {r["key"]: r["value"] for r in cur.fetchall()}


@api.get("/settings")
def get_settings():
    with db() as conn, conn.cursor() as cur:
        s = read_settings(cur)
    s["email_configured"] = email_method() is not None
    s["email_method"] = email_method()
    return s


@api.put("/settings")
def update_settings(p: SettingsPayload):
    updates = {}
    if p.alert_emails is not None:
        emails = [e.strip() for e in p.alert_emails.replace(";", ",").split(",") if e.strip()]
        for e in emails:
            if "@" not in e or " " in e:
                raise HTTPException(400, f"“{e}” doesn't look like an email address.")
        updates["alert_emails"] = ", ".join(emails)
    if p.order_alert_days is not None:
        if not 0 <= p.order_alert_days <= 30:
            raise HTTPException(400, "Order alert days must be between 0 and 30.")
        updates["order_alert_days"] = str(p.order_alert_days)
    if p.alerts_enabled is not None:
        updates["alerts_enabled"] = "true" if p.alerts_enabled else "false"
    with db() as conn, conn.cursor() as cur:
        for k, v in updates.items():
            cur.execute("""
                INSERT INTO settings (key, value) VALUES (%s, %s)
                ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value;
            """, (k, v))
    return get_settings()


# ----------------------------------------------------------------------------
# Email alerts
# ----------------------------------------------------------------------------

def email_method():
    if BREVO_API_KEY and ALERT_FROM_EMAIL:
        return "brevo"
    if SMTP_USER and SMTP_PASSWORD:
        return "smtp"
    return None


def send_email(to: List[str], subject: str, html: str, text: str):
    method = email_method()
    if method is None:
        raise HTTPException(500, "Email isn't set up on the server yet (no email environment variables).")
    if method == "brevo":
        r = requests.post(
            "https://api.brevo.com/v3/smtp/email",
            headers={"api-key": BREVO_API_KEY, "accept": "application/json",
                     "content-type": "application/json"},
            json={"sender": {"name": "Rochar Gelato", "email": ALERT_FROM_EMAIL},
                  "to": [{"email": e} for e in to],
                  "subject": subject, "htmlContent": html, "textContent": text},
            timeout=20,
        )
        if r.status_code >= 300:
            raise HTTPException(502, f"Brevo refused the email: {r.status_code} {r.text[:300]}")
        return
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = f"Rochar Gelato <{ALERT_FROM_EMAIL}>"
    msg["To"] = ", ".join(to)
    msg.attach(MIMEText(text, "plain", "utf-8"))
    msg.attach(MIMEText(html, "html", "utf-8"))
    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=20) as s:
            s.starttls(context=ssl.create_default_context())
            s.login(SMTP_USER, SMTP_PASSWORD)
            s.sendmail(ALERT_FROM_EMAIL, to, msg.as_string())
    except Exception as error:
        raise HTTPException(502, f"Sending through Gmail failed: {error}")


def fmt_qty(x):
    x = float(x)
    return f"{x:,.0f}" if x == int(x) else f"{x:,.2f}"


def build_digest(cur):
    s = read_settings(cur)
    days = int(s.get("order_alert_days") or 2)
    low = low_stock_items(cur)
    due = orders_due_within(cur, days)
    t = today_manila()

    def due_label(d):
        n = int(d)
        return "OVERDUE" if n < 0 else "TODAY" if n == 0 else "tomorrow" if n == 1 else f"in {n} days"

    text_lines, html_parts = [], []
    if due:
        text_lines.append(f"ORDERS DUE (next {days} day{'s' if days != 1 else ''})")
        html_parts.append(f"<h3 style='margin:16px 0 6px'>Orders due (next {days} day{'s' if days != 1 else ''})</h3><ul>")
        for o in due:
            items = ", ".join(f"{fmt_qty(i['qty'])}× {i['name']}" for i in o["items"])
            when = f"{o['due_date']:%a %b %d}" + (f" {o['due_time']}" if o["due_time"] else "")
            line = (f"#{o['id']} {o['customer_name']} — {when} ({due_label(o['days_until_due'])}), "
                    f"{o['fulfillment']}, status: {o['status']} — {items}")
            text_lines.append("- " + line)
            html_parts.append(f"<li>{escape(line)}</li>")
        html_parts.append("</ul>")
    if low:
        text_lines.append("\nLOW STOCK")
        html_parts.append("<h3 style='margin:16px 0 6px'>Low stock</h3><ul>")
        for i in low:
            line = (f"{i['name']} ({i['item_type']}): {fmt_qty(i['current_stock'])} {i['unit']} left "
                    f"— reorder level {fmt_qty(i['reorder_level'])}")
            text_lines.append("- " + line)
            html_parts.append(f"<li>{escape(line)}</li>")
        html_parts.append("</ul>")

    subject_bits = []
    if due:
        subject_bits.append(f"{len(due)} order{'s' if len(due) != 1 else ''} due")
    if low:
        subject_bits.append(f"{len(low)} low-stock item{'s' if len(low) != 1 else ''}")
    subject = f"Rochar Gelato — {', '.join(subject_bits)} ({t:%b %d})" if subject_bits else None
    html = ("<div style='font-family:system-ui,sans-serif;font-size:14px'>"
            f"<p>Daily alert for {t:%A, %B %d, %Y}.</p>{''.join(html_parts)}</div>")
    return {
        "settings": s,
        "subject": subject,
        "text": "\n".join(text_lines),
        "html": html,
        "orders_due": due,
        "low_stock": low,
    }


def recipients(s):
    return [e.strip() for e in (s.get("alert_emails") or "").split(",") if e.strip()]


@api.get("/alerts/preview")
def alerts_preview():
    """Shows what today's alert email would say, without sending it."""
    with db() as conn, conn.cursor() as cur:
        d = build_digest(cur)
    return {"would_send": d["subject"] is not None, "subject": d["subject"], "text": d["text"],
            "recipients": recipients(d["settings"]), "email_method": email_method()}


@api.post("/alerts/test")
def alerts_test():
    """Sends a short test email to the alert address(es)."""
    with db() as conn, conn.cursor() as cur:
        to = recipients(read_settings(cur))
    if not to:
        raise HTTPException(400, "Add an alert email address in Settings first.")
    send_email(to, "Rochar Gelato — test alert",
               "<p>Email alerts are working. 🍨</p>", "Email alerts are working.")
    return {"ok": True, "sent_to": to}


def run_alerts(force: bool = False):
    t = today_manila()
    with db() as conn, conn.cursor() as cur:
        d = build_digest(cur)
        s = d["settings"]
        if s.get("alerts_enabled") != "true":
            return {"sent": False, "reason": "Alerts are turned off in Settings."}
        to = recipients(s)
        if not to:
            return {"sent": False, "reason": "No alert email address set."}
        if d["subject"] is None:
            return {"sent": False, "reason": "Nothing to report today."}
        if not force:
            cur.execute("SELECT 1 FROM alert_log WHERE alert_date = %s AND alert_key = 'daily';", (t,))
            if cur.fetchone():
                return {"sent": False, "reason": "Today's alert was already sent."}
        send_email(to, d["subject"], d["html"], d["text"])
        cur.execute("""
            INSERT INTO alert_log (alert_date, alert_key, sent_to, summary)
            VALUES (%s, 'daily', %s, %s)
            ON CONFLICT (alert_date, alert_key) DO UPDATE
              SET sent_to = EXCLUDED.sent_to, summary = EXCLUDED.summary, created_at = now();
        """, (t, ", ".join(to), d["subject"]))
    return {"sent": True, "to": to, "subject": d["subject"]}


@app.post("/alerts/run")
def alerts_run(request: Request, force: bool = False,
               x_cron_secret: str = Header(default=""), authorization: str = Header(default="")):
    """Called once a day by the scheduled job (with the CRON_SECRET header),
    or manually from the admin app while logged in. Sends at most one
    alert email per day unless force=true."""
    if not (CRON_SECRET and secrets.compare_digest(x_cron_secret, CRON_SECRET)):
        require_login(authorization)
    return run_alerts(force=force)


app.include_router(api)
