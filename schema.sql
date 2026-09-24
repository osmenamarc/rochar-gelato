-- ============================================================================
-- ROCHAR GELATO — POSTGRES SCHEMA (v2: lean, periodic inventory)
--
-- The backend runs this whole file automatically every time it starts up.
-- Every statement is safe to run again and again ("IF NOT EXISTS").
-- To add something later: append a CREATE TABLE IF NOT EXISTS, or an
-- ALTER TABLE ... ADD COLUMN IF NOT EXISTS, at the bottom.
--
-- How inventory works (periodic method): the app does NOT track stock
-- levels day to day. Once a month you count everything; the count × unit
-- cost is the Ending Inventory. Cost of goods sold for the period is
--     Beginning Inventory (previous count) + Purchases − Ending Inventory
-- ============================================================================

CREATE EXTENSION IF NOT EXISTS pgcrypto;   -- PIN hashing + random tokens


-- ============================================================================
-- ONE-TIME: archive the v1 tables (perpetual-inventory design). They are
-- renamed to v1_*, never deleted. Runs only while the v1 marker table
-- "recipe_items" still exists under its old name.
-- ============================================================================
DO $$
DECLARE t TEXT;
BEGIN
  IF to_regclass('public.recipe_items') IS NOT NULL THEN
    FOREACH t IN ARRAY ARRAY['alert_log','stock_adjustments','wastage','sale_items','sales',
                             'order_items','orders','production_ingredients','production_batches',
                             'purchases','recipe_items','products','ingredients','expenses']
    LOOP
      IF to_regclass('public.' || t) IS NOT NULL AND to_regclass('public.v1_' || t) IS NULL THEN
        EXECUTE format('ALTER TABLE %I RENAME TO %I', t, 'v1_' || t);
      END IF;
    END LOOP;
  END IF;
END $$;


-- ============================================================================
-- LOGIN (one shared PIN)
-- ============================================================================
CREATE TABLE IF NOT EXISTS admin_auth (
    id         INT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    pin_hash   TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash  TEXT PRIMARY KEY,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ NOT NULL
);


-- ============================================================================
-- SETTINGS (the copy-paste message texts, editable in the web app)
-- ============================================================================
CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT
);
INSERT INTO settings (key, value) VALUES
    ('msg_customer_header', 'This is your order total:'),
    ('msg_customer_footer', 'Please send payment to this QR so that we can send your order.'),
    ('msg_rider_location',  'Hello Boss, palihug ko sulod anang eskina sa Dink Like David, salamat'),
    ('msg_rider_df',        'Mangayo ko daan sa imo gcash Boss para bayran nako ang df, salamat')
ON CONFLICT (key) DO NOTHING;
DELETE FROM settings WHERE key IN ('alert_emails', 'order_alert_days', 'alerts_enabled', 'alert_hour');


-- ============================================================================
-- MASTER PRODUCTS — every item: gelato (sellable), raw materials, packaging.
-- Gelato items appear on the POS grid; every active item appears on the
-- monthly count checklist.
-- ============================================================================
CREATE TABLE IF NOT EXISTS items (
    id             SERIAL PRIMARY KEY,
    name           TEXT NOT NULL,
    category       TEXT NOT NULL DEFAULT 'Gelato'
                   CHECK (category IN ('Gelato', 'Raw Material', 'Packaging')),
    variant        TEXT NOT NULL DEFAULT '',        -- size / variant / unit, e.g. "Pint 475ml", "1 kg bag"
    unit_cost      NUMERIC(12,2) NOT NULL DEFAULT 0,
    selling_price  NUMERIC(12,2) NOT NULL DEFAULT 0,
    active         BOOLEAN NOT NULL DEFAULT true,
    sort_order     INT NOT NULL DEFAULT 0,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (name, variant)
);


-- ============================================================================
-- ORDERS — an order is "open" while it's being handled in Messenger, then
-- "completed" (it becomes a sale) or "voided" (kept, struck through,
-- excluded from all totals). Item name/variant/price are copied onto each
-- line so history never changes if a product is renamed or repriced.
-- ============================================================================
CREATE TABLE IF NOT EXISTS orders (
    id             SERIAL PRIMARY KEY,
    status         TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'completed', 'voided')),
    customer_name  TEXT NOT NULL DEFAULT '',
    phone          TEXT NOT NULL DEFAULT '',
    address        TEXT NOT NULL DEFAULT '',
    delivery_fee   NUMERIC(12,2) NOT NULL DEFAULT 0,
    rider_name     TEXT NOT NULL DEFAULT '',
    notes          TEXT NOT NULL DEFAULT '',
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at   TIMESTAMPTZ,
    voided_at      TIMESTAMPTZ,
    void_reason    TEXT,
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_v2_orders_status ON orders (status, completed_at);

CREATE TABLE IF NOT EXISTS order_items (
    id          SERIAL PRIMARY KEY,
    order_id    INT NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
    item_id     INT REFERENCES items(id) ON DELETE SET NULL,
    name        TEXT NOT NULL,
    variant     TEXT NOT NULL DEFAULT '',
    qty         INT NOT NULL CHECK (qty > 0),
    unit_price  NUMERIC(12,2) NOT NULL DEFAULT 0,
    UNIQUE (order_id, item_id)
);


-- ============================================================================
-- PAYMENT METHODS used by purchases and expenses
-- ============================================================================
-- (kept as plain text; the app offers: Cash, GCash, Gino, Credit Card, Check)


-- ============================================================================
-- PURCHASES — raw materials & packaging bought. Feeds COGS.
-- ============================================================================
CREATE TABLE IF NOT EXISTS purchases (
    id              SERIAL PRIMARY KEY,
    purchased_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    payment_method  TEXT NOT NULL DEFAULT 'Gino',
    notes           TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_v2_purchases_at ON purchases (purchased_at);

CREATE TABLE IF NOT EXISTS purchase_lines (
    id           SERIAL PRIMARY KEY,
    purchase_id  INT NOT NULL REFERENCES purchases(id) ON DELETE CASCADE,
    item_id      INT REFERENCES items(id) ON DELETE SET NULL,
    item_name    TEXT NOT NULL,
    qty          NUMERIC(12,3) NOT NULL DEFAULT 1,
    amount       NUMERIC(12,2) NOT NULL DEFAULT 0
);


-- ============================================================================
-- EXPENSES — overheads that are not inventory (electricity, rent, ads…).
-- ============================================================================
CREATE TABLE IF NOT EXISTS expenses (
    id              SERIAL PRIMARY KEY,
    spent_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    payment_method  TEXT NOT NULL DEFAULT 'Gino',
    notes           TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_v2_expenses_at ON expenses (spent_at);

CREATE TABLE IF NOT EXISTS expense_lines (
    id           SERIAL PRIMARY KEY,
    expense_id   INT NOT NULL REFERENCES expenses(id) ON DELETE CASCADE,
    particulars  TEXT NOT NULL,
    amount       NUMERIC(12,2) NOT NULL DEFAULT 0
);


-- ============================================================================
-- ATTACHMENTS — proof-of-purchase / proof-of-payment photos and PDFs.
-- Photos are shrunk on the phone before upload (~200 KB each).
-- ============================================================================
CREATE TABLE IF NOT EXISTS attachments (
    id          SERIAL PRIMARY KEY,
    owner_type  TEXT NOT NULL CHECK (owner_type IN ('purchase', 'expense')),
    owner_id    INT NOT NULL,
    filename    TEXT NOT NULL DEFAULT '',
    mime        TEXT NOT NULL,
    data        BYTEA NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_v2_attachments_owner ON attachments (owner_type, owner_id);


-- ============================================================================
-- PRODUCTION LOG — gelato made. Record only; does not touch any stock.
-- ============================================================================
CREATE TABLE IF NOT EXISTS production (
    id           SERIAL PRIMARY KEY,
    produced_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    item_id      INT REFERENCES items(id) ON DELETE SET NULL,
    item_name    TEXT NOT NULL,
    variant      TEXT NOT NULL DEFAULT '',
    qty          NUMERIC(12,3) NOT NULL CHECK (qty > 0),
    notes        TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_v2_production_at ON production (produced_at);


-- ============================================================================
-- INVENTORY COUNTS — the monthly physical count. Each line keeps the unit
-- cost used, so the inventory value never changes if a cost is edited later.
-- ============================================================================
CREATE TABLE IF NOT EXISTS inventory_counts (
    id            SERIAL PRIMARY KEY,
    count_date    DATE NOT NULL,
    notes         TEXT NOT NULL DEFAULT '',
    submitted_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_v2_counts_date ON inventory_counts (count_date);

CREATE TABLE IF NOT EXISTS count_lines (
    id         SERIAL PRIMARY KEY,
    count_id   INT NOT NULL REFERENCES inventory_counts(id) ON DELETE CASCADE,
    item_id    INT REFERENCES items(id) ON DELETE SET NULL,
    name       TEXT NOT NULL,
    variant    TEXT NOT NULL DEFAULT '',
    category   TEXT NOT NULL,
    qty        NUMERIC(12,3) NOT NULL DEFAULT 0,
    unit_cost  NUMERIC(12,2) NOT NULL DEFAULT 0
);
