-- ============================================================================
-- ROCHAR GELATO — POSTGRES SCHEMA
--
-- The backend runs this whole file automatically every time it starts up.
-- Every statement is written so it is safe to run again and again
-- ("IF NOT EXISTS"), so there is no separate one-time setup step.
-- To add something later: append a new CREATE TABLE IF NOT EXISTS, or an
-- ALTER TABLE ... ADD COLUMN IF NOT EXISTS, at the bottom of this file.
--
-- How stock works: ingredients and products each carry a live
-- current_stock number. Every purchase, production batch, sale, wastage
-- entry and stock count moves that number, inside the same database
-- transaction as the entry itself. Deleting an entry puts the stock back.
-- ============================================================================

CREATE EXTENSION IF NOT EXISTS pgcrypto;   -- PIN hashing + random tokens


-- ============================================================================
-- LOGIN (one shared admin PIN for Marc and his wife)
-- ============================================================================
CREATE TABLE IF NOT EXISTS admin_auth (
    id         INT PRIMARY KEY DEFAULT 1 CHECK (id = 1),   -- only ever one row
    pin_hash   TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- A login creates a session token. Only a hash of the token is stored.
CREATE TABLE IF NOT EXISTS sessions (
    token_hash  TEXT PRIMARY KEY,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ NOT NULL
);


-- ============================================================================
-- SETTINGS (alert email address, how many days ahead to warn about orders…)
-- ============================================================================
CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT
);
INSERT INTO settings (key, value) VALUES
    ('alert_emails',          ''),     -- comma-separated list
    ('order_alert_days',      '2'),    -- warn when an order is due within N days
    ('alerts_enabled',        'true'),
    ('alert_hour',            '7')     -- daily alert goes out from 7am Manila time
ON CONFLICT (key) DO NOTHING;


-- ============================================================================
-- INGREDIENTS (raw materials AND packaging — pint tubs, lids, stickers…)
-- cost_per_unit is a weighted average, updated on every purchase.
-- ============================================================================
CREATE TABLE IF NOT EXISTS ingredients (
    id             SERIAL PRIMARY KEY,
    name           TEXT NOT NULL UNIQUE,
    kind           TEXT NOT NULL DEFAULT 'ingredient'
                   CHECK (kind IN ('ingredient', 'packaging', 'other')),
    unit           TEXT NOT NULL DEFAULT 'g',      -- g, ml, pc, kg…
    current_stock  NUMERIC(14,3) NOT NULL DEFAULT 0,
    reorder_level  NUMERIC(14,3) NOT NULL DEFAULT 0,
    cost_per_unit  NUMERIC(14,4) NOT NULL DEFAULT 0,
    supplier       TEXT,
    notes          TEXT,
    active         BOOLEAN NOT NULL DEFAULT true,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);


-- ============================================================================
-- PRODUCTS (sellable finished goods: one row per flavor + size,
-- e.g. "Basque Burnt Cheesecake — Pint 475ml", "Malted Polvoron — Mini 89ml")
-- cost_per_unit is a weighted average of production batch costs.
-- ============================================================================
CREATE TABLE IF NOT EXISTS products (
    id             SERIAL PRIMARY KEY,
    name           TEXT NOT NULL UNIQUE,
    flavor         TEXT,
    size           TEXT,
    selling_price  NUMERIC(12,2) NOT NULL DEFAULT 0,
    current_stock  NUMERIC(14,3) NOT NULL DEFAULT 0,
    reorder_level  NUMERIC(14,3) NOT NULL DEFAULT 0,
    cost_per_unit  NUMERIC(14,4) NOT NULL DEFAULT 0,
    notes          TEXT,
    active         BOOLEAN NOT NULL DEFAULT true,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Recipe: how much of each ingredient ONE unit of a product uses.
-- Used to pre-fill the ingredients on a production batch.
CREATE TABLE IF NOT EXISTS recipe_items (
    product_id     INT NOT NULL REFERENCES products(id) ON DELETE CASCADE,
    ingredient_id  INT NOT NULL REFERENCES ingredients(id),
    qty_per_unit   NUMERIC(14,4) NOT NULL CHECK (qty_per_unit > 0),
    PRIMARY KEY (product_id, ingredient_id)
);


-- ============================================================================
-- INGREDIENT PURCHASES (stock in) — adds to ingredient stock.
-- Counted as inventory, not as an expense (cost reaches the P&L when the
-- gelato made from it is sold or wasted).
-- ============================================================================
CREATE TABLE IF NOT EXISTS purchases (
    id              SERIAL PRIMARY KEY,
    purchase_date   DATE NOT NULL,
    ingredient_id   INT NOT NULL REFERENCES ingredients(id),
    qty             NUMERIC(14,3) NOT NULL CHECK (qty > 0),
    total_cost      NUMERIC(12,2) NOT NULL CHECK (total_cost >= 0),
    supplier        TEXT,
    payment_method  TEXT,
    notes           TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS purchases_date_idx ON purchases (purchase_date);


-- ============================================================================
-- PRODUCTION (batches made) — uses up ingredients, adds product stock.
-- ============================================================================
CREATE TABLE IF NOT EXISTS production_batches (
    id              SERIAL PRIMARY KEY,
    batch_date      DATE NOT NULL,
    product_id      INT NOT NULL REFERENCES products(id),
    units_produced  NUMERIC(14,3) NOT NULL CHECK (units_produced > 0),
    batch_code      TEXT,
    total_cost      NUMERIC(12,2) NOT NULL DEFAULT 0,  -- sum of ingredients used
    notes           TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS production_date_idx ON production_batches (batch_date);

CREATE TABLE IF NOT EXISTS production_ingredients (
    id             SERIAL PRIMARY KEY,
    batch_id       INT NOT NULL REFERENCES production_batches(id) ON DELETE CASCADE,
    ingredient_id  INT NOT NULL REFERENCES ingredients(id),
    qty_used       NUMERIC(14,3) NOT NULL CHECK (qty_used > 0),
    unit_cost      NUMERIC(14,4) NOT NULL DEFAULT 0   -- ingredient cost at the time
);


-- ============================================================================
-- ORDERS (customer orders with due dates — the calendar)
-- Declared before sales because a completed order creates a sale.
-- ============================================================================
CREATE TABLE IF NOT EXISTS orders (
    id              SERIAL PRIMARY KEY,
    customer_name   TEXT NOT NULL,
    contact         TEXT,
    due_date        DATE NOT NULL,
    due_time        TEXT,                -- free text: "3pm", "afternoon"
    fulfillment     TEXT NOT NULL DEFAULT 'pickup'
                    CHECK (fulfillment IN ('pickup', 'delivery')),
    address         TEXT,
    status          TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'confirmed', 'in_production',
                                      'ready', 'completed', 'cancelled')),
    deposit_paid    NUMERIC(12,2) NOT NULL DEFAULT 0,
    delivery_fee    NUMERIC(12,2) NOT NULL DEFAULT 0,
    discount        NUMERIC(12,2) NOT NULL DEFAULT 0,
    notes           TEXT,
    sale_id         INT,                 -- set once the order is completed
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS orders_due_idx ON orders (due_date);

CREATE TABLE IF NOT EXISTS order_items (
    id          SERIAL PRIMARY KEY,
    order_id    INT NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
    product_id  INT NOT NULL REFERENCES products(id),
    qty         NUMERIC(14,3) NOT NULL CHECK (qty > 0),
    unit_price  NUMERIC(12,2) NOT NULL DEFAULT 0
);


-- ============================================================================
-- SALES — takes product stock out. unit_cost is copied from the product
-- at the time of sale, so monthly profit stays correct even after costs move.
-- ============================================================================
CREATE TABLE IF NOT EXISTS sales (
    id              SERIAL PRIMARY KEY,
    sale_date       DATE NOT NULL,
    customer_name   TEXT,
    channel         TEXT,                -- walk-in, online, reseller, event…
    payment_method  TEXT,
    discount        NUMERIC(12,2) NOT NULL DEFAULT 0,
    delivery_fee    NUMERIC(12,2) NOT NULL DEFAULT 0,
    total           NUMERIC(12,2) NOT NULL DEFAULT 0,  -- items − discount + delivery
    order_id        INT REFERENCES orders(id) ON DELETE SET NULL,
    notes           TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS sales_date_idx ON sales (sale_date);

CREATE TABLE IF NOT EXISTS sale_items (
    id          SERIAL PRIMARY KEY,
    sale_id     INT NOT NULL REFERENCES sales(id) ON DELETE CASCADE,
    product_id  INT NOT NULL REFERENCES products(id),
    qty         NUMERIC(14,3) NOT NULL CHECK (qty > 0),
    unit_price  NUMERIC(12,2) NOT NULL DEFAULT 0,
    unit_cost   NUMERIC(14,4) NOT NULL DEFAULT 0
);


-- ============================================================================
-- WASTAGE — melted, expired, damaged, samples… for either an ingredient
-- or a finished product. cost_value = qty × cost at the time.
-- ============================================================================
CREATE TABLE IF NOT EXISTS wastage (
    id             SERIAL PRIMARY KEY,
    waste_date     DATE NOT NULL,
    item_type      TEXT NOT NULL CHECK (item_type IN ('ingredient', 'product')),
    ingredient_id  INT REFERENCES ingredients(id),
    product_id     INT REFERENCES products(id),
    qty            NUMERIC(14,3) NOT NULL CHECK (qty > 0),
    reason         TEXT NOT NULL DEFAULT 'other',
    cost_value     NUMERIC(12,2) NOT NULL DEFAULT 0,
    notes          TEXT,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK ((item_type = 'ingredient' AND ingredient_id IS NOT NULL AND product_id IS NULL)
        OR (item_type = 'product'    AND product_id IS NOT NULL AND ingredient_id IS NULL))
);
CREATE INDEX IF NOT EXISTS wastage_date_idx ON wastage (waste_date);


-- ============================================================================
-- EXPENSES — operating costs that are NOT ingredient/packaging stock
-- (electricity, rent, delivery, marketing, equipment, fees…)
-- ============================================================================
CREATE TABLE IF NOT EXISTS expenses (
    id              SERIAL PRIMARY KEY,
    expense_date    DATE NOT NULL,
    category        TEXT NOT NULL DEFAULT 'Other',
    description     TEXT NOT NULL,
    amount          NUMERIC(12,2) NOT NULL CHECK (amount >= 0),
    payment_method  TEXT,
    vendor          TEXT,
    notes           TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS expenses_date_idx ON expenses (expense_date);


-- ============================================================================
-- STOCK COUNTS — when a physical count disagrees with the system, this
-- records the correction (the difference) and sets stock to the counted number.
-- ============================================================================
CREATE TABLE IF NOT EXISTS stock_adjustments (
    id             SERIAL PRIMARY KEY,
    adjust_date    DATE NOT NULL,
    item_type      TEXT NOT NULL CHECK (item_type IN ('ingredient', 'product')),
    ingredient_id  INT REFERENCES ingredients(id),
    product_id     INT REFERENCES products(id),
    system_qty     NUMERIC(14,3) NOT NULL,
    counted_qty    NUMERIC(14,3) NOT NULL,
    difference     NUMERIC(14,3) NOT NULL,   -- counted − system
    notes          TEXT,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);


-- ============================================================================
-- ALERT LOG — which alert emails were sent, so the same alert is not
-- emailed twice on the same day.
-- ============================================================================
CREATE TABLE IF NOT EXISTS alert_log (
    id          SERIAL PRIMARY KEY,
    alert_date  DATE NOT NULL,
    alert_key   TEXT NOT NULL,
    sent_to     TEXT,
    summary     TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (alert_date, alert_key)
);
