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
    category       TEXT NOT NULL DEFAULT 'Pint',   -- Mini / Pint / Cake (sold) or Raw Material / Packaging (count only)
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


-- ============================================================================
-- v3: CLIENTS, RESELLER PRICING, RECEIVABLES, RECONCILIATION, LIABILITIES
-- ============================================================================

-- Customers (retail) and resellers (wholesale / stockists) in one list.
CREATE TABLE IF NOT EXISTS customers (
    id          SERIAL PRIMARY KEY,
    name        TEXT NOT NULL,
    phone       TEXT NOT NULL DEFAULT '',
    address     TEXT NOT NULL DEFAULT '',
    notes       TEXT NOT NULL DEFAULT '',
    tier        TEXT NOT NULL DEFAULT 'Retail' CHECK (tier IN ('Retail', 'Reseller')),
    active      BOOLEAN NOT NULL DEFAULT true,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_v3_customers_name ON customers (lower(name));

-- A reseller's own price for a product (anything not listed = normal price).
CREATE TABLE IF NOT EXISTS customer_prices (
    customer_id  INT NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
    item_id      INT NOT NULL REFERENCES items(id) ON DELETE CASCADE,
    price        NUMERIC(12,2) NOT NULL CHECK (price >= 0),
    PRIMARY KEY (customer_id, item_id)
);

-- Orders: who bought, and whether it's paid now or on credit (a receivable).
ALTER TABLE orders ADD COLUMN IF NOT EXISTS customer_id INT REFERENCES customers(id) ON DELETE SET NULL;
ALTER TABLE orders ADD COLUMN IF NOT EXISTS payment_status TEXT NOT NULL DEFAULT 'paid';
ALTER TABLE orders ADD COLUMN IF NOT EXISTS payment_method TEXT NOT NULL DEFAULT 'GCash';
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'orders_payment_status_chk') THEN
    ALTER TABLE orders ADD CONSTRAINT orders_payment_status_chk CHECK (payment_status IN ('paid', 'credit'));
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'orders_payment_method_chk') THEN
    ALTER TABLE orders ADD CONSTRAINT orders_payment_method_chk CHECK (payment_method IN ('Cash', 'GCash', 'Bank'));
  END IF;
END $$;

-- Payments received against credit orders.
CREATE TABLE IF NOT EXISTS receivable_payments (
    id          SERIAL PRIMARY KEY,
    order_id    INT NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
    amount      NUMERIC(12,2) NOT NULL CHECK (amount > 0),
    method      TEXT NOT NULL CHECK (method IN ('Cash', 'GCash', 'Bank')),
    paid_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    notes       TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_v3_payments_order ON receivable_payments (order_id);

-- Daily reconciliation: what the system expected vs. what actually landed.
-- Once locked, that day's sales and payments can't be changed.
CREATE TABLE IF NOT EXISTS reconciliations (
    recon_date  DATE PRIMARY KEY,
    expected    JSONB NOT NULL DEFAULT '{}',
    actual      JSONB NOT NULL DEFAULT '{}',
    notes       TEXT NOT NULL DEFAULT '',
    locked      BOOLEAN NOT NULL DEFAULT false,
    locked_at   TIMESTAMPTZ,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Liabilities: purchases/expenses paid by Gino or Credit Card stay UNPAID
-- until reimbursed/settled.
ALTER TABLE purchases ADD COLUMN IF NOT EXISTS settled_at TIMESTAMPTZ;
ALTER TABLE purchases ADD COLUMN IF NOT EXISTS settled_method TEXT;
ALTER TABLE expenses  ADD COLUMN IF NOT EXISTS settled_at TIMESTAMPTZ;
ALTER TABLE expenses  ADD COLUMN IF NOT EXISTS settled_method TEXT;


-- ============================================================================
-- v4: product categories. Finished goods are Mini / Pint / Cake (shown on the
-- POS); Raw Material / Packaging live on the separate Materials page and only
-- feed the monthly count. Old "Gelato" items are sorted by their size text.
-- ============================================================================
ALTER TABLE items DROP CONSTRAINT IF EXISTS items_category_check;
UPDATE items SET category = CASE
    WHEN variant ILIKE '%mini%' OR name ILIKE '%mini%' THEN 'Mini'
    WHEN variant ILIKE '%cake%' OR name ILIKE '%cake%' AND name NOT ILIKE '%cheesecake%' THEN 'Cake'
    ELSE 'Pint' END
  WHERE category = 'Gelato';
ALTER TABLE items ALTER COLUMN category SET DEFAULT 'Pint';
ALTER TABLE items ADD CONSTRAINT items_category_check
    CHECK (category IN ('Mini', 'Pint', 'Cake', 'Raw Material', 'Packaging'));


-- ============================================================================
-- v5: RECIPES + automatic costing, PRODUCT PHOTOS
--
-- Materials get a recipe unit: base_unit (g / ml / pc) and content_qty =
-- how many of those are in one purchase unit (a "1 kg bag" = 1000 g).
-- A material's cost follows its latest purchase (amount ÷ qty bought);
-- a product with a recipe gets its unit cost from the recipe automatically.
-- ============================================================================
ALTER TABLE items ADD COLUMN IF NOT EXISTS base_unit   TEXT NOT NULL DEFAULT '';
ALTER TABLE items ADD COLUMN IF NOT EXISTS content_qty NUMERIC(14,4) NOT NULL DEFAULT 1;

CREATE TABLE IF NOT EXISTS recipes (
    product_id  INT PRIMARY KEY REFERENCES items(id) ON DELETE CASCADE,
    yield_qty   NUMERIC(12,3) NOT NULL DEFAULT 1 CHECK (yield_qty > 0),   -- units one batch makes
    notes       TEXT NOT NULL DEFAULT '',
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS recipe_lines (
    id           SERIAL PRIMARY KEY,
    product_id   INT NOT NULL REFERENCES recipes(product_id) ON DELETE CASCADE,
    material_id  INT NOT NULL REFERENCES items(id) ON DELETE CASCADE,
    qty          NUMERIC(14,4) NOT NULL CHECK (qty > 0),                 -- in the material's base unit
    UNIQUE (product_id, material_id)
);

-- Product photos (kept out of the items table so product lists stay small)
CREATE TABLE IF NOT EXISTS item_images (
    item_id     INT PRIMARY KEY REFERENCES items(id) ON DELETE CASCADE,
    mime        TEXT NOT NULL,
    data        BYTEA NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- v6: delivery date & time on each order (defaults to when the order was rung up; editable)
ALTER TABLE orders ADD COLUMN IF NOT EXISTS delivery_at TIMESTAMPTZ;
UPDATE orders SET delivery_at = created_at WHERE delivery_at IS NULL;
ALTER TABLE orders ALTER COLUMN delivery_at SET DEFAULT now();
ALTER TABLE orders ALTER COLUMN delivery_at SET NOT NULL;
CREATE INDEX IF NOT EXISTS orders_delivery_at_idx ON orders (delivery_at);

-- v7: second phone number, auto-closed orders, phone push notifications, speed indexes
ALTER TABLE orders    ADD COLUMN IF NOT EXISTS phone2 TEXT NOT NULL DEFAULT '';
ALTER TABLE customers ADD COLUMN IF NOT EXISTS phone2 TEXT NOT NULL DEFAULT '';
ALTER TABLE orders    ADD COLUMN IF NOT EXISTS auto_closed BOOLEAN NOT NULL DEFAULT false;
CREATE INDEX IF NOT EXISTS orders_open_delivery_idx ON orders (status, delivery_at);
CREATE INDEX IF NOT EXISTS orders_customer_idx ON orders (customer_id);

CREATE TABLE IF NOT EXISTS app_secrets (          -- never sent to the browser
    key    TEXT PRIMARY KEY,
    value  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS push_subscriptions (   -- one row per phone that turned notifications on
    id          SERIAL PRIMARY KEY,
    endpoint    TEXT NOT NULL UNIQUE,
    p256dh      TEXT NOT NULL,
    auth        TEXT NOT NULL,
    label       TEXT NOT NULL DEFAULT '',
    enabled     BOOLEAN NOT NULL DEFAULT true,
    muted       TEXT[] NOT NULL DEFAULT '{}',     -- notification rule ids this phone switched off
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_sent_at TIMESTAMPTZ
);
CREATE TABLE IF NOT EXISTS notif_log (            -- so each reminder is sent once
    fire_key  TEXT PRIMARY KEY,
    sent_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
DELETE FROM notif_log WHERE sent_at < now() - interval '60 days';

-- v8: Google sign-in with per-person accounts + quick 4-digit PIN on remembered devices
CREATE TABLE IF NOT EXISTS app_users (            -- people allowed to sign in (by Google email)
    id             SERIAL PRIMARY KEY,
    email          TEXT NOT NULL UNIQUE,          -- stored lowercase
    name           TEXT NOT NULL DEFAULT '',
    picture        TEXT NOT NULL DEFAULT '',
    pin_hash       TEXT,                          -- quick-login PIN (same on all of this person's devices)
    active         BOOLEAN NOT NULL DEFAULT true,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_login_at  TIMESTAMPTZ
);
CREATE TABLE IF NOT EXISTS device_logins (        -- a phone/computer that remembers someone after Google sign-in
    id            SERIAL PRIMARY KEY,
    user_id       INT NOT NULL REFERENCES app_users(id) ON DELETE CASCADE,
    token_hash    TEXT NOT NULL UNIQUE,
    failed        INT NOT NULL DEFAULT 0,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS login_codes (          -- one-time hand-off from the Google redirect back to the app
    code_hash   TEXT PRIMARY KEY,
    user_id     INT NOT NULL REFERENCES app_users(id) ON DELETE CASCADE,
    expires_at  TIMESTAMPTZ NOT NULL
);
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS user_id INT REFERENCES app_users(id) ON DELETE CASCADE;
DELETE FROM login_codes WHERE expires_at < now();

-- v9: batch recipes (not tied to products) built from a separate ingredient list
CREATE TABLE IF NOT EXISTS recipe_ingredients (
    id           SERIAL PRIMARY KEY,
    name         TEXT NOT NULL,
    material_id  INT REFERENCES items(id) ON DELETE SET NULL,   -- optional: cost follows this material's latest purchase
    notes        TEXT NOT NULL DEFAULT '',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS recipe_ingredients_name_idx ON recipe_ingredients (lower(name));
CREATE TABLE IF NOT EXISTS batch_recipes (
    id          SERIAL PRIMARY KEY,
    name        TEXT NOT NULL,
    notes       TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS batch_recipe_lines (
    id             SERIAL PRIMARY KEY,
    recipe_id      INT NOT NULL REFERENCES batch_recipes(id) ON DELETE CASCADE,
    ingredient_id  INT NOT NULL REFERENCES recipe_ingredients(id),
    grams          NUMERIC(14,3) NOT NULL CHECK (grams >= 0),
    position       INT NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS batch_recipe_lines_recipe_idx ON batch_recipe_lines (recipe_id, position);

-- one-time move of the old per-product recipes into batch recipes (products then keep a hand-set cost)
DO $$
DECLARE r RECORD; new_id INT;
BEGIN
  IF EXISTS (SELECT 1 FROM recipes) THEN
    INSERT INTO recipe_ingredients (name, material_id)
      SELECT DISTINCT ON (lower(lbl)) lbl, mid FROM (
        SELECT CASE WHEN m.variant <> '' THEN m.name || ' (' || m.variant || ')' ELSE m.name END AS lbl, m.id AS mid
        FROM recipe_lines rl JOIN items m ON m.id = rl.material_id) x
      ON CONFLICT DO NOTHING;
    FOR r IN SELECT rc.product_id, rc.notes, i.name, i.variant FROM recipes rc JOIN items i ON i.id = rc.product_id LOOP
      INSERT INTO batch_recipes (name, notes)
        VALUES (CASE WHEN r.variant <> '' THEN r.name || ' (' || r.variant || ')' ELSE r.name END, r.notes)
        RETURNING id INTO new_id;
      INSERT INTO batch_recipe_lines (recipe_id, ingredient_id, grams, position)
        SELECT new_id, ri.id, rl.qty, ROW_NUMBER() OVER (ORDER BY m.category, m.name)
        FROM recipe_lines rl JOIN items m ON m.id = rl.material_id
        JOIN recipe_ingredients ri ON lower(ri.name) = lower(CASE WHEN m.variant <> '' THEN m.name || ' (' || m.variant || ')' ELSE m.name END)
        WHERE rl.product_id = r.product_id;
    END LOOP;
    DELETE FROM recipes;
  END IF;
END $$;

-- v10: ingredient brand
ALTER TABLE recipe_ingredients ADD COLUMN IF NOT EXISTS brand TEXT NOT NULL DEFAULT '';

-- v11: one-time load of the 500 g base batch recipes Marc sent (Nov 2026). Runs once; editing/deleting them later is safe.
DO $$
DECLARE d JSONB := '{"ing": [{"k": "water", "brand": "", "name": "Water", "aliases": ["water"], "pats": []}, {"k": "bear", "brand": "Bearbrand", "name": "Milk Powder", "aliases": ["bearbrand milk powder", "bear brand milk powder", "bearbrand"], "pats": ["%bear%brand%"]}, {"k": "arla", "brand": "Arla", "name": "Whipping Cream", "aliases": ["arla whipping cream", "whipping cream"], "pats": ["%whipping%"]}, {"k": "sucrose", "brand": "", "name": "Sucrose", "aliases": ["sucrose", "sugar", "white sugar"], "pats": ["%sucrose%", "white sugar", "sugar", "refined sugar%"]}, {"k": "dex", "brand": "", "name": "Dextrose", "aliases": ["dextrose"], "pats": ["%dextrose%"]}, {"k": "smp", "brand": "", "name": "Skim Milk Powder", "aliases": ["skim milk powder", "smp"], "pats": ["%skim%"]}, {"k": "inulin", "brand": "", "name": "Inulin", "aliases": ["inulin"], "pats": ["%inulin%"]}, {"k": "salt", "brand": "", "name": "Salt", "aliases": ["salt"], "pats": ["%salt%"]}, {"k": "base6", "brand": "Mec3", "name": "Base6", "aliases": ["mec3 base6", "mec3 base 6", "base6", "base 6"], "pats": ["%base%6%", "%mec3%", "%mec 3%"]}, {"k": "vbean", "brand": "", "name": "Vanilla Bean", "aliases": ["vanilla bean", "vanilla beans", "vanilla pod"], "pats": ["%vanilla bean%", "%vanilla pod%"]}, {"k": "neco", "brand": "Neco", "name": "Vanilla Imitation Flavor", "aliases": ["neco vanilla imitation flavor", "neco vanilla", "vanilla imitation flavor"], "pats": ["%neco%", "%imitation%"]}, {"k": "bbutter", "brand": "", "name": "Brown Butter", "aliases": ["brown butter"], "pats": ["%butter%"]}, {"k": "horlicks", "brand": "Horlicks", "name": "Malt Powder", "aliases": ["horlicks powder", "horlicks"], "pats": ["%horlick%"]}, {"k": "polv", "brand": "Goldilocks", "name": "Polvoron", "aliases": ["goldilocks polvoron", "polvoron"], "pats": ["%polvoron%"]}, {"k": "cc", "brand": "Philadelphia", "name": "Cream Cheese", "aliases": ["philadelphia cream cheese", "cream cheese"], "pats": ["%cream cheese%", "%philadelphia%"]}, {"k": "dchoc", "brand": "Beryl''s", "name": "Dark Chocolate", "aliases": ["beryl''s dark chocolate", "beryls dark chocolate", "dark chocolate"], "pats": ["%beryl%", "%dark choc%"]}, {"k": "cocoa", "brand": "Hershey''s", "name": "Unsweetened Cocoa Powder", "aliases": ["hershey''s 100% natural unsweetened cocoa powder", "hershey''s cocoa powder", "cocoa powder"], "pats": ["%cocoa%"]}, {"k": "vext", "brand": "", "name": "Vanilla Extract", "aliases": ["vanilla extract"], "pats": ["%vanilla extract%"]}, {"k": "matcha", "brand": "", "name": "Matcha", "aliases": ["matcha", "matcha powder"], "pats": ["%matcha%"]}], "rec": [{"name": "Vanilla Gelato", "lines": [{"k": "water", "g": 215.96}, {"k": "bear", "g": 35.67}, {"k": "arla", "g": 146.01}, {"k": "sucrose", "g": 58.11}, {"k": "dex", "g": 17.75}, {"k": "smp", "g": 15.37}, {"k": "inulin", "g": 6.01}, {"k": "salt", "g": 0.83}, {"k": "base6", "g": 2.5}, {"k": "vbean", "g": 1.67}, {"k": "neco", "g": 0.12}]}, {"name": "Malted Polvoron", "lines": [{"k": "water", "g": 219.015}, {"k": "bear", "g": 28.141}, {"k": "arla", "g": 120.784}, {"k": "sucrose", "g": 49.839}, {"k": "dex", "g": 9.736}, {"k": "inulin", "g": 5.541}, {"k": "salt", "g": 1.521}, {"k": "bbutter", "g": 5.005}, {"k": "neco", "g": 0.3}, {"k": "base6", "g": 2.505}, {"k": "horlicks", "g": 3.506}, {"k": "polv", "g": 54.106}]}, {"name": "Matcha Gelato", "lines": [{"k": "water", "g": 212.13}, {"k": "bear", "g": 35.04}, {"k": "arla", "g": 143.42}, {"k": "sucrose", "g": 57.08}, {"k": "dex", "g": 18.37}, {"k": "smp", "g": 17.38}, {"k": "inulin", "g": 5.89}, {"k": "salt", "g": 0.5}, {"k": "base6", "g": 2.5}, {"k": "neco", "g": 0.2}, {"k": "matcha", "g": 7.5}]}, {"name": "Cheesecake Gelato", "lines": [{"k": "water", "g": 221.999}, {"k": "bear", "g": 36.508}, {"k": "cc", "g": 152.854}, {"k": "sucrose", "g": 64.096}, {"k": "dex", "g": 13.52}, {"k": "inulin", "g": 7.511}, {"k": "salt", "g": 0.755}, {"k": "vext", "g": 0.251}, {"k": "base6", "g": 2.505}]}, {"name": "Chocolate Gelato", "lines": [{"k": "water", "g": 225.454}, {"k": "arla", "g": 107.116}, {"k": "bear", "g": 37.181}, {"k": "dchoc", "g": 32.895}, {"k": "cocoa", "g": 21.791}, {"k": "sucrose", "g": 38.85}, {"k": "dex", "g": 32.947}, {"k": "salt", "g": 0.756}, {"k": "base6", "g": 2.505}, {"k": "neco", "g": 0.504}]}]}'::jsonb; i JSONB; r JSONB; l JSONB; ing_id INT; mat INT; rid INT; pos INT; ids JSONB := '{}'::jsonb; p TEXT;
BEGIN
  IF EXISTS (SELECT 1 FROM app_secrets WHERE key = 'seed_recipes_2026_11') THEN RETURN; END IF;
  FOR i IN SELECT * FROM jsonb_array_elements(d->'ing') LOOP
    SELECT id INTO ing_id FROM recipe_ingredients
      WHERE lower(name) IN (SELECT jsonb_array_elements_text(i->'aliases'))
         OR lower(trim(brand || ' ' || name)) IN (SELECT jsonb_array_elements_text(i->'aliases'))
      ORDER BY id LIMIT 1;
    IF ing_id IS NULL THEN
      INSERT INTO recipe_ingredients (name, brand) VALUES (i->>'name', i->>'brand') ON CONFLICT DO NOTHING RETURNING id INTO ing_id;
      IF ing_id IS NULL THEN SELECT id INTO ing_id FROM recipe_ingredients WHERE lower(name) = lower(i->>'name'); END IF;
    ELSE
      UPDATE recipe_ingredients SET brand = i->>'brand' WHERE id = ing_id AND brand = '';
    END IF;
    -- link to a Material for cost, only when exactly one material clearly matches
    IF (SELECT material_id FROM recipe_ingredients WHERE id = ing_id) IS NULL THEN
      FOR p IN SELECT jsonb_array_elements_text(i->'pats') LOOP
        IF (SELECT count(*) FROM items WHERE category = 'Raw Material' AND active AND lower(name) LIKE p) = 1 THEN
          SELECT id INTO mat FROM items WHERE category = 'Raw Material' AND active AND lower(name) LIKE p;
          UPDATE recipe_ingredients SET material_id = mat WHERE id = ing_id; EXIT;
        END IF;
      END LOOP;
    END IF;
    ids := ids || jsonb_build_object(i->>'k', ing_id);
  END LOOP;
  FOR r IN SELECT * FROM jsonb_array_elements(d->'rec') LOOP
    SELECT id INTO rid FROM batch_recipes WHERE lower(name) = lower(r->>'name') ORDER BY id LIMIT 1;
    IF rid IS NULL THEN
      INSERT INTO batch_recipes (name, notes) VALUES (r->>'name', '') RETURNING id INTO rid;
    ELSE   -- same name already there: replace its lines with the ones Marc sent
      DELETE FROM batch_recipe_lines WHERE recipe_id = rid;
      UPDATE batch_recipes SET notes = CASE WHEN notes = '' THEN '' ELSE notes END, updated_at = now() WHERE id = rid;
    END IF;
    pos := 0;
    FOR l IN SELECT * FROM jsonb_array_elements(r->'lines') LOOP
      INSERT INTO batch_recipe_lines (recipe_id, ingredient_id, grams, position) VALUES (rid, (ids->>(l->>'k'))::int, (l->>'g')::numeric, pos);
      pos := pos + 1;
    END LOOP;
  END LOOP;
  INSERT INTO app_secrets (key, value) VALUES ('seed_recipes_2026_11', now()::text);
END $$;

-- v12: round the loaded batches to exactly 500 g (×8 = 4000 g) by nudging Water. Only touches a recipe whose total is still the off value.
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM app_secrets WHERE key = 'seed_recipes_2026_11_round') THEN RETURN; END IF;
  UPDATE batch_recipe_lines l SET grams = l.grams + (500 - t.total)
    FROM (SELECT b.id, sum(x.grams) AS total FROM batch_recipes b JOIN batch_recipe_lines x ON x.recipe_id = b.id
          WHERE lower(b.name) IN ('malted polvoron', 'cheesecake gelato', 'chocolate gelato', 'matcha gelato')
          GROUP BY b.id HAVING sum(x.grams) IN (499.999, 500.010)) t,
         recipe_ingredients ri
   WHERE l.recipe_id = t.id AND ri.id = l.ingredient_id AND lower(ri.name) = 'water';
  INSERT INTO app_secrets (key, value) VALUES ('seed_recipes_2026_11_round', now()::text);
END $$;

-- v13: drop the "Base batch 500 g" note from the loaded recipes
UPDATE batch_recipes SET notes = '' WHERE notes = 'Base batch 500 g';
