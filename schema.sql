-- ShopBooks database. Run once on an empty database.
CREATE TABLE users(
  id uuid PRIMARY KEY, name text NOT NULL, username text NOT NULL, password_hash text NOT NULL,
  role text NOT NULL CHECK (role IN ('owner','manager','cashier')),
  active boolean NOT NULL DEFAULT true, created_at timestamptz NOT NULL DEFAULT now());
CREATE UNIQUE INDEX users_username ON users(lower(username));

CREATE TABLE customers(
  id uuid PRIMARY KEY, name text NOT NULL, phone text NOT NULL DEFAULT '', created_at timestamptz NOT NULL DEFAULT now());
CREATE UNIQUE INDEX customers_key ON customers(lower(name), phone);

CREATE TABLE items(
  id uuid PRIMARY KEY, name text NOT NULL, category text NOT NULL DEFAULT '',
  buy_price numeric(14,2) NOT NULL DEFAULT 0, sell_price numeric(14,2) NOT NULL DEFAULT 0,
  qty integer NOT NULL DEFAULT 0, min_qty integer NOT NULL DEFAULT 0, created_at timestamptz NOT NULL DEFAULT now());

CREATE SEQUENCE sale_no_seq;
CREATE TABLE sales(
  id uuid PRIMARY KEY, no integer NOT NULL DEFAULT nextval('sale_no_seq') UNIQUE,
  customer_id uuid NOT NULL REFERENCES customers, date date NOT NULL,
  total numeric(14,2) NOT NULL CHECK (total >= 0),
  paid numeric(14,2) NOT NULL CHECK (paid >= 0 AND paid <= total),
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active','void')),
  void_reason text, voided_by uuid REFERENCES users, voided_at timestamptz,
  created_by uuid NOT NULL REFERENCES users, created_at timestamptz NOT NULL DEFAULT now());
CREATE INDEX sales_date ON sales(date);

CREATE TABLE sale_items(
  id uuid PRIMARY KEY, sale_id uuid NOT NULL REFERENCES sales, item_id uuid REFERENCES items,
  name text NOT NULL, qty integer NOT NULL CHECK (qty > 0),
  price numeric(14,2) NOT NULL, cost numeric(14,2) NOT NULL DEFAULT 0);

CREATE TABLE payments(
  id uuid PRIMARY KEY, sale_id uuid NOT NULL REFERENCES sales, amount numeric(14,2) NOT NULL CHECK (amount > 0),
  method text NOT NULL DEFAULT 'cash', created_by uuid NOT NULL REFERENCES users, created_at timestamptz NOT NULL DEFAULT now());

CREATE TABLE expenses(
  id uuid PRIMARY KEY, date date NOT NULL, category text NOT NULL, amount numeric(14,2) NOT NULL CHECK (amount > 0),
  note text NOT NULL DEFAULT '', created_by uuid NOT NULL REFERENCES users, created_at timestamptz NOT NULL DEFAULT now());

CREATE TABLE stock_moves(
  id uuid PRIMARY KEY, item_id uuid NOT NULL REFERENCES items, change integer NOT NULL,
  reason text NOT NULL, ref_id uuid, user_id uuid NOT NULL REFERENCES users, created_at timestamptz NOT NULL DEFAULT now());

-- Tamper-evident log. Each row stores a hash of the previous row.
CREATE TABLE audit_log(
  id bigserial PRIMARY KEY, at timestamptz NOT NULL, user_id uuid, user_name text,
  action text NOT NULL, entity text, entity_id text, body text NOT NULL, prev_hash text NOT NULL, hash text NOT NULL);

-- Remembers every operation already applied, so a retried offline sync never duplicates a sale.
CREATE TABLE applied_ops(op_id uuid PRIMARY KEY, result jsonb, at timestamptz NOT NULL DEFAULT now());

-- LOCKING, enforced by the database itself (not the app).
CREATE FUNCTION block_change() RETURNS trigger AS $$
BEGIN RAISE EXCEPTION 'Records are locked: % is not allowed on %', TG_OP, TG_TABLE_NAME; END $$ LANGUAGE plpgsql;

DO $$ DECLARE t text; BEGIN
  FOREACH t IN ARRAY ARRAY['sale_items','payments','expenses','stock_moves','audit_log'] LOOP
    EXECUTE format('CREATE TRIGGER %I BEFORE UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION block_change()', t||'_lock', t);
    EXECUTE format('CREATE TRIGGER %I BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION block_change()', t||'_nuke', t);
  END LOOP; END $$;

CREATE FUNCTION sales_guard() RETURNS trigger AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN RAISE EXCEPTION 'Sales cannot be deleted'; END IF;
  IF OLD.status = 'void' THEN RAISE EXCEPTION 'A void sale cannot be changed'; END IF;
  IF NEW.id<>OLD.id OR NEW.no<>OLD.no OR NEW.customer_id<>OLD.customer_id OR NEW.date<>OLD.date
     OR NEW.total<>OLD.total OR NEW.paid<>OLD.paid OR NEW.created_by<>OLD.created_by OR NEW.created_at<>OLD.created_at
  THEN RAISE EXCEPTION 'Saved sales are locked and cannot be edited'; END IF;
  IF NEW.status <> 'void' OR coalesce(length(NEW.void_reason),0) < 3
  THEN RAISE EXCEPTION 'A sale can only be voided, with a reason'; END IF;
  RETURN NEW;
END $$ LANGUAGE plpgsql;
CREATE TRIGGER sales_lock BEFORE UPDATE OR DELETE ON sales FOR EACH ROW EXECUTE FUNCTION sales_guard();
CREATE TRIGGER sales_nuke BEFORE TRUNCATE ON sales FOR EACH STATEMENT EXECUTE FUNCTION block_change();
