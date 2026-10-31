require('dotenv').config();
const express = require('express'), helmet = require('helmet'), rateLimit = require('express-rate-limit');
const pg = require('pg'), bcrypt = require('bcryptjs'), jwt = require('jsonwebtoken'), crypto = require('crypto'), path = require('path');
pg.types.setTypeParser(1700, parseFloat); // numeric -> number
pg.types.setTypeParser(20, parseInt);     // bigint -> number
pg.types.setTypeParser(1082, v => v);     // date stays 'YYYY-MM-DD'

const SECRET = process.env.JWT_SECRET;
if (!SECRET || SECRET.length < 32) { console.error('Set JWT_SECRET (32+ characters) in .env'); process.exit(1); }
const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.PGSSL === '1' ? { rejectUnauthorized: false } : undefined });

const app = express();
app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false })); // tightened when the frontend is added
app.use(express.json({ limit: '1mb' }));

const RANK = { cashier: 1, manager: 2, owner: 3 };
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const isUuid = v => typeof v === 'string' && UUID.test(v);
const wrap = fn => (req, res, next) => fn(req, res, next).catch(next);
const loginLimit = rateLimit({ windowMs: 15 * 60 * 1000, max: 20, message: { error: 'Too many attempts. Try again in 15 minutes.' } });

// Checks the token AND that the user is still active with their current role.
function auth(min = 'cashier') {
  return wrap(async (req, res, next) => {
    let p;
    try { p = jwt.verify((req.headers.authorization || '').replace('Bearer ', ''), SECRET); }
    catch { return res.status(401).json({ error: 'Not signed in' }); }
    const u = (await pool.query('SELECT id,name,role,active FROM users WHERE id=$1', [p.id])).rows[0];
    if (!u || !u.active) return res.status(401).json({ error: 'Account disabled' });
    if (RANK[u.role] < RANK[min]) return res.status(403).json({ error: 'Your role cannot do this' });
    req.user = u; next();
  });
}

// Tamper-evident audit log: each row hashes the previous one.
async function audit(c, user, action, entity, entityId, data) {
  await c.query('SELECT pg_advisory_xact_lock(7001)');
  const last = (await c.query('SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1')).rows[0];
  const prev = last ? last.hash : 'GENESIS';
  const at = new Date().toISOString();
  const body = JSON.stringify({ at, user: user.id, action, entity, entityId, data });
  const hash = crypto.createHash('sha256').update(prev + body).digest('hex');
  await c.query('INSERT INTO audit_log(at,user_id,user_name,action,entity,entity_id,body,prev_hash,hash) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)',
    [at, user.id, user.name, action, entity, String(entityId), body, prev, hash]);
}

/* ---------- accounts ---------- */
app.post('/api/setup', loginLimit, wrap(async (req, res) => {
  if ((await pool.query('SELECT count(*)::int n FROM users')).rows[0].n) return res.status(403).json({ error: 'Already set up' });
  const { name, username, password } = req.body || {};
  if (!name || !username || !password || password.length < 8) return res.status(400).json({ error: 'Name, username and a password of 8+ characters are required' });
  await pool.query('INSERT INTO users(id,name,username,password_hash,role) VALUES ($1,$2,$3,$4,$5)',
    [crypto.randomUUID(), name.trim(), username.trim(), await bcrypt.hash(password, 12), 'owner']);
  res.json({ ok: true });
}));

app.get('/api/status', wrap(async (req, res) => {
  res.json({ needsSetup: (await pool.query('SELECT count(*)::int n FROM users')).rows[0].n === 0 });
}));

app.post('/api/login', loginLimit, wrap(async (req, res) => {
  const { username, password } = req.body || {};
  const u = (await pool.query('SELECT * FROM users WHERE lower(username)=lower($1) AND active', [String(username || '')])).rows[0];
  if (!u || !(await bcrypt.compare(String(password || ''), u.password_hash))) return res.status(401).json({ error: 'Wrong username or password' });
  // long expiry so a shop can keep working offline; the server still checks the account on every request
  const token = jwt.sign({ id: u.id }, SECRET, { expiresIn: '30d' });
  res.json({ token, user: { id: u.id, name: u.name, role: u.role } });
}));

app.get('/api/me', auth(), (req, res) => res.json(req.user));

app.get('/api/users', auth('owner'), wrap(async (req, res) => {
  res.json((await pool.query('SELECT id,name,username,role,active FROM users ORDER BY created_at')).rows);
}));

app.post('/api/users', auth('owner'), wrap(async (req, res) => {
  const { name, username, password, role } = req.body || {};
  if (!name || !username || !RANK[role] || !password || password.length < 8) return res.status(400).json({ error: 'Name, username, role and a password of 8+ characters are required' });
  const id = crypto.randomUUID();
  const c = await pool.connect();
  try {
    await c.query('BEGIN');
    await c.query('INSERT INTO users(id,name,username,password_hash,role) VALUES ($1,$2,$3,$4,$5)', [id, name.trim(), username.trim(), await bcrypt.hash(password, 12), role]);
    await audit(c, req.user, 'user.create', 'user', id, { username, role });
    await c.query('COMMIT'); res.json({ id });
  } catch (e) { await c.query('ROLLBACK'); res.status(e.code === '23505' ? 409 : 400).json({ error: e.code === '23505' ? 'Username already taken' : e.message }); }
  finally { c.release(); }
}));

app.patch('/api/users/:id', auth('owner'), wrap(async (req, res) => {
  const { active, role, password } = req.body || {};
  if (req.params.id === req.user.id && (active === false || (role && role !== 'owner'))) return res.status(400).json({ error: 'You cannot disable or demote yourself' });
  const c = await pool.connect();
  try {
    await c.query('BEGIN');
    if (typeof active === 'boolean') await c.query('UPDATE users SET active=$2 WHERE id=$1', [req.params.id, active]);
    if (RANK[role]) await c.query('UPDATE users SET role=$2 WHERE id=$1', [req.params.id, role]);
    if (password) { if (password.length < 8) throw new Error('Password must be 8+ characters'); await c.query('UPDATE users SET password_hash=$2 WHERE id=$1', [req.params.id, await bcrypt.hash(password, 12)]); }
    await audit(c, req.user, 'user.update', 'user', req.params.id, { active, role, passwordChanged: !!password });
    await c.query('COMMIT'); res.json({ ok: true });
  } catch (e) { await c.query('ROLLBACK'); res.status(400).json({ error: e.message }); }
  finally { c.release(); }
}));

/* ---------- read: full snapshot for the offline copy ---------- */
app.get('/api/snapshot', auth(), wrap(async (req, res) => {
  const mgr = RANK[req.user.role] >= 2;
  const q = t => pool.query(t).then(r => r.rows);
  const [items, sales, lines, pays, exp] = await Promise.all([
    q('SELECT * FROM items ORDER BY name'),
    q('SELECT s.*, c.name AS customer, c.phone FROM sales s JOIN customers c ON c.id=s.customer_id ORDER BY s.no DESC LIMIT 3000'),
    q('SELECT * FROM sale_items WHERE sale_id IN (SELECT id FROM sales ORDER BY no DESC LIMIT 3000)'),
    q('SELECT * FROM payments WHERE sale_id IN (SELECT id FROM sales ORDER BY no DESC LIMIT 3000) ORDER BY created_at'),
    mgr ? q('SELECT * FROM expenses ORDER BY date DESC, created_at DESC LIMIT 2000') : Promise.resolve([])
  ]);
  if (!mgr) { items.forEach(i => delete i.buy_price); lines.forEach(l => delete l.cost); }
  res.json({ server_time: new Date().toISOString(), user: req.user, items, sales, lines, payments: pays, expenses: exp });
}));

/* ---------- write: idempotent operations (safe to retry after offline) ---------- */
const today = () => new Date().toISOString().slice(0, 10);
const okDate = d => (/^\d{4}-\d{2}-\d{2}$/.test(d || '') ? d : today());
const mv = (c, item, change, reason, ref, u) => c.query('INSERT INTO stock_moves(id,item_id,change,reason,ref_id,user_id) VALUES ($1,$2,$3,$4,$5,$6)', [crypto.randomUUID(), item, change, reason, ref, u.id]);

async function saleCreate(c, u, p) {
  if (!isUuid(p.id)) throw new Error('Missing sale id');
  const name = String((p.customer || {}).name || '').trim(), phone = String((p.customer || {}).phone || '').trim();
  if (!name) throw new Error('Customer name is required');
  if (!Array.isArray(p.items) || !p.items.length) throw new Error('A sale needs at least one item');
  let cu = (await c.query('SELECT id FROM customers WHERE lower(name)=lower($1) AND phone=$2', [name, phone])).rows[0];
  if (!cu) cu = (await c.query('INSERT INTO customers(id,name,phone) VALUES ($1,$2,$3) RETURNING id', [crypto.randomUUID(), name, phone])).rows[0];
  let total = 0; const lines = [], warnings = [];
  for (const i of p.items) {
    const qty = Math.floor(+i.qty), price = +i.price, nm = String(i.name || '').trim();
    if (!nm || !(qty > 0) || !(price >= 0)) throw new Error('Bad item line');
    let cost = 0, iid = null;
    if (i.item_id) {
      const it = (await c.query('SELECT * FROM items WHERE id=$1 FOR UPDATE', [i.item_id])).rows[0];
      if (!it) throw new Error('Stock item not found');
      iid = it.id; cost = it.buy_price;
      await c.query('UPDATE items SET qty=qty-$1 WHERE id=$2', [qty, iid]);
      await mv(c, iid, -qty, 'sale', p.id, u);
      if (it.qty - qty < 0) warnings.push(it.name + ' is now below zero in stock (sold while offline?)');
    }
    total += qty * price; lines.push([nm, qty, price, cost, iid]);
  }
  const paid = Math.min(Math.max(+p.paid || 0, 0), total);
  const s = (await c.query('INSERT INTO sales(id,customer_id,date,total,paid,created_by) VALUES ($1,$2,$3,$4,$5,$6) RETURNING no', [p.id, cu.id, okDate(p.date), total, paid, u.id])).rows[0];
  for (const l of lines) await c.query('INSERT INTO sale_items(id,sale_id,name,qty,price,cost,item_id) VALUES ($1,$2,$3,$4,$5,$6,$7)', [crypto.randomUUID(), p.id, ...l]);
  await audit(c, u, 'sale.create', 'sale', p.id, { no: s.no, customer: name, total, paid });
  return { id: p.id, no: s.no, warnings };
}

async function payCreate(c, u, p) {
  if (!isUuid(p.id)) throw new Error('Missing payment id');
  const s = (await c.query('SELECT * FROM sales WHERE id=$1 FOR UPDATE', [p.sale_id])).rows[0];
  if (!s) throw new Error('Sale not found');
  if (s.status !== 'active') throw new Error('That sale was voided');
  const got = (await c.query('SELECT COALESCE(sum(amount),0) a FROM payments WHERE sale_id=$1', [s.id])).rows[0].a;
  const amt = +p.amount, bal = Math.round((s.total - s.paid - got) * 100) / 100;
  if (!(amt > 0) || amt > bal + 0.001) throw new Error('Payment must be above 0 and not more than the balance of ' + bal);
  await c.query('INSERT INTO payments(id,sale_id,amount,method,created_by) VALUES ($1,$2,$3,$4,$5)', [p.id, s.id, amt, String(p.method || 'cash').slice(0, 20), u.id]);
  await audit(c, u, 'payment.create', 'sale', s.id, { no: s.no, amount: amt });
  return { id: p.id, balance: bal - amt };
}

async function saleVoid(c, u, p) {
  const reason = String(p.reason || '').trim();
  if (reason.length < 3) throw new Error('A reason is required to void');
  const s = (await c.query('SELECT * FROM sales WHERE id=$1 FOR UPDATE', [p.sale_id])).rows[0];
  if (!s) throw new Error('Sale not found');
  if (s.status === 'void') throw new Error('Already void');
  await c.query("UPDATE sales SET status='void', void_reason=$2, voided_by=$3, voided_at=now() WHERE id=$1", [s.id, reason, u.id]);
  for (const l of (await c.query('SELECT item_id, qty FROM sale_items WHERE sale_id=$1 AND item_id IS NOT NULL', [s.id])).rows) {
    await c.query('UPDATE items SET qty=qty+$1 WHERE id=$2', [l.qty, l.item_id]);
    await mv(c, l.item_id, l.qty, 'void', s.id, u);
  }
  await audit(c, u, 'sale.void', 'sale', s.id, { no: s.no, reason });
  return { ok: true };
}

async function itemCreate(c, u, p) {
  if (!isUuid(p.id)) throw new Error('Missing item id');
  const name = String(p.name || '').trim(); if (!name) throw new Error('Item name is required');
  const qty = Math.max(Math.floor(+p.qty || 0), 0);
  await c.query('INSERT INTO items(id,name,category,buy_price,sell_price,qty,min_qty) VALUES ($1,$2,$3,$4,$5,$6,$7)',
    [p.id, name, String(p.category || ''), +p.buy_price || 0, +p.sell_price || 0, qty, Math.max(Math.floor(+p.min_qty || 0), 0)]);
  if (qty) await mv(c, p.id, qty, 'opening', p.id, u);
  await audit(c, u, 'item.create', 'item', p.id, { name, qty });
  return { id: p.id };
}

async function restock(c, u, p) {
  const n = Math.floor(+p.qty);
  if (!(n > 0)) throw new Error('Quantity must be above 0');
  const r = await c.query('UPDATE items SET qty=qty+$1 WHERE id=$2 RETURNING name', [n, p.item_id]);
  if (!r.rows[0]) throw new Error('Item not found');
  await mv(c, p.item_id, n, 'restock', null, u);
  await audit(c, u, 'item.restock', 'item', p.item_id, { name: r.rows[0].name, qty: n });
  return { ok: true };
}

async function expCreate(c, u, p) {
  if (!isUuid(p.id)) throw new Error('Missing expense id');
  const amt = +p.amount; if (!(amt > 0) || !String(p.category || '').trim()) throw new Error('Category and amount are required');
  await c.query('INSERT INTO expenses(id,date,category,amount,note,created_by) VALUES ($1,$2,$3,$4,$5,$6)', [p.id, okDate(p.date), String(p.category).trim(), amt, String(p.note || ''), u.id]);
  await audit(c, u, 'expense.create', 'expense', p.id, { category: p.category, amount: amt });
  return { id: p.id };
}

const OPS = {
  'sale.create': ['cashier', saleCreate], 'payment.create': ['cashier', payCreate],
  'sale.void': ['manager', saleVoid], 'item.create': ['manager', itemCreate],
  'item.restock': ['manager', restock], 'expense.create': ['manager', expCreate]
};

app.post('/api/sync/push', auth(), wrap(async (req, res) => {
  const ops = Array.isArray((req.body || {}).ops) ? req.body.ops.slice(0, 200) : [];
  const results = [];
  for (const op of ops) {
    const def = OPS[op && op.type];
    if (!def || !isUuid(op.id)) { results.push({ id: op && op.id, ok: false, permanent: true, error: 'Unknown operation' }); continue; }
    if (RANK[req.user.role] < RANK[def[0]]) { results.push({ id: op.id, ok: false, permanent: true, error: 'Your role cannot do this' }); continue; }
    const c = await pool.connect();
    try {
      await c.query('BEGIN');
      const done = (await c.query('SELECT result FROM applied_ops WHERE op_id=$1', [op.id])).rows[0];
      if (done) { await c.query('ROLLBACK'); results.push({ id: op.id, ok: true, duplicate: true, result: done.result }); continue; }
      const result = await def[1](c, req.user, op.payload || {});
      await c.query('INSERT INTO applied_ops(op_id,result) VALUES ($1,$2)', [op.id, result]);
      await c.query('COMMIT');
      results.push({ id: op.id, ok: true, result });
    } catch (e) {
      await c.query('ROLLBACK').catch(() => {});
      results.push({ id: op.id, ok: false, permanent: e.code !== '23505', error: e.message });
    } finally { c.release(); }
  }
  res.json({ results, server_time: new Date().toISOString() });
}));

/* ---------- reports and audit ---------- */
app.get('/api/reports/summary', auth('manager'), wrap(async (req, res) => {
  const m = /^\d{4}-\d{2}$/.test(req.query.month || '') ? req.query.month : today().slice(0, 7);
  const a = (await pool.query(`SELECT COALESCE(sum(s.total),0) sales,
      COALESCE(sum((SELECT sum(l.cost*l.qty) FROM sale_items l WHERE l.sale_id=s.id)),0) cost, count(*)::int count
      FROM sales s WHERE s.status='active' AND to_char(s.date,'YYYY-MM')=$1`, [m])).rows[0];
  const e = (await pool.query("SELECT COALESCE(sum(amount),0) t FROM expenses WHERE to_char(date,'YYYY-MM')=$1", [m])).rows[0].t;
  const owed = (await pool.query(`SELECT COALESCE(sum(s.total - s.paid - COALESCE((SELECT sum(amount) FROM payments p WHERE p.sale_id=s.id),0)),0) t
      FROM sales s WHERE s.status='active'`)).rows[0].t;
  res.json({ month: m, sales: a.sales, count: a.count, gross_profit: a.sales - a.cost, expenses: e, net: a.sales - a.cost - e, owed });
}));

app.get('/api/audit', auth('owner'), wrap(async (req, res) => {
  res.json((await pool.query('SELECT id,at,user_name,action,entity,entity_id,body FROM audit_log ORDER BY id DESC LIMIT $1', [Math.min(+req.query.limit || 200, 1000)])).rows);
}));

app.get('/api/audit/verify', auth('owner'), wrap(async (req, res) => {
  const rows = (await pool.query('SELECT id,body,prev_hash,hash FROM audit_log ORDER BY id')).rows;
  let prev = 'GENESIS';
  for (const r of rows) {
    const h = crypto.createHash('sha256').update(prev + r.body).digest('hex');
    if (r.prev_hash !== prev || r.hash !== h) return res.json({ ok: false, brokenAtId: r.id, message: 'The audit log was altered at entry ' + r.id });
    prev = r.hash;
  }
  res.json({ ok: true, entries: rows.length, message: 'Audit log is intact' });
}));

/* ---------- frontend + errors ---------- */
app.use(express.static(path.join(__dirname, 'public')));
app.use('/api', (req, res) => res.status(404).json({ error: 'Not found' }));
app.use((err, req, res, next) => { console.error(err); res.status(500).json({ error: 'Server error' }); });
app.listen(process.env.PORT || 3000, () => console.log('ShopBooks running on port ' + (process.env.PORT || 3000)));
