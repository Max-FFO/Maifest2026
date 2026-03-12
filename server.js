const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const cors = require('cors');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ── Database ────────────────────────────────────────────────────────────────
const db = new Database(process.env.DB_PATH || 'maifest.db');

function initDB() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'waiter',
      pin TEXT,
      active INTEGER NOT NULL DEFAULT 1,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS categories (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      station TEXT NOT NULL DEFAULT 'bar',
      color TEXT DEFAULT '#3fb950',
      sort_order INTEGER DEFAULT 0,
      active INTEGER DEFAULT 1
    );
    CREATE TABLE IF NOT EXISTS items (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      category_id INTEGER,
      name TEXT NOT NULL,
      price REAL NOT NULL,
      active INTEGER DEFAULT 1,
      sort_order INTEGER DEFAULT 0,
      FOREIGN KEY (category_id) REFERENCES categories(id)
    );
    CREATE TABLE IF NOT EXISTS tables_list (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      number INTEGER NOT NULL UNIQUE,
      name TEXT,
      active INTEGER DEFAULT 1
    );
    CREATE TABLE IF NOT EXISTS orders (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      table_id INTEGER,
      user_id INTEGER,
      status TEXT DEFAULT 'open',
      total REAL DEFAULT 0,
      paid_amount REAL DEFAULT 0,
      payment_method TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (table_id) REFERENCES tables_list(id),
      FOREIGN KEY (user_id) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS order_items (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      order_id INTEGER,
      item_id INTEGER,
      item_name TEXT NOT NULL,
      item_price REAL NOT NULL,
      quantity INTEGER NOT NULL DEFAULT 1,
      station TEXT NOT NULL,
      status TEXT DEFAULT 'pending',
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (order_id) REFERENCES orders(id)
    );
    CREATE TABLE IF NOT EXISTS sessions (
      id TEXT PRIMARY KEY,
      user_id INTEGER,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
  `);

  // Seed data if empty
  const uc = db.prepare('SELECT COUNT(*) as c FROM users').get();
  if (uc.c === 0) {
    const adminPin = bcrypt.hashSync('admin123', 10);
    db.prepare('INSERT INTO users (name, role, pin) VALUES (?,?,?)').run('Admin', 'admin', adminPin);
    db.prepare('INSERT INTO users (name, role) VALUES (?,?)').run('Küche', 'kitchen');
    db.prepare('INSERT INTO users (name, role) VALUES (?,?)').run('Schank', 'bar');
    db.prepare('INSERT INTO users (name, role) VALUES (?,?)').run('Kellner 1', 'waiter');
    db.prepare('INSERT INTO users (name, role) VALUES (?,?)').run('Kellner 2', 'waiter');
    db.prepare('INSERT INTO users (name, role) VALUES (?,?)').run('Kellner 3', 'waiter');
  }

  const tc = db.prepare('SELECT COUNT(*) as c FROM tables_list').get();
  if (tc.c === 0) {
    for (let i = 1; i <= 30; i++) {
      db.prepare('INSERT INTO tables_list (number, name) VALUES (?,?)').run(i, `Tisch ${i}`);
    }
  }

  const cc = db.prepare('SELECT COUNT(*) as c FROM categories').get();
  if (cc.c === 0) {
    db.prepare('INSERT INTO categories (name, station, color, sort_order) VALUES (?,?,?,?)').run('Getränke', 'bar', '#3fb950', 1);
    db.prepare('INSERT INTO categories (name, station, color, sort_order) VALUES (?,?,?,?)').run('Alkoholfrei', 'bar', '#58a6ff', 2);
    db.prepare('INSERT INTO categories (name, station, color, sort_order) VALUES (?,?,?,?)').run('Speisen', 'kitchen', '#f0883e', 3);

    const cat1 = db.prepare('SELECT id FROM categories WHERE name=?').get('Getränke').id;
    const cat2 = db.prepare('SELECT id FROM categories WHERE name=?').get('Alkoholfrei').id;
    const cat3 = db.prepare('SELECT id FROM categories WHERE name=?').get('Speisen').id;

    [['Bier 0,5l', 3.50], ['Bier 0,3l', 2.50], ['Radler 0,5l', 3.50],
     ['Wein rot', 3.00], ['Wein weiß', 3.00], ['Sekt', 3.50],
     ['Schnaps', 2.00], ['Zitronensaft', 2.50]].forEach(([n, p], i) =>
      db.prepare('INSERT INTO items (category_id,name,price,sort_order) VALUES (?,?,?,?)').run(cat1, n, p, i));

    [['Cola', 2.50], ['Fanta', 2.50], ['Sprite', 2.50],
     ['Wasser', 2.00], ['Apfelsaft', 2.50], ['Kaffee', 2.50]].forEach(([n, p], i) =>
      db.prepare('INSERT INTO items (category_id,name,price,sort_order) VALUES (?,?,?,?)').run(cat2, n, p, i));

    [['Grillwurst', 4.00], ['Käsekrainer', 4.50], ['Steak', 8.50],
     ['Pommes', 3.50], ['Hendl', 7.00], ['Gulasch', 6.50],
     ['Brötchen', 1.00], ['Würstel', 3.50]].forEach(([n, p], i) =>
      db.prepare('INSERT INTO items (category_id,name,price,sort_order) VALUES (?,?,?,?)').run(cat3, n, p, i));
  }
}

initDB();

// ── Middleware ───────────────────────────────────────────────────────────────
function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Nicht angemeldet' });
  const s = db.prepare('SELECT s.*,u.name,u.role FROM sessions s JOIN users u ON s.user_id=u.id WHERE s.id=?').get(token);
  if (!s) return res.status(401).json({ error: 'Sitzung abgelaufen' });
  req.user = { id: s.user_id, name: s.name, role: s.role, token };
  next();
}
function adminOnly(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Kein Zugriff' });
  next();
}

// ── Helpers ──────────────────────────────────────────────────────────────────
function getFullOrder(id) {
  const o = db.prepare(`
    SELECT o.*,t.number as table_number,t.name as table_name,u.name as waiter_name
    FROM orders o
    LEFT JOIN tables_list t ON o.table_id=t.id
    LEFT JOIN users u ON o.user_id=u.id
    WHERE o.id=?`).get(id);
  if (!o) return null;
  o.items = db.prepare('SELECT * FROM order_items WHERE order_id=? ORDER BY id').all(id);
  return o;
}
function getTableStatus(tableId) {
  return db.prepare(`
    SELECT t.*,
      (SELECT COUNT(*) FROM orders o WHERE o.table_id=t.id AND o.status NOT IN ('paid','cancelled')) as open_orders,
      (SELECT COALESCE(SUM(oi.quantity*oi.item_price),0) FROM orders o JOIN order_items oi ON oi.order_id=o.id WHERE o.table_id=t.id AND o.status NOT IN ('paid','cancelled')) as balance
    FROM tables_list t WHERE t.id=?`).get(tableId);
}
function broadcastTableUpdate(tableId) {
  io.emit('table_update', getTableStatus(tableId));
}

// ── Auth Routes ──────────────────────────────────────────────────────────────
app.get('/api/users/public', (req, res) => {
  const users = db.prepare('SELECT id,name,role,CASE WHEN pin IS NOT NULL THEN 1 ELSE 0 END as has_pin FROM users WHERE active=1 ORDER BY role,name').all();
  res.json(users);
});

app.post('/api/auth/login', (req, res) => {
  const { userId, pin } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE id=? AND active=1').get(userId);
  if (!user) return res.status(404).json({ error: 'Benutzer nicht gefunden' });
  if (user.pin && (!pin || !bcrypt.compareSync(pin, user.pin))) {
    return res.status(401).json({ error: 'Falscher PIN' });
  }
  const token = uuidv4();
  db.prepare('INSERT INTO sessions (id,user_id) VALUES (?,?)').run(token, user.id);
  res.json({ token, user: { id: user.id, name: user.name, role: user.role } });
});

app.post('/api/auth/logout', auth, (req, res) => {
  db.prepare('DELETE FROM sessions WHERE id=?').run(req.user.token);
  res.json({ ok: true });
});

app.get('/api/auth/me', auth, (req, res) => {
  res.json({ id: req.user.id, name: req.user.name, role: req.user.role });
});

// ── Users ────────────────────────────────────────────────────────────────────
app.get('/api/users', auth, adminOnly, (req, res) => {
  res.json(db.prepare('SELECT id,name,role,active FROM users ORDER BY role,name').all());
});

app.post('/api/users', auth, adminOnly, (req, res) => {
  const { name, role, pin } = req.body;
  const hp = pin ? bcrypt.hashSync(pin, 10) : null;
  const r = db.prepare('INSERT INTO users (name,role,pin) VALUES (?,?,?)').run(name, role || 'waiter', hp);
  res.json(db.prepare('SELECT id,name,role,active FROM users WHERE id=?').get(r.lastInsertRowid));
});

app.put('/api/users/:id', auth, adminOnly, (req, res) => {
  const { name, role, pin, active } = req.body;
  const u = db.prepare('SELECT * FROM users WHERE id=?').get(req.params.id);
  const hp = pin !== undefined ? (pin ? bcrypt.hashSync(pin, 10) : null) : u.pin;
  db.prepare('UPDATE users SET name=?,role=?,pin=?,active=? WHERE id=?')
    .run(name ?? u.name, role ?? u.role, hp, active !== undefined ? (active ? 1 : 0) : u.active, req.params.id);
  res.json(db.prepare('SELECT id,name,role,active FROM users WHERE id=?').get(req.params.id));
});

app.delete('/api/users/:id', auth, adminOnly, (req, res) => {
  db.prepare('DELETE FROM sessions WHERE user_id=?').run(req.params.id);
  db.prepare('DELETE FROM users WHERE id=?').run(req.params.id);
  res.json({ ok: true });
});

// ── Categories ───────────────────────────────────────────────────────────────
app.get('/api/categories', (req, res) => {
  res.json(db.prepare('SELECT * FROM categories WHERE active=1 ORDER BY sort_order,name').all());
});

app.post('/api/categories', auth, adminOnly, (req, res) => {
  const { name, station, color, sort_order } = req.body;
  const r = db.prepare('INSERT INTO categories (name,station,color,sort_order) VALUES (?,?,?,?)').run(name, station, color || '#3fb950', sort_order || 0);
  res.json(db.prepare('SELECT * FROM categories WHERE id=?').get(r.lastInsertRowid));
});

app.put('/api/categories/:id', auth, adminOnly, (req, res) => {
  const { name, station, color, sort_order, active } = req.body;
  const c = db.prepare('SELECT * FROM categories WHERE id=?').get(req.params.id);
  db.prepare('UPDATE categories SET name=?,station=?,color=?,sort_order=?,active=? WHERE id=?')
    .run(name ?? c.name, station ?? c.station, color ?? c.color, sort_order ?? c.sort_order, active !== undefined ? (active ? 1 : 0) : c.active, req.params.id);
  res.json(db.prepare('SELECT * FROM categories WHERE id=?').get(req.params.id));
});

app.delete('/api/categories/:id', auth, adminOnly, (req, res) => {
  db.prepare('DELETE FROM categories WHERE id=?').run(req.params.id);
  res.json({ ok: true });
});

// ── Items ─────────────────────────────────────────────────────────────────────
app.get('/api/items', (req, res) => {
  res.json(db.prepare(`
    SELECT i.*,c.name as category_name,c.station,c.color as category_color
    FROM items i LEFT JOIN categories c ON i.category_id=c.id
    ORDER BY c.sort_order,i.sort_order,i.name`).all());
});

app.post('/api/items', auth, adminOnly, (req, res) => {
  const { category_id, name, price, sort_order } = req.body;
  const r = db.prepare('INSERT INTO items (category_id,name,price,sort_order) VALUES (?,?,?,?)').run(category_id, name, parseFloat(price), sort_order || 0);
  res.json(db.prepare('SELECT i.*,c.name as category_name,c.station FROM items i LEFT JOIN categories c ON i.category_id=c.id WHERE i.id=?').get(r.lastInsertRowid));
});

app.put('/api/items/:id', auth, adminOnly, (req, res) => {
  const { category_id, name, price, active, sort_order } = req.body;
  const it = db.prepare('SELECT * FROM items WHERE id=?').get(req.params.id);
  db.prepare('UPDATE items SET category_id=?,name=?,price=?,active=?,sort_order=? WHERE id=?')
    .run(category_id ?? it.category_id, name ?? it.name, price !== undefined ? parseFloat(price) : it.price, active !== undefined ? (active ? 1 : 0) : it.active, sort_order ?? it.sort_order, req.params.id);
  res.json(db.prepare('SELECT i.*,c.name as category_name,c.station FROM items i LEFT JOIN categories c ON i.category_id=c.id WHERE i.id=?').get(req.params.id));
});

app.delete('/api/items/:id', auth, adminOnly, (req, res) => {
  db.prepare('DELETE FROM items WHERE id=?').run(req.params.id);
  res.json({ ok: true });
});

// ── Tables ────────────────────────────────────────────────────────────────────
app.get('/api/tables', auth, (req, res) => {
  res.json(db.prepare(`
    SELECT t.*,
      (SELECT COUNT(*) FROM orders o WHERE o.table_id=t.id AND o.status NOT IN ('paid','cancelled')) as open_orders,
      (SELECT COALESCE(SUM(oi.quantity*oi.item_price),0) FROM orders o JOIN order_items oi ON oi.order_id=o.id WHERE o.table_id=t.id AND o.status NOT IN ('paid','cancelled')) as balance
    FROM tables_list t WHERE t.active=1 ORDER BY t.number`).all());
});

app.post('/api/tables', auth, adminOnly, (req, res) => {
  const { number, name } = req.body;
  const r = db.prepare('INSERT INTO tables_list (number,name) VALUES (?,?)').run(number, name || `Tisch ${number}`);
  res.json(db.prepare('SELECT * FROM tables_list WHERE id=?').get(r.lastInsertRowid));
});

app.put('/api/tables/:id', auth, adminOnly, (req, res) => {
  const { number, name, active } = req.body;
  const t = db.prepare('SELECT * FROM tables_list WHERE id=?').get(req.params.id);
  db.prepare('UPDATE tables_list SET number=?,name=?,active=? WHERE id=?')
    .run(number ?? t.number, name ?? t.name, active !== undefined ? (active ? 1 : 0) : t.active, req.params.id);
  res.json(db.prepare('SELECT * FROM tables_list WHERE id=?').get(req.params.id));
});

app.delete('/api/tables/:id', auth, adminOnly, (req, res) => {
  db.prepare('DELETE FROM tables_list WHERE id=?').run(req.params.id);
  res.json({ ok: true });
});

// ── Orders ────────────────────────────────────────────────────────────────────
app.post('/api/orders', auth, (req, res) => {
  const { table_id, items } = req.body;
  if (!items?.length) return res.status(400).json({ error: 'Keine Artikel' });

  const total = items.reduce((s, i) => s + i.price * i.quantity, 0);
  const ord = db.prepare('INSERT INTO orders (table_id,user_id,status,total) VALUES (?,?,?,?)').run(table_id, req.user.id, 'open', total);
  const orderId = ord.lastInsertRowid;

  let hasKitchen = false, hasBar = false;
  items.forEach(item => {
    db.prepare('INSERT INTO order_items (order_id,item_id,item_name,item_price,quantity,station) VALUES (?,?,?,?,?,?)')
      .run(orderId, item.id, item.name, item.price, item.quantity, item.station);
    if (item.station === 'kitchen') hasKitchen = true;
    if (item.station === 'bar') hasBar = true;
  });

  const order = getFullOrder(orderId);
  if (hasKitchen) io.to('kitchen').emit('new_order', order);
  if (hasBar) io.to('bar').emit('new_order', order);
  broadcastTableUpdate(table_id);
  res.json(order);
});

app.get('/api/orders', auth, (req, res) => {
  const { station, table_id, status } = req.query;
  let q = `SELECT o.*,t.number as table_number,t.name as table_name,u.name as waiter_name FROM orders o LEFT JOIN tables_list t ON o.table_id=t.id LEFT JOIN users u ON o.user_id=u.id WHERE 1=1`;
  const p = [];
  if (status) { q += ' AND o.status=?'; p.push(status); }
  if (table_id) { q += ' AND o.table_id=?'; p.push(table_id); }
  if (!status && !table_id) { q += ` AND o.status NOT IN ('paid','cancelled')`; }
  q += ' ORDER BY o.created_at ASC';

  let orders = db.prepare(q).all(...p);
  orders = orders.map(o => {
    let itemQ = 'SELECT * FROM order_items WHERE order_id=?';
    const ip = [o.id];
    if (station) { itemQ += ' AND station=?'; ip.push(station); }
    itemQ += ' ORDER BY id';
    o.items = db.prepare(itemQ).all(...ip);
    return o;
  });
  if (station) orders = orders.filter(o => o.items.some(i => i.status === 'pending'));
  res.json(orders);
});

app.get('/api/orders/table/:tableId', auth, (req, res) => {
  const orders = db.prepare(`
    SELECT o.*,u.name as waiter_name FROM orders o LEFT JOIN users u ON o.user_id=u.id
    WHERE o.table_id=? AND o.status NOT IN ('paid','cancelled') ORDER BY o.created_at ASC`).all(req.params.tableId);
  const result = orders.map(o => ({ ...o, items: db.prepare('SELECT * FROM order_items WHERE order_id=? ORDER BY id').all(o.id) }));
  res.json(result);
});

app.put('/api/orders/:id/items-done', auth, (req, res) => {
  const { station } = req.body;
  db.prepare('UPDATE order_items SET status=? WHERE order_id=? AND station=?').run('done', req.params.id, station);

  const all = db.prepare('SELECT * FROM order_items WHERE order_id=?').all(req.params.id);
  const allDone = all.every(i => i.status === 'done');
  const kitchenDone = all.filter(i => i.station === 'kitchen').every(i => i.status === 'done');
  const barDone = all.filter(i => i.station === 'bar').every(i => i.status === 'done');
  const hasKitchen = all.some(i => i.station === 'kitchen');
  const hasBar = all.some(i => i.station === 'bar');

  let newStatus = 'open';
  if (allDone) newStatus = 'ready';
  else if (kitchenDone && hasKitchen && hasBar) newStatus = 'kitchen_done';
  else if (barDone && hasBar && hasKitchen) newStatus = 'bar_done';

  db.prepare('UPDATE orders SET status=?,updated_at=CURRENT_TIMESTAMP WHERE id=?').run(newStatus, req.params.id);
  const order = getFullOrder(req.params.id);
  io.emit('order_update', order);
  broadcastTableUpdate(order.table_id);
  res.json(order);
});

app.post('/api/orders/pay', auth, (req, res) => {
  const { table_id, item_ids, paid_amount, payment_method } = req.body;

  if (item_ids && item_ids.length > 0) {
    // Partial payment: mark specific items as paid
    item_ids.forEach(id => {
      db.prepare('UPDATE order_items SET status=? WHERE id=?').run('paid', id);
    });

    // Check each order - if all items paid, mark order as paid
    const orderIds = [...new Set(
      db.prepare(`SELECT DISTINCT order_id FROM order_items WHERE id IN (${item_ids.map(() => '?').join(',')}) AND order_id IN (SELECT id FROM orders WHERE table_id=?)`)
        .all(...item_ids, table_id).map(r => r.order_id)
    )];

    orderIds.forEach(ordId => {
      const items = db.prepare('SELECT * FROM order_items WHERE order_id=?').all(ordId);
      if (items.every(i => i.status === 'paid' || i.status === 'done')) {
        const total = items.filter(i => i.status === 'paid').reduce((s, i) => s + i.quantity * i.item_price, 0);
        db.prepare('UPDATE orders SET status=?,paid_amount=?,payment_method=?,updated_at=CURRENT_TIMESTAMP WHERE id=?')
          .run('paid', total, payment_method || 'cash', ordId);
      }
    });
  } else {
    // Pay all for table
    const orders = db.prepare(`SELECT id,total FROM orders WHERE table_id=? AND status NOT IN ('paid','cancelled')`).all(table_id);
    orders.forEach(o => {
      db.prepare('UPDATE orders SET status=?,paid_amount=?,payment_method=?,updated_at=CURRENT_TIMESTAMP WHERE id=?')
        .run('paid', o.total, payment_method || 'cash', o.id);
    });
  }

  broadcastTableUpdate(table_id);
  res.json({ ok: true });
});

app.delete('/api/orders/:id', auth, (req, res) => {
  const o = db.prepare('SELECT * FROM orders WHERE id=?').get(req.params.id);
  db.prepare('DELETE FROM order_items WHERE order_id=?').run(req.params.id);
  db.prepare('DELETE FROM orders WHERE id=?').run(req.params.id);
  if (o) broadcastTableUpdate(o.table_id);
  res.json({ ok: true });
});

// ── Dashboard ─────────────────────────────────────────────────────────────────
app.get('/api/dashboard', auth, adminOnly, (req, res) => {
  const today = new Date().toISOString().split('T')[0];
  res.json({
    totalRevenue: db.prepare(`SELECT COALESCE(SUM(total),0) as v FROM orders WHERE status='paid'`).get().v,
    todayRevenue: db.prepare(`SELECT COALESCE(SUM(total),0) as v FROM orders WHERE status='paid' AND DATE(created_at)=?`).get(today).v,
    openOrders: db.prepare(`SELECT COUNT(*) as v FROM orders WHERE status NOT IN ('paid','cancelled')`).get().v,
    totalOrders: db.prepare('SELECT COUNT(*) as v FROM orders').get().v,
    topItems: db.prepare(`
      SELECT oi.item_name,SUM(oi.quantity) as qty,SUM(oi.quantity*oi.item_price) as revenue
      FROM order_items oi JOIN orders o ON oi.order_id=o.id WHERE o.status='paid'
      GROUP BY oi.item_name ORDER BY qty DESC LIMIT 10`).all(),
    recentOrders: db.prepare(`
      SELECT o.*,t.number as table_number,u.name as waiter_name
      FROM orders o LEFT JOIN tables_list t ON o.table_id=t.id LEFT JOIN users u ON o.user_id=u.id
      ORDER BY o.created_at DESC LIMIT 20`).all()
  });
});

// ── Socket.io ──────────────────────────────────────────────────────────────────
io.on('connection', socket => {
  socket.on('join', room => socket.join(room));
  socket.on('leave', room => socket.leave(room));
});

// ── Serve SPA ─────────────────────────────────────────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`🌿 Maifest 2026 läuft auf Port ${PORT}`));
