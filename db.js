import Database from 'better-sqlite3';

const db = new Database(process.env.DB_PATH || 'store.db');
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 name TEXT NOT NULL,
 email TEXT NOT NULL UNIQUE COLLATE NOCASE,
 password_hash TEXT NOT NULL,
 role TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('user','admin')),
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS products (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 name TEXT NOT NULL,
 slug TEXT NOT NULL UNIQUE,
 description TEXT NOT NULL DEFAULT '',
 category TEXT NOT NULL,
 price INTEGER NOT NULL CHECK(price >= 0),
 discount_price INTEGER CHECK(discount_price IS NULL OR discount_price >= 0),
 rating REAL NOT NULL DEFAULT 0,
 active INTEGER NOT NULL DEFAULT 1,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS product_images (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 product_id INTEGER NOT NULL REFERENCES products(id) ON DELETE CASCADE,
 url TEXT NOT NULL,
 sort_order INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS variants (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 product_id INTEGER NOT NULL REFERENCES products(id) ON DELETE CASCADE,
 size TEXT NOT NULL,
 color TEXT NOT NULL,
 stock INTEGER NOT NULL DEFAULT 0 CHECK(stock >= 0),
 UNIQUE(product_id,size,color)
);
CREATE TABLE IF NOT EXISTS carts (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user_id INTEGER NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
 updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS cart_items (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 cart_id INTEGER NOT NULL REFERENCES carts(id) ON DELETE CASCADE,
 variant_id INTEGER NOT NULL REFERENCES variants(id) ON DELETE CASCADE,
 quantity INTEGER NOT NULL CHECK(quantity > 0),
 UNIQUE(cart_id,variant_id)
);
CREATE TABLE IF NOT EXISTS wishlists (
 user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 product_id INTEGER NOT NULL REFERENCES products(id) ON DELETE CASCADE,
 PRIMARY KEY(user_id,product_id)
);
CREATE TABLE IF NOT EXISTS addresses (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 full_name TEXT NOT NULL,
 phone TEXT NOT NULL,
 line1 TEXT NOT NULL,
 line2 TEXT NOT NULL DEFAULT '',
 city TEXT NOT NULL,
 state TEXT NOT NULL,
 postal_code TEXT NOT NULL,
 country TEXT NOT NULL DEFAULT 'India'
);
CREATE TABLE IF NOT EXISTS orders (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user_id INTEGER NOT NULL REFERENCES users(id),
 address_id INTEGER NOT NULL REFERENCES addresses(id),
 status TEXT NOT NULL DEFAULT 'Pending' CHECK(status IN ('Pending','Confirmed','Processing','Shipped','Out for delivery','Delivered','Cancelled','Returned')),
 payment_status TEXT NOT NULL DEFAULT 'Pending' CHECK(payment_status IN ('Pending','Paid','Failed','Refunded')),
 payment_method TEXT NOT NULL DEFAULT 'razorpay',
 payment_reference TEXT,
 subtotal INTEGER NOT NULL,
 delivery_charge INTEGER NOT NULL,
 discount INTEGER NOT NULL DEFAULT 0,
 total INTEGER NOT NULL,
 return_until TEXT,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS order_items (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 order_id INTEGER NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
 product_id INTEGER NOT NULL REFERENCES products(id),
 variant_id INTEGER NOT NULL REFERENCES variants(id),
 product_name TEXT NOT NULL,
 size TEXT NOT NULL,
 color TEXT NOT NULL,
 unit_price INTEGER NOT NULL,
 quantity INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS payments (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 order_id INTEGER NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
 provider TEXT NOT NULL,
 provider_order_id TEXT UNIQUE,
 provider_payment_id TEXT UNIQUE,
 signature TEXT,
 status TEXT NOT NULL,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS returns (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 order_id INTEGER NOT NULL REFERENCES orders(id),
 user_id INTEGER NOT NULL REFERENCES users(id),
 reason TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'Requested' CHECK(status IN ('Requested','Approved','Rejected','Received','Refunded')),
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`);

export default db;