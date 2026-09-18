import Database from 'better-sqlite3';

const db = new Database(process.env.DB_PATH || 'store.db');
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.pragma('busy_timeout = 5000');
db.pragma('synchronous = NORMAL');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 name TEXT NOT NULL CHECK(length(trim(name)) BETWEEN 1 AND 100),
 email TEXT NOT NULL UNIQUE COLLATE NOCASE,
 password_hash TEXT NOT NULL,
 role TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('user','admin')),
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS products (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 name TEXT NOT NULL CHECK(length(trim(name)) BETWEEN 1 AND 200),
 slug TEXT NOT NULL UNIQUE,
 description TEXT NOT NULL DEFAULT '',
 category TEXT NOT NULL,
 subcategory TEXT NOT NULL DEFAULT '',
 brand TEXT NOT NULL DEFAULT '',
 price INTEGER NOT NULL CHECK(price >= 0),
 discount_price INTEGER CHECK(discount_price IS NULL OR (discount_price >= 0 AND discount_price <= price)),
 sku TEXT UNIQUE,
 rating REAL NOT NULL DEFAULT 0 CHECK(rating BETWEEN 0 AND 5),
 active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)),
 featured INTEGER NOT NULL DEFAULT 0 CHECK(featured IN (0,1)),
 new_arrival INTEGER NOT NULL DEFAULT 1 CHECK(new_arrival IN (0,1)),
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS product_images (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 product_id INTEGER NOT NULL REFERENCES products(id) ON DELETE CASCADE,
 url TEXT NOT NULL,
 sort_order INTEGER NOT NULL DEFAULT 0,
 UNIQUE(product_id,url)
);
CREATE TABLE IF NOT EXISTS variants (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 product_id INTEGER NOT NULL REFERENCES products(id) ON DELETE CASCADE,
 size TEXT NOT NULL,
 color TEXT NOT NULL,
 sku TEXT,
 stock INTEGER NOT NULL DEFAULT 0 CHECK(stock >= 0),
 UNIQUE(product_id,size,color),
 UNIQUE(sku)
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
 subtotal INTEGER NOT NULL CHECK(subtotal >= 0),
 delivery_charge INTEGER NOT NULL CHECK(delivery_charge >= 0),
 discount INTEGER NOT NULL DEFAULT 0 CHECK(discount >= 0),
 total INTEGER NOT NULL CHECK(total = subtotal + delivery_charge - discount),
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
 unit_price INTEGER NOT NULL CHECK(unit_price >= 0),
 quantity INTEGER NOT NULL CHECK(quantity > 0)
);
CREATE TABLE IF NOT EXISTS payments (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 order_id INTEGER NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
 provider TEXT NOT NULL,
 provider_order_id TEXT UNIQUE,
 provider_payment_id TEXT UNIQUE,
 signature TEXT,
 status TEXT NOT NULL,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS webhook_events (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 event_id TEXT NOT NULL UNIQUE,
 event TEXT NOT NULL,
 received_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS returns (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 order_id INTEGER NOT NULL REFERENCES orders(id),
 user_id INTEGER NOT NULL REFERENCES users(id),
 reason TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'Requested' CHECK(status IN ('Requested','Approved','Rejected','Received','Refunded')),
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`);

function addColumn(sql){ try { db.exec(sql); } catch(e) { if(!String(e.message).includes('duplicate column name')) throw e; } }
addColumn("ALTER TABLE products ADD COLUMN subcategory TEXT NOT NULL DEFAULT ''");
addColumn("ALTER TABLE products ADD COLUMN brand TEXT NOT NULL DEFAULT ''");
addColumn("ALTER TABLE products ADD COLUMN sku TEXT");
addColumn("ALTER TABLE products ADD COLUMN featured INTEGER NOT NULL DEFAULT 0");
addColumn("ALTER TABLE products ADD COLUMN new_arrival INTEGER NOT NULL DEFAULT 1");
addColumn("ALTER TABLE variants ADD COLUMN sku TEXT");
addColumn("ALTER TABLE payments ADD COLUMN updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP");
addColumn("ALTER TABLE returns ADD COLUMN updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP");
addColumn("ALTER TABLE returns ADD COLUMN inventory_restored INTEGER NOT NULL DEFAULT 0");

db.exec(`
CREATE INDEX IF NOT EXISTS idx_products_active_category ON products(active,category);
CREATE INDEX IF NOT EXISTS idx_products_active_created ON products(active,created_at DESC);
CREATE INDEX IF NOT EXISTS idx_products_active_price ON products(active,discount_price,price);
CREATE INDEX IF NOT EXISTS idx_products_featured ON products(active,featured);
CREATE INDEX IF NOT EXISTS idx_products_new_arrival ON products(active,new_arrival);
CREATE INDEX IF NOT EXISTS idx_variants_product_size_color ON variants(product_id,size,color);
CREATE INDEX IF NOT EXISTS idx_variants_stock ON variants(stock);
CREATE INDEX IF NOT EXISTS idx_cart_items_cart ON cart_items(cart_id);
CREATE INDEX IF NOT EXISTS idx_cart_items_variant ON cart_items(variant_id);
CREATE INDEX IF NOT EXISTS idx_orders_user_created ON orders(user_id,created_at DESC);
CREATE INDEX IF NOT EXISTS idx_orders_status ON orders(status);
CREATE INDEX IF NOT EXISTS idx_orders_payment_status ON orders(payment_status);
CREATE INDEX IF NOT EXISTS idx_order_items_order ON order_items(order_id);
CREATE INDEX IF NOT EXISTS idx_payments_order ON payments(order_id);
CREATE INDEX IF NOT EXISTS idx_payments_provider_order ON payments(provider_order_id);
CREATE INDEX IF NOT EXISTS idx_payments_status ON payments(status);
CREATE INDEX IF NOT EXISTS idx_returns_user ON returns(user_id);
CREATE INDEX IF NOT EXISTS idx_returns_status ON returns(status);
CREATE INDEX IF NOT EXISTS idx_webhook_events_received ON webhook_events(received_at);
`);

export default db;