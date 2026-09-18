import 'dotenv/config';
import express from 'express';
import cookieParser from 'cookie-parser';
import helmet from 'helmet';
import morgan from 'morgan';
import bcrypt from 'bcryptjs';
import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import multer from 'multer';
import Razorpay from 'razorpay';
import db from './db.js';
import { setAuth, clearAuth, requireAuth, requireAdmin } from './auth.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = Number(process.env.PORT || 3000);
const RETURN_DAYS = Number(process.env.RETURN_WINDOW_DAYS || 10);

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({limit:'1mb'}));
app.use(cookieParser());
app.use(morgan('combined'));
app.use(express.static(path.join(__dirname,'public')));

const upload = multer({ dest: path.join(__dirname,'uploads'), limits:{fileSize:5*1024*1024}, fileFilter:(_,f,cb)=>cb(null,/^image\/(jpeg|png|webp)$/.test(f.mimetype)) });
const razorpay = process.env.RAZORPAY_KEY_ID && process.env.RAZORPAY_KEY_SECRET
  ? new Razorpay({key_id:process.env.RAZORPAY_KEY_ID,key_secret:process.env.RAZORPAY_KEY_SECRET}) : null;

const q = (sql,...p) => db.prepare(sql).get(...p);
const all = (sql,...p) => db.prepare(sql).all(...p);
const run = (sql,...p) => db.prepare(sql).run(...p);
const money = n => Math.max(0, Math.round(Number(n)||0));

function slugify(s){ return String(s).toLowerCase().trim().replace(/[^a-z0-9]+/g,'-').replace(/^-|-$/g,'') || crypto.randomUUID(); }
function publicProduct(id){
 const p=q('SELECT * FROM products WHERE id=? AND active=1',id); if(!p)return null;
 return {...p,images:all('SELECT id,url,sort_order FROM product_images WHERE product_id=? ORDER BY sort_order,id',id),variants:all('SELECT id,size,color,stock FROM variants WHERE product_id=? ORDER BY size,color',id)};
}
function seedAdmin(){
 if(!process.env.ADMIN_EMAIL || !process.env.ADMIN_PASSWORD) return;
 const existing=q('SELECT id FROM users WHERE email=?',process.env.ADMIN_EMAIL);
 if(!existing) run('INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,?)','Store Admin',process.env.ADMIN_EMAIL,bcrypt.hashSync(process.env.ADMIN_PASSWORD,12),'admin');
}
seedAdmin();

app.get('/api/health',(req,res)=>res.json({ok:true,service:'clothing-store',database:'sqlite',paymentConfigured:Boolean(razorpay)}));

app.post('/api/auth/signup',async(req,res)=>{
 const {name,email,password}=req.body||{};
 if(!name||!/^\S+@\S+\.\S+$/.test(email||'')||String(password||'').length<8)return res.status(400).json({error:'Name, valid email and 8+ character password are required'});
 if(q('SELECT id FROM users WHERE email=?',email))return res.status(409).json({error:'Email already registered'});
 const user={id:run('INSERT INTO users(name,email,password_hash) VALUES(?,?,?)',name,email.toLowerCase(),await bcrypt.hash(password,12)).lastInsertRowid,email:email.toLowerCase(),role:'user',name};
 setAuth(res,user); res.status(201).json({user});
});
app.post('/api/auth/login',async(req,res)=>{
 const {email,password}=req.body||{}, user=q('SELECT * FROM users WHERE email=?',String(email||'').toLowerCase());
 if(!user||!(await bcrypt.compare(password||'',user.password_hash)))return res.status(401).json({error:'Invalid credentials'});
 setAuth(res,user); res.json({user:{id:user.id,name:user.name,email:user.email,role:user.role}});
});
app.post('/api/auth/logout',(req,res)=>{clearAuth(res);res.json({ok:true})});
app.get('/api/auth/me',requireAuth,(req,res)=>res.json({user:q('SELECT id,name,email,role,created_at FROM users WHERE id=?',req.user.id)}));

app.get('/api/products',(req,res)=>{
 const {q:term,category,size,color,sort='new'}=req.query;
 let sql='SELECT DISTINCT p.* FROM products p LEFT JOIN product_images pi ON pi.product_id=p.id LEFT JOIN variants v ON v.product_id=p.id WHERE p.active=1';
 const params=[];
 if(term){sql+=' AND (p.name LIKE ? OR p.description LIKE ?)';params.push('%'+term+'%','%'+term+'%')}
 if(category){sql+=' AND p.category=?';params.push(category)}
 if(size){sql+=' AND v.size=?';params.push(size)}
 if(color){sql+=' AND v.color=?';params.push(color)}
 sql += sort==='price_asc'?' ORDER BY COALESCE(p.discount_price,p.price) ASC':sort==='price_desc'?' ORDER BY COALESCE(p.discount_price,p.price) DESC':' ORDER BY p.created_at DESC';
 res.json({products:all(sql,...params).map(p=>publicProduct(p.id))});
});
app.get('/api/categories',(req,res)=>res.json({categories:all('SELECT category,COUNT(*) count FROM products WHERE active=1 GROUP BY category ORDER BY category')}));
app.get('/api/products/:id',(req,res)=>{const p=publicProduct(req.params.id);p?res.json({product:p}):res.status(404).json({error:'Product not found'})});

app.use('/api',requireAuth);
app.get('/api/profile',(req,res)=>res.json({user:q('SELECT id,name,email,role,created_at FROM users WHERE id=?',req.user.id)}));

app.get('/api/wishlist',(req,res)=>res.json({products:all('SELECT p.* FROM products p JOIN wishlists w ON w.product_id=p.id WHERE w.user_id=?',req.user.id).map(p=>publicProduct(p.id))}));
app.post('/api/wishlist/:productId',(req,res)=>{const p=q('SELECT id FROM products WHERE id=? AND active=1',req.params.productId);if(!p)return res.status(404).json({error:'Product not found'});const x=q('SELECT 1 FROM wishlists WHERE user_id=? AND product_id=?',req.user.id,p.id);x?run('DELETE FROM wishlists WHERE user_id=? AND product_id=?',req.user.id,p.id):run('INSERT INTO wishlists VALUES(?,?)',req.user.id,p.id);res.json({wishlisted:!x})});

function cart(req){let c=q('SELECT * FROM carts WHERE user_id=?',req.user.id);if(!c)c={id:run('INSERT INTO carts(user_id) VALUES(?)',req.user.id).lastInsertRowid};return c}
function cartData(req){
 const c=cart(req);
 const items=all(`SELECT ci.id,ci.quantity,v.id variant_id,v.size,v.color,v.stock,p.id product_id,p.name,p.price,p.discount_price,COALESCE(p.discount_price,p.price) unit_price,
 (ci.quantity*COALESCE(p.discount_price,p.price)) line_total,(SELECT url FROM product_images WHERE product_id=p.id ORDER BY sort_order,id LIMIT 1) image
 FROM cart_items ci JOIN variants v ON v.id=ci.variant_id JOIN products p ON p.id=v.product_id WHERE ci.cart_id=?`,c.id);
 const subtotal=items.reduce((s,i)=>s+i.line_total,0), delivery=subtotal>=499?0:79, discount=0;
 return {items,subtotal,delivery,discount,total:subtotal+delivery-discount};
}
app.get('/api/cart',(req,res)=>res.json(cartData(req)));
app.post('/api/cart',(req,res)=>{
 const {variantId,quantity=1}=req.body||{}, v=q('SELECT v.*,p.active FROM variants v JOIN products p ON p.id=v.product_id WHERE v.id=?',variantId);
 if(!v||!v.active)return res.status(404).json({error:'Variant not found'});
 const qty=Number(quantity);if(!Number.isInteger(qty)||qty<1||qty>v.stock)return res.status(400).json({error:'Invalid quantity or insufficient stock'});
 const c=cart(req), x=q('SELECT id FROM cart_items WHERE cart_id=? AND variant_id=?',c.id,v.id);
 x?run('UPDATE cart_items SET quantity=? WHERE id=?',qty,x.id):run('INSERT INTO cart_items(cart_id,variant_id,quantity) VALUES(?,?,?)',c.id,v.id,qty);
 res.json(cartData(req));
});
app.patch('/api/cart/:itemId',(req,res)=>{const qty=Number(req.body?.quantity),x=q('SELECT ci.*,v.stock FROM cart_items ci JOIN carts c ON c.id=ci.cart_id JOIN variants v ON v.id=ci.variant_id WHERE ci.id=? AND c.user_id=?',req.params.itemId,req.user.id);if(!x)return res.status(404).json({error:'Cart item not found'});if(!Number.isInteger(qty)||qty<1||qty>x.stock)return res.status(400).json({error:'Invalid quantity'});run('UPDATE cart_items SET quantity=? WHERE id=?',qty,x.id);res.json(cartData(req))});
app.delete('/api/cart/:itemId',(req,res)=>{run('DELETE FROM cart_items WHERE id IN (SELECT ci.id FROM cart_items ci JOIN carts c ON c.id=ci.cart_id WHERE ci.id=? AND c.user_id=?)',req.params.itemId,req.user.id);res.json(cartData(req))});

app.get('/api/addresses',(req,res)=>res.json({addresses:all('SELECT * FROM addresses WHERE user_id=? ORDER BY id DESC',req.user.id)}));
app.post('/api/addresses',(req,res)=>{const a=req.body||{};if(!a.full_name||!a.phone||!a.line1||!a.city||!a.state||!a.postal_code)return res.status(400).json({error:'Complete delivery address required'});const id=run('INSERT INTO addresses(user_id,full_name,phone,line1,line2,city,state,postal_code,country) VALUES(?,?,?,?,?,?,?,?,?)',req.user.id,a.full_name,a.phone,a.line1,a.line2||'',a.city,a.state,a.postal_code,a.country||'India').lastInsertRowid;res.status(201).json({address:q('SELECT * FROM addresses WHERE id=?',id)})});

app.post('/api/payments/create',(req,res)=>{
 if(!razorpay)return res.status(503).json({error:'Online payment is not configured. Add Razorpay credentials.'});
 const {addressId}=req.body||{}, a=q('SELECT id FROM addresses WHERE id=? AND user_id=?',addressId,req.user.id), c=cartData(req);
 if(!a||!c.items.length)return res.status(400).json({error:'Valid address and non-empty cart required'});
 const order=run('INSERT INTO orders(user_id,address_id,status,payment_status,subtotal,delivery_charge,discount,total,return_until) VALUES(?,?,?,?,?,?,?,?,datetime(\'now\',\'+10 days\'))',req.user.id,a.id,'Pending','Pending',c.subtotal,c.delivery,c.discount,c.total);
 const orderId=order.lastInsertRowid;
 const rz=await razorpay.orders.create({amount:c.total*100,currency:'INR',receipt:'STORE-'+orderId,payment_capture:1});
 run('UPDATE orders SET payment_reference=? WHERE id=?',rz.id,orderId);
 run('INSERT INTO payments(order_id,provider,provider_order_id,status) VALUES(?,?,?,?)',orderId,'razorpay',rz.id,'created');
 res.json({orderId,razorpayOrderId:rz.id,amount:c.total,keyId:process.env.RAZORPAY_KEY_ID});
});
app.post('/api/payments/verify',(req,res)=>{
 const {orderId,razorpay_order_id,razorpay_payment_id,razorpay_signature}=req.body||{},o=q('SELECT * FROM orders WHERE id=? AND user_id=?',orderId,req.user.id);
 if(!o||!razorpay_order_id||!razorpay_payment_id||!razorpay_signature)return res.status(400).json({error:'Invalid payment data'});
 const expected=crypto.createHmac('sha256',process.env.RAZORPAY_KEY_SECRET).update(razorpay_order_id+'|'+razorpay_payment_id).digest('hex');
 if(!crypto.timingSafeEqual(Buffer.from(expected),Buffer.from(razorpay_signature))) {run('UPDATE orders SET payment_status=\'Failed\',updated_at=CURRENT_TIMESTAMP WHERE id=?',o.id);return res.status(400).json({error:'Payment signature verification failed'})}
 const tx=db.transaction(()=>{
   const fresh=q('SELECT * FROM orders WHERE id=?',o.id);
   if(fresh.payment_status==='Paid')return;
   for(const i of all('SELECT * FROM order_items WHERE order_id=?',o.id)) {
     const v=q('SELECT stock FROM variants WHERE id=?',i.variant_id);
     if(!v||v.stock<i.quantity)throw new Error('Stock changed during checkout');
   }
   for(const i of all('SELECT * FROM order_items WHERE order_id=?',o.id))run('UPDATE variants SET stock=stock-? WHERE id=?',i.quantity,i.variant_id);
   run('UPDATE orders SET status=\'Confirmed\',payment_status=\'Paid\',payment_reference=?,updated_at=CURRENT_TIMESTAMP WHERE id=?',razorpay_payment_id,o.id);
   run('UPDATE payments SET provider_payment_id=?,signature=?,status=\'paid\' WHERE order_id=?',razorpay_payment_id,razorpay_signature,o.id);
   run('DELETE FROM cart_items WHERE cart_id=(SELECT id FROM carts WHERE user_id=?)',req.user.id);
 });
 try{tx()}catch(e){return res.status(409).json({error:e.message})}
 res.json({ok:true,orderId:o.id});
});

function createOrderFromCart(userId,addressId,paymentMethod='razorpay'){
 const a=q('SELECT * FROM addresses WHERE id=? AND user_id=?',addressId,userId), c=cartData({user:{id:userId}});
 if(!a||!c.items.length)throw new Error('Valid address and non-empty cart required');
 const tx=db.transaction(()=>{
   for(const i of c.items){const v=q('SELECT stock FROM variants WHERE id=?',i.variant_id);if(!v||v.stock<i.quantity)throw new Error('Insufficient stock for '+i.name)}
   const id=run('INSERT INTO orders(user_id,address_id,status,payment_status,payment_method,subtotal,delivery_charge,discount,total,return_until) VALUES(?,?,?,?,?,?,?,?,?,datetime(\'now\',\'+10 days\'))',userId,a.id,'Confirmed',paymentMethod==='cod'?'Pending':'Paid',paymentMethod,c.subtotal,c.delivery,c.discount,c.total).lastInsertRowid;
   for(const i of c.items){run('INSERT INTO order_items(order_id,product_id,variant_id,product_name,size,color,unit_price,quantity) VALUES(?,?,?,?,?,?,?,?)',id,i.product_id,i.variant_id,i.name,i.size,i.color,i.unit_price,i.quantity);run('UPDATE variants SET stock=stock-? WHERE id=?',i.quantity,i.variant_id)}
   run('DELETE FROM cart_items WHERE cart_id=(SELECT id FROM carts WHERE user_id=?)',userId);return id;
 });return tx();
}
app.post('/api/orders/cod',(req,res)=>{try{const id=createOrderFromCart(req.user.id,req.body.addressId,'cod');res.status(201).json({orderId:id})}catch(e){res.status(409).json({error:e.message})}});
app.post('/api/payments/prepare-order',(req,res)=>{try{const id=run('INSERT INTO orders(user_id,address_id,status,payment_status,subtotal,delivery_charge,discount,total,return_until) VALUES(?,?,?,?,?,?,?,?,datetime(\'now\',\'+10 days\'))',req.user.id,req.body.addressId,'Pending','Pending',0,0,0,0).lastInsertRowid;const c=cartData(req);run('UPDATE orders SET subtotal=?,delivery_charge=?,discount=?,total=? WHERE id=?',c.subtotal,c.delivery,c.discount,c.total,id);for(const i of c.items)run('INSERT INTO order_items(order_id,product_id,variant_id,product_name,size,color,unit_price,quantity) VALUES(?,?,?,?,?,?,?,?)',id,i.product_id,i.variant_id,i.name,i.size,i.color,i.unit_price,i.quantity);res.json({orderId:id})}catch(e){res.status(400).json({error:e.message})}});

app.get('/api/orders',(req,res)=>res.json({orders:all('SELECT o.*,a.full_name,a.phone,a.line1,a.line2,a.city,a.state,a.postal_code,a.country FROM orders o JOIN addresses a ON a.id=o.address_id WHERE o.user_id=? ORDER BY o.created_at DESC',req.user.id).map(o=>({...o,items:all('SELECT * FROM order_items WHERE order_id=?',o.id)}))}));
app.get('/api/orders/:id',(req,res)=>{const o=q('SELECT o.*,a.full_name,a.phone,a.line1,a.line2,a.city,a.state,a.postal_code,a.country FROM orders o JOIN addresses a ON a.id=o.address_id WHERE o.id=? AND o.user_id=?',req.params.id,req.user.id);o?res.json({...o,items:all('SELECT * FROM order_items WHERE order_id=?',o.id),returnEligible:o.status==='Delivered'&&new Date(o.return_until)>=new Date()}):res.status(404).json({error:'Order not found'})});
app.post('/api/orders/:id/return',(req,res)=>{const o=q('SELECT * FROM orders WHERE id=? AND user_id=?',req.params.id,req.user.id);if(!o||o.status!=='Delivered'||new Date(o.return_until)<new Date())return res.status(400).json({error:'Return window expired or order is not eligible'});const existing=q('SELECT id FROM returns WHERE order_id=? AND status NOT IN (\'Rejected\')',o.id);if(existing)return res.status(409).json({error:'Return already requested'});const id=run('INSERT INTO returns(order_id,user_id,reason) VALUES(?,?,?)',o.id,req.user.id,String(req.body.reason||'Customer return')).lastInsertRowid;run('UPDATE orders SET status=\'Returned\',updated_at=CURRENT_TIMESTAMP WHERE id=?',o.id);res.status(201).json({returnId:id})});

app.use('/api/admin',requireAdmin);
app.get('/api/admin/stats',(req,res)=>res.json({users:q('SELECT COUNT(*) n FROM users WHERE role=\'user\'').n,products:q('SELECT COUNT(*) n FROM products WHERE active=1').n,orders:q('SELECT COUNT(*) n FROM orders').n,revenue:q('SELECT COALESCE(SUM(total),0) n FROM orders WHERE payment_status=\'Paid\'').n}));
app.get('/api/admin/products',(req,res)=>res.json({products:all('SELECT * FROM products ORDER BY created_at DESC').map(p=>({...p,images:all('SELECT * FROM product_images WHERE product_id=?',p.id),variants:all('SELECT * FROM variants WHERE product_id=?',p.id)}))}));
app.post('/api/admin/products',(req,res)=>{const p=req.body||{};if(!p.name||!p.category||money(p.price)<0)return res.status(400).json({error:'Name, category and price required'});let slug=slugify(p.name);if(q('SELECT id FROM products WHERE slug=?',slug))slug+='-'+Date.now();const id=run('INSERT INTO products(name,slug,description,category,price,discount_price,rating) VALUES(?,?,?,?,?,?,?)',p.name,slug,p.description||'',p.category,money(p.price),p.discount_price==null?null:money(p.discount_price),Number(p.rating)||0).lastInsertRowid;for(const [n,img] of (p.images||[]).entries())run('INSERT INTO product_images(product_id,url,sort_order) VALUES(?,?,?)',id,String(img.url||img),n);for(const v of p.variants||[])run('INSERT INTO variants(product_id,size,color,stock) VALUES(?,?,?,?)',id,v.size,v.color,Math.max(0,Number(v.stock)||0));res.status(201).json({product:publicProduct(id)})});
app.put('/api/admin/products/:id',(req,res)=>{const p=req.body||{},existing=q('SELECT id FROM products WHERE id=?',req.params.id);if(!existing)return res.status(404).json({error:'Product not found'});run('UPDATE products SET name=?,description=?,category=?,price=?,discount_price=?,active=?,updated_at=CURRENT_TIMESTAMP WHERE id=?',p.name,p.description||'',p.category,money(p.price),p.discount_price==null?null:money(p.discount_price),p.active===false?0:1,req.params.id);if(Array.isArray(p.variants)){run('DELETE FROM variants WHERE product_id=?',req.params.id);for(const v of p.variants)run('INSERT INTO variants(product_id,size,color,stock) VALUES(?,?,?,?)',req.params.id,v.size,v.color,Math.max(0,Number(v.stock)||0))}if(Array.isArray(p.images)){run('DELETE FROM product_images WHERE product_id=?',req.params.id);p.images.forEach((img,i)=>run('INSERT INTO product_images(product_id,url,sort_order) VALUES(?,?,?)',req.params.id,String(img.url||img),i))}res.json({product:publicProduct(req.params.id)})});
app.delete('/api/admin/products/:id',(req,res)=>{run('UPDATE products SET active=0,updated_at=CURRENT_TIMESTAMP WHERE id=?',req.params.id);res.json({ok:true})});
app.post('/api/admin/uploads',upload.array('photos',8),(req,res)=>res.json({files:(req.files||[]).map(f=>({name:f.filename,url:'/uploads/'+f.filename}))}));
app.use('/uploads',express.static(path.join(__dirname,'uploads')));
app.get('/api/admin/orders',(req,res)=>res.json({orders:all('SELECT o.*,u.name customer_name,u.email,a.full_name,a.phone,a.line1,a.line2,a.city,a.state,a.postal_code,a.country FROM orders o JOIN users u ON u.id=o.user_id JOIN addresses a ON a.id=o.address_id ORDER BY o.created_at DESC').map(o=>({...o,items:all('SELECT * FROM order_items WHERE order_id=?',o.id)}))}));
app.patch('/api/admin/orders/:id',(req,res)=>{const allowed=['Pending','Confirmed','Processing','Shipped','Out for delivery','Delivered','Cancelled','Returned'];if(!allowed.includes(req.body.status))return res.status(400).json({error:'Invalid order status'});const o=q('SELECT * FROM orders WHERE id=?',req.params.id);if(!o)return res.status(404).json({error:'Order not found'});run('UPDATE orders SET status=?,updated_at=CURRENT_TIMESTAMP WHERE id=?',req.body.status,o.id);res.json({ok:true})});

app.use((err,req,res,next)=>{console.error(err);res.status(500).json({error:'Internal server error'})});
app.get(/.*/,(req,res)=>res.sendFile(path.join(__dirname,'public/index.html')));
app.listen(PORT,()=>console.log('Clothing store listening on '+PORT));