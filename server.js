import 'dotenv/config';
import express from 'express';
import cookieParser from 'cookie-parser';
import helmet from 'helmet';
import morgan from 'morgan';
import bcrypt from 'bcryptjs';
import crypto from 'node:crypto';
import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import multer from 'multer';
import Razorpay from 'razorpay';
import rateLimit from 'express-rate-limit';
import db from './db.js';
import { setAuth, clearAuth, requireAuth, requireAdmin } from './auth.js';

const __dirname=path.dirname(fileURLToPath(import.meta.url));
const app=express();
const PORT=Number(process.env.PORT||3000);
const RETURN_DAYS=Math.max(1,Number(process.env.RETURN_WINDOW_DAYS||10));
const razorpay=process.env.RAZORPAY_KEY_ID&&process.env.RAZORPAY_KEY_SECRET
  ? new Razorpay({key_id:process.env.RAZORPAY_KEY_ID,key_secret:process.env.RAZORPAY_KEY_SECRET}):null;

fs.mkdirSync(path.join(__dirname,'uploads'),{recursive:true});
app.disable('x-powered-by');
app.use(helmet({contentSecurityPolicy:false}));
app.use(morgan(process.env.NODE_ENV==='production'?'combined':'dev'));
app.use(cookieParser());

const apiLimiter=rateLimit({windowMs:15*60*1000,max:300,standardHeaders:true,legacyHeaders:false,message:{error:'Too many requests. Try again later.'}});
const authLimiter=rateLimit({windowMs:15*60*1000,max:20,standardHeaders:true,legacyHeaders:false,message:{error:'Too many authentication attempts. Try again later.'}});

// Razorpay webhooks need the exact raw request body for HMAC verification.
app.post('/api/payments/webhook',express.raw({type:'application/json',limit:'256kb'}),async(req,res)=>{
  const secret=process.env.RAZORPAY_WEBHOOK_SECRET;
  if(!secret)return res.status(503).json({error:'Payment webhook is not configured'});
  const signature=req.get('x-razorpay-signature')||'';
  const expected=crypto.createHmac('sha256',secret).update(req.body).digest('hex');
  if(!signature||signature.length!==expected.length||!crypto.timingSafeEqual(Buffer.from(expected),Buffer.from(signature)))return res.status(400).json({error:'Invalid webhook signature'});
  let event;try{event=JSON.parse(req.body.toString('utf8'))}catch{return res.status(400).json({error:'Invalid webhook payload'})}
  try{
    const eventId=clean(req.get('x-razorpay-event-id'));
    if(!eventId)return res.status(400).json({error:'Missing webhook event id'});
    const inserted=run('INSERT OR IGNORE INTO webhook_events(event_id,event) VALUES(?,?)',eventId,clean(event.event));
    if(inserted.changes===0)return res.json({ok:true,deduplicated:true});
    const p=event.payload?.payment?.entity;
    if(p?.order_id && event.event==='payment.captured'){
      if(p.currency!=='INR'||Number(p.amount)<=0)throw new Error('Invalid payment payload');
      await finalizePaidOrder(p.order_id,p.id,p.signature||null);
    } else if(p?.order_id && ['payment.failed'].includes(event.event)){
      db.prepare("UPDATE payments SET status='failed',updated_at=CURRENT_TIMESTAMP WHERE provider_order_id=? AND status<>'paid'").run(p.order_id);
      db.prepare("UPDATE orders SET payment_status='Failed',updated_at=CURRENT_TIMESTAMP WHERE payment_reference=? AND payment_status='Pending'").run(p.order_id);
    }
    res.json({ok:true});
  }catch(e){
    if(req.get('x-razorpay-event-id'))run('DELETE FROM webhook_events WHERE event_id=?',clean(req.get('x-razorpay-event-id')));
    console.error('webhook',e);res.status(500).json({error:'Webhook processing failed'})
  }
});

app.use(express.json({limit:'1mb'}));
app.use(apiLimiter);
app.use((req,res,next)=>{
  const origin=process.env.CORS_ORIGIN;
  if(origin&&req.headers.origin&&req.headers.origin!==origin)return res.status(403).json({error:'Origin not allowed'});
  if(req.headers.origin){ if(origin&&req.headers.origin===origin)res.setHeader('Access-Control-Allow-Origin',origin); else if(!origin&&process.env.NODE_ENV!=='production')res.setHeader('Access-Control-Allow-Origin',req.headers.origin); else if(!origin)return res.status(403).json({error:'CORS_ORIGIN is required in production'}); }
  res.setHeader('Vary','Origin');
  res.setHeader('Access-Control-Allow-Credentials','true');
  if(req.method==='OPTIONS'){res.setHeader('Access-Control-Allow-Methods','GET,POST,PUT,PATCH,DELETE,OPTIONS');res.setHeader('Access-Control-Allow-Headers','Content-Type');return res.sendStatus(204)}
  next();
});
app.use(express.static(path.join(__dirname,'public'),{maxAge:process.env.NODE_ENV==='production'?'1d':0}));

const q=(sql,...p)=>db.prepare(sql).get(...p);
const all=(sql,...p)=>db.prepare(sql).all(...p);
const run=(sql,...p)=>db.prepare(sql).run(...p);
const money=n=>Math.max(0,Math.round(Number(n)||0));
const int=n=>Number.isInteger(Number(n))?Number(n):NaN;
const clean=s=>String(s??'').trim();
const slugify=s=>clean(s).toLowerCase().replace(/[^a-z0-9]+/g,'-').replace(/^-|-$/g,'')||crypto.randomUUID();
const safeEqual=(a,b)=>{const x=Buffer.from(String(a||''));const y=Buffer.from(String(b||''));return x.length===y.length&&x.length>0&&crypto.timingSafeEqual(x,y)};

function productView(id,includeInactive=false){
  const p=q('SELECT * FROM products WHERE id=? '+(includeInactive?'':'AND active=1'),id);if(!p)return null;
  return {...p,images:all('SELECT id,url,sort_order FROM product_images WHERE product_id=? ORDER BY sort_order,id',id),
    variants:all('SELECT id,size,color,sku,stock FROM variants WHERE product_id=? ORDER BY size,color',id)};
}
function calculateCart(userId){
  const c=q('SELECT id FROM carts WHERE user_id=?',userId);
  if(!c)return {items:[],subtotal:0,delivery:0,discount:0,total:0};
  const items=all(`SELECT ci.id,ci.quantity,v.id variant_id,v.size,v.color,v.stock,p.id product_id,p.name,p.price,p.discount_price,
    COALESCE(p.discount_price,p.price) unit_price,(ci.quantity*COALESCE(p.discount_price,p.price)) line_total,
    (SELECT url FROM product_images WHERE product_id=p.id ORDER BY sort_order,id LIMIT 1) image
    FROM cart_items ci JOIN variants v ON v.id=ci.variant_id JOIN products p ON p.id=v.product_id
    WHERE ci.cart_id=? AND p.active=1`,c.id);
  const subtotal=items.reduce((s,i)=>s+i.line_total,0);
  const delivery=subtotal===0?0:(subtotal>=499?0:79);
  const discount=0;
  return {items,subtotal,delivery,discount,total:subtotal+delivery-discount};
}
function ensureCart(userId){let c=q('SELECT id FROM carts WHERE user_id=?',userId);if(!c)c={id:run('INSERT INTO carts(user_id) VALUES(?)',userId).lastInsertRowid};return c}
function validAddress(userId,id){return q('SELECT * FROM addresses WHERE id=? AND user_id=?',id,userId)}
function validateAddress(a){
  return clean(a.full_name).length<=100&&clean(a.phone).length>=7&&clean(a.phone).length<=20&&clean(a.line1).length>=3&&clean(a.line1).length<=200&&
    clean(a.city).length>=2&&clean(a.city).length<=100&&clean(a.state).length>=2&&clean(a.state).length<=100&&/^\d{4,10}$/.test(clean(a.postal_code))&&clean(a.country).length<=80;
}
function validateVariants(variants){
  if(!Array.isArray(variants)||variants.length>200)return false;
  return variants.every(v=>clean(v.size).length>0&&clean(v.size).length<=30&&clean(v.color).length>0&&clean(v.color).length<=50&&Number.isInteger(Number(v.stock))&&Number(v.stock)>=0&&Number(v.stock)<=100000);
}
function productPayload(body){
  const price=money(body.price),discount=body.discount_price===''||body.discount_price==null?null:money(body.discount_price);
  if(!clean(body.name)||!clean(body.category)||!Number.isFinite(price)||price<0||(discount!==null&&discount>price))throw new Error('Invalid product fields');
  return {name:clean(body.name).slice(0,200),slug:clean(body.slug)||slugify(body.name),description:clean(body.description).slice(0,5000),
    category:clean(body.category).slice(0,100),subcategory:clean(body.subcategory).slice(0,100),brand:clean(body.brand).slice(0,100),
    price,discount_price:discount,sku:clean(body.sku).slice(0,80)||null,active:body.active===false?0:1,featured:body.featured?1:0,new_arrival:body.new_arrival===false?0:1,rating:Math.min(5,Math.max(0,Number(body.rating)||0))};
}
function syncProduct(id,body){
  const p=productPayload(body);
  run('UPDATE products SET name=?,slug=?,description=?,category=?,subcategory=?,brand=?,price=?,discount_price=?,sku=?,active=?,featured=?,new_arrival=?,rating=?,updated_at=CURRENT_TIMESTAMP WHERE id=?',
    p.name,p.slug,p.description,p.category,p.subcategory,p.brand,p.price,p.discount_price,p.sku,p.active,p.featured,p.new_arrival,p.rating,id);
  if(Array.isArray(body.images)){
    run('DELETE FROM product_images WHERE product_id=?',id);
    for(let i=0;i<Math.min(body.images.length,12);i++){const u=clean(body.images[i]);if(u&&u.length<=1000)run('INSERT OR IGNORE INTO product_images(product_id,url,sort_order) VALUES(?,?,?)',id,u,i)}
  }
  if(body.variants!==undefined){
    if(!validateVariants(body.variants))throw new Error('Invalid variants');
    const existing=all('SELECT id,size,color,sku FROM variants WHERE product_id=?',id);
    const incoming=new Map(body.variants.map(v=>[clean(v.size)+'\\0'+clean(v.color),v]));
    for(const old of existing){
      const key=old.size+'\\0'+old.color;
      const v=incoming.get(key);
      if(v){run('UPDATE variants SET sku=?,stock=? WHERE id=?',clean(v.sku).slice(0,80)||null,int(v.stock),old.id);incoming.delete(key)}
      else if(q('SELECT id FROM order_items WHERE variant_id=? LIMIT 1',old.id))throw new Error('Cannot remove a variant used by an order; disable the product instead');
      else run('DELETE FROM variants WHERE id=?',old.id);
    }
    for(const v of incoming.values())run('INSERT INTO variants(product_id,size,color,sku,stock) VALUES(?,?,?,?,?)',id,clean(v.size),clean(v.color),clean(v.sku).slice(0,80)||null,int(v.stock));
  }
  return productView(id,true);
}
function finalizePaidOrder(providerOrderId,paymentId,signature){
  const tx=db.transaction(()=>{
    const o=q('SELECT * FROM orders WHERE payment_reference=?',providerOrderId);
    if(!o)throw new Error('Order not found');
    if(o.payment_status==='Paid'){
      run("UPDATE payments SET provider_payment_id=COALESCE(provider_payment_id,?),signature=COALESCE(signature,?),status='paid',updated_at=CURRENT_TIMESTAMP WHERE order_id=?",paymentId,signature,o.id);
      return o.id;
    }
    const items=all('SELECT * FROM order_items WHERE order_id=?',o.id);
    for(const i of items){
      const changed=run('UPDATE variants SET stock=stock-? WHERE id=? AND stock>=?',i.quantity,i.variant_id,i.quantity);
      if(changed.changes!==1)throw new Error('Insufficient stock');
    }
    run("UPDATE orders SET status='Confirmed',payment_status='Paid',updated_at=CURRENT_TIMESTAMP WHERE id=? AND payment_status='Pending'",o.id);
    run("UPDATE payments SET provider_payment_id=?,signature=?,status='paid',updated_at=CURRENT_TIMESTAMP WHERE order_id=?",paymentId,signature,o.id);
    run('DELETE FROM cart_items WHERE cart_id=(SELECT id FROM carts WHERE user_id=?)',o.user_id);
    return o.id;
  });
  return tx();
}
function seedAdmin(){
  if(!process.env.ADMIN_EMAIL||!process.env.ADMIN_PASSWORD)return;
  if(String(process.env.ADMIN_PASSWORD).length<12)throw new Error('ADMIN_PASSWORD must be at least 12 characters');
  const existing=q('SELECT id,role FROM users WHERE email=?',clean(process.env.ADMIN_EMAIL).toLowerCase());
  if(!existing)run('INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,?)','Store Admin',clean(process.env.ADMIN_EMAIL).toLowerCase(),bcrypt.hashSync(process.env.ADMIN_PASSWORD,12),'admin');
}
seedAdmin();

app.get('/api/health',(req,res)=>res.json({ok:true,service:'clothing-store',database:'sqlite',paymentConfigured:Boolean(razorpay),webhookConfigured:Boolean(process.env.RAZORPAY_WEBHOOK_SECRET)}));

app.post('/api/auth/signup',authLimiter,async(req,res)=>{
  const name=clean(req.body?.name),email=clean(req.body?.email).toLowerCase(),password=String(req.body?.password||'');
  if(name.length<1||name.length>100||!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)||password.length<8||password.length>128)return res.status(400).json({error:'Valid name, email and 8-128 character password are required'});
  if(q('SELECT id FROM users WHERE email=?',email))return res.status(409).json({error:'Email already registered'});
  const id=run('INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,?)',name,email,await bcrypt.hash(password,12),'user').lastInsertRowid;
  setAuth(res,{id,email,role:'user'});res.status(201).json({user:{id,name,email,role:'user'}});
});
app.post('/api/auth/login',authLimiter,async(req,res)=>{
  const email=clean(req.body?.email).toLowerCase(),password=String(req.body?.password||''),u=q('SELECT * FROM users WHERE email=?',email);
  if(!u||!(await bcrypt.compare(password,u.password_hash)))return res.status(401).json({error:'Invalid credentials'});
  setAuth(res,u);res.json({user:{id:u.id,name:u.name,email:u.email,role:u.role}});
});
app.post('/api/auth/logout',(req,res)=>{clearAuth(res);res.json({ok:true})});
app.get('/api/auth/me',requireAuth,(req,res)=>res.json({user:q('SELECT id,name,email,role,created_at FROM users WHERE id=?',req.user.id)}));

app.get('/api/products',(req,res)=>{
  const page=Math.max(1,int(req.query.page)||1),limit=Math.min(48,Math.max(1,int(req.query.limit)||24)),offset=(page-1)*limit;
  const term=clean(req.query.q),category=clean(req.query.category),size=clean(req.query.size),color=clean(req.query.color);
  const min=req.query.minPrice===''?null:money(req.query.minPrice),max=req.query.maxPrice===''?null:money(req.query.maxPrice);
  const sort=['new','price_asc','price_desc','rating'].includes(req.query.sort)?req.query.sort:'new';
  let where='WHERE p.active=1',params=[];
  if(term){where+=' AND (p.name LIKE ? OR p.description LIKE ? OR p.brand LIKE ? OR p.category LIKE ?)';const t='%'+term+'%';params.push(t,t,t,t)}
  if(category){where+=' AND p.category=?';params.push(category)}
  if(size){where+=' AND EXISTS(SELECT 1 FROM variants vx WHERE vx.product_id=p.id AND vx.size=?)';params.push(size)}
  if(color){where+=' AND EXISTS(SELECT 1 FROM variants vx WHERE vx.product_id=p.id AND vx.color=?)';params.push(color)}
  if(min!==null)where+=' AND COALESCE(p.discount_price,p.price)>=?',params.push(min);
  if(max!==null)where+=' AND COALESCE(p.discount_price,p.price)<=?',params.push(max);
  const total=q('SELECT COUNT(*) n FROM products p '+where,...params).n;
  const order=sort==='price_asc'?'COALESCE(p.discount_price,p.price) ASC':sort==='price_desc'?'COALESCE(p.discount_price,p.price) DESC':sort==='rating'?'p.rating DESC,p.created_at DESC':'p.created_at DESC';
  const rows=all('SELECT p.* FROM products p '+where+' ORDER BY '+order+' LIMIT ? OFFSET ?',...params,limit,offset);
  res.json({products:rows.map(p=>productView(p.id)),pagination:{page,limit,total,pages:Math.ceil(total/limit)}});
});
app.get('/api/categories',(req,res)=>res.json({categories:all('SELECT category,COUNT(*) count FROM products WHERE active=1 GROUP BY category ORDER BY category')}));
app.get('/api/catalog/options',(req,res)=>res.json({sizes:all("SELECT DISTINCT size value FROM variants v JOIN products p ON p.id=v.product_id WHERE p.active=1 ORDER BY size").map(x=>x.value),colors:all("SELECT DISTINCT color value FROM variants v JOIN products p ON p.id=v.product_id WHERE p.active=1 ORDER BY color").map(x=>x.value)}));
app.get('/api/products/:id',(req,res)=>{const p=productView(req.params.id);p?res.json({product:p}):res.status(404).json({error:'Product not found'})});

app.use('/api',requireAuth);
app.get('/api/profile',(req,res)=>res.json({user:q('SELECT id,name,email,role,created_at FROM users WHERE id=?',req.user.id)}));
app.get('/api/wishlist',(req,res)=>res.json({products:all('SELECT p.* FROM products p JOIN wishlists w ON w.product_id=p.id WHERE w.user_id=? AND p.active=1',req.user.id).map(p=>productView(p.id))}));
app.post('/api/wishlist/:productId',(req,res)=>{const p=q('SELECT id FROM products WHERE id=? AND active=1',req.params.productId);if(!p)return res.status(404).json({error:'Product not found'});const x=q('SELECT 1 FROM wishlists WHERE user_id=? AND product_id=?',req.user.id,p.id);x?run('DELETE FROM wishlists WHERE user_id=? AND product_id=?',req.user.id,p.id):run('INSERT INTO wishlists(user_id,product_id) VALUES(?,?)',req.user.id,p.id);res.json({wishlisted:!x})});

app.get('/api/cart',(req,res)=>res.json(calculateCart(req.user.id)));
app.post('/api/cart',(req,res)=>{
  const variantId=int(req.body?.variantId),quantity=int(req.body?.quantity??1);
  const v=q('SELECT v.*,p.active FROM variants v JOIN products p ON p.id=v.product_id WHERE v.id=?',variantId);
  if(!v||!v.active)return res.status(404).json({error:'Active variant not found'});
  if(!Number.isInteger(quantity)||quantity<1||quantity>v.stock||quantity>50)return res.status(400).json({error:'Invalid quantity or insufficient stock'});
  const c=ensureCart(req.user.id),x=q('SELECT id FROM cart_items WHERE cart_id=? AND variant_id=?',c.id,v.id);
  if(x)run('UPDATE cart_items SET quantity=?,cart_id=? WHERE id=?',quantity,c.id,x.id);else run('INSERT INTO cart_items(cart_id,variant_id,quantity) VALUES(?,?,?)',c.id,v.id,quantity);
  run('UPDATE carts SET updated_at=CURRENT_TIMESTAMP WHERE id=?',c.id);res.json(calculateCart(req.user.id));
});
app.patch('/api/cart/:itemId',(req,res)=>{
  const quantity=int(req.body?.quantity),x=q('SELECT ci.id,v.stock,p.active FROM cart_items ci JOIN carts c ON c.id=ci.cart_id JOIN variants v ON v.id=ci.variant_id JOIN products p ON p.id=v.product_id WHERE ci.id=? AND c.user_id=?',req.params.itemId,req.user.id);
  if(!x)return res.status(404).json({error:'Cart item not found'});
  if(!x.active||!Number.isInteger(quantity)||quantity<1||quantity>x.stock||quantity>50)return res.status(400).json({error:'Invalid quantity or insufficient stock'});
  run('UPDATE cart_items SET quantity=? WHERE id=?',quantity,x.id);res.json(calculateCart(req.user.id));
});
app.delete('/api/cart/:itemId',(req,res)=>{run('DELETE FROM cart_items WHERE id IN (SELECT ci.id FROM cart_items ci JOIN carts c ON c.id=ci.cart_id WHERE ci.id=? AND c.user_id=?)',req.params.itemId,req.user.id);res.json(calculateCart(req.user.id))});

app.get('/api/addresses',(req,res)=>res.json({addresses:all('SELECT * FROM addresses WHERE user_id=? ORDER BY id DESC',req.user.id)}));
app.post('/api/addresses',(req,res)=>{const a=req.body||{};if(!validateAddress(a))return res.status(400).json({error:'Invalid delivery address'});const id=run('INSERT INTO addresses(user_id,full_name,phone,line1,line2,city,state,postal_code,country) VALUES(?,?,?,?,?,?,?,?,?)',req.user.id,clean(a.full_name),clean(a.phone),clean(a.line1),clean(a.line2).slice(0,200),clean(a.city),clean(a.state),clean(a.postal_code),clean(a.country)||'India').lastInsertRowid;res.status(201).json({address:q('SELECT * FROM addresses WHERE id=?',id)})});
app.put('/api/addresses/:id',(req,res)=>{const a=req.body||{},old=validAddress(req.user.id,req.params.id);if(!old||!validateAddress(a))return res.status(400).json({error:'Invalid address'});run('UPDATE addresses SET full_name=?,phone=?,line1=?,line2=?,city=?,state=?,postal_code=?,country=? WHERE id=? AND user_id=?',clean(a.full_name),clean(a.phone),clean(a.line1),clean(a.line2).slice(0,200),clean(a.city),clean(a.state),clean(a.postal_code),clean(a.country)||'India',old.id,req.user.id);res.json({address:q('SELECT * FROM addresses WHERE id=?',old.id)})});
app.delete('/api/addresses/:id',(req,res)=>{const used=q('SELECT id FROM orders WHERE address_id=? AND user_id=? LIMIT 1',req.params.id,req.user.id);if(used)return res.status(409).json({error:'Address is attached to an order'});run('DELETE FROM addresses WHERE id=? AND user_id=?',req.params.id,req.user.id);res.json({ok:true})});

app.post('/api/payments/create',async(req,res)=>{
  if(!razorpay)return res.status(503).json({error:'Online payment is not configured. Add Razorpay credentials.'});
  const addressId=int(req.body?.addressId),a=validAddress(req.user.id,addressId),c=calculateCart(req.user.id);
  if(!a||!c.items.length)return res.status(400).json({error:'Valid address and non-empty cart required'});
  try{
    for(const i of c.items){const v=q('SELECT stock FROM variants WHERE id=?',i.variant_id);if(!v||v.stock<i.quantity)throw new Error('Stock changed; refresh cart')}
    const orderId=db.transaction(()=>{
      const o=run("INSERT INTO orders(user_id,address_id,status,payment_status,payment_method,subtotal,delivery_charge,discount,total,return_until) VALUES(?,?,?,?,?,?,?,?,?,datetime('now','+'||?||' days'))",req.user.id,a.id,'Pending','Pending','razorpay',c.subtotal,c.delivery,c.discount,c.total,RETURN_DAYS).lastInsertRowid;
      for(const i of c.items)run('INSERT INTO order_items(order_id,product_id,variant_id,product_name,size,color,unit_price,quantity) VALUES(?,?,?,?,?,?,?,?)',o,i.product_id,i.variant_id,i.name,i.size,i.color,i.unit_price,i.quantity);
      return o;
    })();
    const rz=await razorpay.orders.create({amount:c.total*100,currency:'INR',receipt:'STORE-'+orderId,payment_capture:1});
    run('UPDATE orders SET payment_reference=?,updated_at=CURRENT_TIMESTAMP WHERE id=?',rz.id,orderId);
    run("INSERT INTO payments(order_id,provider,provider_order_id,status) VALUES(?,?,?,'created')",orderId,'razorpay',rz.id);
    res.json({orderId,razorpayOrderId:rz.id,amount:c.total,keyId:process.env.RAZORPAY_KEY_ID});
  }catch(e){console.error('payment create',e);res.status(409).json({error:e.message==='Stock changed; refresh cart'?e.message:'Could not create payment order'})}
});
app.post('/api/payments/verify',async(req,res)=>{
  if(!process.env.RAZORPAY_KEY_SECRET||!razorpay)return res.status(503).json({error:'Payment verification is not configured'});
  const orderId=int(req.body?.orderId),ro=clean(req.body?.razorpay_order_id),rp=clean(req.body?.razorpay_payment_id),sig=clean(req.body?.razorpay_signature);
  const o=q('SELECT * FROM orders WHERE id=? AND user_id=?',orderId,req.user.id);
  if(!o||o.payment_reference!==ro||!ro||!rp||!sig)return res.status(400).json({error:'Invalid payment data'});
  const expected=crypto.createHmac('sha256',process.env.RAZORPAY_KEY_SECRET).update(ro+'|'+rp).digest('hex');
  if(!safeEqual(expected,sig)){run("UPDATE orders SET payment_status='Failed',updated_at=CURRENT_TIMESTAMP WHERE id=? AND payment_status='Pending'",o.id);run("UPDATE payments SET status='failed',signature=?,updated_at=CURRENT_TIMESTAMP WHERE order_id=?",sig,o.id);return res.status(400).json({error:'Payment signature verification failed'})}
  try{
    const payment=await razorpay.payments.fetch(rp);
    if(payment.order_id!==ro||payment.currency!=='INR'||Number(payment.amount)!==Number(o.total)*100||payment.status!=='captured')return res.status(400).json({error:'Payment details do not match the order'});
    const id=finalizePaidOrder(ro,rp,sig);res.json({ok:true,orderId:id});
  }catch(e){res.status(409).json({error:e.message==='Insufficient stock'?e.message:'Payment could not be reconciled'})}
});

app.get('/api/orders',(req,res)=>res.json({orders:all('SELECT o.*,a.full_name,a.phone,a.line1,a.line2,a.city,a.state,a.postal_code,a.country FROM orders o JOIN addresses a ON a.id=o.address_id WHERE o.user_id=? ORDER BY o.created_at DESC LIMIT 100',req.user.id).map(o=>({...o,items:all('SELECT * FROM order_items WHERE order_id=?',o.id)}))}));
app.get('/api/orders/:id',(req,res)=>{const o=q('SELECT o.*,a.full_name,a.phone,a.line1,a.line2,a.city,a.state,a.postal_code,a.country FROM orders o JOIN addresses a ON a.id=o.address_id WHERE o.id=? AND o.user_id=?',req.params.id,req.user.id);o?res.json({...o,items:all('SELECT * FROM order_items WHERE order_id=?',o.id)}):res.status(404).json({error:'Order not found'})});
app.post('/api/orders/cod',(req,res)=>{
  const a=validAddress(req.user.id,int(req.body?.addressId)),c=calculateCart(req.user.id);if(!a||!c.items.length)return res.status(400).json({error:'Valid address and non-empty cart required'});
  try{
    const id=db.transaction(()=>{
      for(const i of c.items){const changed=run('UPDATE variants SET stock=stock-? WHERE id=? AND stock>=?',i.quantity,i.variant_id,i.quantity);if(changed.changes!==1)throw new Error('Insufficient stock for '+i.name)}
      const o=run("INSERT INTO orders(user_id,address_id,status,payment_status,payment_method,subtotal,delivery_charge,discount,total,return_until) VALUES(?,?,?,?,?,?,?,?,?,datetime('now','+'||?||' days'))",req.user.id,a.id,'Confirmed','Pending','cod',c.subtotal,c.delivery,c.discount,c.total,RETURN_DAYS).lastInsertRowid;
      for(const i of c.items)run('INSERT INTO order_items(order_id,product_id,variant_id,product_name,size,color,unit_price,quantity) VALUES(?,?,?,?,?,?,?,?)',o,i.product_id,i.variant_id,i.name,i.size,i.color,i.unit_price,i.quantity);
      run('DELETE FROM cart_items WHERE cart_id=(SELECT id FROM carts WHERE user_id=?)',req.user.id);return o;
    })();
    res.status(201).json({orderId:id});
  }catch(e){res.status(409).json({error:e.message})}
});
app.post('/api/orders/:id/return',(req,res)=>{
  const o=q('SELECT * FROM orders WHERE id=? AND user_id=?',req.params.id,req.user.id);
  if(!o)return res.status(404).json({error:'Order not found'});
  if(o.status!=='Delivered'||!o.return_until||new Date(o.return_until+'Z').getTime()<Date.now())return res.status(400).json({error:'Return window is closed'});
  if(q('SELECT id FROM returns WHERE order_id=? AND user_id=?',o.id,req.user.id))return res.status(409).json({error:'Return already requested'});
  const reason=clean(req.body?.reason);if(reason.length<3||reason.length>1000)return res.status(400).json({error:'Valid return reason required'});
  const id=run('INSERT INTO returns(order_id,user_id,reason,status) VALUES(?,?,?,?)',o.id,req.user.id,reason,'Requested').lastInsertRowid;res.status(201).json({returnId:id});
});

app.use('/api/admin',requireAdmin);
app.get('/api/admin/stats',(req,res)=>{
  res.json({users:q("SELECT COUNT(*) n FROM users WHERE role='user'").n,products:q('SELECT COUNT(*) n FROM products WHERE active=1').n,
    orders:q('SELECT COUNT(*) n FROM orders').n,pendingOrders:q("SELECT COUNT(*) n FROM orders WHERE status IN ('Pending','Confirmed','Processing')").n,
    deliveredOrders:q("SELECT COUNT(*) n FROM orders WHERE status='Delivered'").n,cancelledOrders:q("SELECT COUNT(*) n FROM orders WHERE status='Cancelled'").n,
    revenue:q("SELECT COALESCE(SUM(total),0) n FROM orders WHERE payment_status='Paid'").n,
    lowStock:q('SELECT COUNT(*) n FROM variants v JOIN products p ON p.id=v.product_id WHERE p.active=1 AND v.stock<=5').n});
});
app.get('/api/admin/products',(req,res)=>{const page=Math.max(1,int(req.query.page)||1),limit=Math.min(100,Math.max(1,int(req.query.limit)||50)),offset=(page-1)*limit;const total=q('SELECT COUNT(*) n FROM products').n;const rows=all('SELECT * FROM products ORDER BY created_at DESC LIMIT ? OFFSET ?',limit,offset);res.json({products:rows.map(p=>productView(p.id,true)),pagination:{page,limit,total,pages:Math.ceil(total/limit)}})});
app.post('/api/admin/products',(req,res)=>{
  try{
    const p=productPayload(req.body||{});if(!validateVariants(req.body?.variants||[]))return res.status(400).json({error:'At least valid variants are required'});
    const id=db.transaction(()=>{
      const x=run('INSERT INTO products(name,slug,description,category,subcategory,brand,price,discount_price,sku,active,featured,new_arrival,rating) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)',p.name,p.slug,p.description,p.category,p.subcategory,p.brand,p.price,p.discount_price,p.sku,p.active,p.featured,p.new_arrival,p.rating).lastInsertRowid;
      const imgs=Array.isArray(req.body.images)?req.body.images.slice(0,12):[];for(let i=0;i<imgs.length;i++){const u=clean(imgs[i]);if(u)run('INSERT OR IGNORE INTO product_images(product_id,url,sort_order) VALUES(?,?,?)',x,u,i)}
      for(const v of req.body.variants)run('INSERT INTO variants(product_id,size,color,sku,stock) VALUES(?,?,?,?,?)',x,clean(v.size),clean(v.color),clean(v.sku).slice(0,80)||null,int(v.stock));return x;
    })();res.status(201).json({product:productView(id,true)});
  }catch(e){res.status(400).json({error:e.message.includes('UNIQUE')?'Slug/SKU already exists':'Invalid product'})}
});
app.put('/api/admin/products/:id',(req,res)=>{try{if(!q('SELECT id FROM products WHERE id=?',req.params.id))return res.status(404).json({error:'Product not found'});res.json({product:db.transaction(()=>syncProduct(req.params.id,req.body||{}))()})}catch(e){res.status(400).json({error:e.message.includes('UNIQUE')?'Slug/SKU/variant SKU already exists':e.message})}});
app.delete('/api/admin/products/:id',(req,res)=>{run('UPDATE products SET active=0,updated_at=CURRENT_TIMESTAMP WHERE id=?',req.params.id);res.json({ok:true})});
const upload=multer({storage:multer.memoryStorage(),limits:{files:8,fileSize:5*1024*1024},fileFilter:(req,file,cb)=>cb(null,true)}).array('photos',8);
function imageType(buf){
  if(buf.length>=3&&buf[0]===0xff&&buf[1]===0xd8&&buf[2]===0xff)return {mime:'image/jpeg',ext:'.jpg'};
  if(buf.length>=8&&buf.slice(0,8).equals(Buffer.from([137,80,78,71,13,10,26,10])))return {mime:'image/png',ext:'.png'};
  if(buf.length>=12&&buf.slice(0,4).toString('ascii')==='RIFF'&&buf.slice(8,12).toString('ascii')==='WEBP')return {mime:'image/webp',ext:'.webp'};
  return null;
}
app.post('/api/admin/uploads',upload,(req,res)=>{
  if(!req.files?.length)return res.status(400).json({error:'At least one valid image is required'});
  const files=[];
  try{
    for(const f of req.files){
      const type=imageType(f.buffer);
      if(!type)throw Object.assign(new Error('Unsupported or malformed image'),{status:400});
      const name=crypto.randomUUID()+type.ext,pathName=path.join(__dirname,'uploads',name);
      fs.writeFileSync(pathName,f.buffer,{flag:'wx'});
      files.push({name,url:'/uploads/'+name});
    }
    res.status(201).json({files});
  }catch(e){
    for(const f of files)try{fs.unlinkSync(path.join(__dirname,'uploads',f.name))}catch{}
    res.status(e.status||400).json({error:e.message});
  }
});
app.use('/uploads',express.static(path.join(__dirname,'uploads'),{fallthrough:false,maxAge:'7d',index:false}));
app.get('/api/admin/inventory',(req,res)=>res.json({inventory:all('SELECT v.id variant_id,p.id product_id,p.name,p.active,v.size,v.color,v.sku,v.stock FROM variants v JOIN products p ON p.id=v.product_id ORDER BY v.stock ASC,p.name ASC')}));
app.get('/api/admin/orders',(req,res)=>res.json({orders:all('SELECT o.*,u.name customer_name,u.email,a.full_name,a.phone,a.line1,a.line2,a.city,a.state,a.postal_code,a.country FROM orders o JOIN users u ON u.id=o.user_id JOIN addresses a ON a.id=o.address_id ORDER BY o.created_at DESC LIMIT 500').map(o=>({...o,items:all('SELECT * FROM order_items WHERE order_id=?',o.id)}))}));
app.patch('/api/admin/orders/:id',(req,res)=>{
  const allowed=['Pending','Confirmed','Processing','Shipped','Out for delivery','Delivered','Cancelled','Returned'],status=clean(req.body?.status);
  const transitions={
    Pending:new Set(['Confirmed','Cancelled']),
    Confirmed:new Set(['Processing','Cancelled']),
    Processing:new Set(['Shipped','Cancelled']),
    Shipped:new Set(['Out for delivery']),
    'Out for delivery':new Set(['Delivered']),
    Delivered:new Set(['Returned']),
    Cancelled:new Set([]),
    Returned:new Set([])
  };
  if(!allowed.includes(status))return res.status(400).json({error:'Invalid order status'});
  const o=q('SELECT * FROM orders WHERE id=?',req.params.id);if(!o)return res.status(404).json({error:'Order not found'});
  if(status!==o.status&&!transitions[o.status]?.has(status))return res.status(409).json({error:'Invalid order status transition'});
  if(status==='Cancelled'&&o.payment_status==='Paid')return res.status(409).json({error:'Paid orders require a refund workflow before cancellation'});
  if(status==='Returned'&&o.payment_status==='Paid')return res.status(409).json({error:'Paid orders require the return/refund workflow'});
  run('UPDATE orders SET status=?,updated_at=CURRENT_TIMESTAMP WHERE id=?',status,o.id);res.json({order:q('SELECT * FROM orders WHERE id=?',o.id)});
});
app.get('/api/admin/returns',(req,res)=>res.json({returns:all('SELECT r.*,o.total,u.name customer_name,u.email FROM returns r JOIN orders o ON o.id=r.order_id JOIN users u ON u.id=r.user_id ORDER BY r.created_at DESC')}));
app.patch('/api/admin/returns/:id',async(req,res)=>{
  const allowed=['Requested','Approved','Rejected','Received','Refunded'],status=clean(req.body?.status);if(!allowed.includes(status))return res.status(400).json({error:'Invalid return status'});
  const r=q('SELECT * FROM returns WHERE id=?',req.params.id);if(!r)return res.status(404).json({error:'Return not found'});
  try{
    if(status==='Received'&&r.inventory_restored===0){
      db.transaction(()=>{
        for(const i of all('SELECT variant_id,quantity FROM order_items WHERE order_id=?',r.order_id))run('UPDATE variants SET stock=stock+? WHERE id=?',i.quantity,i.variant_id);
        run('UPDATE returns SET status=?,inventory_restored=1,updated_at=CURRENT_TIMESTAMP WHERE id=?',status,r.id);
      })();
    } else if(status==='Refunded'){
      const o=q('SELECT * FROM orders WHERE id=?',r.order_id);
      if(!o||o.payment_status!=='Paid')return res.status(409).json({error:'Order is not eligible for a payment refund'});
      const pay=q("SELECT provider_payment_id FROM payments WHERE order_id=? AND status='paid'",o.id);
      if(!pay?.provider_payment_id||!razorpay)return res.status(503).json({error:'Razorpay refund credentials are not configured'});
      const refund=await razorpay.payments.refund(pay.provider_payment_id,{amount:o.total*100});
      run("UPDATE orders SET payment_status='Refunded',status='Returned',updated_at=CURRENT_TIMESTAMP WHERE id=?",o.id);
      run("UPDATE payments SET status='refunded',updated_at=CURRENT_TIMESTAMP WHERE order_id=?",o.id);
      run("UPDATE returns SET status='Refunded',updated_at=CURRENT_TIMESTAMP WHERE id=?",r.id);
      return res.json({return:q('SELECT * FROM returns WHERE id=?',r.id),refundId:refund.id});
    } else {
      run('UPDATE returns SET status=?,updated_at=CURRENT_TIMESTAMP WHERE id=?',status,r.id);
    }
    res.json({return:q('SELECT * FROM returns WHERE id=?',r.id)});
  }catch(e){console.error('return update',e);res.status(409).json({error:'Return operation failed'})}
});
app.get('/api/admin/customers',(req,res)=>res.json({customers:all("SELECT u.id,u.name,u.email,u.created_at,COUNT(o.id) order_count,COALESCE(SUM(CASE WHEN o.payment_status='Paid' THEN o.total ELSE 0 END),0) paid_total FROM users u LEFT JOIN orders o ON o.user_id=u.id WHERE u.role='user' GROUP BY u.id ORDER BY u.created_at DESC")}));
app.get('/api/admin/customers/:id/orders',(req,res)=>{const u=q("SELECT id,name,email,created_at FROM users WHERE id=? AND role='user'",req.params.id);if(!u)return res.status(404).json({error:'Customer not found'});res.json({customer:u,orders:all('SELECT * FROM orders WHERE user_id=? ORDER BY created_at DESC',u.id).map(o=>({...o,items:all('SELECT * FROM order_items WHERE order_id=?',o.id)}))})});

app.use((err,req,res,next)=>{console.error(err);if(res.headersSent)return next(err);res.status(err.status||500).json({error:process.env.NODE_ENV==='production'?'Request failed':(err.message||'Request failed')})});
app.get(/.*/,(req,res)=>res.sendFile(path.join(__dirname,'public/index.html')));
app.listen(PORT,()=>console.log(`Clothing store listening on ${PORT}`));