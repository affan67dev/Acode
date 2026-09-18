import test from 'node:test';
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import fs from 'node:fs';

const port=3100+Math.floor(Math.random()*200);
const dbPath=`./test-${process.pid}.db`;
const env={...process.env,PORT:String(port),DB_PATH:dbPath,NODE_ENV:'test',JWT_SECRET:'test-secret-which-is-longer-than-32-characters-123',ADMIN_EMAIL:'admin@test.local',ADMIN_PASSWORD:'Admin-password-123456'};
let child;
const base=`http://127.0.0.1:${port}`;

function cookies(res){return res.headers.get('set-cookie')?.split(';')[0]||''}
async function req(path,options={}){return fetch(base+path,{redirect:'manual',...options,headers:{'Content-Type':'application/json',...(options.headers||{})}})}

test.before(async()=>{
 child=spawn(process.execPath,['server.js'],{env,stdio:'ignore'});
 for(let i=0;i<40;i++){try{const r=await fetch(base+'/api/health');if(r.ok)return}catch{}await new Promise(r=>setTimeout(r,250))}
 throw new Error('server did not start');
});
test.after(()=>{child?.kill('SIGTERM');for(const f of [dbPath,dbPath+'-wal',dbPath+'-shm'])try{fs.unlinkSync(f)}catch{}});

test('health and public catalog pagination',async()=>{
 const h=await req('/api/health');assert.equal(h.status,200);
 const p=await req('/api/products?page=1&limit=10');assert.equal(p.status,200);const d=await p.json();assert.ok(d.pagination);assert.ok(Array.isArray(d.products));
});

test('signup/login and IDOR protection',async()=>{
 const s=await req('/api/auth/signup',{method:'POST',body:JSON.stringify({name:'User One',email:'one@test.local',password:'password-123456'})});
 assert.equal(s.status,201);const cookie=cookies(s);
 const me=await req('/api/auth/me',{headers:{Cookie:cookie}});assert.equal(me.status,200);
 const orders=await req('/api/orders',{headers:{Cookie:cookie}});assert.equal(orders.status,200);
 const other=await req('/api/orders/999999',{headers:{Cookie:cookie}});assert.equal(other.status,404);
});

test('normal user cannot access admin API',async()=>{
 const s=await req('/api/auth/login',{method:'POST',body:JSON.stringify({email:'one@test.local',password:'password-123456'})});
 const r=await req('/api/admin/stats',{headers:{Cookie:cookies(s)}});assert.equal(r.status,403);
});

test('admin product CRUD, filtering and stock-safe cart validation',async()=>{
 const login=await req('/api/auth/login',{method:'POST',body:JSON.stringify({email:'admin@test.local',password:'Admin-password-123456'})});
 assert.equal(login.status,200);const cookie=cookies(login);
 const created=await req('/api/admin/products',{method:'POST',headers:{Cookie:cookie},body:JSON.stringify({
   name:'Test Tee',category:'T-Shirts',subcategory:'Basics',brand:'AM',price:1200,discount_price:999,sku:'TEST-TEE',
   variants:[{size:'M',color:'Black',sku:'TEST-M-BLK',stock:2},{size:'L',color:'Black',sku:'TEST-L-BLK',stock:0}],
   images:[]
 })});
 assert.equal(created.status,201);const product=(await created.json()).product;assert.equal(product.variants.length,2);
 const filtered=await req('/api/products?category=T-Shirts&size=M&maxPrice=1000&limit=1');assert.equal(filtered.status,200);assert.equal((await filtered.json()).products.length,1);
 const user=await req('/api/auth/login',{method:'POST',body:JSON.stringify({email:'one@test.local',password:'password-123456'})});const uc=cookies(user);
 const bad=await req('/api/cart',{method:'POST',headers:{Cookie:uc},body:JSON.stringify({variantId:product.variants[1].id,quantity:1})});
 assert.equal(bad.status,400);
 const good=await req('/api/cart',{method:'POST',headers:{Cookie:uc},body:JSON.stringify({variantId:product.variants[0].id,quantity:2})});
 assert.equal(good.status,200);
 const tooMuch=await req('/api/cart',{method:'PATCH',headers:{Cookie:uc},body:JSON.stringify({quantity:3})});
 assert.equal(tooMuch.status,400);
});

test('weak JWT secret fails closed',async()=>{
 const r=spawn(process.execPath,['server.js'],{env:{...env,PORT:String(port+1),JWT_SECRET:'weak'}});
 await new Promise(resolve=>{r.on('exit',resolve);setTimeout(resolve,3000)});
 assert.notEqual(r.exitCode,0);
});
