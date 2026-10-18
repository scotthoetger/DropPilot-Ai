import 'dotenv/config';
import express from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import pg from 'pg';
import Stripe from 'stripe';
import OpenAI from 'openai';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false }));
const db = process.env.DATABASE_URL ? new pg.Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.DB_SSL === 'false' ? false : { rejectUnauthorized: false } }) : null;
const stripe = process.env.STRIPE_SECRET_KEY ? new Stripe(process.env.STRIPE_SECRET_KEY) : null;
const ai = process.env.OPENAI_API_KEY ? new OpenAI({ apiKey: process.env.OPENAI_API_KEY }) : null;
const baseUrl = (process.env.APP_URL || 'http://localhost:3000').replace(/\/$/, '');
const secret = process.env.JWT_SECRET;
const requireDb = (req,res,next) => db ? next() : res.status(503).json({error:'Database not configured. Add DATABASE_URL in Render.'});

// Webhook must receive the unmodified body to verify Stripe's signature.
app.post('/api/stripe/webhook', express.raw({type:'application/json'}), async (req,res) => {
  if (!stripe || !db || !process.env.STRIPE_WEBHOOK_SECRET) return res.sendStatus(503);
  let event;
  try { event = stripe.webhooks.constructEvent(req.body, req.headers['stripe-signature'], process.env.STRIPE_WEBHOOK_SECRET); }
  catch { return res.status(400).send('Invalid webhook signature'); }
  try {
    const obj = event.data.object;
    if (event.type === 'checkout.session.completed' && obj.mode === 'subscription') {
      const userId = Number(obj.client_reference_id);
      if (Number.isSafeInteger(userId) && userId > 0) await db.query('UPDATE users SET stripe_customer_id=$1, subscription_status=$2 WHERE id=$3', [obj.customer, 'active', userId]);
    }
    if (['customer.subscription.updated','customer.subscription.deleted'].includes(event.type)) {
      await db.query('UPDATE users SET subscription_status=$1 WHERE stripe_customer_id=$2', [obj.status, obj.customer]);
    }
    res.json({received:true});
  } catch(e) { console.error('Webhook processing failed',e); res.sendStatus(500); }
});
app.use(express.json({limit:'32kb'}));
app.use('/api',rateLimit({windowMs:15*60*1000,limit:100,standardHeaders:'draft-7',legacyHeaders:false}));
const wrap = fn => (req,res,next) => Promise.resolve(fn(req,res,next)).catch(next);
function tokenFor(user) { return jwt.sign({id:user.id},secret,{expiresIn:'7d'}); }
function auth(req,res,next) {
  if (!secret) return res.status(503).json({error:'JWT_SECRET is not configured'});
  try { req.user = jwt.verify((req.headers.authorization||'').replace(/^Bearer /,''),secret); next(); }
  catch { res.status(401).json({error:'Please sign in again'}); }
}
app.get('/api/health', (req,res)=>res.json({ok:true,database:!!db,ai:!!ai,stripe:!!stripe}));
app.post('/api/register',requireDb,wrap(async(req,res)=>{
  if (!secret) return res.status(503).json({error:'JWT_SECRET not configured'});
  const email = String(req.body.email||'').trim().toLowerCase();
  const password = String(req.body.password||'');
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || password.length<10 || password.length>128) return res.status(400).json({error:'Enter a valid email and a password of 10–128 characters'});
  const hash = await bcrypt.hash(password,12);
  try { const {rows} = await db.query('INSERT INTO users(email,password_hash) VALUES($1,$2) RETURNING id,email,subscription_status',[email,hash]); res.status(201).json({token:tokenFor(rows[0]),user:rows[0]}); }
  catch(e) { if(e.code==='23505') return res.status(409).json({error:'Email already registered'}); throw e; }
}));
app.post('/api/login',requireDb,wrap(async(req,res)=>{
  if (!secret) return res.status(503).json({error:'JWT_SECRET not configured'});
  const {rows} = await db.query('SELECT * FROM users WHERE email=$1',[String(req.body.email||'').trim().toLowerCase()]);
  const valid = rows[0] && await bcrypt.compare(String(req.body.password||''),rows[0].password_hash);
  if (!valid) return res.status(401).json({error:'Invalid email or password'});
  const {id,email,subscription_status} = rows[0]; res.json({token:tokenFor(rows[0]),user:{id,email,subscription_status}});
}));
app.get('/api/me',auth,requireDb,wrap(async(req,res)=>{
  const {rows}=await db.query('SELECT id,email,subscription_status FROM users WHERE id=$1',[req.user.id]);
  if (!rows[0]) return res.sendStatus(404);
  res.json({user:rows[0]});
}));
app.post('/api/checkout',auth,requireDb,wrap(async(req,res)=>{
  if (!stripe || !process.env.STRIPE_PRICE_ID) return res.status(503).json({error:'Stripe is not configured'});
  const {rows}=await db.query('SELECT email,stripe_customer_id FROM users WHERE id=$1',[req.user.id]);
  if (!rows[0]) return res.sendStatus(404);
  const session=await stripe.checkout.sessions.create({mode:'subscription',line_items:[{price:process.env.STRIPE_PRICE_ID,quantity:1}],customer:rows[0].stripe_customer_id||undefined,customer_email:rows[0].stripe_customer_id?undefined:rows[0].email,client_reference_id:String(req.user.id),success_url:baseUrl+'/?checkout=success',cancel_url:baseUrl+'/?checkout=cancel'});
  res.json({url:session.url});
}));
app.post('/api/billing-portal',auth,requireDb,wrap(async(req,res)=>{
  if (!stripe) return res.status(503).json({error:'Stripe is not configured'});
  const {rows}=await db.query('SELECT stripe_customer_id FROM users WHERE id=$1',[req.user.id]);
  if (!rows[0]?.stripe_customer_id) return res.status(400).json({error:'No billing account yet'});
  const session=await stripe.billingPortal.sessions.create({customer:rows[0].stripe_customer_id,return_url:baseUrl});
  res.json({url:session.url});
}));
app.post('/api/generate',auth,requireDb,wrap(async(req,res)=>{
  if (!ai) return res.status(503).json({error:'OPENAI_API_KEY not configured'});
  const product=String(req.body.product||'').trim().slice(0,500);
  const audience=String(req.body.audience||'').trim().slice(0,250);
  if (product.length<3) return res.status(400).json({error:'Enter a product description'});
  const {rows}=await db.query('SELECT subscription_status FROM users WHERE id=$1',[req.user.id]);
  if (!rows[0]) return res.sendStatus(404);
  const paid=['active','trialing'].includes(rows[0].subscription_status);
  const today=new Date().toISOString().slice(0,10);
  // Atomic daily usage limit protects API budget even under concurrent requests.
  const cap=paid?30:3;
  const used=await db.query(`INSERT INTO usage (user_id,day,count) VALUES ($1,$2,1) ON CONFLICT(user_id,day) DO UPDATE SET count=usage.count+1 WHERE usage.count < $3 RETURNING count`,[req.user.id,today,cap]);
  if (!used.rowCount) return res.status(429).json({error:`Daily limit reached (${cap}). Upgrade or return tomorrow.`});
  try {
    const response=await ai.chat.completions.create({model:process.env.OPENAI_MODEL||'gpt-4o-mini',max_tokens:1100,messages:[{role:'system',content:'You are a responsible e-commerce copywriter. Produce a compelling product title, product description, 5 benefit bullets, 3 ad hooks, target customer, and a short pricing research checklist. Never invent test results, certifications, supplier availability, shipping times, customer reviews, or guaranteed sales. Clearly label hypotheses.'},{role:'user',content:`Product: ${product}\nAudience: ${audience||'General online shoppers'}`} ]});
    res.json({result:response.choices[0]?.message?.content||'No response generated',remaining:cap-used.rows[0].count});
  } catch(e) { await db.query('UPDATE usage SET count=GREATEST(count-1,0) WHERE user_id=$1 AND day=$2',[req.user.id,today]); throw e; }
}));
const here=path.dirname(fileURLToPath(import.meta.url));
app.use(express.static(path.join(here,'public')));
app.get('*',(req,res)=>res.sendFile(path.join(here,'public','index.html')));
app.use((err,req,res,next)=>{console.error(err);res.status(500).json({error:'Server error. Check Render logs.'});});
async function start(){
  if(db){await db.query(`CREATE TABLE IF NOT EXISTS users (id BIGSERIAL PRIMARY KEY,email TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL,stripe_customer_id TEXT UNIQUE,subscription_status TEXT NOT NULL DEFAULT 'free',created_at TIMESTAMPTZ DEFAULT now())`);await db.query(`CREATE TABLE IF NOT EXISTS usage (user_id BIGINT REFERENCES users(id) ON DELETE CASCADE,day DATE NOT NULL,count INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(user_id,day))`);}
  app.listen(Number(process.env.PORT)||3000,'0.0.0.0',()=>console.log('DropPilot AI listening'));
}
start().catch(e=>{console.error('Startup error',e);process.exit(1)});
