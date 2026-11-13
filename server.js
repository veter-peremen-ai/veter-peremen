import express from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import session from 'express-session';
import connectPgSimple from 'connect-pg-simple';
import bcrypt from 'bcryptjs';
import pg from 'pg';
import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const { Pool } = pg;
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.DATABASE_SSL === 'true' ? { rejectUnauthorized: true } : undefined });
const PgSession = connectPgSimple(session);
const isProd = process.env.NODE_ENV === 'production';
const sessionSecret = process.env.SESSION_SECRET;
if (!sessionSecret || sessionSecret.length < 32) throw new Error('SESSION_SECRET must be a random string of at least 32 characters');
if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL is required');

app.disable('x-powered-by');
app.set('trust proxy', isProd ? 1 : false);
app.use(helmet({ contentSecurityPolicy: { directives: {
  defaultSrc: ["'self'"], scriptSrc: ["'self'", "'unsafe-inline'"], styleSrc: ["'self'", "'unsafe-inline'"],
  imgSrc: ["'self'", 'data:'], fontSrc: ["'self'", 'data:'], connectSrc: ["'self'"],
  objectSrc: ["'none'"], baseUri: ["'self'"], frameAncestors: ["'none'"], upgradeInsecureRequests: isProd ? [] : null
}}}));
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: false, limit: '10kb' }));
app.use(session({
  store: new PgSession({ pool, tableName: 'user_sessions', createTableIfMissing: true }),
  name: 'vp.sid', secret: sessionSecret, resave: false, saveUninitialized: false,
  cookie: { httpOnly: true, secure: isProd, sameSite: 'lax', maxAge: 1000*60*60*24*14 }
}));
const authLimiter = rateLimit({ windowMs: 15*60*1000, limit: 10, standardHeaders: 'draft-8', legacyHeaders: false });
const asyncRoute = fn => (req,res,next)=>Promise.resolve(fn(req,res,next)).catch(next);
const clean = (v,n=2000)=>String(v??'').trim().slice(0,n);
const currentUser = async req => req.session.userId ? (await pool.query('SELECT id,email,name,role FROM users WHERE id=$1',[req.session.userId])).rows[0] : null;
const requireAuth = asyncRoute(async(req,res,next)=>{const u=await currentUser(req);if(!u)return res.status(401).json({error:'Сначала войдите в аккаунт'});req.user=u;next()});
const requireAuthor = (req,res,next)=>{if(!['author','admin'].includes(req.user.role))return res.status(403).json({error:'Доступ только для авторов'});next()};
const requireAdmin = (req,res,next)=>{if(req.user.role!=='admin')return res.status(403).json({error:'Недостаточно прав'});next()};

app.get('/api/health', asyncRoute(async(req,res)=>{await pool.query('SELECT 1');res.json({ok:true})}));
app.post('/api/auth/register',authLimiter,asyncRoute(async(req,res)=>{
  const email=clean(req.body.email,254).toLowerCase(), name=clean(req.body.name,80), password=String(req.body.password||'');
  if(!/^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/.test(email))return res.status(400).json({error:'Укажите корректную электронную почту'});
  if(password.length<12)return res.status(400).json({error:'Пароль должен содержать не менее 12 символов'});
  if(!name)return res.status(400).json({error:'Укажите имя'});
  const hash=await bcrypt.hash(password,12);
  try { const r=await pool.query("INSERT INTO users(email,name,password_hash,role) VALUES($1,$2,$3,'author') RETURNING id,email,name,role",[email,name,hash]);req.session.userId=r.rows[0].id;res.status(201).json(r.rows[0]); }
  catch(e){if(e.code==='23505')return res.status(409).json({error:'Аккаунт с такой почтой уже существует'});throw e;}
}));
app.post('/api/auth/login',authLimiter,asyncRoute(async(req,res)=>{
  const email=clean(req.body.email,254).toLowerCase(), password=String(req.body.password||'');
  const r=await pool.query('SELECT id,email,name,role,password_hash FROM users WHERE email=$1',[email]);const u=r.rows[0];
  if(!u||!await bcrypt.compare(password,u.password_hash))return res.status(401).json({error:'Неверная почта или пароль'});
  req.session.regenerate(err=>{if(err)throw err;req.session.userId=u.id;res.json({id:u.id,email:u.email,name:u.name,role:u.role});});
}));
app.post('/api/auth/logout',requireAuth,asyncRoute(async(req,res)=>req.session.destroy(()=>res.json({ok:true}))));
app.get('/api/auth/me',requireAuth,asyncRoute(async(req,res)=>res.json({user:req.user})));

app.get('/api/books',asyncRoute(async(req,res)=>{
 const r=await pool.query(`SELECT b.id,b.title,b.author,b.genre,b.description,b.cover_url,b.created_at,
 (SELECT count(*)::int FROM chapters c WHERE c.book_id=b.id) chapter_count
 FROM books b WHERE b.is_published=true ORDER BY b.created_at DESC`);
 res.json(r.rows);
}));
app.get('/api/books/:id',asyncRoute(async(req,res)=>{
 const r=await pool.query(`SELECT b.id,b.title,b.author,b.genre,b.description,b.cover_url,b.created_at,
 (SELECT json_agg(json_build_object('id',c.id,'title',c.title,'content',c.content,'chapter_index',c.chapter_index) ORDER BY c.chapter_index)
 FROM chapters c WHERE c.book_id=b.id) chapters
 FROM books b WHERE b.id=$1 AND b.is_published=true`,[req.params.id]);
 if(!r.rows[0])return res.status(404).json({error:'Книга не найдена'});
 res.json({...r.rows[0],chapters:r.rows[0].chapters||[]});
}));
app.post('/api/books',requireAuth,requireAuthor,asyncRoute(async(req,res)=>{
 const title=clean(req.body.title,180),author=clean(req.body.author,120),genre=clean(req.body.genre,80),description=clean(req.body.description,5000),chapterTitle=clean(req.body.first_chapter_title||'Глава 1',180),content=clean(req.body.first_chapter_content,100000);
 if(!title||!author||!content)return res.status(400).json({error:'Название, автор и текст первой главы обязательны'});
 const client=await pool.connect();
 try{await client.query('BEGIN');const b=await client.query(`INSERT INTO books(title,author,genre,description,owner_id,is_published) VALUES($1,$2,$3,$4,$5,true) RETURNING id`,[title,author,genre,description,req.user.id]);await client.query('INSERT INTO chapters(book_id,chapter_index,title,content) VALUES($1,0,$2,$3)',[b.rows[0].id,chapterTitle,content]);await client.query('COMMIT');res.status(201).json({id:b.rows[0].id});}
 catch(e){await client.query('ROLLBACK');throw e;}finally{client.release();}
}));
app.post('/api/progress',requireAuth,asyncRoute(async(req,res)=>{const bookId=clean(req.body.book_id,80),idx=Number(req.body.chapter_index);if(!Number.isInteger(idx)||idx<0)return res.status(400).json({error:'Некорректная глава'});await pool.query(`INSERT INTO reading_progress(user_id,book_id,chapter_index,updated_at) VALUES($1,$2,$3,NOW()) ON CONFLICT(user_id,book_id) DO UPDATE SET chapter_index=EXCLUDED.chapter_index,updated_at=NOW()`,[req.user.id,bookId,idx]);res.json({ok:true})}));
app.post('/api/bookmarks',requireAuth,asyncRoute(async(req,res)=>{const bookId=clean(req.body.book_id,80),idx=Number(req.body.chapter_index);if(!Number.isInteger(idx)||idx<0)return res.status(400).json({error:'Некорректная глава'});await pool.query('INSERT INTO bookmarks(user_id,book_id,chapter_index) VALUES($1,$2,$3) ON CONFLICT(user_id,book_id,chapter_index) DO NOTHING',[req.user.id,bookId,idx]);res.json({ok:true})}));

app.get('/api/admin/users',requireAuth,requireAdmin,asyncRoute(async(req,res)=>{const r=await pool.query('SELECT id,email,name,role,created_at FROM users ORDER BY created_at DESC');res.json(r.rows)}));
app.patch('/api/admin/users/:id/role',requireAuth,requireAdmin,asyncRoute(async(req,res)=>{const role=clean(req.body.role,20);if(!['reader','author','admin'].includes(role))return res.status(400).json({error:'Недопустимая роль'});const r=await pool.query('UPDATE users SET role=$1 WHERE id=$2 RETURNING id,email,name,role',[role,req.params.id]);if(!r.rows[0])return res.status(404).json({error:'Пользователь не найден'});res.json(r.rows[0])}));

app.use(express.static(path.join(__dirname,'public'),{index:'index.html',maxAge:isProd?'1h':0}));
app.use((err,req,res,next)=>{console.error(err);if(res.headersSent)return next(err);res.status(500).json({error:'Внутренняя ошибка сервера'});});
const port=Number(process.env.PORT||3000);
app.listen(port,'0.0.0.0',()=>console.log(`Ветер Перемен listening on ${port}`));
