import pg from 'pg';
import bcrypt from 'bcryptjs';
const {Pool}=pg;
if(!process.env.DATABASE_URL)throw new Error('DATABASE_URL is required');
const [email,name,password]=process.argv.slice(2);
if(!email||!name||!password||password.length<12){console.error('Usage: npm run admin:create -- email@example.com "Имя" "СложныйПарольНеМенее12Символов"');process.exit(1)}
const pool=new Pool({connectionString:process.env.DATABASE_URL,ssl:process.env.DATABASE_SSL==='true'?{rejectUnauthorized:true}:undefined});
try{const hash=await bcrypt.hash(password,12);const r=await pool.query(`INSERT INTO users(email,name,password_hash,role) VALUES($1,$2,$3,'admin') ON CONFLICT(email) DO UPDATE SET name=EXCLUDED.name,password_hash=EXCLUDED.password_hash,role='admin' RETURNING email,name,role`,[email.toLowerCase(),name,hash]);console.log('Admin ready:',r.rows[0]);}finally{await pool.end()}
