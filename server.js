require('dotenv').config();
const express = require('express'), path = require('path'), fs = require('fs'), crypto = require('crypto');
const Database = require('better-sqlite3'), bcrypt = require('bcryptjs'), nodemailer = require('nodemailer');
const helmet = require('helmet'), rateLimit = require('express-rate-limit'), multer = require('multer');
const sharp = require('sharp'), cookieParser = require('cookie-parser');

const PROD = process.env.NODE_ENV === 'production';
const PORT = process.env.PORT || 3000;
const APP_URL = (process.env.APP_URL || `http://localhost:${PORT}`).replace(/\/$/, '');
const UPLOADS = path.join(__dirname, 'uploads');
const SUPABASE_URL = (process.env.SUPABASE_URL || '').replace(/\/$/, '');
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || '';
const SUPABASE_STORAGE_BUCKET = process.env.SUPABASE_STORAGE_BUCKET || 'dharmovix-uploads';
const supabaseStorageEnabled = Boolean(SUPABASE_URL && SUPABASE_SERVICE_ROLE_KEY);
const CATS = ['Hackathon', 'Workshop', 'Internship', 'Course'];
fs.mkdirSync(UPLOADS, { recursive: true });

/* ---------- Database ---------- */
const db = new Database(process.env.DATABASE_FILE || 'dharmovix.db');
db.pragma('journal_mode = WAL'); db.pragma('foreign_keys = ON');
db.exec(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, full_name TEXT NOT NULL, username TEXT NOT NULL UNIQUE COLLATE NOCASE,
 email TEXT NOT NULL UNIQUE COLLATE NOCASE, password_hash TEXT NOT NULL, payment_status TEXT NOT NULL DEFAULT 'Pending',
 payment_ref TEXT, payment_submitted_at TEXT, account_status TEXT NOT NULL DEFAULT 'Pending', created_at TEXT DEFAULT CURRENT_TIMESTAMP, approved_at TEXT, avatar_url TEXT);
CREATE TABLE IF NOT EXISTS opportunities(id INTEGER PRIMARY KEY, title TEXT NOT NULL, category TEXT NOT NULL, description TEXT NOT NULL,
 image TEXT, date TEXT, registration_link TEXT, additional_info TEXT, status TEXT NOT NULL DEFAULT 'Unpublished', notified INTEGER DEFAULT 0,
 created_at TEXT DEFAULT CURRENT_TIMESTAMP, updated_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS applications(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 opportunity_id INTEGER NOT NULL REFERENCES opportunities(id) ON DELETE CASCADE, status TEXT NOT NULL DEFAULT 'Applied',
 applied_at TEXT DEFAULT CURRENT_TIMESTAMP, UNIQUE(user_id, opportunity_id));
CREATE TABLE IF NOT EXISTS notifications(id INTEGER PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
 opportunity_id INTEGER REFERENCES opportunities(id) ON DELETE CASCADE, notification_type TEXT NOT NULL, email TEXT, status TEXT NOT NULL,
 sent_at TEXT, error_message TEXT);
CREATE TABLE IF NOT EXISTS admin(id INTEGER PRIMARY KEY, email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, role TEXT NOT NULL, subject_id INTEGER NOT NULL, expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT NOT NULL);
`);
try { db.exec('ALTER TABLE users ADD COLUMN avatar_url TEXT'); } catch (e) { if (!String(e.message).includes('duplicate column name')) throw e; }
for (const [k, v] of Object.entries({ notify_new_opportunity: '1', notify_approval: '1', notify_registration: '1' }))
  db.prepare('INSERT OR IGNORE INTO settings VALUES(?,?)').run(k, v);
const setting = k => db.prepare('SELECT value FROM settings WHERE key=?').get(k)?.value === '1';

// Admin initialisation from server-side secrets (hash stored, never the plain password)
if (!db.prepare('SELECT 1 FROM admin').get()) {
  if (!process.env.ADMIN_EMAIL || !process.env.ADMIN_PASSWORD) { console.error('Set ADMIN_EMAIL and ADMIN_PASSWORD'); process.exit(1); }
  db.prepare('INSERT INTO admin(email,password_hash) VALUES(?,?)').run(process.env.ADMIN_EMAIL.toLowerCase(), bcrypt.hashSync(process.env.ADMIN_PASSWORD, 12));
  console.log('Admin account initialised.');
}
if (!db.prepare('SELECT 1 FROM opportunities').get()) {
  const ins = db.prepare("INSERT INTO opportunities(title,category,description,date,registration_link,additional_info,status,notified) VALUES(?,?,?,?,?,?,'Published',1)");
  ins.run('AI Build Sprint 2026', 'Hackathon', 'A 36-hour hackathon to build practical AI tools with mentors from industry.', '2026-11-15', '', 'Teams of 2-4. Bring a laptop.');
  ins.run('Python for Beginners Workshop', 'Workshop', 'Hands-on Python workshop covering syntax, data structures and a mini project.', '2026-10-25', '', 'No prior experience needed.');
  ins.run('Full-Stack Web Intern', 'Internship', 'Three-month remote internship building real features with Node.js and React.', '2026-12-01', '', 'Stipend based on performance.');
  ins.run('Data Analysis with SQL', 'Course', 'Self-paced course on querying, cleaning and presenting data with SQL.', '2026-11-05', '', 'Certificate on completion.');
}

/* ---------- Helpers ---------- */
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const sha = t => crypto.createHash('sha256').update(t).digest('hex');
const EMAIL_RE = /^[^\s@]{1,64}@[^\s@]+\.[^\s@]{2,}$/;
const strong = p => typeof p === 'string' && p.length >= 8 && p.length <= 100 && /[a-z]/.test(p) && /[A-Z]/.test(p) && /\d/.test(p);
const safeUrl = u => { if (!u) return ''; try { const x = new URL(u); return ['http:', 'https:'].includes(x.protocol) ? x.href : null; } catch { return null; } };
const str = (v, max) => (typeof v === 'string' ? v.trim().slice(0, max) : '');
const publicUser = u => u && ({ id: u.id, full_name: u.full_name, username: u.username, email: u.email, payment_status: u.payment_status,
  payment_ref: u.payment_ref, account_status: u.account_status, created_at: u.created_at, approved_at: u.approved_at, avatar_url: u.avatar_url || null });

/* ---------- Sessions (server-side, httpOnly cookies, separate for admin/user) ---------- */
const COOKIE = { admin: 'dv_admin', user: 'dv_user' }, TTL = 8 * 3600e3;
function startSession(res, role, id) {
  const t = crypto.randomBytes(32).toString('hex');
  db.prepare('INSERT INTO sessions VALUES(?,?,?,?)').run(sha(t), role, id, Date.now() + TTL);
  res.cookie(COOKIE[role], t, { httpOnly: true, sameSite: 'strict', secure: PROD, maxAge: TTL, path: '/' });
}
function endSession(req, res, role) {
  const t = req.cookies[COOKIE[role]]; if (t) db.prepare('DELETE FROM sessions WHERE token=?').run(sha(t));
  res.clearCookie(COOKIE[role], { path: '/' });
}
function sessionOf(req, role) {
  const t = req.cookies[COOKIE[role]]; if (!t) return null;
  const s = db.prepare('SELECT * FROM sessions WHERE token=? AND role=? AND expires>?').get(sha(t), role, Date.now());
  if (!s) return null;
  return role === 'admin' ? db.prepare('SELECT id,email FROM admin WHERE id=?').get(s.subject_id) : db.prepare('SELECT * FROM users WHERE id=?').get(s.subject_id);
}
const requireAdmin = (req, res, next) => { const a = sessionOf(req, 'admin'); if (!a) return res.status(401).json({ error: 'Admin login required.' }); req.admin = a; next(); };
const requireUser = (req, res, next) => {
  const u = sessionOf(req, 'user');
  if (!u || u.account_status !== 'Approved') return res.status(401).json({ error: 'Please login to continue.' });
  req.user = u; next();
};
setInterval(() => db.prepare('DELETE FROM sessions WHERE expires<?').run(Date.now()), 3600e3).unref();

/* ---------- Email ---------- */
const transporter = process.env.SMTP_HOST ? nodemailer.createTransport({ host: process.env.SMTP_HOST, port: +process.env.SMTP_PORT || 587,
  secure: +process.env.SMTP_PORT === 465, auth: process.env.SMTP_USER ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASSWORD } : undefined }) : null;
async function sendMail(to, subject, html) {
  if (!transporter) throw new Error('SMTP is not configured on the server');
  await transporter.sendMail({ from: process.env.FROM_EMAIL || process.env.SMTP_USER, to, subject, html });
}
const wrap = body => `<div style="font-family:Arial,sans-serif;max-width:560px;margin:auto;border:1px solid #e5e0d0;border-radius:12px;overflow:hidden">
<div style="background:#0E1F4D;padding:18px 24px;color:#fff;font-size:20px;letter-spacing:1px"><span style="color:#E2B54A">DHARMO</span>VIX</div>
<div style="padding:24px;color:#1b2237;line-height:1.6">${body}</div>
<div style="background:#f6f2e7;padding:12px 24px;font-size:12px;color:#6b7185">© Dharmovix. All Rights Reserved.</div></div>`;
const btn = (href, label) => `<p><a href="${esc(href)}" style="background:#C8962E;color:#fff;padding:12px 22px;border-radius:8px;text-decoration:none;display:inline-block">${esc(label)}</a></p>`;
const SUBJECTS = { Hackathon: '🚀 New Hackathon Opportunity on Dharmovix', Workshop: '📚 New Workshop Available on Dharmovix',
  Internship: 'New Internship Opportunity Available on Dharmovix', Course: '🎓 New Course Available on Dharmovix' };

async function notifyUser(user, opp) {
  const type = 'new_' + opp.category.toLowerCase();
  let row = db.prepare('SELECT * FROM notifications WHERE user_id=? AND opportunity_id=? AND notification_type=?').get(user.id, opp.id, type);
  if (row?.status === 'sent') return;
  if (!row) { const r = db.prepare("INSERT INTO notifications(user_id,opportunity_id,notification_type,email,status) VALUES(?,?,?,?,'pending')").run(user.id, opp.id, type, user.email); row = { id: r.lastInsertRowid }; }
  const link = `${APP_URL}/#/opportunity/${opp.id}`;
  const html = wrap(`<p>Hello ${esc(user.full_name)},</p><p>A new ${esc(opp.category.toLowerCase())} opportunity has been added to Dharmovix.</p>
  <p><b>Opportunity:</b> ${esc(opp.title)}<br><b>Category:</b> ${esc(opp.category)}<br><b>Date:</b> ${esc(opp.date || 'To be announced')}</p>
  <p>${esc(opp.description.slice(0, 220))}${opp.description.length > 220 ? '…' : ''}</p>${btn(link, 'View Opportunity')}
  ${opp.registration_link ? `<p>Registration link: <a href="${esc(opp.registration_link)}">${esc(opp.registration_link)}</a></p>` : ''}
  <p>Log in to Dharmovix to explore the opportunity and apply.</p>`);
  try { await sendMail(user.email, SUBJECTS[opp.category], html);
    db.prepare("UPDATE notifications SET status='sent',sent_at=CURRENT_TIMESTAMP,error_message=NULL WHERE id=?").run(row.id);
  } catch (e) { db.prepare("UPDATE notifications SET status='failed',error_message=? WHERE id=?").run(String(e.message).slice(0, 300), row.id); }
}
async function notifyAll(opp, retryOnly = false) {
  const users = retryOnly
    ? db.prepare("SELECT u.* FROM users u JOIN notifications n ON n.user_id=u.id WHERE n.opportunity_id=? AND n.status!='sent' AND u.account_status='Approved'").all(opp.id)
    : db.prepare("SELECT * FROM users WHERE account_status='Approved'").all();
  for (const u of users) await notifyUser(u, opp);
}
const fire = p => p.catch(e => console.error('Email job error:', e.message));
function maybeNotify(id) {
  const opp = db.prepare('SELECT * FROM opportunities WHERE id=?').get(id);
  if (opp.status === 'Published' && !opp.notified) {
    db.prepare('UPDATE opportunities SET notified=1 WHERE id=?').run(id);
    if (setting('notify_new_opportunity')) fire(notifyAll(opp));
  }
}

/* ---------- App ---------- */
const app = express();
app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: { directives: { defaultSrc: ["'self'"], scriptSrc: ["'self'"], styleSrc: ["'self'", 'https://fonts.googleapis.com'],
  fontSrc: ["'self'", 'https://fonts.gstatic.com'], imgSrc: ["'self'", 'data:', ...(SUPABASE_URL ? [new URL(SUPABASE_URL).origin] : [])], objectSrc: ["'none'"], frameAncestors: ["'none'"] } } }));
app.use(express.json({ limit: '50kb' })); app.use(cookieParser());
app.use('/api', rateLimit({ windowMs: 60e3, max: 200 }));
const authLimit = rateLimit({ windowMs: 15 * 60e3, max: 10, message: { error: 'Too many attempts. Try again in 15 minutes.' } });
app.use('/api', (req, res, next) => {
  res.set('Cache-Control', 'no-store');
  if (req.method !== 'GET' && req.get('x-requested-with') !== 'dharmovix') return res.status(403).json({ error: 'Invalid request.' }); // CSRF guard (+ SameSite=Strict)
  next();
});
app.use('/uploads', express.static(UPLOADS, { maxAge: '7d', index: false, dotfiles: 'deny' }));
app.use(express.static(path.join(__dirname, 'public')));

/* Session info */
app.get('/api/me', (req, res) => {
  const u = sessionOf(req, 'user'), a = sessionOf(req, 'admin');
  res.json({ user: u && u.account_status === 'Approved' ? publicUser(u) : null, admin: a ? { email: a.email } : null });
});

/* Registration + login */
app.post('/api/register', authLimit, (req, res) => {
  const b = req.body, full_name = str(b.full_name, 80), username = str(b.username, 30), email = str(b.email, 120).toLowerCase(), ref = str(b.payment_ref, 40);
  if (full_name.length < 2) return res.status(400).json({ error: 'Enter your full name.' });
  if (!/^[A-Za-z0-9_.]{3,30}$/.test(username)) return res.status(400).json({ error: 'Username must be 3-30 letters, numbers, dots or underscores.' });
  if (!EMAIL_RE.test(email)) return res.status(400).json({ error: 'Enter a valid email address.' });
  if (!strong(b.password)) return res.status(400).json({ error: 'Password needs 8+ characters with upper-case, lower-case and a number.' });
  if (b.password !== b.confirm_password) return res.status(400).json({ error: 'Passwords do not match.' });
  if (!/^[A-Za-z0-9]{6,40}$/.test(ref)) return res.status(400).json({ error: 'Enter the UPI transaction/UTR reference of your ₹49 payment.' });
  if (db.prepare('SELECT 1 FROM users WHERE username=?').get(username)) return res.status(409).json({ error: 'That username is taken.' });
  if (db.prepare('SELECT 1 FROM users WHERE email=?').get(email)) return res.status(409).json({ error: 'That email is already registered.' });
  const r = db.prepare("INSERT INTO users(full_name,username,email,password_hash,payment_status,payment_ref,payment_submitted_at) VALUES(?,?,?,?, 'Submitted', ?, CURRENT_TIMESTAMP)")
    .run(full_name, username, email, bcrypt.hashSync(b.password, 12), ref);
  if (setting('notify_registration')) fire(sendMail(email, 'We received your Dharmovix registration', wrap(`<p>Hello ${esc(full_name)},</p>
    <p>Your registration has been received and is under review. We will email you once your account has been approved.</p>`)).catch(() => {}));
  res.json({ ok: true, id: r.lastInsertRowid });
});
app.post('/api/login', authLimit, (req, res) => {
  const id = str(req.body.identifier, 120), u = db.prepare('SELECT * FROM users WHERE username=? OR email=?').get(id, id.toLowerCase());
  if (!u || !bcrypt.compareSync(String(req.body.password || ''), u.password_hash)) return res.status(401).json({ error: 'Incorrect username/email or password.' });
  if (u.account_status === 'Pending') return res.status(403).json({ error: 'Your account is currently under review. Please wait for approval.' });
  if (u.account_status === 'Rejected') return res.status(403).json({ error: 'Your registration has not been approved. Please contact the administrator for more information.' });
  startSession(res, 'user', u.id); res.json({ user: publicUser(u) });
});
app.post('/api/logout', (req, res) => { endSession(req, res, 'user'); res.json({ ok: true }); });
app.post('/api/admin/login', authLimit, (req, res) => {
  const a = db.prepare('SELECT * FROM admin WHERE email=?').get(str(req.body.email, 120).toLowerCase());
  if (!a || !bcrypt.compareSync(String(req.body.password || ''), a.password_hash)) return res.status(401).json({ error: 'Incorrect email or password.' });
  startSession(res, 'admin', a.id); res.json({ ok: true });
});
app.post('/api/admin/logout', (req, res) => { endSession(req, res, 'admin'); res.json({ ok: true }); });

/* Public opportunities */
app.get('/api/opportunities', (req, res) => {
  const q = `%${str(req.query.q, 80).replace(/[%_]/g, '')}%`, c = CATS.includes(req.query.category) ? req.query.category : null, u = sessionOf(req, 'user');
  const rows = db.prepare(`SELECT o.id,o.title,o.category,o.description,o.image,o.date,
    (SELECT status FROM applications a WHERE a.opportunity_id=o.id AND a.user_id=?) AS my_status FROM opportunities o
    WHERE o.status='Published' AND (o.title LIKE ? OR o.description LIKE ? OR o.category LIKE ?) AND (? IS NULL OR o.category=?) ORDER BY o.created_at DESC`)
    .all(u?.id ?? 0, q, q, q, c, c);
  res.json(rows);
});
app.get('/api/opportunities/:id', (req, res) => {
  const u = sessionOf(req, 'user');
  const o = db.prepare(`SELECT o.*, (SELECT status FROM applications a WHERE a.opportunity_id=o.id AND a.user_id=?) AS my_status FROM opportunities o WHERE id=? AND status='Published'`).get(u?.id ?? 0, +req.params.id);
  if (!o) return res.status(404).json({ error: 'Opportunity not found.' });
  delete o.notified; res.json(o);
});

/* User actions */
app.post('/api/opportunities/:id/apply', requireUser, (req, res) => {
  const o = db.prepare("SELECT id FROM opportunities WHERE id=? AND status='Published'").get(+req.params.id);
  if (!o) return res.status(404).json({ error: 'Opportunity not found.' });
  try { db.prepare('INSERT INTO applications(user_id,opportunity_id) VALUES(?,?)').run(req.user.id, o.id); res.json({ ok: true }); }
  catch { res.status(409).json({ error: 'You have already applied for this opportunity.' }); }
});
app.get('/api/my-applications', requireUser, (req, res) => res.json(db.prepare(
  `SELECT a.id,a.status,a.applied_at,o.id AS opportunity_id,o.title,o.category FROM applications a JOIN opportunities o ON o.id=a.opportunity_id WHERE a.user_id=? ORDER BY a.applied_at DESC`).all(req.user.id)));

/* ---------- Admin API ---------- */
const A = express.Router(); A.use(requireAdmin); app.use('/api/admin', A);
A.get('/stats', (req, res) => {
  const c = (sql, ...p) => db.prepare(sql).get(...p).n;
  res.json({ users: c('SELECT COUNT(*) n FROM users'), pending: c("SELECT COUNT(*) n FROM users WHERE account_status='Pending'"),
    approved: c("SELECT COUNT(*) n FROM users WHERE account_status='Approved'"), rejected: c("SELECT COUNT(*) n FROM users WHERE account_status='Rejected'"),
    opportunities: c('SELECT COUNT(*) n FROM opportunities'), applications: c('SELECT COUNT(*) n FROM applications'),
    byCategory: Object.fromEntries(CATS.map(k => [k, c('SELECT COUNT(*) n FROM opportunities WHERE category=?', k)])) });
});
A.get('/users', (req, res) => {
  const q = `%${str(req.query.q, 60)}%`, s = ['Pending', 'Approved', 'Rejected'].includes(req.query.status) ? req.query.status : null;
  res.json(db.prepare('SELECT * FROM users WHERE (full_name LIKE ? OR username LIKE ? OR email LIKE ?) AND (? IS NULL OR account_status=?) ORDER BY created_at DESC')
    .all(q, q, q, s, s).map(publicUser));
});
A.post('/users/:id/:action', (req, res) => {
  const u = db.prepare('SELECT * FROM users WHERE id=?').get(+req.params.id); if (!u) return res.status(404).json({ error: 'User not found.' });
  const act = req.params.action;
  if (act === 'verify-payment') db.prepare("UPDATE users SET payment_status='Verified' WHERE id=?").run(u.id);
  else if (act === 'reject-payment') db.prepare("UPDATE users SET payment_status='Rejected' WHERE id=?").run(u.id);
  else if (act === 'approve') {
    if (u.payment_status !== 'Verified') return res.status(400).json({ error: 'Verify the payment before approving this user.' });
    db.prepare("UPDATE users SET account_status='Approved', approved_at=CURRENT_TIMESTAMP WHERE id=?").run(u.id);
    if (setting('notify_approval')) fire(sendMail(u.email, 'Your Dharmovix Account Has Been Approved', wrap(`<p>Hello ${esc(u.full_name)},</p>
      <p>Congratulations! Your Dharmovix account has been approved. You can now log in and explore our latest hackathons, workshops, internships, courses and other learning opportunities.</p>
      ${btn(APP_URL + '/#/login', 'Log in to Dharmovix')}`)).catch(e => console.error('Approval email failed:', e.message)));
  } else if (act === 'reject') db.prepare("UPDATE users SET account_status='Rejected' WHERE id=?").run(u.id);
  else return res.status(400).json({ error: 'Unknown action.' });
  db.prepare("DELETE FROM sessions WHERE role='user' AND subject_id=? AND ?='reject'").run(u.id, act);
  res.json({ ok: true });
});

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 5 * 1024 * 1024, files: 1 },
  fileFilter: (r, f, cb) => cb(['image/jpeg', 'image/png', 'image/webp'].includes(f.mimetype) ? null : new Error('Only JPG, PNG or WebP images are allowed.'), true) });
const uploadImage = (req, res, next) => upload.single('image')(req, res, e => e ? res.status(400).json({ error: e.code === 'LIMIT_FILE_SIZE' ? 'Image must be 5 MB or smaller.' : e.message }) : next());
app.post('/api/profile/avatar', requireUser, uploadImage, async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Choose an image to upload.' });
  try { const url = await storeImage(req.file.buffer, { profile: true });
    db.prepare('UPDATE users SET avatar_url=? WHERE id=?').run(/^https?:\/\//i.test(url) ? url : `/uploads/${url}`, req.user.id);
    res.json({ avatar_url: /^https?:\/\//i.test(url) ? url : `/uploads/${url}` });
  } catch (e) { res.status(400).json({ error: e.message }); }
});
async function storeImage(buffer, { profile = false } = {}) {
  let data;
  try { data = await sharp(buffer).rotate().resize(profile ? 600 : 1200, profile ? 600 : 675, { fit: profile ? 'cover' : 'cover' }).webp({ quality: 80 }).toBuffer(); }
  catch { throw new Error('That file is not a valid image.'); }
  const name = `${profile ? 'profiles' : 'opportunities'}/${crypto.randomBytes(16).toString('hex')}.webp`;
  if (supabaseStorageEnabled) {
    const target = `${SUPABASE_URL}/storage/v1/object/${encodeURIComponent(SUPABASE_STORAGE_BUCKET)}/${name.split('/').map(encodeURIComponent).join('/')}`;
    const r = await fetch(target, { method: 'POST', headers: { apikey: SUPABASE_SERVICE_ROLE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`, 'Content-Type': 'image/webp', 'x-upsert': 'false' }, body: data });
    if (!r.ok) { const detail = await r.text().catch(() => ''); console.error('Supabase Storage upload failed:', r.status, detail.slice(0, 300)); throw new Error('Image storage failed. Check Supabase URL, service role key, bucket, and Storage policies.'); }
    return `${SUPABASE_URL}/storage/v1/object/public/${encodeURIComponent(SUPABASE_STORAGE_BUCKET)}/${name.split('/').map(encodeURIComponent).join('/')}`;
  }
  const localName = `${crypto.randomBytes(16).toString('hex')}.webp`;
  await fs.promises.writeFile(path.join(UPLOADS, localName), data);
  return localName;
}
async function deleteStoredImage(value) {
  if (!value) return;
  if (/^https?:\/\//i.test(value)) {
    if (!supabaseStorageEnabled || !value.startsWith(`${SUPABASE_URL}/storage/v1/object/public/${SUPABASE_STORAGE_BUCKET}/`)) return;
    const prefix = `${SUPABASE_URL}/storage/v1/object/public/${SUPABASE_STORAGE_BUCKET}/`;
    const objectPath = decodeURIComponent(value.slice(prefix.length));
    const r = await fetch(`${SUPABASE_URL}/storage/v1/object/${encodeURIComponent(SUPABASE_STORAGE_BUCKET)}/${objectPath.split('/').map(encodeURIComponent).join('/')}`, { method: 'DELETE', headers: { apikey: SUPABASE_SERVICE_ROLE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}` } });
    if (!r.ok) console.error('Supabase Storage delete failed:', r.status);
    return;
  }
  await fs.promises.rm(path.join(UPLOADS, path.basename(value)), { force: true }).catch(() => {});
}
async function parseOpp(req) {
  const b = req.body, o = { title: str(b.title, 140), category: b.category, description: str(b.description, 4000), date: str(b.date, 10),
    additional_info: str(b.additional_info, 2000), status: b.status === 'Published' ? 'Published' : 'Unpublished', registration_link: safeUrl(str(b.registration_link, 500)) };
  if (o.title.length < 3) throw new Error('Enter a title.');
  if (!CATS.includes(o.category)) throw new Error('Choose a category.');
  if (o.description.length < 10) throw new Error('Enter a description (10+ characters).');
  if (o.date && !/^\d{4}-\d{2}-\d{2}$/.test(o.date)) throw new Error('Enter a valid date.');
  if (o.registration_link === null) throw new Error('Registration link must start with http:// or https://');
  if (req.file) o.image = await storeImage(req.file.buffer);
  return o;
}

A.get('/opportunities', (req, res) => res.json(db.prepare(`SELECT o.*,
  (SELECT COUNT(*) FROM notifications n WHERE n.opportunity_id=o.id AND n.status='sent') AS sent,
  (SELECT COUNT(*) FROM notifications n WHERE n.opportunity_id=o.id AND n.status='failed') AS failed FROM opportunities o ORDER BY created_at DESC`).all()));
A.post('/opportunities', uploadImage, async (req, res) => {
  try { const o = await parseOpp(req);
    const r = db.prepare('INSERT INTO opportunities(title,category,description,image,date,registration_link,additional_info,status) VALUES(?,?,?,?,?,?,?,?)')
      .run(o.title, o.category, o.description, o.image || null, o.date, o.registration_link, o.additional_info, o.status);
    maybeNotify(r.lastInsertRowid); res.json({ ok: true, id: r.lastInsertRowid });
  } catch (e) { res.status(400).json({ error: e.message }); }
});
A.put('/opportunities/:id', uploadImage, async (req, res) => {
  const old = db.prepare('SELECT * FROM opportunities WHERE id=?').get(+req.params.id); if (!old) return res.status(404).json({ error: 'Not found.' });
  try { const o = await parseOpp(req);
    db.prepare('UPDATE opportunities SET title=?,category=?,description=?,image=?,date=?,registration_link=?,additional_info=?,status=?,updated_at=CURRENT_TIMESTAMP WHERE id=?')
      .run(o.title, o.category, o.description, o.image || old.image, o.date, o.registration_link, o.additional_info, o.status, old.id);
    if (o.image) fire(deleteStoredImage(old.image)); maybeNotify(old.id); res.json({ ok: true });
  } catch (e) { res.status(400).json({ error: e.message }); }
});
A.post('/opportunities/:id/status', (req, res) => {
  const s = req.body.status === 'Published' ? 'Published' : 'Unpublished';
  if (!db.prepare('UPDATE opportunities SET status=?,updated_at=CURRENT_TIMESTAMP WHERE id=?').run(s, +req.params.id).changes) return res.status(404).json({ error: 'Not found.' });
  maybeNotify(+req.params.id); res.json({ ok: true });
});
A.delete('/opportunities/:id', (req, res) => {
  const o = db.prepare('SELECT image FROM opportunities WHERE id=?').get(+req.params.id); if (!o) return res.status(404).json({ error: 'Not found.' });
  db.prepare('DELETE FROM opportunities WHERE id=?').run(+req.params.id); fire(deleteStoredImage(o.image)); res.json({ ok: true });
});
A.post('/opportunities/:id/retry-notifications', (req, res) => {
  const o = db.prepare('SELECT * FROM opportunities WHERE id=?').get(+req.params.id); if (!o) return res.status(404).json({ error: 'Not found.' });
  fire(notifyAll(o, true)); res.json({ ok: true });
});
A.post('/opportunities/:id/notify', (req, res) => {
  const o = db.prepare('SELECT * FROM opportunities WHERE id=?').get(+req.params.id); if (!o) return res.status(404).json({ error: 'Not found.' });
  if (o.status !== 'Published') return res.status(400).json({ error: 'Publish the opportunity before notifying users.' });
  const queued = db.prepare(`SELECT COUNT(*) n FROM users u WHERE u.account_status='Approved' AND NOT EXISTS
    (SELECT 1 FROM notifications n WHERE n.user_id=u.id AND n.opportunity_id=? AND n.status='sent')`).get(o.id).n;
  fire(notifyAll(o)); res.json({ ok: true, queued });
});
A.get('/applications', (req, res) => res.json(db.prepare(`SELECT a.id,a.status,a.applied_at,u.id AS user_id,u.full_name,u.email,o.id AS opportunity_id,o.title
  FROM applications a JOIN users u ON u.id=a.user_id JOIN opportunities o ON o.id=a.opportunity_id ORDER BY a.applied_at DESC`).all()));
A.post('/applications/:id/status', (req, res) => {
  if (!['Applied', 'Under Review', 'Accepted', 'Rejected'].includes(req.body.status)) return res.status(400).json({ error: 'Invalid status.' });
  db.prepare('UPDATE applications SET status=? WHERE id=?').run(req.body.status, +req.params.id); res.json({ ok: true });
});
A.get('/notifications', (req, res) => res.json(db.prepare(`SELECT n.*,o.title FROM notifications n LEFT JOIN opportunities o ON o.id=n.opportunity_id ORDER BY n.id DESC LIMIT 300`).all()));
A.get('/settings', (req, res) => res.json({ notify_new_opportunity: setting('notify_new_opportunity'), notify_approval: setting('notify_approval'),
  notify_registration: setting('notify_registration'), smtp_configured: !!transporter, smtp_user: process.env.SMTP_USER || '' }));
A.post('/test-email', async (req, res) => {
  if (!transporter) return res.status(400).json({ error: 'SMTP is not configured. Add SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD, and FROM_EMAIL to .env, then restart the server.' });
  try {
    await transporter.verify();
    const admin = db.prepare('SELECT email FROM admin WHERE id=?').get(req.admin.id);
    await sendMail(admin.email, 'Dharmovix SMTP test email', wrap('<p>Your Dharmovix SMTP configuration is working.</p><p>This is a test message from your Dharmovix website.</p>'));
    res.json({ ok: true, message: `SMTP test email sent to ${admin.email}. Check your inbox and spam folder.` });
  } catch (e) {
    console.error('SMTP test failed:', e.message);
    res.status(502).json({ error: 'SMTP test failed. Check your SMTP host, port, username, app password, and sender address in .env. Details: ' + String(e.message).slice(0, 180) });
  }
});
A.put('/settings', (req, res) => {
  for (const k of ['notify_new_opportunity', 'notify_approval', 'notify_registration']) if (k in req.body) db.prepare('UPDATE settings SET value=? WHERE key=?').run(req.body[k] ? '1' : '0', k);
  res.json({ ok: true });
});
A.post('/change-password', authLimit, (req, res) => {
  const a = db.prepare('SELECT * FROM admin WHERE id=?').get(req.admin.id);
  if (!bcrypt.compareSync(String(req.body.current || ''), a.password_hash)) return res.status(400).json({ error: 'Current password is incorrect.' });
  if (!strong(req.body.next)) return res.status(400).json({ error: 'New password needs 8+ characters with upper-case, lower-case and a number.' });
  db.prepare('UPDATE admin SET password_hash=? WHERE id=?').run(bcrypt.hashSync(req.body.next, 12), a.id);
  db.prepare("DELETE FROM sessions WHERE role='admin' AND subject_id=?").run(a.id); res.clearCookie(COOKIE.admin); res.json({ ok: true });
});

app.use('/api', (req, res) => res.status(404).json({ error: 'Not found.' }));
app.use((err, req, res, next) => { console.error(err); res.status(500).json({ error: 'Something went wrong on our side.' }); });
app.listen(PORT, () => console.log(`Dharmovix running at ${APP_URL}`));
