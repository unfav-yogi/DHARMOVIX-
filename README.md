# Dharmovix

Learning & opportunity platform: hackathons, workshops, internships, courses.
Stack: Node.js (Express) · SQLite (better-sqlite3) · Supabase Storage (optional) · vanilla JS single-page frontend.

## 1. Setup
    npm install
    cp .env.example .env     # edit values, including a strong initial admin password
    npm start                # http://localhost:3000
Requires Node 18+.

## 2. Database
SQLite file at `DATABASE_FILE` (default ./dharmovix.db). Tables are created automatically on first start.
On hosts with ephemeral disks, mount a persistent volume for the DB file and `uploads/`. Back it up regularly.

## 3. Environment variables
- ADMIN_EMAIL, ADMIN_PASSWORD: initial admin, read only when no admin exists; the password is bcrypt-hashed into the DB
- SESSION_SECRET: long random string
- APP_URL: public site URL, used for links in emails
- SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD, FROM_EMAIL: email delivery
- DATABASE_FILE, PORT, NODE_ENV
- `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY`, `SUPABASE_STORAGE_BUCKET`: optional Supabase Storage integration. Keep the service-role key server-side only; never put it in frontend JavaScript or commit it.

Never commit `.env`. After first login, change the admin password in Admin > Settings, then remove ADMIN_PASSWORD from the server environment.

## 4. Admin
Open `/#/admin-login` (not linked publicly). Credentials exist only on the server; the password is hashed.

## 5. Email / SMTP setup (Gmail example)
1. In your Google Account, enable 2-Step Verification.
2. Open Google Account > Security > App passwords and create an app password. Google may only show this option when 2-Step Verification is enabled and the account is eligible.
3. Copy `.env.example` to `.env` and set these values. Use the Gmail App Password, not your normal Gmail password:

       SMTP_HOST=smtp.gmail.com
       SMTP_PORT=587
       SMTP_USER=your-gmail-address@gmail.com
       SMTP_PASSWORD=your-16-character-google-app-password
       FROM_EMAIL=Dharmovix <your-gmail-address@gmail.com>

4. Save `.env`, restart the server (`npm start`), sign in as admin, and open Admin > Settings.
5. Click **Send test email**. It sends a test message to the admin email configured for login. Check the inbox and spam folder.
6. Once SMTP works, registration confirmations, approval emails, and opportunity notifications can be delivered. Failed sends are stored in Admin > Email Notifications and can be retried.

Never commit `.env` or share your app password. For larger production email volumes, use a transactional email provider instead of personal Gmail.

## 6. Payment QR
Put your ₹49 QR image at `public/qr.png`. Users enter their UPI/UTR reference; admin must verify payment before approving.

## 7. Production checklist
- NODE_ENV=production (Secure cookies) behind HTTPS (Nginx/Caddy/Render)
- Unique SESSION_SECRET; .env never in git
- Persist DB + uploads/; schedule backups
- Use a transactional email provider for volume (SES, Brevo, Resend)

## 8. Supabase Storage (optional)
1. Create a project at https://supabase.com/dashboard.
2. In Storage, create a **public** bucket named `dharmovix-uploads` (or set `SUPABASE_STORAGE_BUCKET` to your bucket name). Public access is required because opportunity images and profile photos are displayed without signed URLs.
3. In your server environment, set `SUPABASE_URL` to the project URL and `SUPABASE_SERVICE_ROLE_KEY` to the service-role/secret key from the Supabase project API settings. This key is used only by `server.js`; do not expose it in the browser or commit it.
4. Restart the server. New opportunity images and user profile photos are converted to WebP and stored in Supabase Storage. The user/profile records and all existing application data remain in SQLite. Existing local images continue to work.
5. If the Supabase variables are absent, uploads automatically continue to use the local `uploads/` folder.

The profile photo upload appears on the user's Profile page. A `avatar_url` column is added automatically to existing SQLite databases.

## 9. Features added later
- Admin > Opportunities > "Notify users": one click emails every approved user who has not yet received that opportunity.
- 🔔 bell in the header for logged-in users: shows opportunities published since they last opened Opportunities.
- Achieve page (`/#/achieve`): pick a role, see what it leads to and a 5-stage learning roadmap. Edit the `ROLES` list in `public/app.js` to change content.
- Admin login link is in the header; the admin page is `/#/admin-login`.
