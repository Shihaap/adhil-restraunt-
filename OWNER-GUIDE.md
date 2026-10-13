# Aadil Restaurant — Owner Guide

Everything you need to run your own restaurant site. Keep this file safe and private.

---

## 1. Links

| What | URL |
|------|-----|
| **Your live website (customers)** | https://aadil-restaurant.surge.sh |
| **Admin panel (login here)** | https://adhil-restraunt.onrender.com/admin.html |
| **Backend (API / secure server)** | https://adhil-restraunt.onrender.com |
| **Site mirror (public copy)** | https://aadil-restaurant.surge.sh |

- Only the admin panel has a login. Customers never see it.
- The backend URL and the site URL are different on purpose:
  the site is the shop window, the backend is your private control room.

## 2. Admin login

- Username: `admin`
- Password: the value of the `ADMIN_PASSWORD` environment variable on Render.
  It must be **8 or more characters** — if it's shorter, the server ignores it
  and creates a random password instead (printed once in the deploy logs).

> Current status: the deployed password is a generated one (see Deploy logs of
> the first run) because `adil123` is 7 characters and was skipped.
> Fix with one rule change — instruction 6 below ("Reset the admin password").

> Security features built in:
> - Password is stored **hashed (scrypt)** on Render only — never in any file visitors can see.
> - 5 failed password attempts in a short time locks that IP for 15 minutes.
> - Your session lasts 12 hours and is signed; signing out anywhere kills it.
> - The site sends traffic over HTTPS only.

## 3. The 20-second daily routine

1. Open the **Admin panel** link above.
2. Sign in with your username + password.
3. Make changes — every **Save/Delete/Add/Edit** button **auto-publishes** your whole live site instantly.
4. That's it. No copying files, no uploads, nothing else.

## 4. How auto-publish works (one minute of understanding)

- The admin panel (Render) and the site (Surge) are two separate things.
- When you press any save button while signed in, the panel sends your
  content to the Render backend, which stores it, rewrites `data.js`,
  and serves it over HTTPS.
- Visitors' browsers fetch the newest version from the backend and refresh
  automatically (only when the server has newer data than their phone/browser).
- If the backend is unreachable (or you're in **offline mode**), changes are
  saved only on the current device — you'll see a "saved locally" note.

## 5. How to do anything (click path by task)

### Open / Close the shop
- Go to **Dashboard**.
- Press the big green **OPEN** or red **CLOSED** button.
- When CLOSED, every page says you're paused and ordering is disabled.
- Press OPEN to resume normal service hours.

### Add or edit a menu item
- Go to **Menu**.
- Pick a category tab on the left, then **Add item** (or **Edit** / **Copy** / **Delete** on any row).
- Fields: name, price, description, image (pick a preset image or paste any image URL), veg/non-veg, bestseller star, availability (sold out).

### Add / rename / delete a category
- Go to **Menu**. Under the category list use **Add category / Rename / Delete**.

### Change contact details, address, service hours, rating, delivery fee, announcement bar
- Go to **Settings**:
  - Name, short name, tagline, area
  - Phone (display), WhatsApp number, address, map lat/lng
  - Service windows (labels + start/end times) — these drive the Open/Closed status
  - Delivery fee, free-delivery minimum, average cost, rating + count, currency
  - Instagram / Facebook links, closed-day message
  - Top announcement bar (icon + text; delete rows to remove)
- Press **Save settings** at the bottom.

### Change the admin password
- Go to **Settings → Security card**.
- Type current password + new password (min 8 characters, letters AND numbers), press **Change password**.
- This signs you out everywhere; sign in again with the new password.

### View orders
- Go to **Orders**. Orders made through the site appear here
  (and also land on your WhatsApp — that's still your main channel).
- **Clear log** removes the on-panel copy; server-synced orders come back.

### Sign out / offline mode
- **Sign out** — left sidebar bottom, or Settings → Security → Sign out.
- If you ever open the panel without an internet connection to the backend,
  it offers **Continue offline (preview only)** — edits are previews and do NOT go live.

### Preview before publishing
- Open the public site with `?preview=1` added to the URL — it ignores server sync and shows
  exactly what's saved on that device. Example:
  `https://aadil-restaurant.surge.sh/?preview=1`

## 6. Hosting details (if you ever need to redeploy)

- **Render (private backend + admin):** deployed from your GitHub repo
  (`Shihaap/adhil-restraunt`, branch `main`). On every deploy Render clones
  the repo and runs `node server.js`. Environment variables live in
  Dashboard → your service → **Environment**:
  - `ADMIN_PASSWORD` = your login password (**8+ chars**; used on a fresh boot
    to create the hashed login; if shorter it is skipped and a random
    password is generated instead)
  - `ALLOW_ORIGIN` = `https://aadil-restaurant.surge.sh` (lets the public
    site call the API securely)
  - `RESET_ADMIN` = optional. Set to `1`, deploy, then remove the key and
    deploy again (used only to recover a forgotten password).

## 6b. Update the site after editing code

1. Edit files in `C:\Users\aqeel\aadil-restaurant` (git repo for the Render deployment).
2. Commit and push them to GitHub:
   ```
   git add .
   git commit -m "update"
   git push origin main
   ```
3. In Render, press **Manual Deploy → Deploy latest commit**. It goes live in ~1 minute.
4. If you only changed `OWNER-GUIDE.md` there is nothing to redeploy.

Important: use the included `.gitignore`. Files like `auth.json`, `secret.key`,
`sessions.json`, `store.json`, `orders.json` and `security.log` (your real
passwords and data) are excluded automatically. Do not ever add them.

## 6c. Deploying for the first time (or to a new service)

1. In Render: **New + → Web Service**, connect the GitHub repo.
2. Build command: leave empty. Start command: `node server.js`.
3. Plan: **Free**.
4. Add env vars: `ADMIN_PASSWORD` (8+ chars, letters + numbers, e.g. `adil2026`),
   `ALLOW_ORIGIN=https://aadil-restaurant.surge.sh`.
5. **Create Web Service** → wait for logs to show `Your service is live`.
6. Open `<your-app>.onrender.com/admin.html` and sign in.

## 6d. Reset the admin password (forgot / locked out)

1. Edit the environment: `ADMIN_PASSWORD` → a new 8+ char value (example `adil2026`),
   and add `RESET_ADMIN` = `1`.
2. **Save changes** → **Manual Deploy → Deploy latest commit**.
   The old hash is wiped and the new password takes effect on boot.
3. Sign in with the new password.
4. Then remove the `RESET_ADMIN` key and deploy again — otherwise the password
   would reset to the env value on every future deploy (your in-panel password
   changes would keep being overwritten).

## 7. Local copy (optional, for testing on your PC)

- Files live at: `C:\Users\aqeel\aadil-restaurant`
- Run the backend locally:
  ```
  cd C:\Users\aqeel\aadil-restaurant
  node server.js
  ```
  then open http://localhost:3000/ (site) and http://localhost:3000/admin.html (panel).

## 8. Files at a glance

| File | Purpose |
|------|---------|
| `index.html` | Public website (customers) |
| `admin.html` | Owner panel |
| `data.js` | All menu/settings content (single source of truth) |
| `server.js` | The secure backend (login, publish, orders APIs) |
| `render.yaml` | Render.com one-click deploy config |
| `.surgeignore` | Files excluded from the Surge mirror |
| `logo.png`, `logo-256.png` | Your logo (note: 1.5MB PNG — site is fine, still great for a crisp logo) |

Backend-generated files (auto-created at runtime, safe to delete):
`store.json`, `orders.json`, `auth.json`, `secret.key`, `sessions.json`, `security.log`.

## 9. Troubleshooting

- **"Too many attempts — locked"** — wait 15 minutes, then try the right password.
- **Can't log in / forgot password** — follow instruction 6d ("Reset the admin password"). Remember env passwords must be 8+ characters.
- **"Server offline / saved locally"** — the Render free tier sleeps when idle
  (takes ~30-60s to wake). Open the admin panel again and wait a moment.
- **"Session ended — sign in again"** — your 12h session expired; sign in once more.
- **Changed the password but can't remember it** — redeploy Render with a new
  `ADMIN_PASSWORD` value, then sign in with that immediately.
- **Site still shows old prices after editing** — you've most likely made the edit
  in offline mode. Sign in, re-save, and it goes live; visitors auto-refresh.