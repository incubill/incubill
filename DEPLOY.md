# Deploying Incubill's Backend to Render

This replaces the old GitHub Pages static hosting for the actual tool.
GitHub Pages can only serve static files — it can't run this Python
backend, database, or webhook endpoint.

## Step 1: Push this code to a GitHub repo
Create a **new** repo (e.g. `incubill-backend`) — keep it separate from
your old static-site repo, or replace that repo's contents entirely.
Push `app.py`, `requirements.txt`, `templates/`, and `.env.example`
(do NOT push your real `.env` file — see .gitignore note below).

Create a `.gitignore` file with:
```
.env
*.db
__pycache__/
```

## Step 2: Create a Render account
Go to https://render.com and sign up (free to start).

## Step 3: Create a PostgreSQL database
1. Render Dashboard → **New → PostgreSQL**
2. Name it `incubill-db`, free tier is fine to start
3. Once created, copy the **Internal Database URL** — you'll need this

## Step 4: Create the web service
1. Render Dashboard → **New → Web Service**
2. Connect your GitHub repo
3. Runtime: **Python 3**
4. Build command: `pip install -r requirements.txt`
5. Start command: `gunicorn app:app`
6. Choose a plan (free tier works for testing; paid tier recommended once you have real paying customers, since free tier sleeps after inactivity)

## Step 5: Set environment variables
In the Render web service → **Environment**, add:
```
SECRET_KEY=<generate a long random string>
DODO_API_KEY=<your Dodo secret API key>
DODO_ENVIRONMENT=live_mode
DODO_WEBHOOK_SECRET=<from Dodo Dashboard>
DODO_PRODUCT_ID_MONTHLY=pdt_0NixvmMnNF6ocQBAHH4t5
DODO_PRODUCT_ID_YEARLY=pdt_0Niznuz8H4ZBmVMPTpz3X
BASE_URL=https://incubill.com
DATABASE_URL=<paste the Internal Database URL from Step 3>
```

To generate a SECRET_KEY, run locally: `python3 -c "import secrets; print(secrets.token_hex(32))"`

## Step 6: Initialize the database
Once deployed, open the Render **Shell** tab for your web service and run:
```
flask --app app init-db
```

## Step 7: Point your domain at Render instead of GitHub Pages
1. Render → your web service → **Settings → Custom Domain** → add `incubill.com`
2. Render gives you a CNAME target (something like `incubill.onrender.com`)
3. In Cloudflare → DNS → **delete** the old GitHub Pages A records and CNAME
4. Add a new CNAME record: `incubill.com` (or `@`) → the Render target Render gives you
5. Keep the proxy (orange cloud) ON for CDN/DDoS protection, same as before

## Step 8: Update the Dodo webhook URL
1. Dodo Dashboard → Settings → Webhooks
2. Set the endpoint to: `https://incubill.com/webhook/dodo`
3. Copy the signing secret shown there into your Render environment variable `DODO_WEBHOOK_SECRET`

## Step 9: Test the full flow end to end
1. Visit `https://incubill.com` → should redirect to `/login`
2. Sign up with a test email
3. Should redirect to `/subscribe` — pick a plan
4. Complete Dodo checkout (test mode first!)
5. Confirm the webhook fires and your account's `subscription_status` becomes `trialing` or `active` (check the Render Postgres database, or just confirm you get redirected into `/app` successfully)
6. Confirm the tool itself works exactly as before (trade picker, PDF generation, sharing, etc.)

## Step 10: Switch to live mode when ready
Same as before — flip `DODO_ENVIRONMENT` to `live_mode` and confirm your product IDs are the live versions, not test ones.
