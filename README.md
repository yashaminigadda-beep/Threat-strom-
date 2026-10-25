# THREAT STORM — Sovereign Cyber Intelligence Bureau & Planetary Sensor Grid

A state-of-the-art SOC command center and real-time planetary cyber telemetry dashboard featuring live URL threat scanning, AI threat intelligence reasoning, and Supabase cloud persistence.

---

## 🚀 Deploying to Vercel

This repository is pre-configured for **zero-config 1-click deployment on Vercel** with serverless backend APIs (`/api/scan-url`, `/api/ai-chat`, `/api/config`, `/api/env.js`, `/api/evidence-chain`).

### Option 1: Deploy via GitHub (Recommended)

1. **Commit and push** your latest changes to GitHub:
   ```bash
   git add .
   git commit -m "Configure Vercel serverless deployment"
   git push origin main
   ```
2. Navigate to [vercel.com/new](https://vercel.com/new).
3. Import your repository: **`Threat-strom-`**.
4. In **Environment Variables**, optionally configure your production keys:
   - `SUPABASE_URL` — Your Supabase project URL (`https://your-ref.supabase.co`)
   - `SUPABASE_ANON_KEY` — Your Supabase anon public API key
   - `SUPABASE_PROJECT_ID` — Your Supabase project reference
   - `OPENROUTER_API_KEY` or `VOIDX_AI_API_KEY` — (Optional) For live OpenRouter cloud AI inference
5. Click **Deploy**. Vercel will build and assign you a live HTTPS domain (`https://threat-strom-xxx.vercel.app`).

---

### Option 2: Deploy directly via Vercel CLI

Run the following command from the root folder:

```bash
npx vercel
```

- When prompted, log in with your Vercel account.
- Accept the default project settings (`Y` to all prompts).
- To deploy to production:
  ```bash
  npx vercel --prod
  ```

---

## 🛠️ Local Development

To run the platform locally on your machine:

```bash
# 1. Start the native Node.js SOC server
npm start
# or
node server.js
```

Open your browser at `http://localhost:3000`.

---

## 🛡️ Architecture & Endpoints

- **Static Assets**: Root directory (`index.html`, `index.css`, `app.js`, `threats.js`, `evidence-chain.js`, images) served via Vercel Edge CDN.
- **Serverless API Routes**:
  - `GET /env.js` -> Dynamic client configuration provider
  - `GET /api/config` -> Safe public Supabase config
  - `GET /api/evidence-chain` -> Forensic investigation timeline
  - `GET/POST /api/scan-url` -> Live URL / DNS / Heuristic threat analyzer
  - `GET/POST /api/ai-chat` -> Neural Cyber AI threat assessment (VoidX / OpenRouter)
