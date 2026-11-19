# SARKFORCE AI

Bilingual (English/Arabic) SaaS foundation for a multi-tenant AI workforce platform.

## Stack

- Next.js 16 App Router + TypeScript
- Supabase Auth, PostgreSQL, Storage
- Vercel deployment target
- Meta Ads, Google Ads and TikTok Ads integrations planned

## Local setup

1. Install Node.js 20.9+ and pnpm/npm.
2. Copy `.env.example` to `.env.local`.
3. Fill in the Supabase project URL and publishable key.
4. Install and run:

```bash
npm install
npm run dev
```

Open http://localhost:3000.

## Database

The initial schema is in `supabase/migrations/202611190001_initial_platform_schema.sql`.

Apply it only to the dedicated SARKFORCE AI Supabase project after the project is created and healthy. Do not apply it to existing unrelated projects.

## Security notes

- Every tenant-owned public table enables RLS.
- The browser receives only the Supabase publishable key.
- Never expose Supabase secret/service-role keys or ad-platform OAuth tokens to the browser.
- OAuth tokens belong in a server-only encrypted secret store; the database stores references, not raw tokens.
- Publishing ads and changing budgets must be checked server-side against tenant policies and platform constraints.

## Current scope

This is Phase 1 scaffolding, not a finished SaaS or live advertising integration. OAuth flows, billing, agent runtime, workers, and platform API calls are subsequent phases.
