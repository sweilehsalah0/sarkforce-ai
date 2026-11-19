-- SARKFORCE AI — Phase 1 platform foundation
-- Apply only to the dedicated SARKFORCE AI Supabase project.
-- Tenant-owned data is protected by RLS. No ad-platform access tokens are stored here.

create extension if not exists pgcrypto;
create schema if not exists private;
revoke all on schema private from public;
grant usage on schema private to authenticated;

create or replace function public.set_updated_at()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

create table public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  display_name text,
  avatar_url text,
  preferred_locale text not null default 'en' check (preferred_locale in ('en','ar')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table public.organizations (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  slug text not null unique,
  created_by uuid not null references auth.users(id),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table public.organization_members (
  organization_id uuid not null references public.organizations(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  role text not null default 'member' check (role in ('owner','admin','operator','viewer')),
  created_at timestamptz not null default now(),
  primary key (organization_id, user_id)
);

-- Automatically enroll the creator as the initial owner. This avoids a bootstrap
-- deadlock where RLS would otherwise prevent the first membership row.
create or replace function private.bootstrap_organization_owner()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  if new.created_by is distinct from (select auth.uid()) then
    raise exception 'Organization creator must match the authenticated user';
  end if;
  insert into public.organization_members (organization_id, user_id, role)
  values (new.id, new.created_by, 'owner');
  return new;
end;
$$;
revoke all on function private.bootstrap_organization_owner() from public;

create trigger organizations_bootstrap_owner
  after insert on public.organizations
  for each row execute function private.bootstrap_organization_owner();

-- These narrowly-scoped SECURITY DEFINER helpers live outside exposed schemas.
-- They return only membership booleans and cannot read or mutate tenant data.
create or replace function private.is_org_member(target_org uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
    from public.organization_members m
    where m.organization_id = target_org
      and m.user_id = (select auth.uid())
  );
$$;

create or replace function private.is_org_admin(target_org uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
    from public.organization_members m
    where m.organization_id = target_org
      and m.user_id = (select auth.uid())
      and m.role in ('owner','admin')
  );
$$;

revoke all on function private.is_org_member(uuid) from public;
revoke all on function private.is_org_admin(uuid) from public;
grant execute on function private.is_org_member(uuid) to authenticated;
grant execute on function private.is_org_admin(uuid) to authenticated;

create table public.ai_employees (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  employee_type text not null check (employee_type in ('media_buyer','customer_support','sales','finance_assistant','operations')),
  display_name text not null,
  status text not null default 'draft' check (status in ('draft','active','paused','error')),
  configuration jsonb not null default '{}'::jsonb,
  created_by uuid not null references auth.users(id),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table public.agent_runs (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  employee_id uuid not null references public.ai_employees(id) on delete cascade,
  status text not null default 'queued' check (status in ('queued','running','succeeded','failed','cancelled')),
  trigger_type text not null default 'manual' check (trigger_type in ('manual','scheduled','webhook','system')),
  input jsonb not null default '{}'::jsonb,
  output jsonb,
  error_code text,
  started_at timestamptz,
  finished_at timestamptz,
  created_at timestamptz not null default now()
);

create table public.agent_tasks (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  run_id uuid not null references public.agent_runs(id) on delete cascade,
  task_type text not null,
  status text not null default 'pending' check (status in ('pending','running','succeeded','failed','blocked')),
  input jsonb not null default '{}'::jsonb,
  output jsonb,
  attempts integer not null default 0 check (attempts >= 0),
  idempotency_key text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (organization_id, idempotency_key)
);

create table public.brand_profiles (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null unique references public.organizations(id) on delete cascade,
  brand_name text not null,
  website_url text,
  industry text,
  target_markets text[] not null default '{}',
  target_audiences jsonb not null default '[]'::jsonb,
  brand_voice text,
  approved_claims text[] not null default '{}',
  prohibited_claims text[] not null default '{}',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table public.connected_ad_accounts (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  provider text not null check (provider in ('meta','google','tiktok')),
  external_account_id text not null,
  account_name text,
  connection_status text not null default 'pending' check (connection_status in ('pending','connected','expired','revoked','error')),
  token_secret_ref text,
  granted_scopes text[] not null default '{}',
  connected_by uuid references auth.users(id),
  last_synced_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (organization_id, provider, external_account_id)
);

create table public.campaign_records (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  ad_account_id uuid not null references public.connected_ad_accounts(id) on delete cascade,
  provider_campaign_id text,
  name text not null,
  objective text,
  status text not null default 'draft',
  daily_budget_minor bigint check (daily_budget_minor is null or daily_budget_minor >= 0),
  currency_code text,
  settings jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table public.approval_policies (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  policy_name text not null,
  provider text check (provider is null or provider in ('meta','google','tiktok')),
  max_daily_budget_minor bigint check (max_daily_budget_minor is null or max_daily_budget_minor >= 0),
  max_monthly_budget_minor bigint check (max_monthly_budget_minor is null or max_monthly_budget_minor >= 0),
  allow_campaign_creation boolean not null default false,
  allow_publish boolean not null default false,
  allow_budget_changes boolean not null default false,
  require_approval_above_minor bigint check (require_approval_above_minor is null or require_approval_above_minor >= 0),
  enabled boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table public.audit_logs (
  id bigint generated always as identity primary key,
  organization_id uuid not null references public.organizations(id) on delete cascade,
  actor_user_id uuid references auth.users(id),
  actor_type text not null check (actor_type in ('user','ai_employee','system','integration')),
  action text not null,
  resource_type text not null,
  resource_id text,
  outcome text not null check (outcome in ('success','failure','blocked')),
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create index organization_members_user_idx on public.organization_members(user_id);
create index ai_employees_org_status_idx on public.ai_employees(organization_id, status);
create index agent_runs_org_created_idx on public.agent_runs(organization_id, created_at desc);
create index agent_tasks_run_status_idx on public.agent_tasks(run_id, status);
create index campaign_records_org_idx on public.campaign_records(organization_id);
create index audit_logs_org_created_idx on public.audit_logs(organization_id, created_at desc);

-- RLS on every exposed tenant table.
alter table public.profiles enable row level security;
alter table public.organizations enable row level security;
alter table public.organization_members enable row level security;
alter table public.ai_employees enable row level security;
alter table public.agent_runs enable row level security;
alter table public.agent_tasks enable row level security;
alter table public.brand_profiles enable row level security;
alter table public.connected_ad_accounts enable row level security;
alter table public.campaign_records enable row level security;
alter table public.approval_policies enable row level security;
alter table public.audit_logs enable row level security;

create policy "profiles_select_self" on public.profiles
for select to authenticated using (id = (select auth.uid()));
create policy "profiles_insert_self" on public.profiles
for insert to authenticated with check (id = (select auth.uid()));
create policy "profiles_update_self" on public.profiles
for update to authenticated using (id = (select auth.uid())) with check (id = (select auth.uid()));

create policy "organizations_select_member" on public.organizations
for select to authenticated using (private.is_org_member(id));
create policy "organizations_insert_creator" on public.organizations
for insert to authenticated with check (created_by = (select auth.uid()));
create policy "organizations_update_admin" on public.organizations
for update to authenticated using (private.is_org_admin(id)) with check (private.is_org_admin(id));

create policy "members_select_same_org" on public.organization_members
for select to authenticated using (private.is_org_member(organization_id));
create policy "members_insert_admin" on public.organization_members
for insert to authenticated with check (private.is_org_admin(organization_id));
create policy "members_update_admin" on public.organization_members
for update to authenticated using (private.is_org_admin(organization_id)) with check (private.is_org_admin(organization_id));
create policy "members_delete_admin" on public.organization_members
for delete to authenticated using (private.is_org_admin(organization_id));

create policy "employees_select_member" on public.ai_employees
for select to authenticated using (private.is_org_member(organization_id));
create policy "employees_insert_operator" on public.ai_employees
for insert to authenticated with check (private.is_org_admin(organization_id) or exists (
  select 1 from public.organization_members m
  where m.organization_id = ai_employees.organization_id
    and m.user_id = (select auth.uid())
    and m.role = 'operator'
));
create policy "employees_update_operator" on public.ai_employees
for update to authenticated using (private.is_org_admin(organization_id) or exists (
  select 1 from public.organization_members m
  where m.organization_id = ai_employees.organization_id
    and m.user_id = (select auth.uid())
    and m.role = 'operator'
)) with check (private.is_org_admin(organization_id) or exists (
  select 1 from public.organization_members m
  where m.organization_id = ai_employees.organization_id
    and m.user_id = (select auth.uid())
    and m.role = 'operator'
));

create policy "runs_select_member" on public.agent_runs
for select to authenticated using (private.is_org_member(organization_id));
create policy "tasks_select_member" on public.agent_tasks
for select to authenticated using (private.is_org_member(organization_id));
create policy "brand_select_member" on public.brand_profiles
for select to authenticated using (private.is_org_member(organization_id));
create policy "brand_manage_admin" on public.brand_profiles
for all to authenticated using (private.is_org_admin(organization_id)) with check (private.is_org_admin(organization_id));
create policy "ad_accounts_select_member" on public.connected_ad_accounts
for select to authenticated using (private.is_org_member(organization_id));
create policy "campaigns_select_member" on public.campaign_records
for select to authenticated using (private.is_org_member(organization_id));
create policy "policies_select_member" on public.approval_policies
for select to authenticated using (private.is_org_member(organization_id));
create policy "policies_manage_admin" on public.approval_policies
for all to authenticated using (private.is_org_admin(organization_id)) with check (private.is_org_admin(organization_id));
create policy "audit_select_admin" on public.audit_logs
for select to authenticated using (private.is_org_admin(organization_id));

-- No client-side insert/update policies for audit logs, ad accounts, campaigns,
-- runs or tasks: these are written by trusted server-side workers only.

create trigger profiles_updated_at before update on public.profiles
for each row execute function public.set_updated_at();
create trigger organizations_updated_at before update on public.organizations
for each row execute function public.set_updated_at();
create trigger ai_employees_updated_at before update on public.ai_employees
for each row execute function public.set_updated_at();
create trigger agent_tasks_updated_at before update on public.agent_tasks
for each row execute function public.set_updated_at();
create trigger brand_profiles_updated_at before update on public.brand_profiles
for each row execute function public.set_updated_at();
create trigger connected_ad_accounts_updated_at before update on public.connected_ad_accounts
for each row execute function public.set_updated_at();
create trigger campaign_records_updated_at before update on public.campaign_records
for each row execute function public.set_updated_at();
create trigger approval_policies_updated_at before update on public.approval_policies
for each row execute function public.set_updated_at();

-- Deliberately no broad GRANTs here. Review Data API exposure and grant the
-- minimum table privileges only after policies and application flows are tested.
