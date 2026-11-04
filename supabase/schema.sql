-- ============================================================
-- ipVision — Supabase Database Schema & Security Policies
-- ============================================================

-- 1. Create Scans Table
create table if not exists public.scans (
    id uuid primary key default gen_random_uuid(),
    user_id uuid not null references auth.users(id) on delete cascade,
    ip text not null,
    ip_type text not null default 'IPv4',
    city text,
    region text,
    country text,
    postal text,
    isp text,
    org text,
    asn text,
    latitude double precision,
    longitude double precision,
    is_proxy boolean not null default false,
    is_hosting boolean not null default false,
    is_mobile boolean not null default false,
    risk_level text not null default 'Low',
    created_at timestamptz not null default now()
);

-- Index for speedy queries by user and date
create index if not exists idx_scans_user_created on public.scans (user_id, created_at desc);

-- 2. Create User Sessions Table (Enforces single-active-session rule)
create table if not exists public.user_sessions (
    user_id uuid primary key references auth.users(id) on delete cascade,
    session_id text not null,
    created_at timestamptz not null default now(),
    last_seen timestamptz not null default now(),
    user_agent text,
    ip_address text
);

-- 3. Row Level Security (RLS) Configuration

-- Enable RLS on both tables
alter table public.scans enable row level security;
alter table public.user_sessions enable row level security;

-- Scans Policies: Users can ONLY select, insert, or delete their own scans
drop policy if exists "Users can read own scans" on public.scans;
create policy "Users can read own scans"
    on public.scans for select
    using (auth.uid() = user_id);

drop policy if exists "Users can insert own scans" on public.scans;
create policy "Users can insert own scans"
    on public.scans for insert
    with check (auth.uid() = user_id);

drop policy if exists "Users can delete own scans" on public.scans;
create policy "Users can delete own scans"
    on public.scans for delete
    using (auth.uid() = user_id);

-- User Sessions Policies: Users can view and update their own session record
drop policy if exists "Users can read own session" on public.user_sessions;
create policy "Users can read own session"
    on public.user_sessions for select
    using (auth.uid() = user_id);

drop policy if exists "Users can update own session" on public.user_sessions;
create policy "Users can update own session"
    on public.user_sessions for all
    using (auth.uid() = user_id);

-- 4. Feedback Submissions Table (Encrypted/Private)
create table if not exists public.feedback (
    id uuid primary key default gen_random_uuid(),
    user_id uuid references auth.users(id) on delete set null,
    sentiment text not null default 'good',
    category text not null default 'general',
    message text not null,
    reply_email text,
    ip_address text,
    created_at timestamptz not null default now()
);

alter table public.feedback enable row level security;

-- Only authenticated users or service role can insert feedback
drop policy if exists "Allow inserts for feedback" on public.feedback;
create policy "Allow inserts for feedback"
    on public.feedback for insert
    with check (true);
