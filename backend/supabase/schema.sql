-- Shared analysis cache for TrustPack. Run once in the Supabase SQL editor.
-- The backend talks to it with the service_role key; RLS is enabled with no policies, so the public
-- anon key can neither read nor write this table.

create table if not exists public.analysis_cache (
    cache_key      text primary key,          -- "<ecosystem>|<name>|<version>|<repo>|<engine version>"
    ecosystem      text not null,
    package_name   text not null,
    version        text not null,
    repository     text not null default '',
    engine_version text not null,
    verdict        text,
    document       jsonb not null,            -- the full deterministic report
    created_at     timestamptz not null default now()
);

create index if not exists analysis_cache_package_idx
    on public.analysis_cache (ecosystem, package_name, version);
create index if not exists analysis_cache_created_idx
    on public.analysis_cache (created_at desc);

alter table public.analysis_cache enable row level security;

-- Durable history survives backend restarts and redeploys on hosts with ephemeral filesystems.
-- The backend accesses this table with the service_role key; browser/anon access stays blocked.
create table if not exists public.analysis_reports (
    id           text primary key,
    created_at   timestamptz not null,
    ecosystem    text not null,
    package_name text not null,
    version      text not null,
    verdict      text,
    document     jsonb not null
);

create index if not exists analysis_reports_created_idx
    on public.analysis_reports (created_at desc);
create index if not exists analysis_reports_package_idx
    on public.analysis_reports (ecosystem, package_name, version);

alter table public.analysis_reports enable row level security;
