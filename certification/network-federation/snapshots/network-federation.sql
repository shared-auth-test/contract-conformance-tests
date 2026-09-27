-- shared_auth — durable network-federation identity state.
--
-- This file is additive to schema.sql. It does not change the existing
-- (application_id, shared_user_id) application-account key or oauth_clients
-- registration surface, so older consumers remain valid while newer OIDC
-- flows gain stable opaque account and pairwise identifiers.
--
-- Pairwise subjects are persisted authority data rather than recomputed from
-- the JWT signing key. Signing-key rotation therefore cannot silently change
-- an RP's subject identifier. Multiple clients explicitly registered to one
-- subject sector may resolve the same subject for one principal; clients in
-- different sectors cannot do so through this schema.

-- Give every application enrollment a stable opaque row identifier while
-- preserving the existing composite primary key for compatibility.
alter table shared_auth.application_accounts
    add column if not exists application_account_id uuid not null default gen_random_uuid();

create unique index if not exists application_accounts_id_unique_idx
    on shared_auth.application_accounts (application_account_id);

-- A sector is public registration metadata. It is not a credential and does
-- not contain pairwise derivation material. sector_identifier is represented as
-- a bounded HTTPS identifier; application validation performs full URL checks.
create table if not exists shared_auth.subject_sectors (
    sector_id           uuid        primary key default gen_random_uuid(),
    sector_identifier   text        not null unique,
    subject_version     text        not null default 'opaque-random-v1',
    active              boolean     not null default true,
    created_at          timestamptz not null default now(),
    updated_at          timestamptz not null default now(),
    check (length(sector_identifier) between 9 and 2048),
    check (sector_identifier like 'https://%'),
    check (length(subject_version) between 1 and 64)
);

-- One OAuth client belongs to exactly one subject sector once pairwise mode is
-- enabled for that client. Keeping the binding separate from oauth_clients is
-- additive and lets legacy public-subject clients migrate explicitly.
create table if not exists shared_auth.oauth_client_subject_sectors (
    client_id           text        primary key
                                    references shared_auth.oauth_clients(client_id) on delete cascade,
    sector_id           uuid        not null
                                    references shared_auth.subject_sectors(sector_id) on delete restrict,
    created_at          timestamptz not null default now()
);

create index if not exists oauth_client_subject_sectors_sector_idx
    on shared_auth.oauth_client_subject_sectors (sector_id, client_id);

-- Canonical pairwise identity. Exactly one opaque subject exists for a
-- principal inside a sector. It may therefore be shared by multiple clients in
-- that same sector, while the same principal receives another opaque subject in
-- another sector.
create table if not exists shared_auth.sector_pairwise_subjects (
    sector_id           uuid        not null
                                    references shared_auth.subject_sectors(sector_id) on delete restrict,
    shared_user_id      uuid        not null
                                    references shared_auth.principals(shared_user_id) on delete cascade,
    subject             text        not null unique,
    subject_version     text        not null default 'opaque-random-v1',
    created_at          timestamptz not null default now(),
    primary key (sector_id, shared_user_id),
    check (length(subject) between 20 and 128),
    check (subject ~ '^[A-Za-z0-9_-]+$'),
    check (length(subject_version) between 1 and 64)
);

create index if not exists sector_pairwise_subjects_principal_idx
    on shared_auth.sector_pairwise_subjects (shared_user_id, sector_id);

-- Read model used by admin/debug tooling and conformance tests. Product clients
-- must never receive shared_user_id or application_account_id from this view;
-- the runtime selects only `subject` into an OIDC assertion.
create or replace view shared_auth.application_pairwise_subjects as
select
    aa.application_account_id,
    aa.application_id,
    aa.shared_user_id,
    c.client_id,
    cs.sector_id,
    s.sector_identifier,
    ps.subject,
    ps.subject_version
from shared_auth.application_accounts aa
join shared_auth.oauth_clients c
  on c.application_id = aa.application_id
join shared_auth.oauth_client_subject_sectors cs
  on cs.client_id = c.client_id
join shared_auth.subject_sectors s
  on s.sector_id = cs.sector_id
join shared_auth.sector_pairwise_subjects ps
  on ps.sector_id = cs.sector_id
 and ps.shared_user_id = aa.shared_user_id
where aa.status = 'active'
  and c.status = 'active'
  and s.active = true;
