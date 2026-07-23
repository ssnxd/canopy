package postgres

const Migration = `
create table if not exists "user" (
	id text primary key,
	name text not null,
	email text not null,
	email_verified boolean not null default false,
	image text not null default '',
	created_at timestamptz not null,
	updated_at timestamptz not null
);

create unique index if not exists user_email_unique on "user" (lower(email));

create table if not exists session (
	id text primary key,
	user_id text not null references "user"(id) on delete cascade,
	token text not null unique,
	expires_at timestamptz not null,
	ip_address text not null default '',
	user_agent text not null default '',
	created_at timestamptz not null,
	updated_at timestamptz not null
);

create index if not exists session_user_id_idx on session (user_id);
create index if not exists session_expires_at_idx on session (expires_at);

create table if not exists account (
	id text primary key,
	user_id text not null references "user"(id) on delete cascade,
	account_id text not null,
	provider_id text not null,
	access_token text not null default '',
	refresh_token text not null default '',
	access_token_expires_at timestamptz,
	refresh_token_expires_at timestamptz,
	scope text not null default '',
	id_token text not null default '',
	password text not null default '',
	created_at timestamptz not null,
	updated_at timestamptz not null
);

create unique index if not exists account_provider_account_unique on account (provider_id, account_id);
create unique index if not exists account_user_provider_unique on account (user_id, provider_id);

create table if not exists verification (
	id text primary key,
	identifier text not null,
	value text not null,
	expires_at timestamptz not null,
	created_at timestamptz not null,
	updated_at timestamptz not null
);

create unique index if not exists verification_identifier_value_unique on verification (identifier, value);
create index if not exists verification_expires_at_idx on verification (expires_at);

alter table "user" add column if not exists role text not null default '';
alter table "user" add column if not exists banned boolean not null default false;
alter table "user" add column if not exists ban_reason text not null default '';
alter table "user" add column if not exists ban_expires_at timestamptz;

alter table session add column if not exists active_organization_id text not null default '';
alter table session add column if not exists impersonated_by text not null default '';
`
