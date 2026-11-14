-- Rewardly: sichere Grundtabellen (MVP)
-- In Supabase SQL Editor ausführen. Guthaben und Rollen dürfen NICHT vom Browser geändert werden.

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  username text,
  role text not null default 'user' check (role in ('user','admin')),
  created_at timestamptz not null default now()
);

create table if not exists public.tickets (
  id bigint generated always as identity primary key,
  user_id uuid not null references auth.users(id) on delete cascade,
  subject text not null check (char_length(subject) between 3 and 120),
  message text not null check (char_length(message) between 3 and 5000),
  status text not null default 'open' check (status in ('open','in_progress','resolved','closed')),
  created_at timestamptz not null default now()
);

create table if not exists public.ticket_messages (
  id bigint generated always as identity primary key,
  ticket_id bigint not null references public.tickets(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  message text not null check (char_length(message) between 1 and 5000),
  created_at timestamptz not null default now()
);

create table if not exists public.reward_ledger (
  id bigint generated always as identity primary key,
  user_id uuid not null references auth.users(id) on delete cascade,
  amount_cents integer not null,
  entry_type text not null check (entry_type in ('reward','reversal','adjustment','payout')),
  description text not null default '',
  created_at timestamptz not null default now()
);

create table if not exists public.payout_requests (
  id bigint generated always as identity primary key,
  user_id uuid not null references auth.users(id) on delete cascade,
  amount_cents integer not null check (amount_cents >= 500),
  method text not null check (method in ('bank','paypal','amazon','roblox','google_play')),
  destination text not null,
  status text not null default 'pending' check (status in ('pending','processing','completed','rejected')),
  created_at timestamptz not null default now()
);

create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  insert into public.profiles (id, username)
  values (new.id, coalesce(new.raw_user_meta_data ->> 'username', split_part(new.email, '@', 1)));
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute procedure public.handle_new_user();

alter table public.profiles enable row level security;
alter table public.tickets enable row level security;
alter table public.ticket_messages enable row level security;
alter table public.reward_ledger enable row level security;
alter table public.payout_requests enable row level security;

drop policy if exists "Users can read own profile" on public.profiles;
create policy "Users can read own profile" on public.profiles
  for select to authenticated using (auth.uid() = id);

drop policy if exists "Users can read own tickets" on public.tickets;
create policy "Users can read own tickets" on public.tickets
  for select to authenticated using (auth.uid() = user_id);
drop policy if exists "Users can create own tickets" on public.tickets;
create policy "Users can create own tickets" on public.tickets
  for insert to authenticated with check (auth.uid() = user_id);

drop policy if exists "Users can read messages on own tickets" on public.ticket_messages;
create policy "Users can read messages on own tickets" on public.ticket_messages
  for select to authenticated using (
    exists (select 1 from public.tickets t where t.id = ticket_id and t.user_id = auth.uid())
  );
drop policy if exists "Users can reply to own tickets" on public.ticket_messages;
create policy "Users can reply to own tickets" on public.ticket_messages
  for insert to authenticated with check (
    auth.uid() = user_id and
    exists (select 1 from public.tickets t where t.id = ticket_id and t.user_id = auth.uid())
  );

drop policy if exists "Users can read own reward ledger" on public.reward_ledger;
create policy "Users can read own reward ledger" on public.reward_ledger
  for select to authenticated using (auth.uid() = user_id);

drop policy if exists "Users can read own payout requests" on public.payout_requests;
create policy "Users can read own payout requests" on public.payout_requests
  for select to authenticated using (auth.uid() = user_id);
drop policy if exists "Users can request own payout" on public.payout_requests;
create policy "Users can request own payout" on public.payout_requests
  for insert to authenticated with check (auth.uid() = user_id and status = 'pending');

-- Absichtlich keine Browser-Rechte zum Ändern von Rollen, Guthaben, Ledger oder Auszahlungsstatus.

-- Sichere Prüfung für Auszahlungsanträge: feste Beträge und kein Überziehen des bestätigten Guthabens.
create or replace function public.validate_payout_request()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  available_cents integer;
begin
  if auth.uid() is null or new.user_id <> auth.uid() then
    raise exception 'Nicht berechtigt.';
  end if;
  if new.amount_cents not in (500,1000,2000,3000,5000,10000,20000,50000) then
    raise exception 'Bitte einen der erlaubten Auszahlungsbeträge auswählen.';
  end if;
  select coalesce(sum(amount_cents),0)::integer into available_cents
  from public.reward_ledger where user_id = new.user_id;
  select available_cents - coalesce(sum(amount_cents),0)::integer into available_cents
  from public.payout_requests
  where user_id = new.user_id and status in ('pending','processing');
  if new.amount_cents > available_cents then
    raise exception 'Dein bestätigtes verfügbares Guthaben reicht dafür nicht aus.';
  end if;
  return new;
end;
$$;

drop trigger if exists validate_payout_request_before_insert on public.payout_requests;
create trigger validate_payout_request_before_insert
before insert on public.payout_requests
for each row execute function public.validate_payout_request();

-- Admin-Rechte: Nur Profile mit role='admin' dürfen Verwaltungsdaten sehen/bearbeiten.
create or replace function public.is_admin()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1 from public.profiles p
    where p.id = (select auth.uid()) and p.role = 'admin'
  );
$$;

revoke all on function public.is_admin() from public;
grant execute on function public.is_admin() to authenticated;

drop policy if exists "Admins can read all profiles" on public.profiles;
create policy "Admins can read all profiles" on public.profiles
  for select to authenticated using ((select public.is_admin()));

drop policy if exists "Admins can read all tickets" on public.tickets;
create policy "Admins can read all tickets" on public.tickets
  for select to authenticated using ((select public.is_admin()));
drop policy if exists "Admins can update tickets" on public.tickets;
create policy "Admins can update tickets" on public.tickets
  for update to authenticated using ((select public.is_admin()))
  with check ((select public.is_admin()));

drop policy if exists "Admins can read all ticket messages" on public.ticket_messages;
create policy "Admins can read all ticket messages" on public.ticket_messages
  for select to authenticated using ((select public.is_admin()));
drop policy if exists "Admins can reply to tickets" on public.ticket_messages;
create policy "Admins can reply to tickets" on public.ticket_messages
  for insert to authenticated with check (
    user_id = (select auth.uid()) and (select public.is_admin())
  );

drop policy if exists "Admins can read all reward ledger" on public.reward_ledger;
create policy "Admins can read all reward ledger" on public.reward_ledger
  for select to authenticated using ((select public.is_admin()));

drop policy if exists "Admins can read all payout requests" on public.payout_requests;
create policy "Admins can read all payout requests" on public.payout_requests
  for select to authenticated using ((select public.is_admin()));
drop policy if exists "Admins can update payout requests" on public.payout_requests;
create policy "Admins can update payout requests" on public.payout_requests
  for update to authenticated using ((select public.is_admin()))
  with check ((select public.is_admin()));



-- Nutzer sperren/entsperren: zusätzliche Statusfelder.
alter table public.profiles
  add column if not exists is_banned boolean not null default false,
  add column if not exists ban_reason text,
  add column if not exists banned_at timestamptz;

create or replace function public.is_active_user()
returns boolean
language sql stable security definer
set search_path = ''
as $$
  select exists (
    select 1 from public.profiles p
    where p.id = (select auth.uid()) and p.is_banned = false
  );
$$;
revoke all on function public.is_active_user() from public;
grant execute on function public.is_active_user() to authenticated;

-- Admin darf nur Sperrspalten ändern, nicht die Admin-Rolle.
grant update (is_banned, ban_reason, banned_at) on public.profiles to authenticated;
drop policy if exists "Admins can update user ban status" on public.profiles;
create policy "Admins can update user ban status" on public.profiles
  for update to authenticated
  using ((select public.is_admin()))
  with check ((select public.is_admin()));

drop policy if exists "Users can read own tickets" on public.tickets;
create policy "Users can read own tickets" on public.tickets
  for select to authenticated using (auth.uid() = user_id and (select public.is_active_user()));
drop policy if exists "Users can create own tickets" on public.tickets;
create policy "Users can create own tickets" on public.tickets
  for insert to authenticated with check (auth.uid() = user_id and (select public.is_active_user()));

drop policy if exists "Users can read messages on own tickets" on public.ticket_messages;
create policy "Users can read messages on own tickets" on public.ticket_messages
  for select to authenticated using (
    (select public.is_active_user()) and
    exists (select 1 from public.tickets t where t.id = ticket_id and t.user_id = auth.uid())
  );
drop policy if exists "Users can reply to own tickets" on public.ticket_messages;
create policy "Users can reply to own tickets" on public.ticket_messages
  for insert to authenticated with check (
    auth.uid() = user_id and (select public.is_active_user()) and
    exists (select 1 from public.tickets t where t.id = ticket_id and t.user_id = auth.uid())
  );

drop policy if exists "Users can read own reward ledger" on public.reward_ledger;
create policy "Users can read own reward ledger" on public.reward_ledger
  for select to authenticated using (auth.uid() = user_id and (select public.is_active_user()));

drop policy if exists "Users can read own payout requests" on public.payout_requests;
create policy "Users can read own payout requests" on public.payout_requests
  for select to authenticated using (auth.uid() = user_id and (select public.is_active_user()));
drop policy if exists "Users can request own payout" on public.payout_requests;
create policy "Users can request own payout" on public.payout_requests
  for insert to authenticated with check (auth.uid() = user_id and status = 'pending' and (select public.is_active_user()));

create or replace function public.validate_payout_request()
returns trigger
language plpgsql security definer
set search_path = ''
as $$
declare
  available_cents integer;
begin
  if auth.uid() is null or new.user_id <> auth.uid() then
    raise exception 'Nicht berechtigt.';
  end if;
  if not public.is_active_user() then
    raise exception 'Dieses Konto ist gesperrt. Auszahlungen sind blockiert.';
  end if;
  if new.amount_cents not in (500,1000,2000,3000,5000,10000,20000,50000) then
    raise exception 'Bitte einen der erlaubten Auszahlungsbeträge auswählen.';
  end if;
  select coalesce(sum(amount_cents),0)::integer into available_cents
  from public.reward_ledger where user_id = new.user_id;
  select available_cents - coalesce(sum(amount_cents),0)::integer into available_cents
  from public.payout_requests
  where user_id = new.user_id and status in ('pending','processing');
  if new.amount_cents > available_cents then
    raise exception 'Dein bestätigtes verfügbares Guthaben reicht dafür nicht aus.';
  end if;
  return new;
end;
$$;
