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
