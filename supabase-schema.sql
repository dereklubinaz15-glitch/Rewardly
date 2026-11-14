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


-- Spiele-Aktivität im Nutzerkonto (keine automatische Prämiengutschrift).
create table if not exists public.game_activity (
  id bigint generated always as identity primary key,
  user_id uuid not null references auth.users(id) on delete cascade,
  game_name text not null check (char_length(game_name) between 2 and 100),
  event_type text not null default 'opened' check (event_type in ('opened','started')),
  created_at timestamptz not null default now()
);
alter table public.game_activity enable row level security;
drop policy if exists "Users can read own game activity" on public.game_activity;
create policy "Users can read own game activity" on public.game_activity
  for select to authenticated using (auth.uid() = user_id and (select public.is_active_user()));
drop policy if exists "Users can add own game activity" on public.game_activity;
create policy "Users can add own game activity" on public.game_activity
  for insert to authenticated with check (auth.uid() = user_id and (select public.is_active_user()));
drop policy if exists "Admins can read all game activity" on public.game_activity;
create policy "Admins can read all game activity" on public.game_activity
  for select to authenticated using ((select public.is_admin()));


-- Rewardly-Erweiterungen: Login-Bonus-Punkte, Empfehlungen, Rangliste und Benachrichtigungen.
alter table public.profiles add column if not exists referral_code text unique;
alter table public.profiles alter column referral_code set default upper(substr(replace(gen_random_uuid()::text,'-',''),1,8));
update public.profiles set referral_code = upper(substr(replace(id::text,'-',''),1,8)) where referral_code is null;

create table if not exists public.reward_points (
  user_id uuid primary key references auth.users(id) on delete cascade,
  points integer not null default 0 check (points >= 0),
  updated_at timestamptz not null default now()
);
create table if not exists public.daily_bonus_claims (
  id bigint generated always as identity primary key,
  user_id uuid not null references auth.users(id) on delete cascade,
  claim_date date not null default (now() at time zone 'utc')::date,
  points integer not null default 10,
  streak integer not null default 1,
  created_at timestamptz not null default now(),
  unique(user_id,claim_date)
);
create table if not exists public.referrals (
  id bigint generated always as identity primary key,
  referrer_id uuid not null references auth.users(id) on delete cascade,
  referred_id uuid not null unique references auth.users(id) on delete cascade,
  referral_code text not null,
  status text not null default 'registered' check (status in ('registered','qualified','rejected')),
  created_at timestamptz not null default now(),
  check (referrer_id <> referred_id)
);
create table if not exists public.notifications (
  id bigint generated always as identity primary key,
  user_id uuid not null references auth.users(id) on delete cascade,
  title text not null,
  message text not null,
  is_read boolean not null default false,
  created_at timestamptz not null default now()
);
alter table public.reward_points enable row level security;
alter table public.daily_bonus_claims enable row level security;
alter table public.referrals enable row level security;
alter table public.notifications enable row level security;

drop policy if exists "Users read own points" on public.reward_points;
create policy "Users read own points" on public.reward_points for select to authenticated using(user_id=auth.uid());
drop policy if exists "Users read own bonus claims" on public.daily_bonus_claims;
create policy "Users read own bonus claims" on public.daily_bonus_claims for select to authenticated using(user_id=auth.uid());
drop policy if exists "Users read own referrals" on public.referrals;
create policy "Users read own referrals" on public.referrals for select to authenticated using(referrer_id=auth.uid() or referred_id=auth.uid());
drop policy if exists "Users read own notifications" on public.notifications;
create policy "Users read own notifications" on public.notifications for select to authenticated using(user_id=auth.uid());
drop policy if exists "Users mark own notifications read" on public.notifications;
create policy "Users mark own notifications read" on public.notifications for update to authenticated using(user_id=auth.uid()) with check(user_id=auth.uid());

create or replace function public.claim_daily_bonus()
returns table(points_awarded integer, current_points integer, current_streak integer)
language plpgsql security definer set search_path=''
as $$
declare
  v_user uuid := auth.uid();
  v_today date := (now() at time zone 'utc')::date;
  v_streak integer := 1;
  v_points integer := 10;
  v_total integer;
begin
  if v_user is null or not public.is_active_user() then raise exception 'Bitte anmelden. Gesperrte Konten sind ausgeschlossen.'; end if;
  if exists(select 1 from public.daily_bonus_claims where user_id=v_user and claim_date=v_today) then
    raise exception 'Der Tagesbonus wurde heute bereits abgeholt.';
  end if;
  select coalesce(streak,0)+1 into v_streak from public.daily_bonus_claims
   where user_id=v_user and claim_date=v_today-1;
  v_streak := coalesce(v_streak,1);
  if v_streak >= 7 then v_points := 25; end if;
  insert into public.daily_bonus_claims(user_id,claim_date,points,streak) values(v_user,v_today,v_points,v_streak);
  insert into public.reward_points(user_id,points) values(v_user,v_points)
    on conflict(user_id) do update set points=public.reward_points.points+excluded.points,updated_at=now();
  select points into v_total from public.reward_points where user_id=v_user;
  return query select v_points,v_total,v_streak;
end $$;
revoke all on function public.claim_daily_bonus() from public;
grant execute on function public.claim_daily_bonus() to authenticated;

create or replace function public.apply_referral_code(p_code text)
returns void language plpgsql security definer set search_path=''
as $$
declare v_referrer uuid;
begin
  if auth.uid() is null or not public.is_active_user() then raise exception 'Bitte anmelden.'; end if;
  if exists(select 1 from public.referrals where referred_id=auth.uid()) then raise exception 'Ein Einladungscode wurde bereits verwendet.'; end if;
  select id into v_referrer from public.profiles where upper(referral_code)=upper(trim(p_code));
  if v_referrer is null then raise exception 'Einladungscode nicht gefunden.'; end if;
  if v_referrer=auth.uid() then raise exception 'Du kannst deinen eigenen Code nicht verwenden.'; end if;
  insert into public.referrals(referrer_id,referred_id,referral_code) values(v_referrer,auth.uid(),upper(trim(p_code)));
end $$;
revoke all on function public.apply_referral_code(text) from public;
grant execute on function public.apply_referral_code(text) to authenticated;

create or replace function public.public_reward_leaderboard()
returns table(username text,total_cents bigint)
language sql stable security definer set search_path=''
as $$
 select coalesce(p.username,'Rewardly-Nutzer'),coalesce(sum(l.amount_cents),0)::bigint
 from public.profiles p
 join public.reward_ledger l on l.user_id=p.id
 where p.is_banned=false
 group by p.id,p.username
 order by sum(l.amount_cents) desc
 limit 10
$$;
revoke all on function public.public_reward_leaderboard() from public;
grant execute on function public.public_reward_leaderboard() to anon,authenticated;

create or replace function public.notify_ticket_reply()
returns trigger language plpgsql security definer set search_path=''
as $$
declare v_owner uuid;
begin
  select user_id into v_owner from public.tickets where id=new.ticket_id;
  if v_owner is not null and new.user_id<>v_owner then
    insert into public.notifications(user_id,title,message)
    values(v_owner,'Neue Support-Antwort','Dein Support-Ticket hat eine neue Antwort erhalten.');
  end if;
  return new;
end $$;
drop trigger if exists ticket_reply_notification on public.ticket_messages;
create trigger ticket_reply_notification after insert on public.ticket_messages
for each row execute function public.notify_ticket_reply();

create or replace function public.notify_payout_change()
returns trigger language plpgsql security definer set search_path=''
as $$
begin
 if new.status is distinct from old.status then
   insert into public.notifications(user_id,title,message)
   values(new.user_id,'Auszahlungsstatus aktualisiert','Dein Auszahlungsantrag hat jetzt den Status: '||new.status||'.');
 end if;
 return new;
end $$;
drop trigger if exists payout_status_notification on public.payout_requests;
create trigger payout_status_notification after update on public.payout_requests
for each row execute function public.notify_payout_change();

-- Realtime für Support-Antworten (Live-Aktualisierung im geöffneten Browser).
do $$
begin
  alter publication supabase_realtime add table public.ticket_messages;
exception when duplicate_object then
  null;
end $$;


-- Bonuspunkte können nur gegen tatsächlich vorfinanzierte Nutzer-Rewards eingelöst werden.
-- 100 Punkte = 10 Cent. Der Pool enthält ausschließlich bereits bestätigte und
-- für Nutzer-Rewards reservierte Beträge (der Betreiberanteil wurde vorher abgezogen).
create table if not exists public.bonus_funding_pool (
  id boolean primary key default true check (id = true),
  available_user_cents integer not null default 0 check (available_user_cents >= 0),
  updated_at timestamptz not null default now()
);
insert into public.bonus_funding_pool(id,available_user_cents)
values(true,0) on conflict(id) do nothing;
alter table public.bonus_funding_pool enable row level security;
drop policy if exists "Admins manage bonus funding pool" on public.bonus_funding_pool;
create policy "Admins manage bonus funding pool" on public.bonus_funding_pool
  for update to authenticated using ((select public.is_admin()))
  with check ((select public.is_admin()));
grant update (available_user_cents,updated_at) on public.bonus_funding_pool to authenticated;

create or replace function public.redeem_bonus_points(p_points integer)
returns table(points_left integer, credited_cents integer, funding_left_cents integer)
language plpgsql security definer set search_path=''
as $$
declare
  v_user uuid := auth.uid();
  v_points integer;
  v_credit integer;
  v_fund integer;
begin
  if v_user is null or not public.is_active_user() then raise exception 'Bitte anmelden. Gesperrte Konten sind ausgeschlossen.'; end if;
  if p_points is null or p_points < 100 or p_points % 100 <> 0 then
    raise exception 'Mindestens 100 Punkte und nur Schritte von 100 Punkten sind möglich.';
  end if;
  v_credit := (p_points / 100) * 10;
  select points into v_points from public.reward_points where user_id=v_user for update;
  if coalesce(v_points,0) < p_points then raise exception 'Du hast nicht genügend Punkte.'; end if;
  select available_user_cents into v_fund from public.bonus_funding_pool where id=true for update;
  if coalesce(v_fund,0) < v_credit then
    raise exception 'Noch nicht genug bestätigte Partner-Einnahmen für die Umwandlung. Deine Punkte bleiben erhalten.';
  end if;
  update public.reward_points set points=points-p_points,updated_at=now() where user_id=v_user returning points into v_points;
  update public.bonus_funding_pool set available_user_cents=available_user_cents-v_credit,updated_at=now()
    where id=true returning available_user_cents into v_fund;
  insert into public.reward_ledger(user_id,amount_cents,entry_type,description)
    values(v_user,v_credit,'reward','Umwandlung von Bonuspunkten ('||p_points||' Punkte)');
  return query select v_points,v_credit,v_fund;
end $$;
revoke all on function public.redeem_bonus_points(integer) from public;
grant execute on function public.redeem_bonus_points(integer) to authenticated;
