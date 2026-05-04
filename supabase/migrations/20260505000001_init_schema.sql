-- ===== USERS =====
create table if not exists public.users (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  email text unique not null,
  pass text not null,
  phone text default '',
  join_date text default '',
  created_at timestamptz default now()
);
alter table public.users enable row level security;
create policy "users_all" on public.users for all to anon using (true) with check (true);

-- ===== BOOKINGS =====
create table if not exists public.bookings (
  id bigint primary key,
  email text not null,
  name text default '',
  service text not null,
  date text not null,
  slot text not null,
  msg text default '',
  status text default 'pending',
  payment text default 'unpaid',
  trx_id text default '',
  trx_amt text default '',
  pay_method text default '',
  created_at timestamptz default now()
);
alter table public.bookings enable row level security;
create policy "bookings_all" on public.bookings for all to anon using (true) with check (true);

-- ===== VIDEOS =====
create table if not exists public.videos (
  id serial primary key,
  title text not null,
  url text not null,
  description text default '',
  access text default 'public',
  created_at timestamptz default now()
);
alter table public.videos enable row level security;
create policy "videos_all" on public.videos for all to anon using (true) with check (true);

-- ===== CHATS =====
create table if not exists public.chats (
  id serial primary key,
  user_email text not null,
  from_role text not null,
  message text not null,
  time text default '',
  created_at timestamptz default now()
);
alter table public.chats enable row level security;
create policy "chats_all" on public.chats for all to anon using (true) with check (true);

-- ===== REVIEWS =====
create table if not exists public.reviews (
  id bigint primary key,
  email text not null,
  name text not null,
  stars int not null,
  text text not null,
  date text default '',
  approved boolean default false,
  created_at timestamptz default now()
);
alter table public.reviews enable row level security;
create policy "reviews_all" on public.reviews for all to anon using (true) with check (true);

-- ===== SETTINGS =====
create table if not exists public.settings (
  id int primary key default 1,
  status text default 'available',
  title text default '',
  announcement text default ''
);
alter table public.settings enable row level security;
create policy "settings_all" on public.settings for all to anon using (true) with check (true);
insert into public.settings (id, status, title, announcement) values (1, 'available', '', '') on conflict (id) do nothing;

-- ===== ADMIN SETTINGS =====
create table if not exists public.admin_settings (
  key text primary key,
  value text not null
);
alter table public.admin_settings enable row level security;
create policy "admin_settings_all" on public.admin_settings for all to anon using (true) with check (true);
