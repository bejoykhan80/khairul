-- ===== PROJECTS =====
create table if not exists public.projects (
  id serial primary key,
  title text not null,
  category text default '',
  description text default '',
  full_desc text default '',
  tech text default '',
  icon text default '🔍',
  color text default 'a',
  video_url text default '',
  doc_url text default '',
  doc_name text default '',
  link text default '',
  created_at timestamptz default now()
);
alter table public.projects enable row level security;
create policy "projects_all" on public.projects for all to anon using (true) with check (true);

-- Seed default projects
insert into public.projects (title, category, description, full_desc, tech, icon, color, video_url, doc_url, doc_name, link) values
('E-Commerce Security Audit','Pen Test','১২টি critical vulnerability পাওয়া ও ঠিক করা হয়েছে।','বাংলাদেশের একটি বড় e-commerce platform-এর full security audit পরিচালনা করা হয়েছে। OWASP Top 10 methodology অনুসরণ করে ১২টি critical vulnerability পাওয়া গেছে — SQL Injection, XSS, IDOR এবং broken authentication সহ। সব vulnerability responsible disclosure-এর মাধ্যমে report করা হয়েছে এবং ঠিক করার পরামর্শ দেওয়া হয়েছে।','Burp Suite · Nmap · Metasploit · OWASP ZAP','🔍','a','','','',''),
('Corporate Dashboard','Web App','Fortune 500 কোম্পানির নিরাপদ analytics platform।','একটি multinational কোম্পানির জন্য secure analytics dashboard তৈরি করা হয়েছে। Role-based access control, end-to-end encryption এবং real-time monitoring সহ। Deployment-এর আগে সম্পূর্ণ VAPT করা হয়েছে। Zero critical vulnerability নিশ্চিত করা হয়েছে।','React · Node.js · PostgreSQL · Docker','🌐','b','','','',''),
('National CTF 2025','CTF','জাতীয় CTF competition-এ ১ম স্থান অর্জন।','Bangladesh National Cybersecurity CTF 2025-এ প্রথম স্থান অর্জন করা হয়েছে। Web exploitation, cryptography, reverse engineering এবং forensics categories-এ সব challenges সফলভাবে solve করা হয়েছে। মোট ৪৮ ঘণ্টার competition-এ ১২০+ টিমের মধ্যে প্রথম।','Python · GDB · Ghidra · Wireshark · CyberChef','🏆','c','','','',''),
('Bug Bounty Findings','Bug Bounty','Bugcrowd-এ critical ও high severity bugs রিপোর্ট।','Bugcrowd platform-এ বিভিন্ন কোম্পানির programs-এ অংশ নিয়ে multiple critical ও high severity vulnerabilities report করা হয়েছে। P1 ও P2 level findings-এ SSRF, Authentication Bypass এবং Information Disclosure ছিল।','Burp Suite · Maltego · Shodan · Subfinder','📊','d','','','','https://bugcrowd.com/h/khairulislam5b75f040-4d84-4921-bd5a-8fdfbbb59ba7')
on conflict do nothing;

-- ===== STORAGE BUCKET =====
insert into storage.buckets (id, name, public) values ('project-files', 'project-files', true) on conflict do nothing;
create policy "project_files_all" on storage.objects for all to anon using (bucket_id = 'project-files') with check (bucket_id = 'project-files');
