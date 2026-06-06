const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuid } = require('uuid');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'ausgg_demo_jwt_change_me';
const ADMIN_KEY = process.env.ADMIN_KEY || 'demo_master_key_change_me';
const DB_PATH = path.join(__dirname, 'data', 'db.json');
const loginHits = new Map();
const sessions = new Map();

app.use(cors({ origin: '*', allowedHeaders: ['Content-Type','Authorization','x-admin-key'] }));
app.use(express.json({ limit: '15mb' }));
app.use(express.static(path.join(__dirname, 'public')));

function db(){ return JSON.parse(fs.readFileSync(DB_PATH,'utf8')); }
function save(x){ fs.writeFileSync(DB_PATH, JSON.stringify(x,null,2)); return x; }
function money(n){ return Math.round((Number(n)||0)*100)/100; }
function pid(){ return Math.random().toString(36).toUpperCase().replace(/[^A-Z0-9]/g,'').slice(0,8).padEnd(8,'X'); }
function safeUser(u){ const {password, resetCode, ...s}=u; return s; }
function audit(action, actor='system', meta={}){ const d=db(); d.audit=d.audit||[]; d.audit.unshift({id:uuid(), action, actor, meta, at:new Date().toISOString()}); save(d); }
function addNotification(userId, title, body, type='info'){ const d=db(); d.notifications=d.notifications||[]; d.notifications.unshift({id:uuid(), userId, title, body, type, read:false, at:new Date().toISOString()}); save(d); }
function auth(req,res,next){ try{ const h=req.headers.authorization||''; req.user=jwt.verify(h.replace('Bearer ',''),JWT_SECRET); next(); }catch(e){ res.status(401).json({error:'Login required'}); } }
function admin(req,res,next){ if((req.headers['x-admin-key']||'')!==ADMIN_KEY) return res.status(403).json({error:'Admin only'}); next(); }
function rateLimit(key){ const now=Date.now(); const arr=(loginHits.get(key)||[]).filter(t=>now-t<60000); arr.push(now); loginHits.set(key,arr); return arr.length<=8; }
function vip(total=0){ if(total>=50000) return 'Platinum'; if(total>=15000) return 'Gold'; if(total>=3000) return 'Silver'; return 'Bronze'; }

app.get('/', (req,res)=>res.json({status:'online', server:'AUSGG everything build', time:new Date()}));
app.get('/api/config', (req,res)=>{ const d=db(); res.json({siteConfig:d.siteConfig, depositSettings:d.depositSettings, withdrawalFields:d.withdrawalFields, games:d.games.filter(g=>g.enabled!==false), promos:d.promos}); });

app.post('/api/auth/register', async (req,res)=>{
  const {username,email,password,firstName,lastName,phone,bankInfo,referralCode}=req.body;
  if(!username||!email||!password) return res.status(400).json({error:'Missing username, email, or password'});
  const clean=(phone||'').replace(/[^0-9]/g,'');
  if(phone && !/^(04\d{8}|614\d{8})$/.test(clean)) return res.status(400).json({error:'Australian phone must start with 04'});
  const d=db(); if(d.users.find(u=>u.email===email||u.username===username)) return res.status(409).json({error:'User already exists'});
  const refBy=d.users.find(u=>u.referralCode===referralCode);
  const u={id:uuid(), playerId:pid(), username,email, password:await bcrypt.hash(password,10), firstName:firstName||'', lastName:lastName||'', phone:phone||'', bankInfo:bankInfo||{}, balance:1000, totalWagered:0,totalWon:0,totalLost:0,totalDeposited:0,totalWithdrawn:0, vip:'Bronze', achievements:['Welcome'], referralCode:pid(), referredBy:refBy?.id||null, emailVerified:true, banned:false, createdAt:new Date().toISOString(), lastLogin:null, lastDailyBonus:null};
  d.users.push(u); if(refBy){ refBy.balance=money(refBy.balance+25); addNotification(refBy.id,'Referral bonus','A new player used your referral. +$25 demo credit','bonus'); }
  save(d); audit('user_registered', u.username); const token=jwt.sign({id:u.id},JWT_SECRET,{expiresIn:'7d'}); res.json({token,user:safeUser(u)});
});
app.post('/api/auth/login', async (req,res)=>{
  const ip=req.ip||'local'; if(!rateLimit('user:'+ip)) return res.status(429).json({error:'Too many login attempts'});
  const {identifier,password}=req.body; const d=db(); const u=d.users.find(x=>x.email===identifier||x.username===identifier||x.playerId===identifier);
  if(!u||u.banned||!(await bcrypt.compare(password,u.password))) return res.status(401).json({error:'Invalid credentials'});
  u.lastLogin=new Date().toISOString(); u.ip=ip; save(d); sessions.set(u.id,{username:u.username, at:new Date().toISOString(), ip}); const token=jwt.sign({id:u.id},JWT_SECRET,{expiresIn:'7d'}); res.json({token,user:safeUser(u)});
});
app.post('/api/auth/forgot', (req,res)=>{ const d=db(); const u=d.users.find(x=>x.email===req.body.email); if(u){ u.resetCode=String(Math.floor(100000+Math.random()*900000)); save(d); console.log('Reset code:', u.email, u.resetCode); } res.json({message:'If email exists, reset code was generated.'}); });
app.post('/api/auth/reset', async (req,res)=>{ const d=db(); const u=d.users.find(x=>x.email===req.body.email && x.resetCode===req.body.code); if(!u) return res.status(400).json({error:'Invalid reset code'}); u.password=await bcrypt.hash(req.body.password,10); delete u.resetCode; save(d); res.json({success:true}); });

app.get('/api/me', auth, (req,res)=>{ const d=db(); const u=d.users.find(x=>x.id===req.user.id); res.json({user:safeUser(u), vip:vip(u.totalWagered)}); });
app.put('/api/me', auth, (req,res)=>{ const d=db(); const u=d.users.find(x=>x.id===req.user.id); Object.assign(u, req.body); save(d); res.json({user:safeUser(u)}); });
app.get('/api/balance', auth, (req,res)=>{ const u=db().users.find(x=>x.id===req.user.id); res.json({balance:u?.balance||0}); });
app.post('/api/daily-bonus', auth, (req,res)=>{ const d=db(); const u=d.users.find(x=>x.id===req.user.id); const today=new Date().toISOString().slice(0,10); if(u.lastDailyBonus===today) return res.status(400).json({error:'Already claimed today'}); u.lastDailyBonus=today; u.balance=money(u.balance+50); save(d); addNotification(u.id,'Daily bonus','+$50 demo credit claimed','bonus'); res.json({success:true,balance:u.balance}); });
app.post('/api/redeem', auth, (req,res)=>{ const d=db(); const u=d.users.find(x=>x.id===req.user.id); const p=d.promos.find(x=>x.code?.toLowerCase()===String(req.body.code).toLowerCase()&&x.active); if(!p) return res.status(404).json({error:'Invalid promo'}); u.balance=money(u.balance+(p.bonus||0)); save(d); res.json({success:true,balance:u.balance}); });

app.get('/api/games', (req,res)=>res.json({games:db().games.filter(g=>g.enabled!==false)}));
app.post('/api/play/:game', auth, (req,res)=>{ const d=db(); const u=d.users.find(x=>x.id===req.user.id); const bet=money(req.body.bet||1); if(bet<=0||bet>u.balance) return res.status(400).json({error:'Invalid bet'}); const game=req.params.game; const roll=Math.random(); let mult=0, detail='';
  if(game==='dice'){ const target=Number(req.body.target||50); const n=Math.floor(Math.random()*100)+1; const win=n<target; mult=win?money(98/target):0; detail=`Rolled ${n}`; }
  else if(game==='coinflip'){ const side=req.body.side||'heads'; const result=Math.random()<.5?'heads':'tails'; mult=result===side?1.96:0; detail=`${result}`; }
  else if(game==='slots'){ const symbols=['🍒','🍋','🔔','💎','7️⃣']; const r=[0,1,2].map(()=>symbols[Math.floor(Math.random()*symbols.length)]); mult=(r[0]===r[1]&&r[1]===r[2])?10:(r[0]===r[1]||r[1]===r[2]?2:0); detail=r.join(' '); }
  else if(game==='blackjack'){ const player=16+Math.floor(Math.random()*7), dealer=15+Math.floor(Math.random()*8); mult=(player<=21&&(dealer>21||player>dealer))?2:0; detail=`You ${player} / Dealer ${dealer}`; }
  else if(game==='roulette'){ const color=req.body.color||'red'; const result=['red','black','green'][Math.floor(Math.random()*3)]; mult=result===color?(color==='green'?14:2):0; detail=result; }
  else if(game==='crash'){ const crash=money(1+Math.random()*5); const cash=Number(req.body.cashout||2); mult=crash>=cash?cash:0; detail=`Crashed at ${crash}x`; }
  else if(game==='plinko'){ const bucket=[0,0.5,1,1.5,3,5][Math.floor(Math.random()*6)]; mult=bucket; detail=`${bucket}x bucket`; }
  else { mult=roll<.48?2:0; detail='Demo result'; }
  const payout=money(bet*mult); u.balance=money(u.balance-bet+payout); u.totalWagered=money((u.totalWagered||0)+bet); if(payout>0)u.totalWon=money((u.totalWon||0)+payout); else u.totalLost=money((u.totalLost||0)+bet); u.vip=vip(u.totalWagered); d.bets=d.bets||[]; d.bets.unshift({id:uuid(), userId:u.id, username:u.username, game, bet, payout, profit:money(payout-bet), detail, at:new Date().toISOString()}); save(d); res.json({balance:u.balance, payout, profit:money(payout-bet), detail, vip:u.vip}); });
app.get('/api/bets', auth, (req,res)=>{ const d=db(); res.json({bets:(d.bets||[]).filter(b=>b.userId===req.user.id).slice(0,100)}); });
app.get('/api/leaderboard', (req,res)=>{ const users=db().users.map(u=>({username:u.username, playerId:u.playerId, totalWon:u.totalWon||0, totalWagered:u.totalWagered||0, vip:vip(u.totalWagered)})).sort((a,b)=>b.totalWon-a.totalWon).slice(0,20); res.json({users}); });

app.post('/api/wallet/request', auth, (req,res)=>{ const d=db(); const u=d.users.find(x=>x.id===req.user.id); const r={id:'REQ-'+Date.now(), userId:u.id, username:u.username, playerId:u.playerId, kind:req.body.kind, method:req.body.method||'bank', amount:money(req.body.amount), receipt:req.body.receipt||'', formData:req.body.formData||{}, status:'pending', note:'', timeline:[{status:'pending', at:new Date().toISOString(), note:'Request submitted'}], at:new Date().toISOString()}; d.walletRequests.unshift(r); save(d); audit('wallet_request_created',u.username,{id:r.id,kind:r.kind}); res.json({success:true,request:r}); });
app.get('/api/my-requests', auth, (req,res)=>{ const d=db(); res.json({walletRequests:d.walletRequests.filter(r=>r.userId===req.user.id), supportRequests:d.supportRequests.filter(r=>r.userId===req.user.id)}); });

app.get('/api/chat', auth, (req,res)=>{ const d=db(); res.json({messages:(d.chats||[]).filter(m=>m.userId===req.user.id).slice(-100)}); });
app.post('/api/chat', auth, (req,res)=>{ const d=db(); const u=d.users.find(x=>x.id===req.user.id); d.chats=d.chats||[]; d.chats.push({id:uuid(),userId:u.id,username:u.username,from:'user',text:req.body.text||'',image:req.body.image||'',at:new Date().toISOString()}); save(d); res.json({success:true}); });
app.post('/api/support/request', auth, (req,res)=>{ const d=db(); const u=d.users.find(x=>x.id===req.user.id); const r={id:'SUP-'+Date.now(), userId:u.id, username:u.username, category:req.body.category||'General', subject:req.body.subject||'Support request', fields:req.body.fields||{}, status:'pending', note:'', timeline:[{status:'pending',note:'Submitted',at:new Date().toISOString()}], at:new Date().toISOString()}; d.supportRequests.unshift(r); save(d); res.json({success:true,request:r}); });
app.get('/api/notifications', auth, (req,res)=>{ const d=db(); res.json({notifications:(d.notifications||[]).filter(n=>!n.userId||n.userId===req.user.id).slice(0,50)}); });

app.post('/api/admin/auth/login',(req,res)=>{ const ip=req.ip||'admin'; if(!rateLimit('admin:'+ip)) return res.status(429).json({error:'Too many admin attempts'}); if(req.body.masterKey!==ADMIN_KEY) return res.status(403).json({error:'Wrong admin key'}); audit('admin_login','master',{ip}); res.json({success:true,adminKey:ADMIN_KEY,role:'master',permissions:['all']}); });
app.get('/api/admin/stats', admin, (req,res)=>{ const d=db(); res.json({users:d.users.length,balance:d.users.reduce((s,u)=>s+(u.balance||0),0),walletPending:d.walletRequests.filter(r=>['pending','processing'].includes(r.status)).length,supportPending:d.supportRequests.filter(r=>['pending','processing'].includes(r.status)).length,bets:(d.bets||[]).length,online:sessions.size}); });
app.get('/api/admin/users', admin, (req,res)=>res.json({users:db().users.map(safeUser)}));
app.put('/api/admin/users/:id', admin, (req,res)=>{ const d=db(); const u=d.users.find(x=>x.id===req.params.id); if(!u)return res.status(404).json({error:'No user'}); Object.assign(u,req.body); save(d); audit('admin_edit_user','master',{id:u.id}); res.json({user:safeUser(u)}); });
app.post('/api/admin/users', admin, async (req,res)=>{ const d=db(); const u={id:uuid(),playerId:req.body.playerId||pid(),username:req.body.username||req.body.name,email:req.body.email,password:await bcrypt.hash(req.body.password||'123456',10),balance:money(req.body.balance||1000),createdAt:new Date().toISOString(),vip:'Bronze',achievements:['Created by admin']}; d.users.push(u); save(d); res.json({user:safeUser(u)}); });
app.get('/api/admin/export/users.csv', admin, (req,res)=>{ const rows=['username,email,playerId,balance,totalWagered,vip']; db().users.forEach(u=>rows.push([u.username,u.email,u.playerId,u.balance,u.totalWagered||0,vip(u.totalWagered)].join(','))); res.type('text/csv').send(rows.join('\n')); });
app.get('/api/admin/report', admin, (req,res)=>{ const d=db(); const wager=(d.bets||[]).reduce((s,b)=>s+b.bet,0), payout=(d.bets||[]).reduce((s,b)=>s+b.payout,0); res.json({wager:money(wager),payout:money(payout),profit:money(wager-payout),deposits:d.walletRequests.filter(r=>r.kind==='deposit').length,withdrawals:d.walletRequests.filter(r=>r.kind==='withdraw').length}); });
app.get('/api/admin/wallet-requests', admin, (req,res)=>res.json({requests:db().walletRequests}));
app.put('/api/admin/wallet-requests/:id', admin, (req,res)=>{ const d=db(); const r=d.walletRequests.find(x=>x.id===req.params.id); if(!r)return res.status(404).json({error:'No request'}); r.status=req.body.status||r.status; r.note=req.body.note||r.note||''; r.timeline=r.timeline||[]; r.timeline.push({status:r.status,note:r.note,at:new Date().toISOString()}); const u=d.users.find(x=>x.id===r.userId); if(u && req.body.status==='approved' && r.kind==='deposit'){ u.balance=money(u.balance+r.amount); u.totalDeposited=money((u.totalDeposited||0)+r.amount); }
 if(u && req.body.status==='approved' && r.kind==='withdraw'){ u.balance=money(u.balance-r.amount); u.totalWithdrawn=money((u.totalWithdrawn||0)+r.amount); }
 save(d); addNotification(r.userId,`Request ${r.status}`,r.note||`${r.kind} request is ${r.status}`,'wallet'); audit('wallet_request_update','master',{id:r.id,status:r.status}); res.json({request:r}); });
app.get('/api/admin/support-requests', admin, (req,res)=>res.json({requests:db().supportRequests}));
app.put('/api/admin/support-requests/:id', admin, (req,res)=>{ const d=db(); const r=d.supportRequests.find(x=>x.id===req.params.id); if(!r)return res.status(404).json({error:'No request'}); r.status=req.body.status||r.status; r.note=req.body.note||r.note||''; r.timeline.push({status:r.status,note:r.note,at:new Date().toISOString()}); save(d); addNotification(r.userId,`Support ${r.status}`,r.note||`Your support request is ${r.status}`,'support'); res.json({request:r}); });
app.get('/api/admin/chat', admin, (req,res)=>res.json({messages:db().chats||[]}));
app.post('/api/admin/chat', admin, (req,res)=>{ const d=db(); d.chats.push({id:uuid(),userId:req.body.userId,from:'admin',text:req.body.text||'',formTemplate:req.body.formTemplate||null,at:new Date().toISOString()}); save(d); res.json({success:true}); });
app.get('/api/admin/games', admin, (req,res)=>res.json({games:db().games}));
app.post('/api/admin/games', admin, (req,res)=>{ const d=db(); const g={id:req.body.id||uuid(), name:req.body.name||'New Game', category:req.body.category||'Egame', icon:req.body.icon||'🎮', type:req.body.type||'url', playUrl:req.body.playUrl||'', enabled:req.body.enabled!==false, rtp:Number(req.body.rtp||96)}; d.games.unshift(g); save(d); audit('game_added','master',{name:g.name}); res.json({game:g}); });
app.put('/api/admin/games/:id', admin, (req,res)=>{ const d=db(); const g=d.games.find(x=>x.id===req.params.id); if(!g)return res.status(404).json({error:'No game'}); Object.assign(g,req.body); save(d); res.json({game:g}); });
app.delete('/api/admin/games/:id', admin, (req,res)=>{ const d=db(); d.games=d.games.filter(x=>x.id!==req.params.id); save(d); res.json({success:true}); });
app.get('/api/admin/settings', admin, (req,res)=>{ const d=db(); res.json({siteConfig:d.siteConfig,depositSettings:d.depositSettings,withdrawalFields:d.withdrawalFields,promos:d.promos,adminSettings:d.adminSettings}); });
app.put('/api/admin/settings', admin, (req,res)=>{ const d=db(); ['siteConfig','depositSettings','withdrawalFields','promos','adminSettings'].forEach(k=>{ if(req.body[k]!==undefined)d[k]=req.body[k]; }); save(d); audit('settings_updated','master'); res.json({success:true}); });
app.post('/api/admin/bulk-message', admin, (req,res)=>{ const d=db(); d.users.forEach(u=>d.notifications.unshift({id:uuid(),userId:u.id,title:req.body.title||'AUSGG',body:req.body.body||'',type:'message',read:false,at:new Date().toISOString()})); save(d); res.json({success:true}); });
app.get('/api/admin/audit', admin, (req,res)=>res.json({audit:db().audit||[]}));
app.get('/api/admin/sessions', admin, (req,res)=>res.json({sessions:[...sessions.values()]}));

app.use((req,res)=>res.status(404).json({error:'Not found'}));
app.listen(PORT,()=>console.log(`AUSGG everything build running on ${PORT}`));
