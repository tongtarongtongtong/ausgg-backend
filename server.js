const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'ausgg_demo_jwt_change_me';
const ADMIN_KEY = process.env.ADMIN_KEY || 'demo_master_key_change_me';
const DB_PATH = path.join(__dirname, 'data', 'db.json');

app.use(cors({ origin: '*', methods: ['GET','POST','PUT','DELETE','OPTIONS'], allowedHeaders: ['Content-Type','Authorization','x-admin-key'] }));
app.use(express.json({ limit: '15mb' }));
app.use(express.static(path.join(__dirname, 'public')));

const DEFAULT_DB = {
  users: [], admins: [], transactions: [], depositRequests: [], withdrawalRequests: [],
  supportChats: [], supportRequests: [], games: [], siteConfig: {}, depositSettings: {}, withdrawSettings: {}, announcements: [], notifications: [], adminLogs: []
};
function readDB(){
  try{
    if(!fs.existsSync(DB_PATH)){ fs.mkdirSync(path.dirname(DB_PATH), {recursive:true}); fs.writeFileSync(DB_PATH, JSON.stringify(DEFAULT_DB,null,2)); }
    return { ...DEFAULT_DB, ...JSON.parse(fs.readFileSync(DB_PATH,'utf8')) };
  }catch(e){ return {...DEFAULT_DB}; }
}
function writeDB(db){ fs.writeFileSync(DB_PATH, JSON.stringify(db,null,2)); }
function safeUser(user){ const {password, ...safe} = user; return safe; }
function money(n){ return Math.round((Number(n)||0)*100)/100; }
function tokenFor(user){ return jwt.sign({ userId:user.id }, JWT_SECRET, { expiresIn:'7d' }); }
function auth(req,res,next){
  const h = req.headers.authorization || '';
  try { req.userId = jwt.verify(h.replace('Bearer ',''), JWT_SECRET).userId; next(); }
  catch(e){ res.status(401).json({error:'Please log in'}); }
}
function adminAuth(req,res,next){
  if(req.headers['x-admin-key'] === ADMIN_KEY){ req.admin = {role:'master'}; return next(); }
  res.status(403).json({error:'Admin access denied'});
}
function logAdmin(db, action, detail=''){
  db.adminLogs.unshift({ id:'LOG-'+Date.now(), action, detail, at:new Date().toISOString() });
  db.adminLogs = db.adminLogs.slice(0,300);
}
function notify(db, type, text){
  db.notifications.unshift({ id:'N-'+Date.now(), type, text, read:false, at:new Date().toISOString() });
  db.notifications = db.notifications.slice(0,200);
}
function findUser(db, id){ return db.users.find(u => u.id === id); }

app.get('/', (req,res)=>res.json({status:'online', server:'AUSGG clean demo', time:new Date().toISOString()}));
app.get('/api/config', (req,res)=>{ const db=readDB(); res.json({siteConfig:db.siteConfig, categories:['Slot','Casino','Sport','Egame']}); });
app.get('/api/site-config', (req,res)=>{ const db=readDB(); res.json(db.siteConfig); });

app.post('/api/auth/register', async (req,res)=>{
  const {username,email,password} = req.body;
  if(!username || !email || !password) return res.status(400).json({error:'Username, email and password required'});
  if(password.length < 6) return res.status(400).json({error:'Password must be at least 6 characters'});
  const db=readDB();
  if(db.users.some(u=>u.username===username || u.email===email)) return res.status(409).json({error:'Username or email already exists'});
  const user = { id:uuidv4(), playerId:'AUS'+Math.floor(100000+Math.random()*900000), username, email, password:await bcrypt.hash(password,10), balance:1000, banned:false, createdAt:new Date().toISOString() };
  db.users.push(user); writeDB(db);
  res.json({token:tokenFor(user), user:safeUser(user)});
});
app.post('/api/auth/login', async (req,res)=>{
  const {identifier,password} = req.body;
  const db=readDB(); const user=db.users.find(u=>u.username===identifier || u.email===identifier || u.playerId===identifier);
  if(!user || !(await bcrypt.compare(password, user.password))) return res.status(401).json({error:'Invalid login'});
  if(user.banned) return res.status(403).json({error:'Account banned'});
  res.json({token:tokenFor(user), user:safeUser(user)});
});
app.get('/api/user/profile', auth, (req,res)=>{ const db=readDB(); const user=findUser(db, req.userId); if(!user) return res.status(404).json({error:'User not found'}); res.json(safeUser(user)); });
app.get('/api/user/balance', auth, (req,res)=>{ const db=readDB(); const user=findUser(db, req.userId); if(!user) return res.status(404).json({error:'User not found'}); res.json({balance:user.balance}); });

app.get('/api/games', (req,res)=>{ const db=readDB(); res.json({games:(db.games||[]).filter(g=>g.enabled!==false)}); });

app.post('/api/wallet/deposit-request', auth, (req,res)=>{
  const {amount,method,note,receipt} = req.body; const amt=money(amount); const db=readDB(); const user=findUser(db, req.userId);
  if(!user) return res.status(404).json({error:'User not found'});
  if(amt < (db.depositSettings.minAmount||10)) return res.status(400).json({error:'Amount too low'});
  const r={id:'DEP-'+Date.now(), type:'deposit', userId:user.id, playerId:user.playerId, username:user.username, amount:amt, method:method||'Demo Bank', note:note||'', receipt:receipt||'', status:'pending', adminNote:'', createdAt:new Date().toISOString()};
  db.depositRequests.unshift(r); notify(db,'deposit',`New deposit request from ${user.username}: $${amt}`); writeDB(db); res.json({success:true, request:r});
});
app.post('/api/wallet/withdraw', auth, (req,res)=>{
  const {amount,method,formData,note} = req.body; const amt=money(amount); const db=readDB(); const user=findUser(db, req.userId);
  if(!user) return res.status(404).json({error:'User not found'});
  if(amt < (db.withdrawSettings.minAmount||10)) return res.status(400).json({error:'Amount too low'});
  if(amt > user.balance) return res.status(400).json({error:'Insufficient balance'});
  const r={id:'WD-'+Date.now(), type:'withdrawal', userId:user.id, playerId:user.playerId, username:user.username, amount:amt, method:method||'Manual Review', formData:formData||{}, note:note||'', status:'pending', adminNote:'', createdAt:new Date().toISOString()};
  db.withdrawalRequests.unshift(r); notify(db,'withdrawal',`New withdrawal request from ${user.username}: $${amt}`); writeDB(db); res.json({success:true, request:r});
});
app.get('/api/wallet/transactions', auth, (req,res)=>{ const db=readDB(); res.json({transactions:db.transactions.filter(t=>t.userId===req.userId)}); });
app.get('/api/wallet/pending', auth, (req,res)=>{ const db=readDB(); res.json({deposits:db.depositRequests.filter(r=>r.userId===req.userId), withdrawals:db.withdrawalRequests.filter(r=>r.userId===req.userId), support:db.supportRequests.filter(r=>r.userId===req.userId)}); });

app.get('/api/support/chat', auth, (req,res)=>{ const db=readDB(); res.json({messages:db.supportChats.filter(m=>m.userId===req.userId)}); });
app.post('/api/support/chat', auth, (req,res)=>{ const db=readDB(); const user=findUser(db, req.userId); const msg={id:'MSG-'+Date.now(), userId:user.id, username:user.username, from:'user', message:req.body.message||'', at:new Date().toISOString()}; db.supportChats.push(msg); notify(db,'chat',`New chat from ${user.username}`); writeDB(db); res.json({success:true,message:msg}); });
app.post('/api/support/request', auth, (req,res)=>{ const db=readDB(); const user=findUser(db, req.userId); const r={id:'REQ-'+Date.now(), userId:user.id, username:user.username, category:req.body.category||'General', subject:req.body.subject||'Support request', message:req.body.message||'', fields:req.body.fields||{}, status:'pending', adminNote:'', createdAt:new Date().toISOString()}; db.supportRequests.unshift(r); notify(db,'request',`New support request from ${user.username}`); writeDB(db); res.json({success:true,request:r}); });

app.post('/api/admin/auth/login', (req,res)=>{
  const {masterKey,username,password}=req.body;
  if(masterKey && masterKey===ADMIN_KEY) return res.json({success:true,role:'master',permissions:['all'],adminKey:ADMIN_KEY});
  const db=readDB(); const staff=(db.admins||[]).find(a=>a.username===username && a.password===password && a.active!==false);
  if(!staff) return res.status(403).json({error:'Invalid admin login'});
  res.json({success:true,role:staff.role||'staff',permissions:staff.permissions||[],adminKey:ADMIN_KEY,admin:{id:staff.id,username:staff.username,role:staff.role||'staff'}});
});
app.get('/api/admin/dashboard', adminAuth, (req,res)=>{ const db=readDB(); res.json({users:db.users.length, pendingDeposits:db.depositRequests.filter(r=>r.status==='pending').length, pendingWithdrawals:db.withdrawalRequests.filter(r=>r.status==='pending').length, pendingSupport:db.supportRequests.filter(r=>r.status!=='completed').length, games:db.games.length, notifications:db.notifications.filter(n=>!n.read).length}); });
app.get('/api/admin/users', adminAuth, (req,res)=>{ const db=readDB(); res.json({users:db.users.map(safeUser)}); });
app.post('/api/admin/users', adminAuth, async (req,res)=>{ const db=readDB(); const u={id:uuidv4(),playerId:req.body.playerId||'AUS'+Date.now().toString().slice(-6),username:req.body.username||req.body.name||'user'+Date.now(),email:req.body.email||'',password:await bcrypt.hash(req.body.password||'123456',10),balance:money(req.body.balance||1000),banned:false,createdAt:new Date().toISOString()}; db.users.push(u); logAdmin(db,'add_user',u.username); writeDB(db); res.json({success:true,user:safeUser(u)}); });
app.post('/api/admin/users/:id/balance', adminAuth, (req,res)=>{ const db=readDB(); const user=findUser(db,req.params.id); if(!user)return res.status(404).json({error:'User not found'}); user.balance=money(req.body.balance); logAdmin(db,'set_balance',`${user.username} -> ${user.balance}`); writeDB(db); res.json({success:true,user:safeUser(user)}); });

app.get('/api/admin/requests', adminAuth, (req,res)=>{ const db=readDB(); res.json({deposits:db.depositRequests, withdrawals:db.withdrawalRequests, support:db.supportRequests}); });
function updateRequest(collection, id, status, adminNote){ const db=readDB(); const r=db[collection].find(x=>x.id===id); if(!r) return null; r.status=status; if(adminNote!==undefined) r.adminNote=adminNote; r.updatedAt=new Date().toISOString(); if(status==='approved' && collection==='depositRequests'){ const u=findUser(db,r.userId); if(u){ u.balance=money(u.balance+r.amount); db.transactions.unshift({id:'TX-'+Date.now(),userId:u.id,type:'deposit',amount:r.amount,status:'completed',createdAt:new Date().toISOString()}); } } if(status==='approved' && collection==='withdrawalRequests'){ const u=findUser(db,r.userId); if(u){ u.balance=money(u.balance-r.amount); db.transactions.unshift({id:'TX-'+Date.now(),userId:u.id,type:'withdrawal',amount:r.amount,status:'completed',createdAt:new Date().toISOString()}); } } logAdmin(db,'request_update',`${id} -> ${status}`); writeDB(db); return r; }
app.post('/api/admin/deposits/:id/status', adminAuth, (req,res)=>{ const r=updateRequest('depositRequests',req.params.id,req.body.status,req.body.adminNote); if(!r)return res.status(404).json({error:'Not found'}); res.json({success:true,request:r}); });
app.post('/api/admin/withdrawals/:id/status', adminAuth, (req,res)=>{ const r=updateRequest('withdrawalRequests',req.params.id,req.body.status,req.body.adminNote); if(!r)return res.status(404).json({error:'Not found'}); res.json({success:true,request:r}); });
app.post('/api/admin/support/:id/status', adminAuth, (req,res)=>{ const r=updateRequest('supportRequests',req.params.id,req.body.status,req.body.adminNote); if(!r)return res.status(404).json({error:'Not found'}); res.json({success:true,request:r}); });
app.get('/api/admin/chats', adminAuth, (req,res)=>{ const db=readDB(); res.json({messages:db.supportChats}); });
app.post('/api/admin/chats/:userId', adminAuth, (req,res)=>{ const db=readDB(); const msg={id:'MSG-'+Date.now(),userId:req.params.userId,from:'admin',message:req.body.message||'',form:req.body.form||null,at:new Date().toISOString()}; db.supportChats.push(msg); writeDB(db); res.json({success:true,message:msg}); });

app.get('/api/admin/games', adminAuth, (req,res)=>{ const db=readDB(); res.json({games:db.games||[]}); });
app.post('/api/admin/games', adminAuth, (req,res)=>{ const db=readDB(); const g={id:req.body.id||'GAME-'+Date.now(),name:req.body.name||'Untitled Game',category:req.body.category||'Egame',thumbnail:req.body.thumbnail||'🎮',description:req.body.description||'',playUrl:req.body.playUrl||'',rtp:money(req.body.rtp||96),minBet:money(req.body.minBet||1),maxBet:money(req.body.maxBet||1000),enabled:req.body.enabled!==false,createdAt:new Date().toISOString()}; db.games.unshift(g); logAdmin(db,'add_game',g.name); writeDB(db); res.json({success:true,game:g}); });
app.put('/api/admin/games/:id', adminAuth, (req,res)=>{ const db=readDB(); const g=db.games.find(x=>x.id===req.params.id); if(!g)return res.status(404).json({error:'Game not found'}); Object.assign(g, req.body, {updatedAt:new Date().toISOString()}); writeDB(db); res.json({success:true,game:g}); });
app.delete('/api/admin/games/:id', adminAuth, (req,res)=>{ const db=readDB(); db.games=db.games.filter(g=>g.id!==req.params.id); writeDB(db); res.json({success:true}); });

app.get('/api/admin/settings', adminAuth, (req,res)=>{ const db=readDB(); res.json({siteConfig:db.siteConfig,depositSettings:db.depositSettings,withdrawSettings:db.withdrawSettings}); });
app.post('/api/admin/settings', adminAuth, (req,res)=>{ const db=readDB(); ['siteConfig','depositSettings','withdrawSettings'].forEach(k=>{ if(req.body[k]) db[k]={...db[k],...req.body[k]}; }); logAdmin(db,'settings_update'); writeDB(db); res.json({success:true}); });
app.get('/api/admin/notifications', adminAuth, (req,res)=>{ const db=readDB(); res.json({notifications:db.notifications}); });
app.post('/api/admin/notifications/read', adminAuth, (req,res)=>{ const db=readDB(); db.notifications.forEach(n=>n.read=true); writeDB(db); res.json({success:true}); });
app.get('/api/admin/logs', adminAuth, (req,res)=>{ const db=readDB(); res.json({logs:db.adminLogs}); });

app.use((req,res)=>res.status(404).json({error:'Not found'}));
app.listen(PORT, ()=>console.log(`AUSGG clean demo running on ${PORT}`));
