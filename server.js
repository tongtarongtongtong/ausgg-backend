// ═══════════════════════════════════════════════════════════
//  AUSGG CASINO — Backend v5 (Full Feature)
// ═══════════════════════════════════════════════════════════
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const nodemailer = require('nodemailer');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = 'ausgg_secret_2024';
const EMAIL_USER = process.env.EMAIL_USER || 'your_gmail@gmail.com';
const EMAIL_PASS = process.env.EMAIL_PASS || 'your_app_password';
const ADMIN_KEY = 'ausgg_admin_2024';

const transporter = nodemailer.createTransport({ service:'gmail', auth:{user:EMAIL_USER,pass:EMAIL_PASS} });
app.use(cors({ origin:'*', methods:['GET','POST','PUT','DELETE','OPTIONS'], allowedHeaders:['Content-Type','Authorization','x-admin-key'] }));
app.options('*', cors());
app.use(express.json({ limit: '10mb' })); // large for receipt uploads
app.use(express.static(path.join(__dirname,'public')));
app.use((req,res,next)=>{ console.log(`[${new Date().toLocaleTimeString()}] ${req.method} ${req.path}`); next(); });

// ── DB ──
const DB_PATH = path.join(__dirname,'data','db.json');
const DEFAULT_DB = {
  users:[], pendingUsers:[], transactions:[], bets:[],
  chats:[], bonuses:[], promoCodes:[], announcements:[],
  notifications:[], gameConfig:{}, siteConfig:{},
  depositInstructions:{}, depositRequests:[], withdrawalRequests:[],
  withdrawalFormFields:[], games:[], gameCategories:['Casino','Slots','Sports','Quickgame']
};

function readDB() {
  try {
    if (!fs.existsSync(DB_PATH)) { fs.writeFileSync(DB_PATH, JSON.stringify(DEFAULT_DB,null,2)); return {...DEFAULT_DB}; }
    const data = JSON.parse(fs.readFileSync(DB_PATH,'utf8'));
    return { ...DEFAULT_DB, ...data };
  } catch(e) { return {...DEFAULT_DB}; }
}
function writeDB(data) { fs.writeFileSync(DB_PATH, JSON.stringify(data,null,2)); return data; }

// ── Auth ──
function auth(req,res,next) {
  const h = req.headers['authorization'];
  if (!h) return res.status(401).json({error:'No token'});
  try { req.userId = jwt.verify(h.split(' ')[1], JWT_SECRET).userId; next(); }
  catch(e) { res.status(401).json({error:'Invalid token'}); }
}
function admin(req,res,next) {
  if (req.headers['x-admin-key'] !== ADMIN_KEY) return res.status(403).json({error:'Forbidden'});
  next();
}

function fmt2(n) { return parseFloat((n||0).toFixed(2)); }
function code6() { return Math.floor(100000+Math.random()*900000).toString(); }
function genPlayerId() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  const db = readDB();
  let id;
  do { id = Array.from({length:8},()=>chars[Math.floor(Math.random()*chars.length)]).join(''); }
  while (db.users.find(u=>u.playerId===id));
  return id;
}

// ══════════════════════════════════════════
//  AUTH
// ══════════════════════════════════════════
app.get('/', (req,res) => res.json({status:'online',server:'AUSGG v5',time:new Date()}));

app.post('/api/auth/register', async (req,res) => {
  const {username,email,password,firstName,lastName,phone,bankInfo} = req.body;
  if (!username||!email||!password) return res.status(400).json({error:'All fields required'});
  if (password.length<6) return res.status(400).json({error:'Password min 6 chars'});
  if (!firstName||!lastName) return res.status(400).json({error:'Full name is required'});
  if (!phone) return res.status(400).json({error:'Australian phone number is required'});
  const phoneClean = phone.replace(/[^0-9]/g,'');
  if (!/^(04\d{8}|614\d{8}|6104\d{8})$/.test(phoneClean.replace(/^\+/,''))) return res.status(400).json({error:'Invalid Australian mobile number (must start with 04)'});
  const db = readDB();
  if (db.users.find(u=>u.username===username)) return res.status(409).json({error:'Username taken'});
  if (db.users.find(u=>u.email===email)) return res.status(409).json({error:'Email already registered'});
  db.pendingUsers = (db.pendingUsers||[]).filter(u=>u.email!==email);
  const verifyCode = code6();
  const hashed = await bcrypt.hash(password,10);
  db.pendingUsers.push({username,email,password:hashed,firstName:firstName||'',lastName:lastName||'',phone:phone||'',bankInfo:bankInfo||{},code:verifyCode,expiresAt:new Date(Date.now()+10*60000).toISOString()});
  writeDB(db);
  try {
    await transporter.sendMail({from:`"AUSGG" <${EMAIL_USER}>`,to:email,subject:`${verifyCode} - AUSGG Verification`,html:`<div style="font-family:Arial;padding:30px;background:#0f1923;color:#fff;border-radius:12px"><h2 style="color:#00e701">🎰 AUSGG</h2><p>Your verification code:</p><div style="font-size:40px;font-weight:700;color:#00e701;letter-spacing:10px">${verifyCode}</div><p style="color:#888">Expires in 10 minutes</p></div>`});
    res.json({message:'Code sent!',email});
  } catch(e) {
    console.log(`⚠️ Email failed. Code for ${email}: ${verifyCode}`);
    res.json({message:'Code generated (check server console)',email,devCode:EMAIL_USER.includes('your_gmail')?verifyCode:undefined});
  }
});

app.post('/api/auth/verify', async (req,res) => {
  const {email,code} = req.body;
  const db = readDB();
  const pending = (db.pendingUsers||[]).find(u=>u.email===email);
  if (!pending) return res.status(404).json({error:'No pending registration'});
  if (new Date()>new Date(pending.expiresAt)) return res.status(410).json({error:'Code expired'});
  if (pending.code!==code?.trim()) return res.status(400).json({error:'Wrong code'});
  const cfg = db.gameConfig?.global||{};
  const playerId = genPlayerId();
  const newUser = {
    id:uuidv4(), playerId, username:pending.username, email:pending.email,
    password:pending.password, balance:fmt2(cfg.startBalance||1000),
    emailVerified:true, banned:false,
    totalDeposited:0, totalWithdrawn:0, totalBets:0, totalWon:0, totalLost:0,
    firstName:pending.firstName||'', lastName:pending.lastName||'', phone:pending.phone||'', bankInfo:pending.bankInfo||{}, notes:'', createdAt:new Date().toISOString(), lastLogin:new Date().toISOString()
  };
  db.users.push(newUser);
  db.pendingUsers = db.pendingUsers.filter(u=>u.email!==email);
  if (cfg.autoBonus&&cfg.autoBonusAmount) {
    newUser.balance = fmt2(newUser.balance+cfg.autoBonusAmount);
    db.bonuses.push({id:'BON-'+uuidv4().slice(0,8).toUpperCase(),userId:newUser.id,username:newUser.username,amount:cfg.autoBonusAmount,reason:'Welcome bonus',bonusType:'welcome',createdAt:new Date().toISOString()});
  }
  writeDB(db);
  const token = jwt.sign({userId:newUser.id},JWT_SECRET,{expiresIn:'7d'});
  const {password:_,...safe} = newUser;
  res.status(201).json({message:'Account created!',token,user:safe});
});

app.post('/api/auth/resend-code', async (req,res) => {
  const {email} = req.body;
  const db = readDB();
  const pending = (db.pendingUsers||[]).find(u=>u.email===email);
  if (!pending) return res.status(404).json({error:'No pending registration'});
  const newCode = code6();
  pending.code=newCode; pending.expiresAt=new Date(Date.now()+10*60000).toISOString();
  writeDB(db);
  try { await transporter.sendMail({from:`"AUSGG" <${EMAIL_USER}>`,to:email,subject:`${newCode} - New Code`,html:`<h2>New code: <strong>${newCode}</strong></h2>`}); res.json({message:'New code sent!'}); }
  catch(e) { console.log(`Resend: ${newCode}`); res.json({message:'Check server console',devCode:EMAIL_USER.includes('your_gmail')?newCode:undefined}); }
});

app.post('/api/auth/login', async (req,res) => {
  const {identifier,password} = req.body;
  const db = readDB();
  const user = db.users.find(u=>u.username===identifier||u.email===identifier||u.playerId===identifier);
  if (!user) return res.status(401).json({error:'Invalid credentials'});
  if (user.banned) return res.status(403).json({error:'Account banned'});
  if (!await bcrypt.compare(password,user.password)) return res.status(401).json({error:'Invalid credentials'});
  user.lastLogin=new Date().toISOString();
  writeDB(db);
  const token = jwt.sign({userId:user.id},JWT_SECRET,{expiresIn:'7d'});
  const {password:_,...safe} = user;
  res.json({message:'Login successful',token,user:safe});
});

// ══════════════════════════════════════════
//  USER
// ══════════════════════════════════════════
app.get('/api/user/profile', auth, (req,res) => {
  const db = readDB();
  const user = db.users.find(u=>u.id===req.userId);
  if (!user) return res.status(404).json({error:'Not found'});
  const {password:_,...safe} = user;
  res.json(safe);
});

app.get('/api/user/balance', auth, (req,res) => {
  const db = readDB();
  const user = db.users.find(u=>u.id===req.userId);
  if (!user) return res.status(404).json({error:'Not found'});
  res.json({balance:user.balance});
});

// ══════════════════════════════════════════
//  DEPOSIT — with receipt upload
// ══════════════════════════════════════════
app.post('/api/wallet/deposit-request', auth, (req,res) => {
  const {amount,method,receipt,note} = req.body;
  const amt = parseFloat(amount);
  if (!amt||amt<10) return res.status(400).json({error:'Min deposit $10'});
  const db = readDB();
  const user = db.users.find(u=>u.id===req.userId);
  if (!user) return res.status(404).json({error:'Not found'});
  const req_id = 'DEP-'+uuidv4().slice(0,8).toUpperCase();
  const depReq = {
    id:req_id, userId:user.id, playerId:user.playerId, username:user.username,
    amount:amt, method:method||'bank', receipt:receipt||null,
    note:note||'', status:'pending',
    createdAt:new Date().toISOString()
  };
  if (!db.depositRequests) db.depositRequests=[];
  db.depositRequests.push(depReq);
  // Notify admin (via notification log)
  if (!db.notifications) db.notifications=[];
  writeDB(db);
  console.log(`💰 Deposit request: ${user.username} $${amt} via ${method}`);
  res.json({message:'Deposit request submitted! Awaiting admin approval.',request:depReq});
});

// Old direct deposit (keep for compatibility)
app.post('/api/wallet/deposit', auth, (req,res) => {
  const {amount,method} = req.body;
  const amt = parseFloat(amount);
  if (!amt||amt<10) return res.status(400).json({error:'Min deposit $10'});
  if (amt>10000) return res.status(400).json({error:'Max $10,000'});
  const db = readDB();
  const user = db.users.find(u=>u.id===req.userId);
  if (!user) return res.status(404).json({error:'Not found'});
  user.balance=fmt2(user.balance+amt);
  user.totalDeposited=fmt2((user.totalDeposited||0)+amt);
  const tx={id:'DEP-'+uuidv4().slice(0,8).toUpperCase(),userId:user.id,username:user.username,type:'deposit',method:method||'card',amount:amt,fee:0,status:'completed',createdAt:new Date().toISOString(),balanceAfter:user.balance};
  db.transactions.push(tx);
  writeDB(db);
  res.json({message:`Deposit successful!`,transaction:tx,newBalance:user.balance});
});

app.get('/api/wallet/transactions', auth, (req,res) => {
  const db = readDB();
  const txs = (db.transactions||[]).filter(t=>t.userId===req.userId).sort((a,b)=>new Date(b.createdAt)-new Date(a.createdAt));
  res.json({transactions:txs});
});

// Customer pending requests
app.get('/api/wallet/pending', auth, (req,res) => {
  const db = readDB();
  const deps = (db.depositRequests||[]).filter(r=>r.userId===req.userId).sort((a,b)=>new Date(b.createdAt)-new Date(a.createdAt));
  const wds = (db.withdrawalRequests||[]).filter(r=>r.userId===req.userId).sort((a,b)=>new Date(b.createdAt)-new Date(a.createdAt));
  res.json({deposits:deps,withdrawals:wds});
});

// ══════════════════════════════════════════
//  WITHDRAWAL — with form fields
// ══════════════════════════════════════════
app.get('/api/wallet/withdrawal-form', auth, (req,res) => {
  const db = readDB();
  const defaultFields = [
    {id:'fullName',label:'Full Name',type:'text',placeholder:'Your full name',required:true},
    {id:'bankName',label:'Bank Name',type:'text',placeholder:'e.g. ANZ, Commonwealth',required:true},
    {id:'accountNumber',label:'Account Number',type:'text',placeholder:'123456789',required:true},
    {id:'bsb',label:'BSB / Routing',type:'text',placeholder:'062-000',required:false},
    {id:'note',label:'Note (optional)',type:'textarea',placeholder:'Any additional info',required:false},
  ];
  res.json({fields: db.withdrawalFormFields?.length ? db.withdrawalFormFields : defaultFields});
});

app.post('/api/wallet/withdraw', auth, (req,res) => {
  const {amount,method,formData} = req.body;
  const amt = parseFloat(amount);
  if (!amt||amt<10) return res.status(400).json({error:'Min withdrawal $10'});
  const db = readDB();
  const user = db.users.find(u=>u.id===req.userId);
  if (!user) return res.status(404).json({error:'Not found'});
  if (amt>user.balance) return res.status(400).json({error:'Insufficient balance'});
  const fee = fmt2(amt*0.015);
  user.balance = fmt2(user.balance-amt);
  user.totalWithdrawn = fmt2((user.totalWithdrawn||0)+amt);
  const wdReq = {
    id:'WD-'+uuidv4().slice(0,8).toUpperCase(),
    userId:user.id, playerId:user.playerId, username:user.username,
    amount:amt, fee, netAmount:fmt2(amt-fee),
    method:method||'bank', formData:formData||{},
    status:'pending', processedAt:null, approvedAt:null,
    createdAt:new Date().toISOString(), balanceAfter:user.balance
  };
  if (!db.withdrawalRequests) db.withdrawalRequests=[];
  db.withdrawalRequests.push(wdReq);
  // Also add to transactions
  db.transactions.push({...wdReq,type:'withdraw'});
  // Save bank info to user profile
  if (formData) user.bankInfo = formData;
  writeDB(db);
  console.log(`📤 Withdrawal request: ${user.username} $${amt}`);
  res.json({message:'Withdrawal submitted! Pending review.',request:wdReq,newBalance:user.balance});
});

// ══════════════════════════════════════════
//  BETS
// ══════════════════════════════════════════
app.post('/api/bets/record', auth, (req,res) => {
  const {game,betAmount,win,payout,detail} = req.body;
  const bet=parseFloat(betAmount),pay=parseFloat(payout)||0;
  const db = readDB();
  const user = db.users.find(u=>u.id===req.userId);
  if (!user) return res.status(404).json({error:'Not found'});
  user.totalBets=(user.totalBets||0)+1;
  if (win){user.totalWon=fmt2((user.totalWon||0)+pay);user.balance=fmt2(user.balance+pay-bet);}
  else{user.totalLost=fmt2((user.totalLost||0)+bet);user.balance=fmt2(user.balance-bet);}
  if(user.balance<0)user.balance=0;
  const b={id:'BET-'+uuidv4().slice(0,8).toUpperCase(),userId:user.id,playerId:user.playerId,username:user.username,game,betAmount:bet,win:!!win,payout:pay,profit:win?fmt2(pay-bet):-bet,detail:detail||'',createdAt:new Date().toISOString()};
  db.bets.push(b);
  writeDB(db);
  res.json({bet:b,newBalance:user.balance});
});

app.get('/api/bets/history', auth, (req,res) => {
  const db = readDB();
  res.json({bets:(db.bets||[]).filter(b=>b.userId===req.userId).sort((a,b)=>new Date(b.createdAt)-new Date(a.createdAt)).slice(0,200)});
});

app.get('/api/bets/stats', auth, (req,res) => {
  const db = readDB();
  const user = db.users.find(u=>u.id===req.userId);
  if (!user) return res.status(404).json({error:'Not found'});
  const bets = (db.bets||[]).filter(b=>b.userId===req.userId);
  const wins = bets.filter(b=>b.win).length;
  res.json({totalBets:bets.length,wins,losses:bets.length-wins,winRate:bets.length>0?((wins/bets.length)*100).toFixed(1)+'%':'0%',totalWagered:fmt2(bets.reduce((s,b)=>s+b.betAmount,0)),totalWon:user.totalWon||0,totalLost:user.totalLost||0,biggestWin:fmt2(bets.reduce((m,b)=>b.win&&b.profit>m?b.profit:m,0)),balance:user.balance});
});

// ══════════════════════════════════════════
//  CHAT
// ══════════════════════════════════════════
app.post('/api/chat/send', auth, (req,res) => {
  const {text} = req.body;
  if (!text?.trim()) return res.status(400).json({error:'Message required'});
  const db = readDB();
  const user = db.users.find(u=>u.id===req.userId);
  if (!user) return res.status(404).json({error:'Not found'});
  if (!db.chats) db.chats=[];
  let chat = db.chats.find(c=>c.userId===req.userId);
  if (!chat){chat={userId:req.userId,playerId:user.playerId,username:user.username,messages:[]};db.chats.push(chat);}
  chat.messages.push({from:'user',text:text.trim(),time:new Date().toISOString(),read:false});
  writeDB(db);
  console.log(`💬 ${user.username}: ${text}`);
  res.json({message:'Sent',success:true});
});

app.get('/api/chat/history', auth, (req,res) => {
  const db = readDB();
  const chat = (db.chats||[]).find(c=>c.userId===req.userId);
  res.json({messages:chat?chat.messages:[]});
});

// ══════════════════════════════════════════
//  NOTIFICATIONS
// ══════════════════════════════════════════
app.get('/api/notifications', auth, (req,res) => {
  const db = readDB();
  res.json({notifications:(db.notifications||[]).filter(n=>n.userId===req.userId&&!n.read).sort((a,b)=>new Date(b.createdAt)-new Date(a.createdAt))});
});
app.post('/api/notifications/read', auth, (req,res) => {
  const db = readDB();
  (db.notifications||[]).filter(n=>n.userId===req.userId).forEach(n=>n.read=true);
  writeDB(db);
  res.json({message:'Read'});
});

// ══════════════════════════════════════════
//  PROMO CODES
// ══════════════════════════════════════════
app.post('/api/promo/redeem', auth, (req,res) => {
  const {code} = req.body;
  const db = readDB();
  const promo = (db.promoCodes||[]).find(p=>p.code===code?.toUpperCase());
  if (!promo) return res.status(404).json({error:'Invalid code'});
  if (!promo.active) return res.status(400).json({error:'Code inactive'});
  if (promo.usedCount>=promo.maxUses) return res.status(400).json({error:'Code fully used'});
  if (promo.expiresAt&&new Date()>new Date(promo.expiresAt)) return res.status(400).json({error:'Code expired'});
  if ((promo.usedBy||[]).includes(req.userId)) return res.status(400).json({error:'Already used'});
  const user = db.users.find(u=>u.id===req.userId);
  user.balance=fmt2(user.balance+promo.amount);
  promo.usedCount++; if(!promo.usedBy)promo.usedBy=[]; promo.usedBy.push(req.userId);
  db.transactions.push({id:'PROMO-'+uuidv4().slice(0,8).toUpperCase(),userId:user.id,username:user.username,type:'bonus',method:'promo',amount:promo.amount,fee:0,status:'completed',reason:`Promo: ${promo.code}`,createdAt:new Date().toISOString(),balanceAfter:user.balance});
  writeDB(db);
  res.json({message:`🎉 +$${promo.amount} added!`,amount:promo.amount,newBalance:user.balance});
});

// ══════════════════════════════════════════
//  PUBLIC CONFIGS
// ══════════════════════════════════════════
app.get('/api/config', (req,res) => { const db=readDB(); res.json({config:db.gameConfig||{}}); });
app.get('/api/site-config', (req,res) => { const db=readDB(); res.json({config:db.siteConfig||{}}); });
app.get('/api/deposit-instructions', (req,res) => {
  const db=readDB();
  const def={cardInstructions:'Enter your card details and click Deposit.',cryptoAddress:'bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh',cryptoCoin:'Bitcoin (BTC)',bankName:'AUSGG Bank',bankAcc:'1234-5678-9012',bankHolder:'AUSGG Casino Ltd',bankBSB:'062-000',ewalletProvider:'PayPal',ewalletAcc:'payments@ausgg.com'};
  res.json({instructions:{...def,...db.depositInstructions}});
});
app.get('/api/announcements', (req,res) => { const db=readDB(); res.json({announcements:(db.announcements||[]).slice(0,5)}); });
app.get('/api/games', (req,res) => { const db=readDB(); res.json({games:db.games||[],categories:db.gameCategories||['Casino','Slots','Sports','Quickgame']}); });
app.get('/api/leaderboard', (req,res) => { const db=readDB(); res.json({leaderboard:(db.users||[]).map(u=>({playerId:u.playerId,username:u.username,totalWon:u.totalWon||0,balance:u.balance,totalBets:u.totalBets||0})).sort((a,b)=>b.totalWon-a.totalWon).slice(0,10)}); });

// ══════════════════════════════════════════
//  ADMIN ROUTES
// ══════════════════════════════════════════
app.get('/api/admin/users', admin, (req,res) => { const db=readDB(); res.json({users:db.users.map(({password:_,...u})=>u),count:db.users.length}); });
app.get('/api/admin/pending-users', admin, (req,res) => { const db=readDB(); res.json({pendingUsers:(db.pendingUsers||[]).map(({password:_,...u})=>u)}); });
app.get('/api/admin/transactions', admin, (req,res) => { const db=readDB(); res.json({transactions:(db.transactions||[]).sort((a,b)=>new Date(b.createdAt)-new Date(a.createdAt))}); });
app.get('/api/admin/bets', admin, (req,res) => { const db=readDB(); res.json({bets:(db.bets||[]).sort((a,b)=>new Date(b.createdAt)-new Date(a.createdAt))}); });
app.get('/api/admin/chats', admin, (req,res) => { const db=readDB(); res.json({chats:db.chats||[]}); });
app.get('/api/admin/bonuses', admin, (req,res) => { const db=readDB(); res.json({bonuses:(db.bonuses||[]).sort((a,b)=>new Date(b.createdAt)-new Date(a.createdAt))}); });
app.get('/api/admin/promos', admin, (req,res) => { const db=readDB(); res.json({promos:db.promoCodes||[]}); });
app.get('/api/admin/announcements', admin, (req,res) => { const db=readDB(); res.json({announcements:db.announcements||[]}); });
app.get('/api/admin/deposit-requests', admin, (req,res) => { const db=readDB(); res.json({requests:(db.depositRequests||[]).sort((a,b)=>new Date(b.createdAt)-new Date(a.createdAt))}); });
app.get('/api/admin/withdrawal-requests', admin, (req,res) => { const db=readDB(); res.json({requests:(db.withdrawalRequests||[]).sort((a,b)=>new Date(b.createdAt)-new Date(a.createdAt))}); });
app.get('/api/admin/games', admin, (req,res) => { const db=readDB(); res.json({games:db.games||[],categories:db.gameCategories||['Casino','Slots','Sports','Quickgame']}); });
app.get('/api/admin/game-config', admin, (req,res) => { const db=readDB(); const def={dice:{rtp:99,minBet:0.01,maxBet:10000,enabled:true},mines:{rtp:99,minBet:0.01,maxBet:10000,enabled:true},slots:{rtp:96,minBet:0.01,maxBet:10000,enabled:true},coin:{rtp:98,minBet:0.01,maxBet:10000,enabled:true},global:{maxWin:50000,startBalance:1000,maintenance:false,allowReg:true,autoBonus:false,autoBonusAmount:100}}; res.json({config:{...def,...(db.gameConfig||{})}}); });
app.get('/api/admin/site-config', admin, (req,res) => { const db=readDB(); res.json({config:db.siteConfig||{}}); });
app.get('/api/admin/deposit-instructions', admin, (req,res) => { const db=readDB(); res.json({instructions:db.depositInstructions||{}}); });
app.get('/api/admin/reg-feed', admin, (req,res) => { const db=readDB(); res.json({users:(db.users||[]).sort((a,b)=>new Date(b.createdAt)-new Date(a.createdAt)),pending:(db.pendingUsers||[]).map(({password:_,...u})=>u),totalUsers:(db.users||[]).length,totalPending:(db.pendingUsers||[]).length}); });
app.get('/api/admin/withdrawal-form', admin, (req,res) => { const db=readDB(); res.json({fields:db.withdrawalFormFields||[]}); });

// Get single customer full details
app.get('/api/admin/customer/:id', admin, (req,res) => {
  const db=readDB();
  const user=db.users.find(u=>u.id===req.params.id||u.playerId===req.params.id||u.username===req.params.id);
  if(!user) return res.status(404).json({error:'Not found'});
  const bets=(db.bets||[]).filter(b=>b.userId===user.id);
  const txs=(db.transactions||[]).filter(t=>t.userId===user.id);
  const chats=(db.chats||[]).find(c=>c.userId===user.id);
  const depReqs=(db.depositRequests||[]).filter(r=>r.userId===user.id);
  const wdReqs=(db.withdrawalRequests||[]).filter(r=>r.userId===user.id);
  res.json({user,bets,transactions:txs,chat:chats||null,depositRequests:depReqs,withdrawalRequests:wdReqs});
});

// Update customer info
app.post('/api/admin/customer/:id/update', admin, async (req,res) => {
  const {username,email,balance,banned,bankInfo,newPassword} = req.body;
  const db=readDB();
  const user=db.users.find(u=>u.id===req.params.id||u.playerId===req.params.id);
  if(!user) return res.status(404).json({error:'Not found'});
  if(username) user.username=username;
  if(email) user.email=email;
  if(balance!==undefined) user.balance=fmt2(parseFloat(balance));
  if(banned!==undefined) user.banned=!!banned;
  if(bankInfo) user.bankInfo={...user.bankInfo,...bankInfo};
  if(newPassword&&newPassword.length>=6) user.password=await bcrypt.hash(newPassword,10);
  writeDB(db);
  const {password:_,...safe}=user;
  res.json({message:'Customer updated',user:safe});
});

// Approve deposit request
app.post('/api/admin/approve-deposit', admin, (req,res) => {
  const {id,action,note} = req.body;
  const db=readDB();
  const req_ = (db.depositRequests||[]).find(r=>r.id===id);
  if(!req_) return res.status(404).json({error:'Not found'});
  const user=db.users.find(u=>u.id===req_.userId);
  if(!user) return res.status(404).json({error:'User not found'});
  if(action==='approve'){
    req_.status='approved'; req_.approvedAt=new Date().toISOString(); req_.adminNote=note||'';
    user.balance=fmt2(user.balance+req_.amount);
    user.totalDeposited=fmt2((user.totalDeposited||0)+req_.amount);
    db.transactions.push({id:req_.id,userId:user.id,username:user.username,type:'deposit',method:req_.method,amount:req_.amount,fee:0,status:'completed',createdAt:req_.createdAt,approvedAt:req_.approvedAt,balanceAfter:user.balance});
    if(!db.notifications)db.notifications=[];
    db.notifications.push({id:uuidv4(),userId:user.id,message:`✅ Your deposit of $${req_.amount} has been approved! Balance updated.`,type:'success',read:false,createdAt:new Date().toISOString()});
  } else {
    req_.status='rejected'; req_.rejectedAt=new Date().toISOString(); req_.adminNote=note||'';
    if(!db.notifications)db.notifications=[];
    db.notifications.push({id:uuidv4(),userId:user.id,message:`❌ Your deposit of $${req_.amount} was rejected. ${note||''}`,type:'warning',read:false,createdAt:new Date().toISOString()});
  }
  writeDB(db);
  res.json({message:`Deposit ${action}d`,request:req_});
});

// Process/Approve withdrawal
app.post('/api/admin/process-withdrawal', admin, (req,res) => {
  const {id,action,note} = req.body;
  const db=readDB();
  const wr=(db.withdrawalRequests||[]).find(r=>r.id===id);
  if(!wr) return res.status(404).json({error:'Not found'});
  const user=db.users.find(u=>u.id===wr.userId);
  if(action==='process'){
    wr.status='processing'; wr.processedAt=new Date().toISOString();
    if(!db.notifications)db.notifications=[];
    db.notifications.push({id:uuidv4(),userId:wr.userId,message:`⏳ Your withdrawal of $${wr.amount} is being processed.`,type:'info',read:false,createdAt:new Date().toISOString()});
  } else if(action==='approve'){
    wr.status='approved'; wr.approvedAt=new Date().toISOString();
    const tx=db.transactions.find(t=>t.id===wr.id);
    if(tx) tx.status='approved';
    if(!db.notifications)db.notifications=[];
    db.notifications.push({id:uuidv4(),userId:wr.userId,message:`✅ Your withdrawal of $${wr.amount} has been approved and sent!`,type:'success',read:false,createdAt:new Date().toISOString()});
  } else if(action==='reject'){
    wr.status='rejected'; wr.rejectedAt=new Date().toISOString(); wr.adminNote=note||'';
    if(user){user.balance=fmt2(user.balance+wr.amount);user.totalWithdrawn=fmt2((user.totalWithdrawn||0)-wr.amount);}
    const tx=db.transactions.find(t=>t.id===wr.id);
    if(tx) tx.status='rejected';
    if(!db.notifications)db.notifications=[];
    db.notifications.push({id:uuidv4(),userId:wr.userId,message:`❌ Withdrawal of $${wr.amount} rejected & refunded. ${note||''}`,type:'warning',read:false,createdAt:new Date().toISOString()});
  }
  writeDB(db);
  res.json({message:`Withdrawal ${action}d`,request:wr});
});

// Games management
app.post('/api/admin/games', admin, (req,res) => {
  const {name,category,thumbnail,description,url,enabled} = req.body;
  if(!name||!category) return res.status(400).json({error:'Name and category required'});
  const db=readDB();
  if(!db.games)db.games=[];
  const game={id:uuidv4(),name,category,thumbnail:thumbnail||'',description:description||'',url:url||'',enabled:enabled!==false,createdAt:new Date().toISOString()};
  db.games.push(game);
  writeDB(db);
  res.json({message:'Game added!',game});
});
app.put('/api/admin/games/:id', admin, (req,res) => {
  const db=readDB();
  const game=(db.games||[]).find(g=>g.id===req.params.id);
  if(!game) return res.status(404).json({error:'Not found'});
  Object.assign(game,req.body);
  writeDB(db);
  res.json({message:'Updated',game});
});
app.delete('/api/admin/games/:id', admin, (req,res) => {
  const db=readDB();
  db.games=(db.games||[]).filter(g=>g.id!==req.params.id);
  writeDB(db);
  res.json({message:'Deleted'});
});

// Admin actions
app.post('/api/admin/reset-balance', admin, (req,res) => {
  const {username,amount}=req.body; const db=readDB();
  const user=db.users.find(u=>u.username===username||u.playerId===username);
  if(!user) return res.status(404).json({error:'Not found'});
  user.balance=fmt2(parseFloat(amount)||0); writeDB(db);
  res.json({message:`Balance set to $${user.balance}`,newBalance:user.balance});
});
app.post('/api/admin/ban-user', admin, (req,res) => {
  const {username}=req.body; const db=readDB();
  const user=db.users.find(u=>u.username===username||u.playerId===username);
  if(!user) return res.status(404).json({error:'Not found'});
  user.banned=!user.banned; writeDB(db);
  res.json({message:`User ${user.banned?'banned':'unbanned'}`,banned:user.banned});
});
app.post('/api/admin/give-bonus', admin, (req,res) => {
  const {username,amount,reason,bonusType}=req.body;
  const amt=parseFloat(amount);
  if(!amt||amt<=0) return res.status(400).json({error:'Invalid amount'});
  const db=readDB();
  const user=db.users.find(u=>u.username===username||u.playerId===username);
  if(!user) return res.status(404).json({error:'Not found'});
  user.balance=fmt2(user.balance+amt);
  const bonus={id:'BON-'+uuidv4().slice(0,8).toUpperCase(),userId:user.id,username,amount:amt,reason:reason||'Admin bonus',bonusType:bonusType||'manual',createdAt:new Date().toISOString()};
  db.bonuses.push(bonus);
  db.transactions.push({id:bonus.id,userId:user.id,username,type:'bonus',method:'admin',amount:amt,fee:0,status:'completed',reason:bonus.reason,createdAt:bonus.createdAt,balanceAfter:user.balance});
  if(!db.notifications)db.notifications=[];
  db.notifications.push({id:uuidv4(),userId:user.id,message:`🎁 You received $${amt} bonus! Reason: ${reason||'Admin bonus'}`,type:'bonus',read:false,createdAt:new Date().toISOString()});
  writeDB(db);
  res.json({message:`$${amt} given to ${username}!`,newBalance:user.balance});
});
app.post('/api/admin/give-bonus-all', admin, (req,res) => {
  const {amount,reason}=req.body; const amt=parseFloat(amount);
  const db=readDB(); let count=0;
  db.users.forEach(user=>{
    if(user.banned)return;
    user.balance=fmt2(user.balance+amt);
    db.bonuses.push({id:'BON-'+uuidv4().slice(0,8).toUpperCase(),userId:user.id,username:user.username,amount:amt,reason:reason||'Global bonus',bonusType:'global',createdAt:new Date().toISOString()});
    if(!db.notifications)db.notifications=[];
    db.notifications.push({id:uuidv4(),userId:user.id,message:`🎁 Global bonus $${amt}! ${reason||''}`,type:'bonus',read:false,createdAt:new Date().toISOString()});
    count++;
  });
  writeDB(db);
  res.json({message:`Bonus given to ${count} users!`,count});
});
app.post('/api/admin/create-promo', admin, (req,res) => {
  const {code,amount,maxUses,expiresAt}=req.body; const db=readDB();
  if(!db.promoCodes)db.promoCodes=[];
  if(db.promoCodes.find(p=>p.code===code?.toUpperCase())) return res.status(409).json({error:'Code exists'});
  const promo={id:uuidv4(),code:code.toUpperCase(),amount:parseFloat(amount),maxUses:parseInt(maxUses)||999,usedCount:0,usedBy:[],expiresAt:expiresAt||null,active:true,createdAt:new Date().toISOString()};
  db.promoCodes.push(promo); writeDB(db);
  res.json({message:'Created!',promo});
});
app.post('/api/admin/toggle-promo', admin, (req,res) => {
  const {code}=req.body; const db=readDB();
  const promo=(db.promoCodes||[]).find(p=>p.code===code);
  if(!promo) return res.status(404).json({error:'Not found'});
  promo.active=!promo.active; writeDB(db);
  res.json({message:`Promo ${promo.active?'enabled':'disabled'}`});
});
app.post('/api/admin/send-message', admin, (req,res) => {
  const {userId,text}=req.body; const db=readDB();
  if(!db.chats)db.chats=[];
  let chat=db.chats.find(c=>c.userId===userId);
  if(!chat) return res.status(404).json({error:'Chat not found'});
  chat.messages.push({from:'admin',text,time:new Date().toISOString(),read:true});
  if(!db.notifications)db.notifications=[];
  db.notifications.push({id:uuidv4(),userId,message:`💬 Support replied: ${text.substring(0,60)}`,type:'info',read:false,createdAt:new Date().toISOString()});
  writeDB(db);
  res.json({message:'Sent'});
});
app.post('/api/admin/mark-read', admin, (req,res) => {
  const {userId}=req.body; const db=readDB();
  const chat=(db.chats||[]).find(c=>c.userId===userId);
  if(chat){chat.messages.forEach(m=>{if(m.from==='user')m.read=true;});writeDB(db);}
  res.json({message:'Read'});
});
app.post('/api/admin/notify-user', admin, (req,res) => {
  const {username,message,type}=req.body; const db=readDB();
  const user=db.users.find(u=>u.username===username||u.playerId===username);
  if(!user) return res.status(404).json({error:'Not found'});
  if(!db.notifications)db.notifications=[];
  db.notifications.push({id:uuidv4(),userId:user.id,username,message,type:type||'info',read:false,createdAt:new Date().toISOString()});
  writeDB(db);
  res.json({message:'Sent'});
});
app.post('/api/admin/game-config', admin, (req,res) => {
  const {game,config}=req.body; const db=readDB();
  if(!db.gameConfig)db.gameConfig={};
  db.gameConfig[game]={...(db.gameConfig[game]||{}),...config};
  writeDB(db);
  res.json({message:'Saved'});
});
app.post('/api/admin/global-config', admin, (req,res) => {
  const {config}=req.body; const db=readDB();
  if(!db.gameConfig)db.gameConfig={};
  db.gameConfig.global={...(db.gameConfig.global||{}),...config};
  writeDB(db);
  res.json({message:'Saved'});
});
app.post('/api/admin/site-config', admin, (req,res) => {
  const {config}=req.body; const db=readDB();
  db.siteConfig={...(db.siteConfig||{}),...config,banner:{...(db.siteConfig?.banner||{}),...(config.banner||{})}};
  writeDB(db);
  res.json({message:'Saved',config:db.siteConfig});
});
app.post('/api/admin/deposit-instructions', admin, (req,res) => {
  const {instructions}=req.body; const db=readDB();
  db.depositInstructions={...(db.depositInstructions||{}),...instructions};
  writeDB(db);
  res.json({message:'Saved'});
});
app.post('/api/admin/withdrawal-form', admin, (req,res) => {
  const {fields}=req.body; const db=readDB();
  db.withdrawalFormFields=fields;
  writeDB(db);
  res.json({message:'Form saved',fields});
});
app.post('/api/admin/announcement', admin, (req,res) => {
  const {title,body,type}=req.body; const db=readDB();
  if(!db.announcements)db.announcements=[];
  db.announcements.unshift({id:uuidv4(),title,body,type:type||'info',createdAt:new Date().toISOString()});
  db.announcements=db.announcements.slice(0,50);
  writeDB(db);
  res.json({message:'Posted'});
});
app.post('/api/admin/delete-pending', admin, (req,res) => {
  const {email}=req.body; const db=readDB();
  db.pendingUsers=(db.pendingUsers||[]).filter(u=>u.email!==email);
  writeDB(db);
  res.json({message:'Removed'});
});

app.use((req,res)=>res.status(404).json({error:'Not found'}));

app.listen(PORT,()=>{
  console.log('\n🎰 ══════════════════════════════════════');
  console.log('   AUSGG Backend v5 — Full Feature Build');
  console.log('════════════════════════════════════════');
  console.log(`✅ Server:  http://localhost:${PORT}`);
  console.log(`🎮 Admin:   http://localhost:${PORT}/admin.html`);
  console.log(`📁 DB:      ${DB_PATH}`);
  console.log('════════════════════════════════════════\n');
});

// ══════════════════════════════════════════
//  PLAYER ID GENERATION (8 char alphanumeric)
// ══════════════════════════════════════════
function generatePlayerId(existingIds) {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let id;
  do { id = Array.from({length:8}, ()=>chars[Math.floor(Math.random()*chars.length)]).join(''); }
  while (existingIds.includes(id));
  return id;
}

// Patch register to add playerId
const _origVerify = app._router.stack.find(r=>r.route?.path==='/api/auth/verify');
// We'll add playerId in the verify route — patch db write
// Actually let's add a migration endpoint + auto-add on profile fetch
app.get('/api/admin/assign-ids', admin, (req,res) => {
  const db = readDB();
  const existingIds = db.users.filter(u=>u.playerId).map(u=>u.playerId);
  let count = 0;
  db.users.forEach(u => {
    if (!u.playerId) { u.playerId = generatePlayerId(existingIds); existingIds.push(u.playerId); count++; }
  });
  writeDB(db);
  res.json({ message:`Assigned IDs to ${count} users` });
});

// ══════════════════════════════════════════
//  DEPOSIT WITH RECEIPT
// ══════════════════════════════════════════
app.post('/api/wallet/deposit-request', auth, (req, res) => {
  const { amount, method, receipt, receiptName, note } = req.body;
  const amt = parseFloat(amount);
  if (!amt||amt<1) return res.status(400).json({ error:'Invalid amount' });
  const db = readDB();
  const user = db.users.find(u=>u.id===req.userId);
  if (!user) return res.status(404).json({ error:'Not found' });
  const req_ = {
    id: 'DREQ-'+uuidv4().slice(0,8).toUpperCase(),
    type: 'deposit_request',
    userId: user.id, username: user.username, playerId: user.playerId||'—',
    amount: amt, method: method||'bank', note: note||'',
    receipt: receipt||null, receiptName: receiptName||null,
    status: 'pending', createdAt: new Date().toISOString()
  };
  if (!db.pendingRequests) db.pendingRequests = [];
  db.pendingRequests.unshift(req_);
  writeDB(db);
  console.log(`📥 Deposit request from ${user.username}: $${amt}`);
  res.json({ message:'Deposit request submitted! Admin will review.', requestId: req_.id });
});

// ══════════════════════════════════════════
//  WITHDRAWAL FORM CONFIG + REQUEST
// ══════════════════════════════════════════
app.get('/api/withdrawal-form', (req, res) => {
  const db = readDB();
  const def = [
    { id:'fullName', label:'Full Name', type:'text', placeholder:'Your full name', required:true },
    { id:'bankName', label:'Bank Name', type:'text', placeholder:'e.g. ANZ, Commonwealth', required:true },
    { id:'accountNumber', label:'Account Number', type:'text', placeholder:'123456789', required:true },
    { id:'bsb', label:'BSB / Routing Number', type:'text', placeholder:'062-000', required:false },
    { id:'note', label:'Note (optional)', type:'textarea', placeholder:'Any additional info...', required:false },
  ];
  res.json({ fields: db.withdrawalFormFields || def });
});

app.post('/api/admin/withdrawal-form', admin, (req, res) => {
  const { fields } = req.body;
  const db = readDB();
  db.withdrawalFormFields = fields;
  writeDB(db);
  res.json({ message:'Withdrawal form updated' });
});

app.post('/api/wallet/withdraw-request', auth, (req, res) => {
  const { amount, method, formData } = req.body;
  const amt = parseFloat(amount);
  if (!amt||amt<10) return res.status(400).json({ error:'Min withdrawal $10' });
  const db = readDB();
  const user = db.users.find(u=>u.id===req.userId);
  if (!user) return res.status(404).json({ error:'Not found' });
  if (amt>user.balance) return res.status(400).json({ error:'Insufficient balance' });
  // Hold the funds
  user.balance = fmt2(user.balance - amt);
  const req_ = {
    id: 'WREQ-'+uuidv4().slice(0,8).toUpperCase(),
    type: 'withdrawal_request',
    userId: user.id, username: user.username, playerId: user.playerId||'—',
    amount: amt, method: method||'bank', formData: formData||{},
    fee: fmt2(amt*0.015), netAmount: fmt2(amt*0.985),
    status: 'pending', createdAt: new Date().toISOString()
  };
  if (!db.pendingRequests) db.pendingRequests = [];
  db.pendingRequests.unshift(req_);
  writeDB(db);
  console.log(`📤 Withdrawal request from ${user.username}: $${amt}`);
  res.json({ message:'Withdrawal request submitted!', requestId:req_.id, newBalance:user.balance });
});

// ══════════════════════════════════════════
//  PENDING REQUESTS (admin)
// ══════════════════════════════════════════
app.get('/api/admin/pending-requests', admin, (req, res) => {
  const db = readDB();
  res.json({ requests: (db.pendingRequests||[]).sort((a,b)=>new Date(b.createdAt)-new Date(a.createdAt)) });
});

app.post('/api/admin/process-request', admin, (req, res) => {
  const { id, action, note } = req.body; // action: approve|reject|process
  const db = readDB();
  const req_ = (db.pendingRequests||[]).find(r=>r.id===id);
  if (!req_) return res.status(404).json({ error:'Not found' });
  const user = db.users.find(u=>u.id===req_.userId);
  req_.status = action;
  req_.processedAt = new Date().toISOString();
  req_.adminNote = note||'';

  if (action==='approve') {
    if (req_.type==='deposit_request' && user) {
      user.balance = fmt2(user.balance + req_.amount);
      user.totalDeposited = fmt2((user.totalDeposited||0)+req_.amount);
      db.transactions.push({ id:req_.id, userId:user.id, username:user.username, type:'deposit', method:req_.method, amount:req_.amount, fee:0, status:'completed', createdAt:req_.createdAt, balanceAfter:user.balance });
      if (!db.notifications) db.notifications=[];
      db.notifications.push({ id:uuidv4(), userId:user.id, message:`✅ Your deposit of $${req_.amount} has been approved!`, type:'success', read:false, createdAt:new Date().toISOString() });
    }
    if (req_.type==='withdrawal_request') {
      db.transactions.push({ id:req_.id, userId:req_.userId, username:req_.username, type:'withdraw', method:req_.method, amount:req_.amount, fee:req_.fee, netAmount:req_.netAmount, status:'approved', createdAt:req_.createdAt });
      if (!db.notifications) db.notifications=[];
      db.notifications.push({ id:uuidv4(), userId:req_.userId, message:`✅ Your withdrawal of $${req_.amount} has been approved and processed!`, type:'success', read:false, createdAt:new Date().toISOString() });
    }
  }
  if (action==='reject') {
    if (req_.type==='withdrawal_request' && user) {
      user.balance = fmt2(user.balance + req_.amount); // refund
    }
    if (!db.notifications) db.notifications=[];
    db.notifications.push({ id:uuidv4(), userId:req_.userId, message:`❌ Your ${req_.type==='deposit_request'?'deposit':'withdrawal'} request of $${req_.amount} was rejected. ${note||''}`, type:'warning', read:false, createdAt:new Date().toISOString() });
  }
  writeDB(db);
  res.json({ message:`Request ${action}d`, request:req_ });
});

// User: see their own requests
app.get('/api/my-requests', auth, (req, res) => {
  const db = readDB();
  const reqs = (db.pendingRequests||[]).filter(r=>r.userId===req.userId).sort((a,b)=>new Date(b.createdAt)-new Date(a.createdAt));
  res.json({ requests: reqs });
});

// ══════════════════════════════════════════
//  GAME MANAGEMENT
// ══════════════════════════════════════════
function getGames(db) {
  if (!db.games) db.games = { casino:[], slots:[], sports:[], quickgames:[] };
  return db.games;
}

app.get('/api/games', (req, res) => {
  const db = readDB();
  res.json({ games: getGames(db) });
});

app.get('/api/admin/games', admin, (req, res) => {
  const db = readDB();
  res.json({ games: getGames(db) });
});

app.post('/api/admin/games/add', admin, (req, res) => {
  const { category, name, thumbnail, description, rtp, minBet, maxBet, enabled } = req.body;
  const cats = ['casino','slots','sports','quickgames'];
  if (!cats.includes(category)) return res.status(400).json({ error:'Invalid category' });
  const db = readDB();
  const games = getGames(db);
  const game = { id:uuidv4(), name, thumbnail:thumbnail||'🎮', description:description||'', rtp:rtp||96, minBet:parseFloat(minBet)||0.01, maxBet:parseFloat(maxBet)||10000, enabled:enabled!==false, createdAt:new Date().toISOString() };
  games[category].push(game);
  db.games = games;
  writeDB(db);
  res.json({ message:'Game added!', game });
});

app.post('/api/admin/games/update', admin, (req, res) => {
  const { category, gameId, updates } = req.body;
  const db = readDB();
  const games = getGames(db);
  const game = games[category]?.find(g=>g.id===gameId);
  if (!game) return res.status(404).json({ error:'Not found' });
  Object.assign(game, updates);
  db.games = games;
  writeDB(db);
  res.json({ message:'Updated', game });
});

app.post('/api/admin/games/delete', admin, (req, res) => {
  const { category, gameId } = req.body;
  const db = readDB();
  const games = getGames(db);
  if (games[category]) games[category] = games[category].filter(g=>g.id!==gameId);
  db.games = games;
  writeDB(db);
  res.json({ message:'Deleted' });
});

// ══════════════════════════════════════════
//  FULL CUSTOMER EDITOR
// ══════════════════════════════════════════
app.post('/api/admin/edit-user', admin, async (req, res) => {
  const { userId, updates } = req.body;
  const db = readDB();
  const user = db.users.find(u=>u.id===userId);
  if (!user) return res.status(404).json({ error:'Not found' });
  const allowed = ['username','email','balance','banned','bankInfo','notes'];
  allowed.forEach(k => { if(updates[k]!==undefined) user[k]=updates[k]; });
  if (updates.newPassword && updates.newPassword.length>=6) {
    user.password = await bcrypt.hash(updates.newPassword, 10);
  }
  writeDB(db);
  const {password:_,...safe} = user;
  res.json({ message:'User updated', user:safe });
});

app.get('/api/admin/user-detail/:userId', admin, (req, res) => {
  const db = readDB();
  const user = db.users.find(u=>u.id===req.params.userId);
  if (!user) return res.status(404).json({ error:'Not found' });
  const bets = (db.bets||[]).filter(b=>b.userId===user.id);
  const txs = (db.transactions||[]).filter(t=>t.userId===user.id);
  const reqs = (db.pendingRequests||[]).filter(r=>r.userId===user.id);
  const {password:_,...safe} = user;
  res.json({ user:safe, bets, transactions:txs, requests:reqs });
});

// ══════════════════════════════════════════
//  ABOUT US
// ══════════════════════════════════════════
app.get('/api/about', (req,res) => {
  const db = readDB();
  const def = {
    title: 'About AUSGG Casino',
    subtitle: 'Australia\'s Premier Online Gaming Destination',
    description: 'AUSGG Casino was founded with one mission: to provide Australian players with the safest, most exciting, and most rewarding online casino experience available.',
    mission: 'Our mission is to deliver world-class entertainment with complete transparency, security, and fairness.',
    heroImage: '',
    stats: [
      { label: 'Active Players', value: '10,000+', icon: '👥' },
      { label: 'Games Available', value: '500+', icon: '🎮' },
      { label: 'Years Operating', value: '5+', icon: '📅' },
      { label: 'Satisfaction Rate', value: '98%', icon: '⭐' }
    ],
    team: [
      { name: 'James Wilson', role: 'CEO & Founder', image: '', bio: 'Passionate about creating safe gaming environments.' },
      { name: 'Sarah Chen', role: 'Head of Operations', image: '', bio: 'Ensuring every player has the best experience.' },
      { name: 'Mike Torres', role: 'Chief Security Officer', image: '', bio: 'Keeping your funds and data 100% secure.' }
    ],
    features: [
      { icon: '🔒', title: 'Bank-Level Security', description: '256-bit SSL encryption protects all transactions' },
      { icon: '⚡', title: 'Instant Payouts', description: 'Withdrawals processed within 24 hours' },
      { icon: '🎮', title: '500+ Games', description: 'From slots to live dealer games' },
      { icon: '💬', title: '24/7 Support', description: 'Our team is always here to help' },
      { icon: '🇦🇺', title: 'Australian Owned', description: 'Proudly Australian, built for Australians' },
      { icon: '✅', title: 'Licensed & Regulated', description: 'Fully compliant with Australian gaming laws' }
    ],
    licenseText: 'AUSGG Casino operates under a valid gaming license. We are committed to responsible gambling.',
    contactEmail: 'support@ausgg.com',
    contactPhone: '1800 AUSGG',
    address: 'Level 10, 123 Collins Street, Melbourne VIC 3000',
    socials: { facebook: '', instagram: '', twitter: '', youtube: '' }
  };
  res.json({ about: { ...def, ...(db.about||{}) } });
});

app.post('/api/admin/about', admin, (req,res) => {
  const { about } = req.body;
  const db = readDB();
  db.about = { ...(db.about||{}), ...about };
  writeDB(db);
  res.json({ message: 'About page updated', about: db.about });
});

// ══════════════════════════════════════════
//  PROMOTIONS / BONUSES
// ══════════════════════════════════════════
function getPromos(db) {
  if (!db.promotions) db.promotions = {
    depositBonuses: [
      { id: 'dep1', title: '🎉 Welcome Deposit Bonus', description: 'Get 100% match bonus on your first deposit up to $500! Use code WELCOME100', image: '', badge: 'NEW', badgeColor: '#00e701', minDeposit: 10, maxBonus: 500, bonusPercent: 100, code: 'WELCOME100', type: 'deposit', active: true, order: 0 },
      { id: 'dep2', title: '🔥 Reload Bonus', description: '50% reload bonus every Friday. Minimum deposit $20 to claim.', image: '', badge: 'WEEKLY', badgeColor: '#f59e0b', minDeposit: 20, maxBonus: 200, bonusPercent: 50, code: 'RELOAD50', type: 'deposit', active: true, order: 1 }
    ],
    noDepositBonuses: [
      { id: 'nodep1', title: '🎁 Free Welcome Bonus', description: 'Get $10 free play money just for registering! No deposit required.', image: '', badge: 'FREE', badgeColor: '#a855f7', amount: 10, code: 'FREETEN', type: 'nodeposit', active: true, order: 0 },
      { id: 'nodep2', title: '🌟 VIP Loyalty Reward', description: 'Earn loyalty points with every bet. Redeem for bonus cash anytime!', image: '', badge: 'VIP', badgeColor: '#f59e0b', amount: 50, code: 'VIP50', type: 'nodeposit', active: true, order: 1 }
    ],
    pageTitle: 'Promotions & Bonuses',
    pageSubtitle: 'Exclusive offers for AUSGG players',
    heroBanner: { enabled: true, title: '🎰 BIGGEST BONUSES IN AUSTRALIA', subtitle: 'Claim your welcome bonus today', image: '', bgColor: '#0f1923' }
  };
  return db.promotions;
}

app.get('/api/promotions', (req,res) => {
  const db = readDB();
  res.json({ promotions: getPromos(db) });
});

app.get('/api/admin/promotions', admin, (req,res) => {
  const db = readDB();
  res.json({ promotions: getPromos(db) });
});

app.post('/api/admin/promotions', admin, (req,res) => {
  const { promotions } = req.body;
  const db = readDB();
  db.promotions = { ...getPromos(db), ...promotions };
  writeDB(db);
  res.json({ message: 'Promotions updated' });
});

app.post('/api/admin/promotions/add', admin, (req,res) => {
  const { bonus } = req.body;
  const db = readDB();
  const promos = getPromos(db);
  const newBonus = { ...bonus, id: uuidv4().slice(0,8), active: true };
  if (bonus.type === 'deposit') promos.depositBonuses.push(newBonus);
  else promos.noDepositBonuses.push(newBonus);
  db.promotions = promos;
  writeDB(db);
  res.json({ message: 'Bonus added', bonus: newBonus });
});

app.post('/api/admin/promotions/update', admin, (req,res) => {
  const { id, type, updates } = req.body;
  const db = readDB();
  const promos = getPromos(db);
  const arr = type === 'deposit' ? promos.depositBonuses : promos.noDepositBonuses;
  const idx = arr.findIndex(b => b.id === id);
  if (idx === -1) return res.status(404).json({ error: 'Not found' });
  arr[idx] = { ...arr[idx], ...updates };
  db.promotions = promos;
  writeDB(db);
  res.json({ message: 'Updated' });
});

app.post('/api/admin/promotions/delete', admin, (req,res) => {
  const { id, type } = req.body;
  const db = readDB();
  const promos = getPromos(db);
  if (type === 'deposit') promos.depositBonuses = promos.depositBonuses.filter(b => b.id !== id);
  else promos.noDepositBonuses = promos.noDepositBonuses.filter(b => b.id !== id);
  db.promotions = promos;
  writeDB(db);
  res.json({ message: 'Deleted' });
});

// ══════════════════════════════════════════
//  CHAT WITH IMAGES
// ══════════════════════════════════════════
// Override chat send to support images
app.post('/api/chat/send-media', auth, (req,res) => {
  const { text, image, imageName } = req.body;
  if (!text && !image) return res.status(400).json({ error: 'Message or image required' });
  const db = readDB();
  const user = db.users.find(u=>u.id===req.userId);
  if (!user) return res.status(404).json({ error: 'Not found' });
  if (!db.chats) db.chats = [];
  let chat = db.chats.find(c=>c.userId===req.userId);
  if (!chat) { chat = { userId:req.userId, username:user.username, messages:[] }; db.chats.push(chat); }
  const msg = { from:'user', text:text||'', image:image||null, imageName:imageName||null, time:new Date().toISOString(), read:false };
  chat.messages.push(msg);
  writeDB(db);
  console.log(`💬 Chat from ${user.username}: ${text||'[image]'}`);
  res.json({ message:'Sent', success:true });
});

// Admin send with image
app.post('/api/admin/send-message-media', admin, (req,res) => {
  const { userId, text, image, imageName } = req.body;
  const db = readDB();
  if (!db.chats) db.chats = [];
  let chat = db.chats.find(c=>c.userId===userId);
  if (!chat) return res.status(404).json({ error: 'Chat not found' });
  const msg = { from:'admin', text:text||'', image:image||null, imageName:imageName||null, time:new Date().toISOString(), read:true };
  chat.messages.push(msg);
  if (!db.notifications) db.notifications = [];
  if (text) db.notifications.push({ id:uuidv4(), userId, message:`💬 Support: ${text.substring(0,60)}`, type:'info', read:false, createdAt:new Date().toISOString() });
  writeDB(db);
  res.json({ message:'Sent' });
});

// ══════════════════════════════════════════
//  EXTENDED SITE EDITOR
// ══════════════════════════════════════════
app.get('/api/admin/full-site-config', admin, (req,res) => {
  const db = readDB();
  res.json({
    siteConfig: db.siteConfig||{},
    gameConfig: db.gameConfig||{},
    depositInstructions: db.depositInstructions||{},
    withdrawalFormFields: db.withdrawalFormFields||[],
    about: db.about||{},
    promotions: getPromos(db)
  });
});

// ══════════════════════════════════════════
//  FORGOT PASSWORD
// ══════════════════════════════════════════
app.post('/api/auth/forgot-password', async (req,res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email required' });
  const db = readDB();
  const user = db.users.find(u => u.email === email);
  if (!user) return res.status(404).json({ error: 'No account found with that email' });
  const resetCode = code6();
  if (!db.resetCodes) db.resetCodes = [];
  db.resetCodes = db.resetCodes.filter(r => r.email !== email);
  db.resetCodes.push({ email, code: resetCode, userId: user.id, expiresAt: new Date(Date.now()+10*60000).toISOString() });
  writeDB(db);
  try {
    await transporter.sendMail({
      from: `"AUSGG" <${EMAIL_USER}>`,
      to: email,
      subject: `${resetCode} - AUSGG Password Reset`,
      html: `<div style="font-family:Arial;padding:30px;background:#0f1923;color:#fff;border-radius:12px">
        <h2 style="color:#00e701">🎰 AUSGG — Password Reset</h2>
        <p>Hi ${user.username},</p>
        <p>Your password reset code:</p>
        <div style="font-size:40px;font-weight:700;color:#00e701;letter-spacing:10px;padding:20px 0">${resetCode}</div>
        <p style="color:#888">Expires in 10 minutes. If you didn't request this, ignore this email.</p>
      </div>`
    });
    res.json({ message: 'Reset code sent to your email!', email });
  } catch(e) {
    console.log(`⚠️ Reset code for ${email}: ${resetCode}`);
    res.json({ message: 'Code sent (check server console if email fails)', email, devCode: EMAIL_USER.includes('your_gmail') ? resetCode : undefined });
  }
});

app.post('/api/auth/reset-password', async (req,res) => {
  const { email, code, newPassword } = req.body;
  if (!email||!code||!newPassword) return res.status(400).json({ error: 'All fields required' });
  if (newPassword.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  const db = readDB();
  const reset = (db.resetCodes||[]).find(r => r.email === email);
  if (!reset) return res.status(404).json({ error: 'No reset request found. Request a new code.' });
  if (new Date() > new Date(reset.expiresAt)) return res.status(410).json({ error: 'Code expired. Request a new one.' });
  if (reset.code !== code.trim()) return res.status(400).json({ error: 'Invalid code' });
  const user = db.users.find(u => u.id === reset.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });
  user.password = await bcrypt.hash(newPassword, 10);
  db.resetCodes = db.resetCodes.filter(r => r.email !== email);
  writeDB(db);
  console.log(`🔑 Password reset: ${user.username}`);
  res.json({ message: 'Password reset successfully! You can now log in.' });
});

// ══════════════════════════════════════════
//  CUSTOMER PROFILE — view & update own info
// ══════════════════════════════════════════
app.get('/api/user/full-profile', auth, (req,res) => {
  const db = readDB();
  const user = db.users.find(u => u.id === req.userId);
  if (!user) return res.status(404).json({ error: 'Not found' });
  const { password:_, ...safe } = user;
  res.json({ user: safe });
});

app.post('/api/user/update-profile', auth, async (req,res) => {
  const { firstName, lastName, phone, bankInfo } = req.body;
  const db = readDB();
  const user = db.users.find(u => u.id === req.userId);
  if (!user) return res.status(404).json({ error: 'Not found' });
  if (firstName) user.firstName = firstName;
  if (lastName) user.lastName = lastName;
  if (phone) {
    const phoneClean = phone.replace(/[^0-9]/g,'');
    if (!/^(04\d{8}|614\d{8})$/.test(phoneClean.replace(/^\+/,''))) 
      return res.status(400).json({ error: 'Invalid Australian mobile number' });
    user.phone = phone;
  }
  if (bankInfo) user.bankInfo = { ...user.bankInfo, ...bankInfo };
  writeDB(db);
  const { password:_, ...safe } = user;
  res.json({ message: 'Profile updated!', user: safe });
});

app.post('/api/user/change-password', auth, async (req,res) => {
  const { currentPassword, newPassword } = req.body;
  if (!currentPassword||!newPassword) return res.status(400).json({ error: 'Both passwords required' });
  if (newPassword.length < 6) return res.status(400).json({ error: 'New password min 6 chars' });
  const db = readDB();
  const user = db.users.find(u => u.id === req.userId);
  if (!user) return res.status(404).json({ error: 'Not found' });
  if (!await bcrypt.compare(currentPassword, user.password)) return res.status(400).json({ error: 'Current password is incorrect' });
  user.password = await bcrypt.hash(newPassword, 10);
  writeDB(db);
  res.json({ message: 'Password changed successfully!' });
});

// ══════════════════════════════════════════
//  ADMIN — ADD CUSTOMER MANUALLY
// ══════════════════════════════════════════
app.post('/api/admin/add-customer', admin, async (req,res) => {
  const { username, email, password, firstName, lastName, phone, balance, bankInfo } = req.body;
  if (!username||!email||!password) return res.status(400).json({ error:'Username, email and password required' });
  if (password.length < 6) return res.status(400).json({ error:'Password must be at least 6 characters' });
  const db = readDB();
  if (db.users.find(u=>u.username===username)) return res.status(409).json({ error:'Username already taken' });
  if (db.users.find(u=>u.email===email)) return res.status(409).json({ error:'Email already registered' });
  const existingIds = db.users.map(u=>u.playerId).filter(Boolean);
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let playerId; 
  do { playerId = Array.from({length:8},()=>chars[Math.floor(Math.random()*chars.length)]).join(''); } 
  while(existingIds.includes(playerId));
  const hashed = await bcrypt.hash(password, 10);
  const newUser = {
    id: uuidv4(), playerId,
    username, email, password: hashed,
    firstName: firstName||'', lastName: lastName||'',
    phone: phone||'',
    balance: fmt2(parseFloat(balance)||1000),
    bankInfo: bankInfo||{},
    emailVerified: true, banned: false,
    totalDeposited:0, totalWithdrawn:0, totalBets:0, totalWon:0, totalLost:0,
    notes: 'Created by admin', createdAt: new Date().toISOString(), lastLogin: null
  };
  db.users.push(newUser);
  writeDB(db);
  console.log(`👤 Admin created customer: ${username} (${playerId})`);
  res.json({ message:`Customer ${username} created!`, playerId, userId: newUser.id });
});

// ══════════════════════════════════════════
//  ADMIN — ADD CUSTOMER MANUALLY
// ══════════════════════════════════════════
app.post('/api/admin/add-customer', admin, async (req,res) => {
  const { firstName, lastName, username, email, phone, password, balance, bankInfo } = req.body;
  if (!username||!email||!password) return res.status(400).json({ error:'Username, email and password required' });
  if (password.length < 6) return res.status(400).json({ error:'Password min 6 chars' });
  const db = readDB();
  if (db.users.find(u=>u.username===username)) return res.status(409).json({ error:'Username already taken' });
  if (db.users.find(u=>u.email===email)) return res.status(409).json({ error:'Email already registered' });
  const existingIds = db.users.map(u=>u.playerId).filter(Boolean);
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let playerId; 
  do { playerId = Array.from({length:8},()=>chars[Math.floor(Math.random()*chars.length)]).join(''); } 
  while(existingIds.includes(playerId));
  const hashed = await bcrypt.hash(password, 10);
  const newUser = {
    id: uuidv4(), playerId,
    username, email, password: hashed,
    firstName: firstName||'', lastName: lastName||'', phone: phone||'',
    balance: parseFloat(balance)||1000,
    emailVerified: true, banned: false,
    totalDeposited: 0, totalWithdrawn: 0, totalBets: 0, totalWon: 0, totalLost: 0,
    bankInfo: bankInfo||{}, notes: 'Added by admin',
    createdAt: new Date().toISOString(), lastLogin: new Date().toISOString()
  };
  db.users.push(newUser);
  writeDB(db);
  console.log(`👤 Admin created user: ${username} (${playerId})`);
  const { password:_, ...safe } = newUser;
  res.status(201).json({ message:`Customer "${username}" created!`, user: safe });
});
