# 🎰 AUSGG Mock Backend
### Study Purpose Only — No Real Money

---

## 🚀 Quick Start (3 steps)

### Step 1 — Install Node.js
Download from https://nodejs.org (choose LTS version)

### Step 2 — Install dependencies
Open a terminal/command prompt in this folder and run:
```
npm install
```

### Step 3 — Start the server
```
npm start
```

Server will run at: **http://localhost:3001**

---

## 📡 API Endpoints

### Auth
| Method | URL | Body | Description |
|--------|-----|------|-------------|
| POST | /api/auth/register | `{username, email, password}` | Create account |
| POST | /api/auth/login | `{identifier, password}` | Login |

### User (requires token)
| Method | URL | Description |
|--------|-----|-------------|
| GET | /api/user/profile | Get user info |
| GET | /api/user/balance | Get current balance |

### Wallet (requires token)
| Method | URL | Body | Description |
|--------|-----|------|-------------|
| POST | /api/wallet/deposit | `{amount, method}` | Deposit funds |
| POST | /api/wallet/withdraw | `{amount, method}` | Withdraw funds |
| GET | /api/wallet/transactions | — | Transaction history |

### Bets (requires token)
| Method | URL | Body | Description |
|--------|-----|------|-------------|
| POST | /api/bets/record | `{game, betAmount, win, payout, detail}` | Record a bet |
| GET | /api/bets/history | — | Bet history |
| GET | /api/bets/stats | — | Stats summary |

### Public
| Method | URL | Description |
|--------|-----|-------------|
| GET | /api/leaderboard | Top 10 players |

### Admin (header: x-admin-key: ausgg_admin_2024)
| Method | URL | Body | Description |
|--------|-----|------|-------------|
| GET | /api/admin/users | — | List all users |
| POST | /api/admin/reset-balance | `{username, amount}` | Reset a user balance |
| DELETE | /api/admin/clear-db | — | Wipe database |

---

## 🔑 Authentication
After login/register, you get a JWT token. Send it with every protected request:
```
Authorization: Bearer YOUR_TOKEN_HERE
```

---

## 🧪 Test with curl

**Register:**
```bash
curl -X POST http://localhost:3001/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","email":"test@test.com","password":"123456"}'
```

**Login:**
```bash
curl -X POST http://localhost:3001/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"identifier":"testuser","password":"123456"}'
```

**Deposit (replace TOKEN):**
```bash
curl -X POST http://localhost:3001/api/wallet/deposit \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer TOKEN" \
  -d '{"amount":100,"method":"card"}'
```

---

## 📁 File Structure
```
ausgg-backend/
├── server.js        ← Main server
├── package.json     ← Dependencies
├── data/
│   └── db.json      ← JSON database (auto-created)
└── README.md
```

## 🔧 Dev Mode (auto-restart on changes)
```
npm run dev
```
Requires nodemon (installed automatically with npm install).

---

*Study purpose only. No real payments are processed.*
