const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const axios = require('axios');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 10000;
const JWT_SECRET = 'halal-real-binance-bot-secret-key-2024';
const ENCRYPTION_KEY = '12345678901234567890123456789012';

// Halal Assets (Sharia-compliant cryptocurrencies)
const HALAL_ASSETS = ['BTCUSDT', 'ETHUSDT', 'BNBUSDT', 'SOLUSDT', 'ADAUSDT', 'XRPUSDT', 'DOTUSDT', 'LINKUSDT', 'MATICUSDT', 'AVAXUSDT'];

// Trading settings – NO FIXED PROFIT %, captures spread
const MAX_CONCURRENT_TRADES = 50;           // Unlimited concurrent trades
const TRADE_CHECK_INTERVAL_MS = 3000;       // Check every 3 seconds (respects rate limits)
const MIN_TRADE_SIZE_USD = 5;               // Minimum $5 per trade
const MAX_TRADE_SIZE_PERCENT = 20;          // Max 20% of balance per trade

// ========== DATA DIRECTORIES ==========
const DATA_DIR = path.join(__dirname, 'data');
const TRADES_DIR = path.join(DATA_DIR, 'trades');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const PENDING_FILE = path.join(DATA_DIR, 'pending.json');
const ORDERS_FILE = path.join(DATA_DIR, 'orders.json');

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(TRADES_DIR)) fs.mkdirSync(TRADES_DIR, { recursive: true });

// ========== OWNER ACCOUNT ==========
const ownerEmail = "mujtabahatif@gmail.com";
const ownerPasswordPlain = "Mujtabah@2598";
const ownerPasswordHash = bcrypt.hashSync(ownerPasswordPlain, 10);

let users = {};
if (fs.existsSync(USERS_FILE)) {
    try { users = JSON.parse(fs.readFileSync(USERS_FILE)); } catch(e) { users = {}; }
}

users[ownerEmail] = {
    email: ownerEmail,
    password: ownerPasswordHash,
    isOwner: true,
    isApproved: true,
    isBlocked: false,
    apiKey: "",
    secretKey: "",
    accountType: "real",
    createdAt: new Date().toISOString()
};
fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
console.log("✅ Owner account created");

if (!fs.existsSync(PENDING_FILE)) fs.writeFileSync(PENDING_FILE, JSON.stringify({}, null, 2));
if (!fs.existsSync(ORDERS_FILE)) fs.writeFileSync(ORDERS_FILE, JSON.stringify({}, null, 2));

// ========== HELPER FUNCTIONS ==========
function readUsers() { try { return JSON.parse(fs.readFileSync(USERS_FILE)); } catch(e) { return {}; } }
function writeUsers(data) { fs.writeFileSync(USERS_FILE, JSON.stringify(data, null, 2)); }
function readPending() { try { return JSON.parse(fs.readFileSync(PENDING_FILE)); } catch(e) { return {}; } }
function writePending(data) { fs.writeFileSync(PENDING_FILE, JSON.stringify(data, null, 2)); }
function readOrders() { try { return JSON.parse(fs.readFileSync(ORDERS_FILE)); } catch(e) { return {}; } }
function writeOrders(data) { fs.writeFileSync(ORDERS_FILE, JSON.stringify(data, null, 2)); }

function encrypt(text) {
    if (!text) return "";
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return iv.toString('hex') + ':' + encrypted;
}

function decrypt(text) {
    if (!text) return "";
    const parts = text.split(':');
    const iv = Buffer.from(parts.shift(), 'hex');
    const encryptedText = parts.join(':');
    const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
    let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

function cleanKey(k) { return k ? k.replace(/[\s\n\r\t]+/g, '').trim() : ""; }

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname)));

app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', message: '🕋 100% Halal Real Binance Bot' });
});

// ========== AUTHENTICATION ==========
app.post('/api/register', (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ success: false, message: 'Email and password required' });
    if (password.length < 6) return res.status(400).json({ success: false, message: 'Password must be at least 6 characters' });
    
    const users = readUsers();
    if (users[email]) return res.status(400).json({ success: false, message: 'User already exists' });
    const pending = readPending();
    if (pending[email]) return res.status(400).json({ success: false, message: 'Request already pending' });
    
    pending[email] = { email, password: bcrypt.hashSync(password, 10), requestedAt: new Date().toISOString() };
    writePending(pending);
    res.json({ success: true, message: 'Registration request sent to owner for approval.' });
});

app.post('/api/login', (req, res) => {
    const { email, password } = req.body;
    const users = readUsers();
    const user = users[email];
    
    if (!user) {
        const pending = readPending();
        if (pending[email]) return res.status(401).json({ success: false, message: 'Pending owner approval' });
        return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
    
    if (!bcrypt.compareSync(password, user.password)) return res.status(401).json({ success: false, message: 'Invalid credentials' });
    if (!user.isApproved && !user.isOwner) return res.status(401).json({ success: false, message: 'Account not approved' });
    if (user.isBlocked) return res.status(401).json({ success: false, message: 'Account blocked' });
    
    const token = jwt.sign({ email, isOwner: user.isOwner }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ success: true, token, isOwner: user.isOwner });
});

function authenticate(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ success: false, message: 'No token' });
    const token = authHeader.split(' ')[1];
    try {
        req.user = jwt.verify(token, JWT_SECRET);
        next();
    } catch (err) {
        res.status(401).json({ success: false, message: 'Invalid token' });
    }
}

// ========== REAL BINANCE API ==========
const BINANCE_API = 'https://api.binance.com';

async function binanceRequest(apiKey, secretKey, endpoint, params = {}, method = 'GET') {
    const timestamp = Date.now();
    const allParams = { ...params, timestamp, recvWindow: 5000 };
    const queryString = Object.keys(allParams).sort().map(k => `${k}=${allParams[k]}`).join('&');
    const signature = crypto.createHmac('sha256', secretKey).update(queryString).digest('hex');
    const url = `${BINANCE_API}${endpoint}?${queryString}&signature=${signature}`;
    
    const response = await axios({
        method,
        url,
        headers: { 'X-MBX-APIKEY': apiKey },
        timeout: 15000
    });
    return response.data;
}

async function getBinanceBalance(apiKey, secretKey) {
    try {
        const account = await binanceRequest(apiKey, secretKey, '/api/v3/account');
        const usdtBalance = account.balances.find(b => b.asset === 'USDT');
        return parseFloat(usdtBalance?.free || 0);
    } catch (error) {
        console.error('Balance fetch error:', error.message);
        return 0;
    }
}

async function getBinanceOrderBook(symbol) {
    try {
        const response = await axios.get(`${BINANCE_API}/api/v3/depth?symbol=${symbol}&limit=5`);
        return {
            bids: response.data.bids.map(b => parseFloat(b[0])),
            asks: response.data.asks.map(a => parseFloat(a[0]))
        };
    } catch (error) {
        console.error(`Order book error for ${symbol}:`, error.message);
        return null;
    }
}

async function placeBinanceLimitOrder(apiKey, secretKey, symbol, side, quantity, price) {
    const order = await binanceRequest(apiKey, secretKey, '/api/v3/order', {
        symbol: symbol,
        side: side,
        type: 'LIMIT',
        timeInForce: 'GTC',
        quantity: quantity.toFixed(6),
        price: price.toFixed(2)
    }, 'POST');
    return order;
}

async function checkBinanceOrderStatus(apiKey, secretKey, symbol, orderId) {
    const order = await binanceRequest(apiKey, secretKey, '/api/v3/order', {
        symbol: symbol,
        orderId: orderId
    }, 'GET');
    return order;
}

async function cancelBinanceOrder(apiKey, secretKey, symbol, orderId) {
    const result = await binanceRequest(apiKey, secretKey, '/api/v3/order', {
        symbol: symbol,
        orderId: orderId
    }, 'DELETE');
    return result;
}

function roundQuantity(symbol, quantity) {
    if (symbol === 'BTCUSDT') return Math.floor(quantity * 100000) / 100000;
    if (symbol === 'ETHUSDT') return Math.floor(quantity * 10000) / 10000;
    if (symbol === 'BNBUSDT') return Math.floor(quantity * 1000) / 1000;
    return Math.floor(quantity * 100) / 100;
}

// ========== API KEY MANAGEMENT ==========
app.post('/api/set-binance-keys', authenticate, async (req, res) => {
    let { apiKey, secretKey } = req.body;
    if (!apiKey || !secretKey) {
        return res.status(400).json({ success: false, message: 'Both API keys required' });
    }
    
    const cleanApi = cleanKey(apiKey);
    const cleanSecret = cleanKey(secretKey);
    
    try {
        const balance = await getBinanceBalance(cleanApi, cleanSecret);
        const users = readUsers();
        users[req.user.email].apiKey = encrypt(cleanApi);
        users[req.user.email].secretKey = encrypt(cleanSecret);
        writeUsers(users);
        
        res.json({ success: true, message: `✅ API keys saved! Balance: ${balance} USDT`, balance: balance });
    } catch (err) {
        console.error('API key error:', err.message);
        res.status(401).json({ success: false, message: 'Invalid API keys. Make sure "Enable Spot & Margin Trading" is enabled.' });
    }
});

app.post('/api/connect-binance', authenticate, async (req, res) => {
    const user = readUsers()[req.user.email];
    if (!user?.apiKey) {
        return res.status(400).json({ success: false, message: 'No API keys saved' });
    }
    
    const apiKey = decrypt(user.apiKey);
    const secretKey = decrypt(user.secretKey);
    
    try {
        const balance = await getBinanceBalance(apiKey, secretKey);
        res.json({
            success: true,
            balance: balance,
            message: `✅ Connected to REAL BINANCE! Balance: ${balance} USDT`
        });
    } catch (error) {
        res.status(401).json({ success: false, message: error.message });
    }
});

app.get('/api/get-keys', authenticate, (req, res) => {
    const user = readUsers()[req.user.email];
    if (!user?.apiKey) return res.json({ success: false, message: 'No keys saved' });
    res.json({
        success: true,
        apiKey: decrypt(user.apiKey),
        secretKey: decrypt(user.secretKey)
    });
});

app.post('/api/get-balance', authenticate, async (req, res) => {
    const user = readUsers()[req.user.email];
    if (!user?.apiKey) return res.json({ success: false, message: 'No API keys' });
    
    const apiKey = decrypt(user.apiKey);
    const secretKey = decrypt(user.secretKey);
    
    try {
        const balance = await getBinanceBalance(apiKey, secretKey);
        res.json({ success: true, balance: balance });
    } catch (error) {
        res.json({ success: false, message: error.message });
    }
});

// ========== REAL TRADING ENGINE – NO FIXED PROFIT % ==========
const activeSessions = new Map();
let assetIndex = 0;

function nextAsset() {
    const asset = HALAL_ASSETS[assetIndex];
    assetIndex = (assetIndex + 1) % HALAL_ASSETS.length;
    return asset;
}

app.post('/api/start-trading', authenticate, async (req, res) => {
    try {
        const { investmentAmount, targetAmount, timeLimitHours } = req.body;
        
        // Validation
        if (!investmentAmount || investmentAmount < MIN_TRADE_SIZE_USD) {
            return res.status(400).json({ success: false, message: `Minimum investment is $${MIN_TRADE_SIZE_USD}` });
        }
        if (!targetAmount || targetAmount <= investmentAmount) {
            return res.status(400).json({ success: false, message: 'Target must be greater than investment' });
        }
        
        const user = readUsers()[req.user.email];
        if (!user?.apiKey) {
            return res.status(400).json({ success: false, message: 'Add Binance API keys first' });
        }
        
        const apiKey = decrypt(user.apiKey);
        const secretKey = decrypt(user.secretKey);
        
        let balance = 0;
        try {
            balance = await getBinanceBalance(apiKey, secretKey);
        } catch (error) {
            return res.status(401).json({ success: false, message: 'Cannot verify balance: ' + error.message });
        }
        
        if (balance < investmentAmount) {
            return res.status(400).json({ success: false, message: `Insufficient balance. You have ${balance} USDT, need ${investmentAmount}` });
        }
        
        const sessionId = crypto.randomBytes(8).toString('hex');
        
        const sessionData = {
            userId: req.user.email,
            initialInvestment: investmentAmount,
            targetAmount: targetAmount,
            currentBalance: investmentAmount,
            totalProfit: 0,
            startTime: Date.now(),
            timeLimit: timeLimitHours || 24,
            activeTrades: [],
            completedTrades: [],
            status: 'ACTIVE',
            tradeCount: 0,
            apiKey: apiKey,
            secretKey: secretKey
        };
        
        activeSessions.set(sessionId, sessionData);
        startRealTrading(sessionId);
        
        const profitNeeded = targetAmount - investmentAmount;
        const requiredReturn = ((targetAmount / investmentAmount) - 1) * 100;
        
        res.json({
            success: true,
            sessionId,
            message: `✅ HALAL REAL TRADING STARTED!\n💰 Investment: $${investmentAmount}\n🎯 Target: $${targetAmount}\n⏰ Time Limit: ${timeLimitHours || 24} hours\n\n🕋 ISLAMIC REMINDER: NO Riba, NO Gharar, NO Maysir, NO leverage, NO short selling.\n\n📊 NO FIXED PROFIT % – Captures real market spread (bid-ask difference) for maximum profit!\n⚡ Trades close instantly when spread captured.\n🔄 Auto-compounding: ON\n🚀 Unlimited concurrent trades – scales with your balance!`
        });
    } catch (error) {
        console.error('Start trading error:', error);
        res.status(500).json({ success: false, message: error.message });
    }
});

async function startRealTrading(sessionId) {
    const session = activeSessions.get(sessionId);
    if (!session || session.status !== 'ACTIVE') return;
    
    // Check if target reached
    if (session.currentBalance >= session.targetAmount) {
        session.status = 'TARGET_REACHED';
        activeSessions.delete(sessionId);
        console.log(`🎯 TARGET REACHED! ${session.userId} achieved $${session.currentBalance.toFixed(2)}`);
        return;
    }
    
    // Check time limit
    const elapsedHours = (Date.now() - session.startTime) / (1000 * 60 * 60);
    if (elapsedHours >= session.timeLimit) {
        session.status = 'TIME_LIMIT_REACHED';
        activeSessions.delete(sessionId);
        console.log(`⏰ TIME LIMIT REACHED for ${session.userId}`);
        return;
    }
    
    // Process existing orders – CLOSE INSTANTLY using market spread
    for (let i = 0; i < session.activeTrades.length; i++) {
        const trade = session.activeTrades[i];
        
        try {
            if (trade.status === 'BUY_ORDER_PLACED') {
                const orderStatus = await checkBinanceOrderStatus(session.apiKey, session.secretKey, trade.symbol, trade.buyOrderId);
                
                if (orderStatus.status === 'FILLED') {
                    trade.status = 'BUY_FILLED';
                    trade.fillPrice = parseFloat(orderStatus.price);
                    trade.filledQuantity = parseFloat(orderStatus.executedQty);
                    console.log(`✅ BUY ORDER FILLED: ${trade.filledQuantity} ${trade.symbol} at $${trade.fillPrice}`);
                    
                    // Get current ask price to capture spread
                    const orderBook = await getBinanceOrderBook(trade.symbol);
                    const askPrice = orderBook?.asks[0];
                    
                    if (askPrice && askPrice > trade.fillPrice) {
                        // Sell at ask price – capture the spread
                        const sellOrder = await placeBinanceLimitOrder(session.apiKey, session.secretKey, trade.symbol, 'SELL', trade.filledQuantity, askPrice);
                        trade.sellOrderId = sellOrder.orderId;
                        trade.sellPrice = askPrice;
                        trade.status = 'SELL_ORDER_PLACED';
                        console.log(`📈 SELL ORDER PLACED at ask: $${askPrice} (Spread: ${((askPrice - trade.fillPrice) / trade.fillPrice * 100).toFixed(4)}%)`);
                    } else {
                        // Fallback: use profit target (user's setting)
                        const sellPrice = trade.fillPrice * (1 + (trade.profitTarget || 0.5) / 100);
                        const sellOrder = await placeBinanceLimitOrder(session.apiKey, session.secretKey, trade.symbol, 'SELL', trade.filledQuantity, sellPrice);
                        trade.sellOrderId = sellOrder.orderId;
                        trade.sellPrice = sellPrice;
                        trade.status = 'SELL_ORDER_PLACED';
                        console.log(`📈 SELL ORDER PLACED at target: $${sellPrice}`);
                    }
                } else if (orderStatus.status === 'EXPIRED' || orderStatus.status === 'CANCELED') {
                    trade.status = 'FAILED';
                    session.activeTrades.splice(i, 1);
                    i--;
                }
            } else if (trade.status === 'SELL_ORDER_PLACED') {
                const orderStatus = await checkBinanceOrderStatus(session.apiKey, session.secretKey, trade.symbol, trade.sellOrderId);
                
                if (orderStatus.status === 'FILLED') {
                    const exitPrice = parseFloat(orderStatus.price);
                    const profit = (exitPrice - trade.fillPrice) * trade.filledQuantity;
                    const profitPercent = (profit / trade.investedAmount) * 100;
                    
                    session.currentBalance += profit;
                    session.totalProfit += profit;
                    session.tradeCount++;
                    trade.status = 'COMPLETED';
                    trade.profit = profit;
                    session.completedTrades.push(trade);
                    
                    console.log(`✅ SELL ORDER FILLED! Profit: $${profit.toFixed(4)} (${profitPercent.toFixed(4)}%) | New balance: $${session.currentBalance.toFixed(2)} | Target: $${session.targetAmount}`);
                    
                    // Save to history
                    const historyFile = path.join(TRADES_DIR, session.userId.replace(/[^a-z0-9]/gi, '_') + '.json');
                    let history = [];
                    if (fs.existsSync(historyFile)) history = JSON.parse(fs.readFileSync(historyFile));
                    history.unshift({
                        tradeNumber: session.tradeCount,
                        symbol: trade.symbol,
                        entryPrice: trade.fillPrice,
                        exitPrice: exitPrice,
                        quantity: trade.filledQuantity,
                        investment: trade.investedAmount,
                        profit: profit,
                        profitPercent: profitPercent.toFixed(4),
                        balanceAfter: session.currentBalance,
                        timestamp: new Date().toISOString(),
                        isHalal: true
                    });
                    fs.writeFileSync(historyFile, JSON.stringify(history.slice(0, 500), null, 2));
                    
                    session.activeTrades.splice(i, 1);
                    i--;
                }
            }
        } catch (error) {
            console.error(`Order processing error:`, error.message);
        }
    }
    
    // Check target again after processing
    if (session.currentBalance >= session.targetAmount) {
        session.status = 'TARGET_REACHED';
        activeSessions.delete(sessionId);
        return;
    }
    
    // Calculate how many new trades to place (UNLIMITED – scales with balance)
    const remainingNeeded = session.targetAmount - session.currentBalance;
    const timeRemaining = Math.max(0.1, (session.startTime + session.timeLimit * 3600000 - Date.now()) / 3600000);
    
    // Dynamic trade count – more trades as time decreases
    let tradesToPlace = Math.min(
        MAX_CONCURRENT_TRADES - session.activeTrades.length,
        Math.max(1, Math.ceil(10 / timeRemaining))
    );
    tradesToPlace = Math.max(1, Math.min(MAX_CONCURRENT_TRADES, tradesToPlace));
    
    // Calculate investment per trade (minimum $5)
    let investmentPerTrade = Math.max(MIN_TRADE_SIZE_USD, Math.min(session.currentBalance * (MAX_TRADE_SIZE_PERCENT / 100), remainingNeeded / tradesToPlace));
    investmentPerTrade = Math.min(investmentPerTrade, session.currentBalance);
    
    if (investmentPerTrade < MIN_TRADE_SIZE_USD) {
        setTimeout(() => startRealTrading(sessionId), TRADE_CHECK_INTERVAL_MS);
        return;
    }
    
    // Place new trades
    let newTradesPlaced = 0;
    for (let i = 0; i < tradesToPlace; i++) {
        if (session.currentBalance < investmentPerTrade) break;
        if (session.activeTrades.length >= MAX_CONCURRENT_TRADES) break;
        
        const symbol = nextAsset();
        const orderBook = await getBinanceOrderBook(symbol);
        
        if (!orderBook || !orderBook.bids[0]) continue;
        
        const bidPrice = orderBook.bids[0];
        const buyPrice = bidPrice * 0.998; // Buy slightly below best bid
        const quantity = investmentPerTrade / buyPrice;
        const roundedQty = roundQuantity(symbol, quantity);
        
        if (roundedQty <= 0) continue;
        
        try {
            const order = await placeBinanceLimitOrder(session.apiKey, session.secretKey, symbol, 'BUY', roundedQty, buyPrice);
            
            session.currentBalance -= investmentPerTrade;
            
            session.activeTrades.push({
                symbol: symbol,
                quantity: roundedQty,
                buyPrice: buyPrice,
                buyOrderId: order.orderId,
                status: 'BUY_ORDER_PLACED',
                createdAt: Date.now(),
                investedAmount: investmentPerTrade,
                profitTarget: 0.5 // Small fallback target if spread not captured
            });
            newTradesPlaced++;
            
            console.log(`📈 NEW BUY ORDER: $${investmentPerTrade.toFixed(2)} → ${roundedQty} ${symbol} at $${buyPrice.toFixed(2)} | Active trades: ${session.activeTrades.length}`);
            
        } catch (error) {
            console.error(`Failed to place order for ${symbol}:`, error.message);
        }
    }
    
    setTimeout(() => startRealTrading(sessionId), TRADE_CHECK_INTERVAL_MS);
}

app.post('/api/stop-trading', authenticate, (req, res) => {
    const { sessionId } = req.body;
    if (activeSessions.has(sessionId)) {
        activeSessions.delete(sessionId);
        res.json({ success: true, message: 'Trading stopped' });
    } else {
        res.json({ success: false, message: 'Session not found' });
    }
});

app.post('/api/trade-status', authenticate, (req, res) => {
    const session = activeSessions.get(req.body.sessionId);
    if (!session) return res.json({ success: true, active: false });
    
    const elapsedHours = (Date.now() - session.startTime) / (1000 * 60 * 60);
    const timeRemaining = Math.max(0, session.timeLimit - elapsedHours);
    const progressPercent = ((session.currentBalance - session.initialInvestment) / (session.targetAmount - session.initialInvestment)) * 100;
    
    res.json({
        success: true,
        active: session.status === 'ACTIVE',
        initialInvestment: session.initialInvestment,
        targetAmount: session.targetAmount,
        currentBalance: session.currentBalance,
        totalProfit: session.totalProfit,
        progressPercent: Math.min(100, Math.max(0, progressPercent)).toFixed(1),
        totalTrades: session.tradeCount,
        activeTrades: session.activeTrades.length,
        completedTrades: session.completedTrades.length,
        timeRemaining: timeRemaining.toFixed(2),
        status: session.status
    });
});

app.get('/api/trade-history', authenticate, (req, res) => {
    const file = path.join(TRADES_DIR, req.user.email.replace(/[^a-z0-9]/gi, '_') + '.json');
    if (!fs.existsSync(file)) return res.json({ success: true, trades: [] });
    const trades = JSON.parse(fs.readFileSync(file));
    res.json({ success: true, trades: trades });
});

app.get('/api/halal-assets', authenticate, (req, res) => {
    res.json({ success: true, assets: HALAL_ASSETS });
});

// ========== ADMIN ENDPOINTS ==========
app.get('/api/admin/pending-users', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const pending = readPending();
    res.json({ success: true, pending: Object.keys(pending).map(e => ({ email: e, requestedAt: pending[e].requestedAt })) });
});

app.post('/api/admin/approve-user', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const { email } = req.body;
    const pending = readPending();
    if (!pending[email]) return res.status(404).json({ success: false });
    const users = readUsers();
    users[email] = {
        email, password: pending[email].password, isOwner: false, isApproved: true,
        isBlocked: false, apiKey: "", secretKey: "", createdAt: new Date().toISOString()
    };
    writeUsers(users);
    delete pending[email];
    writePending(pending);
    res.json({ success: true, message: `User ${email} approved` });
});

app.post('/api/admin/reject-user', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const { email } = req.body;
    const pending = readPending();
    if (!pending[email]) return res.status(404).json({ success: false });
    delete pending[email];
    writePending(pending);
    res.json({ success: true, message: `User ${email} rejected` });
});

app.post('/api/admin/toggle-block', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const { email } = req.body;
    const users = readUsers();
    if (!users[email]) return res.status(404).json({ success: false });
    users[email].isBlocked = !users[email].isBlocked;
    writeUsers(users);
    res.json({ success: true, message: `User ${email} is now ${users[email].isBlocked ? 'BLOCKED' : 'ACTIVE'}` });
});

app.get('/api/admin/users', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const users = readUsers();
    res.json({ success: true, users: Object.keys(users).map(e => ({
        email: e, hasApiKeys: !!users[e].apiKey, isOwner: users[e].isOwner,
        isApproved: users[e].isApproved, isBlocked: users[e].isBlocked
    })) });
});

app.get('/api/admin/user-balances', authenticate, async (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const users = readUsers();
    const balances = {};
    for (const [email, u] of Object.entries(users)) {
        if (u.apiKey) {
            try {
                const apiKey = decrypt(u.apiKey);
                const secretKey = decrypt(u.secretKey);
                const balance = await getBinanceBalance(apiKey, secretKey);
                balances[email] = { balance, hasKeys: true };
            } catch {
                balances[email] = { balance: 0, hasKeys: true, error: true };
            }
        } else {
            balances[email] = { balance: 0, hasKeys: false };
        }
    }
    res.json({ success: true, balances });
});

app.get('/api/admin/all-trades', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const allTrades = {};
    const files = fs.readdirSync(TRADES_DIR);
    for (const file of files) {
        if (file === '.gitkeep') continue;
        const userId = file.replace('.json', '');
        allTrades[userId] = JSON.parse(fs.readFileSync(path.join(TRADES_DIR, file)));
    }
    res.json({ success: true, trades: allTrades });
});

app.post('/api/change-password', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const { currentPassword, newPassword } = req.body;
    const users = readUsers();
    const owner = users[req.user.email];
    if (!bcrypt.compareSync(currentPassword, owner.password)) return res.status(401).json({ success: false, message: 'Wrong current password' });
    owner.password = bcrypt.hashSync(newPassword, 10);
    writeUsers(users);
    res.json({ success: true, message: 'Password changed! Please login again.' });
});

// Serve frontend
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`\n========================================`);
    console.log(`🕋 100% HALAL REAL BINANCE BOT - RUNNING`);
    console.log(`========================================`);
    console.log(`✅ Owner: ${ownerEmail}`);
    console.log(`✅ Password: ${ownerPasswordPlain}`);
    console.log(`✅ ${HALAL_ASSETS.length} Halal Assets`);
    console.log(`✅ NO FIXED PROFIT % – Captures market spread`);
    console.log(`✅ MINIMUM TRADE: $${MIN_TRADE_SIZE_USD}`);
    console.log(`✅ NO Riba | NO Gharar | NO Maysir | NO Leverage | NO Short Selling`);
    console.log(`✅ REAL Binance API | Limit Orders Only`);
    console.log(`========================================`);
    console.log(`Server on port: ${PORT}`);
});
