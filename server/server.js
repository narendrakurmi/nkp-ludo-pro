/**
 * NKP Ludo Pro — Render.com Server (Razorpay Only)
 * 
 * APIs:
 *   GET  /health                        — health check
 *   GET  /api/wake                       — wake-up ping
 *   POST /api/razorpay/create-order      — create Razorpay order
 *   POST /api/razorpay/verify-payment   — verify Razorpay payment signature
 */

const http = require('http');
const https = require('https');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// === CONFIG ===
const PORT = process.env.PORT || 3000;

// Razorpay keys (set via environment variables on Render.com)
// Test: rzp_test_TW2NhaO2R893Ln / YrzALgIhaNjkOW15who7bJso
// Live: set RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET on Render.com
const RAZORPAY_KEY_ID = process.env.RAZORPAY_KEY_ID || 'rzp_live_TVe8itpX9P9LHl';
const RAZORPAY_KEY_SECRET = process.env.RAZORPAY_KEY_SECRET || 'YrzALgIhaNjkOW15who7bJso';

// Razorpay order storage (in-memory, resets on server restart)
const razorpayOrders = new Map();

// === HELPERS ===
function readBody(req) {
  return new Promise((resolve) => {
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
      try { resolve(JSON.parse(body)); }
      catch(e) { resolve({}); }
    });
  });
}

function sendJSON(res, status, data) {
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  });
  res.end(JSON.stringify(data));
}

// Razorpay API call helper
function razorpayRequest(endpoint, method, body) {
  return new Promise((resolve, reject) => {
    const auth = Buffer.from(RAZORPAY_KEY_ID + ':' + RAZORPAY_KEY_SECRET).toString('base64');
    const postData = JSON.stringify(body);
    
    const options = {
      hostname: 'api.razorpay.com',
      path: '/v1/' + endpoint,
      method: method,
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Basic ' + auth,
        'Content-Length': Buffer.byteLength(postData),
      },
    };
    
    const rq = https.request(options, (rs) => {
      let data = '';
      rs.on('data', chunk => { data += chunk; });
      rs.on('end', () => {
        try { resolve(JSON.parse(data)); }
        catch(e) { resolve({ error: 'parse error', raw: data }); }
      });
    });
    
    rq.on('error', (e) => { reject(e); });
    rq.write(postData);
    rq.end();
  });
}

// === SERVER ===
const server = http.createServer(async (req, res) => {
  // Handle CORS preflight
  if (req.method === 'OPTIONS') {
    sendJSON(res, 200, { ok: true });
    return;
  }

  const url = new URL(req.url, 'http://localhost:' + PORT);
  const reqPath = url.pathname;
  const method = req.method;

  // === HEALTH CHECK ===
  if (reqPath === '/health' && method === 'GET') {
    sendJSON(res, 200, { 
      status: 'ok', 
      server: 'NKP Ludo Pro',
      time: Date.now(),
      uptime: process.uptime(),
      razorpay: RAZORPAY_KEY_ID ? 'configured' : 'not_configured'
    });
    return;
  }

  // === WAKE-UP PING ===
  if (reqPath === '/api/wake' && method === 'GET') {
    sendJSON(res, 200, { awake: true, time: Date.now() });
    return;
  }

  // === RAZORPAY: CREATE ORDER ===
  if (reqPath === '/api/razorpay/create-order' && method === 'POST') {
    const body = await readBody(req);
    const amount = body.amount || 0; // in paise
    const itemName = body.item || 'coins';
    
    if (!amount || amount < 100) {
      sendJSON(res, 400, { success: false, message: 'Invalid amount (min 100 paise = Rs 1)' });
      return;
    }
    
    if (!RAZORPAY_KEY_ID || !RAZORPAY_KEY_SECRET) {
      sendJSON(res, 503, { success: false, message: 'Razorpay not configured on server' });
      return;
    }
    
    try {
      const order = await razorpayRequest('orders', 'POST', {
        amount: amount,
        currency: 'INR',
        receipt: 'nkp_' + Date.now(),
        notes: { app: 'NKP Ludo Pro', item: itemName }
      });
      
      if (order.id) {
        razorpayOrders.set(order.id, {
          orderId: order.id,
          amount: amount,
          item: itemName,
          status: 'created',
          timestamp: Date.now()
        });
        console.log('Razorpay order created: ' + order.id + ' amount=' + amount);
        sendJSON(res, 200, { success: true, order_id: order.id, amount: order.amount, currency: order.currency });
      } else {
        console.error('Razorpay order error:', order);
        sendJSON(res, 500, { success: false, message: 'Order creation failed', error: order.error || order });
      }
    } catch(e) {
      console.error('Razorpay error:', e);
      sendJSON(res, 500, { success: false, message: 'Razorpay request failed', error: e.message });
    }
    return;
  }

  // === RAZORPAY: VERIFY PAYMENT ===
  if (reqPath === '/api/razorpay/verify-payment' && method === 'POST') {
    const body = await readBody(req);
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = body;
    
    if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature) {
      sendJSON(res, 400, { success: false, message: 'Missing payment details' });
      return;
    }
    
    if (!RAZORPAY_KEY_SECRET) {
      sendJSON(res, 503, { success: false, message: 'Razorpay not configured on server' });
      return;
    }
    
    // Verify signature: HMAC-SHA256(razorpay_order_id + '|' + razorpay_payment_id, key_secret)
    const expectedSignature = crypto
      .createHmac('sha256', RAZORPAY_KEY_SECRET)
      .update(razorpay_order_id + '|' + razorpay_payment_id)
      .digest('hex');
    
    if (expectedSignature === razorpay_signature) {
      const order = razorpayOrders.get(razorpay_order_id);
      if (order) {
        order.status = 'paid';
        order.paymentId = razorpay_payment_id;
        order.verifiedAt = Date.now();
      }
      
      console.log('Razorpay payment verified: ' + razorpay_payment_id);
      sendJSON(res, 200, { 
        success: true, 
        status: 'approved',
        verified: true,
        message: 'Payment verified successfully'
      });
    } else {
      console.error('Razorpay signature mismatch for order: ' + razorpay_order_id);
      sendJSON(res, 400, { success: false, message: 'Signature verification failed' });
    }
    return;
  }

  // === SERVE STATIC FILES FROM public/ ===
  if (method === 'GET' && !reqPath.startsWith('/api/')) {
    let filePath = path.join(__dirname, 'public', req.url === '/' ? 'index.html' : req.url);
    const ext = path.extname(filePath);
    const mimeTypes = {
      '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css',
      '.json': 'application/json', '.png': 'image/png', '.jpg': 'image/jpeg',
      '.gif': 'image/gif', '.svg': 'image/svg+xml', '.ico': 'image/x-icon',
    };
    try {
      const data = fs.readFileSync(filePath);
      res.writeHead(200, { 'Content-Type': mimeTypes[ext] || 'application/octet-stream' });
      res.end(data);
      return;
    } catch(e) {
      // File not found, fall through to 404
    }
  }

  // === 404 ===
  sendJSON(res, 404, { error: 'Not found', path: reqPath });
});

server.listen(PORT, () => {
  console.log('NKP Ludo Pro server running on port ' + PORT);
  console.log('Razorpay: ' + (RAZORPAY_KEY_ID ? 'configured' : 'NOT configured (set RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET env vars)'));
});

// Keep server alive (prevent Render.com sleep)
setInterval(() => {
  console.log('Server alive — ' + razorpayOrders.size + ' razorpay orders in memory');
}, 600000); // every 10 minutes
