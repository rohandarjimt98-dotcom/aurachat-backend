// Standalone dev gateway for rapid local testing without external Redis/Postgres
import http from 'http';
import { WebSocketServer } from 'ws';

const PORT = process.env.PORT || 8080;
const GRACE_PERIOD_MS = 15000;

// In-memory data store
const users = new Map(); // id -> user
const activePasses = new Map(); // userId -> pass
const reports = [];
const rooms = new Map(); // roomId -> { user1, user2, messages: [] }
const userToRoom = new Map(); // userId -> roomId
const graceTimers = new Map(); // userId -> timer

// Queues: 'all', 'male', 'female'
const queueAll = [];
const queuePrefMale = [];
const queuePrefFemale = [];

// Connected clients: userId -> ws client
const clients = new Map();

// Pluggable Regex Content Moderation
const BLOCKED_PATTERNS = [
  /(?:kill\s+yourself|commit\s+suicide)/i,
  /(?:cp|childporn|underage\s+nudes?)/i,
  /(?:bomb\s+threat|terrorist\s+attack)/i,
];

const CENSOR_PATTERNS = [
  /\b(?:fuck|shit|bitch|asshole|dick|cunt|slut|whore)\b/gi,
];

const PII_PATTERNS = [
  /\b(?:\+?(\d{1,3}))?[-. (]*(\d{3})[-. )]*(\d{3})[-. ]*(\d{4})\b/g,
  /\b\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}\b/g,
];

function moderateMessage(text) {
  for (const pat of BLOCKED_PATTERNS) {
    if (pat.test(text)) {
      return {
        allowed: false,
        reason: 'Message violates safety guidelines (severe content/harassment).',
      };
    }
  }

  let censored = text;
  for (const pii of PII_PATTERNS) {
    censored = censored.replace(pii, '[phone/card redacted]');
  }
  for (const cp of CENSOR_PATTERNS) {
    censored = censored.replace(cp, (m) => m[0] + '*'.repeat(m.length - 2) + m[m.length - 1]);
  }

  return { allowed: true, text: censored };
}

// Age Gate Calculation
function calculateAge(birthDateStr) {
  const dob = new Date(birthDateStr);
  const now = new Date();
  let age = now.getFullYear() - dob.getFullYear();
  const m = now.getMonth() - dob.getMonth();
  if (m < 0 || (m === 0 && now.getDate() < dob.getDate())) {
    age--;
  }
  return age;
}

// HTTP Server for REST endpoints & CORS
const server = http.createServer((req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (req.method === 'OPTIONS') {
    res.writeHead(200);
    res.end();
    return;
  }

  const url = new URL(req.url, `http://${req.headers.host}`);

  // Stats (Online Count)
  if (url.pathname === '/api/stats') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ online_count: getOnlineCount() }));
    return;
  }

  // Health
  if (url.pathname === '/api/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 'healthy', mode: 'dev-standalone', online_count: getOnlineCount() }));
    return;
  }

  // Auth / Session (Age Gate & Fingerprint)
  if (url.pathname === '/api/auth/session' && req.method === 'POST') {
    let body = '';
    req.on('data', (chunk) => (body += chunk));
    req.on('end', () => {
      try {
        const data = JSON.parse(body);
        if (!data.birth_date) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Date of birth is required' }));
          return;
        }

        const age = calculateAge(data.birth_date);
        if (age < 18) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'You must be at least 18 years of age.' }));
          return;
        }

        // Find or create user
        let user = Array.from(users.values()).find((u) => u.device_fingerprint === data.fingerprint);
        if (!user) {
          user = {
            id: 'usr_' + Math.random().toString(36).substring(2, 11),
            device_fingerprint: data.fingerprint,
            gender: data.gender || 'male',
            birth_date: data.birth_date,
            created_at: new Date().toISOString(),
            last_active_at: new Date().toISOString(),
          };
          users.set(user.id, user);
        } else {
          user.gender = data.gender || user.gender;
          user.last_active_at = new Date().toISOString();
        }

        const pass = activePasses.get(user.id);
        const hasActivePass = Boolean(pass && new Date(pass.expires_at) > new Date());

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(
          JSON.stringify({
            user,
            has_active_pass: hasActivePass,
            active_pass: hasActivePass ? pass : null,
          })
        );
      } catch (err) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid JSON request' }));
      }
    });
    return;
  }

  // Entitlement status
  if (url.pathname === '/api/entitlement/status') {
    const userId = url.searchParams.get('user_id');
    const pass = activePasses.get(userId);
    const hasActivePass = Boolean(pass && new Date(pass.expires_at) > new Date());
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ has_active_pass: hasActivePass, active_pass: hasActivePass ? pass : null }));
    return;
  }

  // Pass activation
  if (url.pathname === '/api/entitlement/activate-pass' && req.method === 'POST') {
    let body = '';
    req.on('data', (chunk) => (body += chunk));
    req.on('end', () => {
      try {
        const { user_id, tier } = JSON.parse(body);
        let durationMs = 3 * 3600 * 1000;
        if (tier === '6h') durationMs = 6 * 3600 * 1000;
        if (tier === '24h') durationMs = 24 * 3600 * 1000;

        const pass = {
          id: 'pass_' + Math.random().toString(36).substring(2, 9),
          user_id,
          tier: tier || '3h',
          granted_at: new Date().toISOString(),
          expires_at: new Date(Date.now() + durationMs).toISOString(),
        };

        activePasses.set(user_id, pass);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true, pass }));
      } catch (err) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: err.message }));
      }
    });
    return;
  }

  res.writeHead(404);
  res.end('Not found');
});

// WebSocket Server
const wss = new WebSocketServer({ server, path: '/ws' });

function removeFromQueues(userId) {
  const filterOut = (arr) => {
    const idx = arr.findIndex((item) => item.userId === userId);
    if (idx !== -1) arr.splice(idx, 1);
  };
  filterOut(queueAll);
  filterOut(queuePrefMale);
  filterOut(queuePrefFemale);
}

function tryMatchUsers() {
  // Check male filter queue
  matchQueue(queuePrefMale, ['male']);
  // Check female filter queue
  matchQueue(queuePrefFemale, ['female']);
  // Match remaining free queue
  while (queueAll.length >= 2) {
    const u1 = queueAll.shift();
    const u2 = queueAll.shift();
    createRoom(u1, u2);
  }
}

function matchQueue(seekerQueue, targetGenders) {
  for (let i = seekerQueue.length - 1; i >= 0; i--) {
    const seeker = seekerQueue[i];
    // Look in free queue or compatible queues
    const candidateIdx = queueAll.findIndex((c) => targetGenders.includes(c.gender) && c.userId !== seeker.userId);
    if (candidateIdx !== -1) {
      const candidate = queueAll.splice(candidateIdx, 1)[0];
      seekerQueue.splice(i, 1);
      createRoom(seeker, candidate);
    }
  }
}

function createRoom(u1, u2) {
  const roomId = 'room_' + Math.random().toString(36).substring(2, 12);
  rooms.set(roomId, {
    roomId,
    user1: u1,
    user2: u2,
    messages: [],
  });

  userToRoom.set(u1.userId, roomId);
  userToRoom.set(u2.userId, roomId);

  // Notify user 1
  const ws1 = clients.get(u1.userId);
  if (ws1 && ws1.readyState === 1) {
    ws1.send(
      JSON.stringify({
        type: 'matched',
        room_id: roomId,
        data: { partner_gender: u2.gender },
      })
    );
  }

  // Notify user 2
  const ws2 = clients.get(u2.userId);
  if (ws2 && ws2.readyState === 1) {
    ws2.send(
      JSON.stringify({
        type: 'matched',
        room_id: roomId,
        data: { partner_gender: u1.gender },
      })
    );
  }

  console.log(`[DevGateway] Paired ${u1.userId} & ${u2.userId} into ${roomId}`);
}

function teardownRoom(roomId, reason, triggeringUserId) {
  const room = rooms.get(roomId);
  if (!room) return;

  const partnerId = room.user1.userId === triggeringUserId ? room.user2.userId : room.user1.userId;
  const partnerWs = clients.get(partnerId);

  if (partnerWs && partnerWs.readyState === 1) {
    partnerWs.send(
      JSON.stringify({
        type: reason,
        room_id: roomId,
      })
    );
  }

  userToRoom.delete(room.user1.userId);
  userToRoom.delete(room.user2.userId);
  rooms.delete(roomId);
}

// Real-time Online Presence (Strictly actual connected clients count)
function getOnlineCount() {
  return clients.size;
}

function broadcastOnlineCount() {
  const count = getOnlineCount();
  const payload = JSON.stringify({ type: 'online_count', count });
  for (const client of clients.values()) {
    if (client.readyState === 1) {
      client.send(payload);
    }
  }
}

wss.on('connection', (ws, req) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const userId = url.searchParams.get('user_id');
  const gender = url.searchParams.get('gender') || 'male';
  const fingerprint = url.searchParams.get('fingerprint') || '';

  if (!userId) {
    ws.close();
    return;
  }

  if (req.socket) {
    req.socket.setNoDelay(true);
  }

  ws.isAlive = true;
  ws.on('pong', () => {
    ws.isAlive = true;
  });

  clients.set(userId, ws);
  console.log(`[DevGateway] User connected: ${userId}`);

  // Send online count immediately to new client
  ws.send(JSON.stringify({ type: 'online_count', count: getOnlineCount() }));
  broadcastOnlineCount();

  // Check 15-second grace reconnect
  if (graceTimers.has(userId)) {
    clearTimeout(graceTimers.get(userId));
    graceTimers.delete(userId);
    console.log(`[DevGateway] User ${userId} reconnected within grace period!`);

    const existingRoomId = userToRoom.get(userId);
    if (existingRoomId && rooms.has(existingRoomId)) {
      const room = rooms.get(existingRoomId);
      const partnerId = room.user1.userId === userId ? room.user2.userId : room.user1.userId;
      const partnerWs = clients.get(partnerId);

      ws.send(
        JSON.stringify({
          type: 'matched',
          room_id: existingRoomId,
          data: { resumed: true },
        })
      );

      if (partnerWs && partnerWs.readyState === 1) {
        partnerWs.send(
          JSON.stringify({
            type: 'partner_status',
            room_id: existingRoomId,
            data: { status: 'connected' },
          })
        );
      }
    }
  }

  ws.on('message', (dataStr) => {
    try {
      const msg = JSON.parse(dataStr);

      switch (msg.type) {
        case 'join_queue': {
          removeFromQueues(userId);
          const filterGender = msg.data?.filter_gender || 'all';

          // Entitlement check
          if (filterGender !== 'all') {
            const pass = activePasses.get(userId);
            const hasPass = pass && new Date(pass.expires_at) > new Date();
            if (!hasPass) {
              ws.send(
                JSON.stringify({
                  type: 'error',
                  data: {
                    code: 'PREMIUM_REQUIRED',
                    message: 'Gender filtering requires an active AuraChat Premium pass.',
                  },
                })
              );
              return;
            }
          }

          const entry = { userId, gender, filterGender, fingerprint };
          if (filterGender === 'male') {
            queuePrefMale.push(entry);
          } else if (filterGender === 'female') {
            queuePrefFemale.push(entry);
          } else {
            queueAll.push(entry);
          }

          ws.send(JSON.stringify({ type: 'queue_joined' }));
          tryMatchUsers();
          break;
        }

        case 'leave_queue': {
          removeFromQueues(userId);
          ws.send(JSON.stringify({ type: 'queue_left' }));
          break;
        }

        case 'ping': {
          ws.isAlive = true;
          ws.send(JSON.stringify({ type: 'pong' }));
          break;
        }

        case 'pong': {
          ws.isAlive = true;
          break;
        }

        case 'chat_message': {
          const roomId = userToRoom.get(userId);
          if (!roomId || !rooms.has(roomId)) {
            ws.send(
              JSON.stringify({
                type: 'partner_disconnected',
                room_id: roomId || '',
                data: { message: 'Stranger is no longer in this room. Click Next to find someone new.' },
              })
            );
            return;
          }

          const room = rooms.get(roomId);
          const partnerId = room.user1.userId === userId ? room.user2.userId : room.user1.userId;
          const partnerWs = clients.get(partnerId);

          if (!partnerWs || partnerWs.readyState !== 1) {
            ws.send(
              JSON.stringify({
                type: 'partner_status',
                room_id: roomId,
                data: { status: 'reconnecting', graceSeconds: 15 },
              })
            );
            return;
          }

          const mod = moderateMessage(msg.text || '');
          if (!mod.allowed) {
            ws.send(
              JSON.stringify({
                type: 'error',
                data: { message: mod.reason },
              })
            );
            return;
          }

          const outgoingText = mod.text;
          room.messages.push({ sender: userId, text: outgoingText, time: Date.now() });

          if (partnerWs && partnerWs.readyState === 1) {
            partnerWs.send(
              JSON.stringify({
                type: 'chat_message',
                room_id: roomId,
                text: outgoingText,
                timestamp: Date.now(),
              })
            );
          }

          if (outgoingText !== msg.text) {
            ws.send(
              JSON.stringify({
                type: 'message_sanitized',
                room_id: roomId,
                text: outgoingText,
                timestamp: Date.now(),
              })
            );
          }
          break;
        }

        case 'typing': {
          const roomId = userToRoom.get(userId);
          if (!roomId || !rooms.has(roomId)) return;
          const room = rooms.get(roomId);
          const partnerId = room.user1.userId === userId ? room.user2.userId : room.user1.userId;
          const partnerWs = clients.get(partnerId);
          if (partnerWs && partnerWs.readyState === 1) {
            partnerWs.send(
              JSON.stringify({
                type: 'typing',
                room_id: roomId,
                data: msg.data,
              })
            );
          }
          break;
        }

        case 'skip_room': {
          const roomId = userToRoom.get(userId);
          if (roomId) {
            teardownRoom(roomId, 'partner_skipped', userId);
            if (msg.data?.auto_requeue) {
              queueAll.push({ userId, gender, filterGender: 'all', fingerprint });
              ws.send(JSON.stringify({ type: 'queue_joined' }));
              tryMatchUsers();
            }
          }
          break;
        }

        case 'stop_room': {
          const roomId = userToRoom.get(userId);
          if (roomId) {
            teardownRoom(roomId, 'partner_stopped', userId);
          }
          break;
        }

        case 'report_room': {
          const roomId = userToRoom.get(userId);
          if (roomId) {
            const room = rooms.get(roomId);
            reports.push({
              reporter: userId,
              room_id: roomId,
              reason: msg.data?.reason || 'Reported',
              messages: room ? room.messages : [],
              timestamp: new Date(),
            });
            console.log(`[Moderation] Report submitted for room ${roomId}`);
            teardownRoom(roomId, 'partner_reported', userId);
            ws.send(
              JSON.stringify({
                type: 'report_confirmed',
              })
            );
          }
          break;
        }
      }
    } catch (err) {
      console.error('[DevGateway] Error processing message:', err);
    }
  });

  ws.on('close', () => {
    clients.delete(userId);
    removeFromQueues(userId);
    broadcastOnlineCount();

    const roomId = userToRoom.get(userId);
    if (roomId && rooms.has(roomId)) {
      const room = rooms.get(roomId);
      const partnerId = room.user1.userId === userId ? room.user2.userId : room.user1.userId;
      const partnerWs = clients.get(partnerId);

      // Notify partner about 15s grace period
      if (partnerWs && partnerWs.readyState === 1) {
        partnerWs.send(
          JSON.stringify({
            type: 'partner_status',
            room_id: roomId,
            data: { status: 'reconnecting', graceSeconds: 15 },
          })
        );
      }

      // Start 15s timer
      const timer = setTimeout(() => {
        graceTimers.delete(userId);
        console.log(`[DevGateway] Grace expired for ${userId} in ${roomId}`);
        teardownRoom(roomId, 'partner_disconnected', userId);
      }, GRACE_PERIOD_MS);

      graceTimers.set(userId, timer);
    }
  });
});

// Periodic server-side ping keepalive to prevent Cloud / Render proxy idle disconnects
const heartbeatInterval = setInterval(() => {
  for (const [userId, ws] of clients.entries()) {
    if (ws.isAlive === false) {
      console.log(`[Heartbeat] Inactive client timeout: ${userId}`);
      ws.terminate();
      continue;
    }
    ws.isAlive = false;
    if (ws.readyState === 1) {
      try {
        ws.ping();
        ws.send(JSON.stringify({ type: 'ping' }));
      } catch (err) {}
    }
  }
}, 10000);

server.listen(PORT, () => {
  console.log(`[DevGateway] AuraChat Dev Gateway listening on http://localhost:${PORT} and ws://localhost:${PORT}/ws`);
});
