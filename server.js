'use strict';
const http = require('node:http');
const crypto = require('node:crypto');
const {createDynamicFlag, verifyDynamicFlag} = require('./flags');
const config = {currentKeyId: 'demo', keys: new Map([['demo', crypto.randomBytes(32)]])};
const sessions = new Map();
const port = Number(process.env.PORT || 8080);
const server = http.createServer(async (req, res) => {
    const origin = 'http://127.0.0.1:' + port;
    function reply(status, body, type = 'text/plain') {
        res.writeHead(status, {'Content-Type': type + '; charset=utf-8', 'Cache-Control': 'no-store'});
        res.end(body);
    }
    if (req.headers.host !== '127.0.0.1:' + port) return reply(403, 'Use the loopback address.');
    if (req.method === 'POST' && req.headers.origin && req.headers.origin !== origin) return reply(403, 'Local requests only.');
    const token = (req.headers.cookie || '').match(/(?:^|; )seat=([a-f0-9]{48})(?:;|$)/)?.[1];
    const seat = sessions.get(token);
    if (req.url === '/' && req.method === 'GET') {
        return reply(200, '<h1>CTF Square | Sealed Ledger</h1><p>Start a synthetic analyst session. Inspect your note, then test whether the ledger enforces ownership.</p><form method="post" action="/start"><button>Start a fresh seat</button></form>', 'text/html');
    }
    if (req.url === '/start' && req.method === 'POST') {
        const id = crypto.randomBytes(24).toString('hex');
        sessions.set(id, sessions.size + 1);
        res.writeHead(303, {'Set-Cookie': 'seat=' + id + '; HttpOnly; SameSite=Strict; Path=/', Location: '/desk'});
        return res.end();
    }
    if (!seat) return reply(401, 'Start a seat first.');
    const context = {userId: seat, challengeId: 1, eventId: 1};
    if (req.url === '/desk' && req.method === 'GET') return reply(200, '<h1>Analyst desk</h1><a href="/notes/7">Open my note</a><form method="post" action="/submit"><label>Recovered flag <input name="flag" required></label><button>Verify</button></form><a href="/">Start over</a>', 'text/html');
    if (req.method === 'GET' && req.url === '/notes/7') return reply(200, 'Owner: analyst. Shift handover complete.');
    // Deliberately missing object-level authorization, scoped to this synthetic lab.
    if (req.method === 'GET' && req.url === '/notes/1') return reply(200, 'Owner: supervisor. Recovery token: ' + createDynamicFlag(context, config));
    if (req.url === '/submit' && req.method === 'POST') {
        let body = '';
        for await (const chunk of req) {
            body += chunk;
            if (body.length > 1024) return reply(413, 'Input too long.');
        }
        const ok = verifyDynamicFlag(new URLSearchParams(body).get('flag'), context, config);
        return reply(ok ? 200 : 403, ok ? 'Accepted for this seat.' : 'Rejected for this seat.');
    }
    reply(404, 'Unknown route.');
});
server.listen(port, '127.0.0.1', () => console.log('Open http://127.0.0.1:' + port));
