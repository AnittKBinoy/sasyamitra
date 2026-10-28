'use strict';
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const mysql = require('mysql2/promise');
const { OAuth2Client } = require('google-auth-library');

const app = express();
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true });
}

const PORT = process.env.PORT || 3000;
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const FREE_ATTEMPTS = 10;

// ലോഗിൻ ലോഗ് ഔട്ട് ചെയ്യുന്നതുവരെ നിലനിൽക്കും (10 വർഷം)
const SESSION_DAYS = 3650;

// സെർവർ റീസ്റ്റാർട്ട് ചെയ്താലും ലോഗിൻ പോകാതിരിക്കാൻ secret ഫയലിൽ സേവ് ചെയ്യുന്നു
function loadSessionSecret() {
    if (process.env.SESSION_SECRET) return process.env.SESSION_SECRET;
    const secretFile = path.join(__dirname, '.session_secret');
    try {
        const saved = fs.readFileSync(secretFile, 'utf8').trim();
        if (saved.length >= 32) return saved;
    } catch (e) { /* ഫയൽ ഇല്ല */ }
    const fresh = crypto.randomBytes(32).toString('hex');
    try {
        fs.writeFileSync(secretFile, fresh, { mode: 0o600 });
    } catch (e) {
        console.error('Could not save session secret:', e.message);
    }
    return fresh;
}
const SESSION_SECRET = loadSessionSecret();

const oauthClient = new OAuth2Client(GOOGLE_CLIENT_ID);

const pool = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'sasyamitra_db',
    charset: 'utf8mb4',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

function signToken(userId) {
    const payload = Buffer.from(JSON.stringify({
        uid: userId,
        exp: Date.now() + SESSION_DAYS * 24 * 60 * 60 * 1000
    })).toString('base64url');
    const sig = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('base64url');
    return `${payload}.${sig}`;
}

function verifyToken(token) {
    if (typeof token !== 'string' || !token.includes('.')) return null;
    const [payload, sig] = token.split('.');
    const expected = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('base64url');
    const a = Buffer.from(sig || '');
    const b = Buffer.from(expected);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
    try {
        const data = JSON.parse(Buffer.from(payload, 'base64url').toString());
        if (!data.uid || !data.exp || data.exp < Date.now()) return null;
        return data;
    } catch (e) {
        return null;
    }
}

function requireAuth(req, res, next) {
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : '';
    const data = verifyToken(token);
    if (!data) return res.status(401).json({ error: 'Please sign in again. (വീണ്ടും സൈൻ ഇൻ ചെയ്യുക)' });
    req.userId = data.uid;
    next();
}

async function getActiveSubscription(userId) {
    const [rows] = await pool.query(
        `SELECT *, (expires_at IS NOT NULL AND expires_at < NOW()) AS is_expired
           FROM subscriptions WHERE user_id = ? AND status = 'active' ORDER BY id DESC LIMIT 1`,
        [userId]
    );
    const sub = rows[0];
    if (!sub) return null;
    if (sub.is_expired) {
        if (sub.plan_name === 'Free') {
            await pool.query(
                'UPDATE subscriptions SET attempts_left = ?, expires_at = DATE_ADD(NOW(), INTERVAL 30 DAY) WHERE id = ?',
                [FREE_ATTEMPTS, sub.id]
            );
            sub.attempts_left = FREE_ATTEMPTS;
        } else {
            return { ...sub, expired: true };
        }
    }
    return sub;
}

app.post('/api/auth/google', async (req, res) => {
    try {
        if (!GOOGLE_CLIENT_ID) {
            return res.status(500).json({ error: 'Server login is not configured.' });
        }
        const { token } = req.body;
        const ticket = await oauthClient.verifyIdToken({ idToken: token, audience: GOOGLE_CLIENT_ID });
        const payload = ticket.getPayload();
        if (!payload.email || payload.email_verified === false) {
            return res.status(401).json({ error: 'Google account email is not verified.' });
        }
        const { email, name, sub: googleId } = payload;

        await pool.query(
            `INSERT INTO users (email, name, google_id) VALUES (?, ?, ?)
             ON DUPLICATE KEY UPDATE name = VALUES(name), google_id = VALUES(google_id)`,
            [email, name || null, googleId]
        );
        const [userRows] = await pool.query('SELECT id, email, name FROM users WHERE email = ?', [email]);
        const user = userRows[0];

        let sub = await getActiveSubscription(user.id);
        if (!sub) {
            await pool.query(
                `INSERT INTO subscriptions (user_id, plan_name, attempts_left, expires_at)
                 VALUES (?, 'Free', ?, DATE_ADD(NOW(), INTERVAL 30 DAY))`,
                [user.id, FREE_ATTEMPTS]
            );
            sub = await getActiveSubscription(user.id);
        }

        res.json({ success: true, user, token: signToken(user.id), attemptsLeft: sub ? sub.attempts_left : 0 });
    } catch (err) {
        console.error('Google auth failed:', err.message);
        res.status(401).json({ error: 'Google Authentication failed.' });
    }
});

app.get('/api/history', requireAuth, async (req, res) => {
    try {
        const [rows] = await pool.query(
            'SELECT query_text, created_at FROM chat_history WHERE user_id = ? ORDER BY id DESC LIMIT 30',
            [req.userId]
        );
        res.json({ history: rows });
    } catch (err) {
        res.status(500).json({ error: 'Could not load history.' });
    }
});

// ---------------------------------------------------------------
// സഹായ ഫംഗ്ഷനുകൾ
// ---------------------------------------------------------------
const LANG_CODES = { ml: 'ml', en: 'en', ta: 'ta', hi: 'hi', kn: 'kn' };

const LABELS = {
    ml: {
        google: '**ഗൂഗിൾ സെർച്ച് ഫലങ്ങൾ:**',
        youtube: '**യൂട്യൂബ് വീഡിയോകൾ:**',
        more: 'കൂടുതൽ വായിക്കാം',
        watch: 'വീഡിയോ കാണാം',
        none: 'ക്ഷമിക്കണം, ഈ ചോദ്യത്തിനുള്ള കൃത്യമായ വിവരം ഡാറ്റാബേസിലോ ഗൂഗിൾ സെർച്ചിലോ യൂട്യൂബിലോ ലഭ്യമായില്ല.'
    },
    en: {
        google: '**Google search results:**',
        youtube: '**YouTube videos:**',
        more: 'Read more',
        watch: 'Watch video',
        none: 'Sorry, no matching information was found in the database, Google search or YouTube.'
    }
};

function cleanText(str) {
    return String(str || '').replace(/[\[\]]/g, '').replace(/\s+/g, ' ').trim();
}

async function saveAndReply(res, userId, query, responseText) {
    await pool.query(
        'INSERT INTO chat_history (user_id, query_text, response_text, is_new_knowledge) VALUES (?, ?, ?, ?)',
        [userId, query, responseText, 0]
    );
    const subCheck = await getActiveSubscription(userId);
    return res.json({ response: responseText, attemptsLeft: subCheck ? subCheck.attempts_left : FREE_ATTEMPTS });
}

async function googleSearch(query, language) {
    const key = process.env.GOOGLE_SEARCH_API_KEY;
    const cx = process.env.GOOGLE_SEARCH_CX;
    if (!key || !cx) return [];
    const url = `https://www.googleapis.com/customsearch/v1?key=${encodeURIComponent(key)}&cx=${encodeURIComponent(cx)}` +
        `&q=${encodeURIComponent(query)}&num=3&hl=${LANG_CODES[language] || 'ml'}`;
    const r = await fetch(url);
    const data = await r.json();
    if (data.error) throw new Error(data.error.message || 'Google Search error');
    return (data.items || []).slice(0, 3);
}

async function youtubeSearch(query, language) {
    const key = process.env.YOUTUBE_API_KEY;
    if (!key) return [];
    const url = `https://www.googleapis.com/youtube/v3/search?part=snippet&type=video&maxResults=3` +
        `&q=${encodeURIComponent(query)}&relevanceLanguage=${LANG_CODES[language] || 'ml'}&regionCode=IN&key=${encodeURIComponent(key)}`;
    const r = await fetch(url);
    const data = await r.json();
    if (data.error) throw new Error(data.error.message || 'YouTube API error');
    return (data.items || []).filter(v => v.id && v.id.videoId).slice(0, 3);
}

// ---------------------------------------------------------------
// Chat Endpoint: 1) sasyamitra_db  2) Google Search + YouTube
// ---------------------------------------------------------------
app.post('/api/chat', requireAuth, async (req, res) => {
    try {
        const userId = req.userId;
        const query = String((req.body && req.body.query) || '').trim();
        const language = String((req.body && req.body.language) || 'ml').trim();
        const labels = LABELS[language] || LABELS.ml;
        const imageData = req.body.image;

        let savedImagePath = null;
        if (imageData) {
            const matches = imageData.match(/^data:image\/([A-Za-z-+\/]+);base64,(.+)$/);
            if (matches && matches.length === 3) {
                const ext = matches[1] === 'jpeg' ? 'jpg' : matches[1];
                const base64Data = matches[2];
                const fileName = `img_${Date.now()}_${Math.floor(Math.random() * 1000)}.${ext}`;
                const filePath = path.join(uploadDir, fileName);
                fs.writeFileSync(filePath, Buffer.from(base64Data, 'base64'));
                savedImagePath = `/uploads/${fileName}`;
            }
        }

        if (!query && !savedImagePath) {
            return res.status(400).json({ error: 'Please type a question or upload an image.' });
        }

        const cleanQuery = query.toLowerCase();

        // 1. ലോക്കൽ ഡാറ്റാബേസ് (sasyamitra_db)
        if (cleanQuery && !savedImagePath) {
            const [greetingRows] = await pool.query(
                `SELECT response_text FROM multi_language_greetings 
                 WHERE language_code = ? AND keyword <> '' AND (
                    ? LIKE CONCAT('%', keyword, '%') 
                    OR keyword LIKE CONCAT('%', ?, '%')
                 ) LIMIT 1`,
                [language, cleanQuery, cleanQuery]
            );
            if (greetingRows.length > 0) {
                return await saveAndReply(res, userId, query, greetingRows[0].response_text);
            }

            try {
                const [keywordRows] = await pool.query(
                    `SELECT problem_name, symptoms, organic_remedy, chemical_remedy 
                     FROM kw_problem_keywords 
                     WHERE (problem_name <> '' AND ? LIKE CONCAT('%', problem_name, '%')) 
                        OR (keywords <> '' AND ? LIKE CONCAT('%', keywords, '%'))
                     LIMIT 1`,
                    [cleanQuery, cleanQuery]
                );
                if (keywordRows.length > 0) {
                    const prob = keywordRows[0];
                    const responseText = `**വിള രോഗ വിവരങ്ങൾ (${prob.problem_name}):**\n\n* **ലക്ഷണങ്ങൾ:** ${prob.symptoms}\n* **ജൈവ പ്രതിവിധി:** ${prob.organic_remedy}\n* **രാസ പ്രതിവിധി:** ${prob.chemical_remedy}`;
                    return await saveAndReply(res, userId, query, responseText);
                }
            } catch (dbSearchErr) {
                console.log('Keyword search table check skipped:', dbSearchErr.message);
            }
        }

        // 2. ഗൂഗിൾ സെർച്ചും യൂട്യൂബും ഒരുമിച്ച്
        if (cleanQuery) {
            const [googleResult, youtubeResult] = await Promise.allSettled([
                googleSearch(query, language),
                youtubeSearch(query, language)
            ]);

            if (googleResult.status === 'rejected') console.error('Google Search error:', googleResult.reason.message);
            if (youtubeResult.status === 'rejected') console.error('YouTube error:', youtubeResult.reason.message);

            const googleItems = googleResult.status === 'fulfilled' ? googleResult.value : [];
            const youtubeItems = youtubeResult.status === 'fulfilled' ? youtubeResult.value : [];

            const parts = [];
            if (googleItems.length > 0) {
                const lines = googleItems.map(item =>
                    `* **${cleanText(item.title)}**\n${cleanText(item.snippet)}\n[${labels.more}](${item.link})`
                );
                parts.push(`${labels.google}\n\n${lines.join('\n\n')}`);
            }
            if (youtubeItems.length > 0) {
                const lines = youtubeItems.map(v =>
                    `* [${cleanText(v.snippet.title)}](https://www.youtube.com/watch?v=${v.id.videoId})`
                );
                parts.push(`${labels.youtube}\n\n${lines.join('\n')}`);
            }

            if (parts.length > 0) {
                return await saveAndReply(res, userId, query, parts.join('\n\n'));
            }
        }

        // ഒന്നും കിട്ടിയില്ലെങ്കിൽ
        return await saveAndReply(res, userId, query || '[Image Upload]', labels.none);

    } catch (err) {
        console.error('Chat error:', err);
        res.status(500).json({ error: 'Server error occurred.' });
    }
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`Sasyamitra server running at http://localhost:${PORT}`);
});
