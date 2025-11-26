const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const app = express();
const PORT = process.env.PORT || 4000; 
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-this';

// ====== 미들웨어 ======
app.use(cors());              // CORS 허용 (개발용)
app.use(express.json());      // JSON 바디 파싱

// ====== DB 초기화 ======
const dbPath = path.join(__dirname, 'database.sqlite');
const db = new sqlite3.Database(dbPath);

// 테이블 생성
db.serialize(() => {
  // 유저 테이블
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL
    )
  `);

  // 멤버 테이블 (캐릭터)
  db.run(`
    CREATE TABLE IF NOT EXISTS members (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      name TEXT NOT NULL,
      data_json TEXT NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id)
    )
  `);
});

// ====== JWT 인증 미들웨어 ======
function authMiddleware(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'No token' });

  const [, token] = authHeader.split(' '); // 'Bearer xxx'

  if (!token) return res.status(401).json({ error: 'Invalid token format' });

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ error: 'Invalid token' });
    req.user = decoded; // { id, username }
    next();
  });
}

// ====== 회원가입 ======
app.post('/api/auth/register', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ error: 'username, password 필요' });

  const saltRounds = 10;
  bcrypt.hash(password, saltRounds, (err, hash) => {
    if (err) return res.status(500).json({ error: 'hash error' });

    const stmt = db.prepare('INSERT INTO users (username, password_hash) VALUES (?, ?)');
    stmt.run(username, hash, function (err2) {
      if (err2) {
        if (err2.message.includes('UNIQUE')) {
          return res.status(400).json({ error: '이미 존재하는 아이디' });
        }
        return res.status(500).json({ error: 'db error' });
      }

      const user = { id: this.lastID, username };
      const token = jwt.sign(user, JWT_SECRET, { expiresIn: '7d' });
      res.json({ user, token });
    });
    stmt.finalize();
  });
});

// ====== 로그인 ======
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ error: 'username, password 필요' });

  db.get('SELECT * FROM users WHERE username = ?', [username], (err, row) => {
    if (err) return res.status(500).json({ error: 'db error' });
    if (!row) return res.status(400).json({ error: '존재하지 않는 계정' });

    bcrypt.compare(password, row.password_hash, (err2, same) => {
      if (err2) return res.status(500).json({ error: 'compare error' });
      if (!same) return res.status(400).json({ error: '비밀번호 불일치' });

      const user = { id: row.id, username: row.username };
      const token = jwt.sign(user, JWT_SECRET, { expiresIn: '7d' });
      res.json({ user, token });
    });
  });
});

// ====== 내 정보 (테스트용) ======
app.get('/api/me', authMiddleware, (req, res) => {
  res.json({ user: req.user });
});

// 멤버 목록 조회 ======
app.get('/api/members', authMiddleware, (req, res) => {
  const userId = req.user.id;
  db.all('SELECT * FROM members WHERE user_id = ?', [userId], (err, rows) => {
    if (err) return res.status(500).json({ error: 'db error' });

    const members = rows.map(r => {
        try {
            const obj = JSON.parse(r.data_json || '{}');
            // data_json 안에 name이 없으면 DB name 컬럼을 채워준다
            if (!obj.name) obj.name = r.name;
            return obj;    // ★ 프론트에서 만든 id 포함 전체 객체 그대로 반환
            } catch (e) {
                console.error('member 파싱 실패', e);
            // 문제가 있어도 최소한 이름만 가진 객체 하나는 돌려줌
        return { name: r.name };
    }
    });

    res.json(members);
  });
});

app.post('/api/members', authMiddleware, (req, res) => {
  const userId = req.user.id;
  const members = req.body.members;

  if (!Array.isArray(members)) {
    return res.status(400).json({ error: 'members 배열 필요' });
  }

  db.serialize(() => {
    db.run('DELETE FROM members WHERE user_id = ?', [userId], err => {
      if (err) return res.status(500).json({ error: 'db delete error' });

      const stmt = db.prepare(
        'INSERT INTO members (user_id, name, data_json) VALUES (?, ?, ?)'
      );

      for (const m of members) {
        const { name, ...rest } = m;
        stmt.run(
          userId,
          name || 'NoName',
          JSON.stringify(rest || {})
        );
      }

      stmt.finalize(err2 => {
        if (err2) return res.status(500).json({ error: 'db insert error' });
        res.json({ ok: true });
      });
    });
  });
});

// 서버 스타트
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
