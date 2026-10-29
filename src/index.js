
const SESSION_DAYS = 7;
const PASSWORD_ITERATIONS = 310000;
const ALLOWED_ORIGIN = "https://clearcents.acrunch2012.workers.dev";

function json(data, status = 200, origin = ALLOWED_ORIGIN) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "Access-Control-Allow-Origin": origin,
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
      "Vary": "Origin"
    }
  });
}

function randomToken() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return Array.from(bytes, b => b.toString(16).padStart(2, "0")).join("");
}

async function sha256(value) {
  const data = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value)
  );
  return Array.from(new Uint8Array(data), b =>
    b.toString(16).padStart(2, "0")
  ).join("");
}

async function hashPassword(password, saltHex) {
  const salt = Uint8Array.from(
    saltHex.match(/.{2}/g),
    byte => parseInt(byte, 16)
  );

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt,
      iterations: PASSWORD_ITERATIONS
    },
    key,
    256
  );

  return Array.from(new Uint8Array(bits), b =>
    b.toString(16).padStart(2, "0")
  ).join("");
}

function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  let difference = 0;
  for (let i = 0; i < a.length; i++) {
    difference |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return difference === 0;
}

async function createSession(env, userId) {
  const token = randomToken();
  const tokenHash = await sha256(token);
  const expires = new Date(Date.now() + SESSION_DAYS * 86400000)
    .toISOString();

  await env.DB.prepare(
    `INSERT INTO sessions (id, user_id, token_hash, expires_at)
     VALUES (?, ?, ?, ?)`
  ).bind(crypto.randomUUID(), userId, tokenHash, expires).run();

  return { token, expires };
}

async function authenticatedUser(request, env) {
  const header = request.headers.get("Authorization") || "";
  const match = header.match(/^Bearer ([a-f0-9]{64})$/i);
  if (!match) return null;

  const tokenHash = await sha256(match[1]);

  return await env.DB.prepare(
    `SELECT users.id, users.email
     FROM sessions
     JOIN users ON users.id = sessions.user_id
     WHERE sessions.token_hash = ?
       AND sessions.expires_at > ?`
  ).bind(tokenHash, new Date().toISOString()).first();
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const origin = request.headers.get("Origin") || "";

    if (origin && origin !== ALLOWED_ORIGIN) {
      return json({ error: "Origin not allowed" }, 403);
    }

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: {
          "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
          "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type, Authorization",
          "Vary": "Origin"
        }
      });
    }

    if (url.pathname === "/api/health" && request.method === "GET") {
      return json({ app: "ClearCents", status: "online" });
    }

    if (url.pathname === "/api/db-test" && request.method === "GET") {
      const result = await env.DB.prepare(
        "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name"
      ).all();

      return json({
        app: "ClearCents",
        database: "connected",
        tables: result.results.map(row => row.name)
      });
    }

    if (url.pathname === "/api/signup" && request.method === "POST") {
      let body;
      try {
        body = await request.json();
      } catch {
        return json({ error: "Invalid JSON" }, 400);
      }

      const email = typeof body.email === "string"
        ? body.email.trim().toLowerCase()
        : "";
      const password = typeof body.password === "string"
        ? body.password
        : "";

      if (email.length > 254 ||
          !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        return json({ error: "Enter a valid email address" }, 400);
      }

      if (password.length < 12 || password.length > 128) {
        return json({
          error: "Password must be between 12 and 128 characters"
        }, 400);
      }

      const existing = await env.DB.prepare(
        "SELECT id FROM users WHERE email = ?"
      ).bind(email).first();

      if (existing) {
        return json({ error: "Unable to create account with these details" }, 409);
      }

      const salt = randomToken().slice(0, 32);
      const passwordHash = await hashPassword(password, salt);
      const userId = crypto.randomUUID();

      try {
        await env.DB.prepare(
          `INSERT INTO users (id, email, password_hash)
           VALUES (?, ?, ?)`
        ).bind(userId, email, `${salt}:${passwordHash}`).run();
      } catch {
        return json({ error: "Unable to create account. Please try again." }, 409);
      }

      const session = await createSession(env, userId);

      return json({
        user: { id: userId, email },
        token: session.token,
        expiresAt: session.expires
      }, 201);
    }

    if (url.pathname === "/api/login" && request.method === "POST") {
      let body;
      try {
        body = await request.json();
      } catch {
        return json({ error: "Invalid JSON" }, 400);
      }

      const email = typeof body.email === "string"
        ? body.email.trim().toLowerCase()
        : "";
      const password = typeof body.password === "string"
        ? body.password
        : "";

      if (!email || !password || password.length > 128) {
        return json({ error: "Invalid email or password" }, 400);
      }

      const user = await env.DB.prepare(
        "SELECT id, email, password_hash FROM users WHERE email = ?"
      ).bind(email).first();

      if (!user) {
        return json({ error: "Invalid email or password" }, 401);
      }

      const [salt, storedHash] = user.password_hash.split(":");
      if (!salt || !storedHash) {
        return json({ error: "Unable to log in" }, 500);
      }

      const suppliedHash = await hashPassword(password, salt);
      if (!safeEqual(suppliedHash, storedHash)) {
        return json({ error: "Invalid email or password" }, 401);
      }

      const session = await createSession(env, user.id);

      return json({
        user: { id: user.id, email: user.email },
        token: session.token,
        expiresAt: session.expires
      });
    }

    if (url.pathname === "/api/me" && request.method === "GET") {
      const user = await authenticatedUser(request, env);
      if (!user) return json({ error: "Please log in" }, 401);
      return json({ user });
    }

    if (url.pathname === "/api/logout" && request.method === "POST") {
      const header = request.headers.get("Authorization") || "";
      const match = header.match(/^Bearer ([a-f0-9]{64})$/i);

      if (match) {
        await env.DB.prepare(
          "DELETE FROM sessions WHERE token_hash = ?"
        ).bind(await sha256(match[1])).run();
      }

      return json({ success: true });
    }

    return json({ error: "Not found" }, 404);
  }
};
