// Login + roles: admin / analyst / viewer, and the closed registration hole.
// Run: npm test   (no MongoDB needed - the User model is faked in memory)
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import jwt from 'jsonwebtoken';

process.env.ALERT_STORE = 'memory';
process.env.JWT_SECRET = 'test-secret';
process.env.AGENT_API_KEY = 'test-agent-key';

const bcrypt = (await import('bcryptjs')).default;
const mongoose = (await import('mongoose')).default;
const User = (await import('../models/User.js')).default;
const { default: authRoutes } = await import('../routes/auth.routes.js');
const { default: userRoutes } = await import('../routes/user.routes.js');
const { default: agentRoutes } = await import('../routes/agent.routes.js');
const { errorHandler } = await import('../middleware/error.js');

// Pretend MongoDB is connected so the auth middleware re-reads the user from our
// fake store (that is what makes "disable now" and "role change now" work).
// Must happen after the User model is compiled.
Object.defineProperty(mongoose.connection, 'readyState', { value: 1, configurable: true, writable: true });

// ---------------------------------------------------------------- fake store
// The real queries the services use: find/findOne/findById/create/save.
const users = [];
let seq = 0;
const hashed = (pw) => String(pw || '').startsWith('$2') ? pw : bcrypt.hashSync(pw, 4);

const asQuery = (arr) => {
  const q = {
    select() { return q; },
    sort() { return q; },
    then(res, rej) { return Promise.resolve(arr).then(res, rej); },
  };
  return q;
};
const asDoc = (doc) => {
  const q = {
    select() { return q; },
    sort() { return q; },
    then(res, rej) { return Promise.resolve(doc).then(res, rej); },
  };
  return q;
};
const matches = (doc, q) => Object.entries(q || {}).every(([k, v]) => String(doc[k] ?? '').toLowerCase() === String(v).toLowerCase());

const makeUser = (doc) => {
  const u = {
    _id: `u${++seq}`,
    name: doc.name,
    email: doc.email,
    password: hashed(doc.password),
    role: doc.role || 'viewer',
    active: doc.active !== false,
    lastLogin: doc.lastLogin || null,
    createdAt: new Date(),
    async matchPassword(pw) { return bcrypt.compare(pw, this.password); },
    async save() { this.password = hashed(this.password); return this; },
  };
  users.push(u);
  return u;
};

User.find = (q) => asQuery(users.filter((u) => matches(u, q)));
User.findOne = async (q) => users.find((u) => matches(u, q)) || null;
User.findById = (id) => asDoc(users.find((u) => String(u._id) === String(id)) || null);
User.findByIdAndUpdate = async (id, patch) => { const u = await User.findById(id); if (u) Object.assign(u, patch); return u; };

User.create = async (doc) => makeUser(doc);

// ---------------------------------------------------------------- test server
let server;
let base;
const token = (role, email = `${role}@test`, id = `t_${role}`) => jwt.sign({ id, role, email, name: role }, 'test-secret');
const call = async (method, path, { body, tok } = {}) => {
  const headers = { 'Content-Type': 'application/json' };
  if (tok) headers.Authorization = `Bearer ${tok}`;
  const res = await fetch(base + path, { method, headers, body: body ? JSON.stringify(body) : undefined });
  const text = await res.text();
  let data; try { data = JSON.parse(text); } catch { data = text; }
  return { status: res.status, data };
};

// Tokens carry the real _id: the API compares it with the stored user to stop
// an admin from changing their own role.
let ADMIN;
let ANALYST;
let VIEWER;

before(async () => {
  const a = makeUser({ name: 'Admin', email: 'admin@test', password: 'Admin12345', role: 'admin' });
  const n = makeUser({ name: 'Analyst', email: 'analyst@test', password: 'Analyst12345', role: 'analyst' });
  const v = makeUser({ name: 'Viewer', email: 'viewer@test', password: 'Viewer12345', role: 'viewer' });
  makeUser({ name: 'Gone', email: 'off@test', password: 'Off12345678', role: 'analyst', active: false });
  ADMIN = token('admin', 'admin@test', a._id);
  ANALYST = token('analyst', 'analyst@test', n._id);
  VIEWER = token('viewer', 'viewer@test', v._id);

  const app = express();
  app.use(express.json());
  app.use('/api/auth', authRoutes);
  app.use('/api/users', userRoutes);
  app.use('/api/agent', agentRoutes);
  app.use(errorHandler);
  await new Promise((resolve) => { server = app.listen(0, resolve); });
  base = `http://127.0.0.1:${server.address().port}`;
});

after(() => server?.close());

// ------------------------------------------------------------------ the hole
test('a stranger can no longer register (that used to create admins)', async () => {
  const res = await call('POST', '/api/auth/register', { body: { name: 'X', email: 'x@evil', password: 'Evil12345678', role: 'admin' } });
  assert.equal(res.status, 401);
  assert.equal(await User.findOne({ email: 'x@evil' }), null);
});

test('an analyst cannot create accounts', async () => {
  const res = await call('POST', '/api/auth/register', { tok: ANALYST, body: { name: 'X', email: 'x2@evil', password: 'Evil12345678', role: 'admin' } });
  assert.equal(res.status, 403);
  assert.equal(await User.findOne({ email: 'x2@evil' }), null);
});

test('an admin creates a user, and the role defaults to viewer', async () => {
  const res = await call('POST', '/api/users', { tok: ADMIN, body: { name: 'New Person', email: 'new@test', password: 'NewPerson123' } });
  assert.equal(res.status, 201);
  assert.equal(res.data.user.role, 'viewer');
  assert.equal(res.data.user.active, true);
});

test('weak passwords are refused with the real rule', async () => {
  const res = await call('POST', '/api/users', { tok: ADMIN, body: { name: 'W', email: 'w@test', password: 'password' } });
  assert.equal(res.status, 400);
  assert.match(res.data.message, /default|common|at least/i);
});

test('a bad role is refused', async () => {
  const res = await call('POST', '/api/users', { tok: ADMIN, body: { name: 'R', email: 'r@test', password: 'RoleCheck123', role: 'root' } });
  assert.equal(res.status, 400);
  assert.match(res.data.message, /role must be one of/i);
});

// -------------------------------------------------------------------- logins
test('all three roles can log in and get their role back', async () => {
  for (const [email, pw, role] of [
    ['admin@test', 'Admin12345', 'admin'],
    ['analyst@test', 'Analyst12345', 'analyst'],
    ['viewer@test', 'Viewer12345', 'viewer'],
  ]) {
    const res = await call('POST', '/api/auth/login', { body: { email, password: pw } });
    assert.equal(res.status, 200, `${role} login failed`);
    assert.equal(res.data.user.role, role);
    assert.ok(res.data.token);
    assert.equal(res.data.user.password, undefined, 'the hash must never be sent');
  }
});

test('a wrong password is still refused', async () => {
  const res = await call('POST', '/api/auth/login', { body: { email: 'admin@test', password: 'wrong' } });
  assert.equal(res.status, 401);
});

test('a disabled account cannot log in', async () => {
  const res = await call('POST', '/api/auth/login', { body: { email: 'off@test', password: 'Off12345678' } });
  assert.equal(res.status, 403);
  assert.match(res.data.message, /disabled/i);
});

// --------------------------------------------------------------- role gates
test('only an admin can see or manage users', async () => {
  assert.equal((await call('GET', '/api/users', { tok: ANALYST })).status, 403);
  assert.equal((await call('GET', '/api/users', { tok: VIEWER })).status, 403);
  const admin = await call('GET', '/api/users', { tok: ADMIN });
  assert.equal(admin.status, 200);
  assert.ok(Array.isArray(admin.data.users));
  assert.ok(admin.data.users.every((u) => u.password === undefined));
});

test('a viewer cannot dispatch a response command, an analyst can', async () => {
  const asViewer = await call('POST', '/api/agent/commands', { tok: VIEWER, body: { endpoint_id: 'linux-01', action: 'block_access', target: '45.95.147.3' } });
  assert.equal(asViewer.status, 403);
  const asAnalyst = await call('POST', '/api/agent/commands', { tok: ANALYST, body: { endpoint_id: 'linux-01', action: 'block_access', target: '45.95.147.3' } });
  assert.equal(asAnalyst.status, 202);
});

// --------------------------------------------------------- lock-out guards
test('an admin cannot change their own role or disable themselves', async () => {
  const me = await User.findOne({ email: 'admin@test' });
  const demote = await call('PATCH', `/api/users/${me._id}`, { tok: ADMIN, body: { role: 'viewer' } });
  assert.equal(demote.status, 400);
  assert.match(demote.data.message, /your own role/i);
  const off = await call('PATCH', `/api/users/${me._id}`, { tok: ADMIN, body: { active: false } });
  assert.equal(off.status, 400);
  assert.match(off.data.message, /your own account/i);
});

test('one admin can demote another, but the last admin is protected', async () => {
  const svc = await import('../services/auth.service.js');
  const first = await User.findOne({ email: 'admin@test' });
  const second = makeUser({ name: 'Admin Two', email: 'admin2@test', password: 'AdminTwo123', role: 'admin' });
  const third = makeUser({ name: 'Admin Three', email: 'admin3@test', password: 'AdminThree123', role: 'admin' });
  const secondTok = token('admin', 'admin2@test', second._id);
  const thirdTok = token('admin', 'admin3@test', third._id);

  // admin1 demotes admin2 - allowed, two admins are left
  const ok = await call('PATCH', `/api/users/${second._id}`, { tok: ADMIN, body: { role: 'analyst' } });
  assert.equal(ok.status, 200);
  assert.equal(ok.data.user.role, 'analyst');

  // admin3 demotes admin1 - now admin3 is the only admin left
  const ok2 = await call('PATCH', `/api/users/${first._id}`, { tok: thirdTok, body: { role: 'analyst' } });
  assert.equal(ok2.status, 200);

  // the guard itself (belt and braces, also used by the add-user script)
  await assert.rejects(
    () => svc.updateUser(third._id, { role: 'analyst' }, { id: second._id, role: 'admin' }),
    (err) => /last admin/i.test(String(err?.message)),
  );
  await assert.rejects(
    () => svc.disableUser(third._id, { id: second._id, role: 'admin' }),
    (err) => /last admin/i.test(String(err?.message)),
  );

  // put admin1 back so the tests below keep their admin
  await svc.updateUser(first._id, { role: 'admin' }, { id: third._id, role: 'admin' });
  assert.equal((await User.findById(first._id)).role, 'admin');
});

test('deleting a user only disables the account', async () => {
  const created = await call('POST', '/api/users', { tok: ADMIN, body: { name: 'Temp', email: 'temp@test', password: 'TempPass1234', role: 'analyst' } });
  const id = created.data.user.id;
  const del = await call('DELETE', `/api/users/${id}`, { tok: ADMIN });
  assert.equal(del.status, 200);
  assert.equal(del.data.user.active, false);
  assert.ok(await User.findById(id), 'the account is kept for history');
  const login = await call('POST', '/api/auth/login', { body: { email: 'temp@test', password: 'TempPass1234' } });
  assert.equal(login.status, 403);
});

test('an admin can reset another user password, and the new one works', async () => {
  const v = await User.findOne({ email: 'viewer@test' });
  const res = await call('PATCH', `/api/users/${v._id}`, { tok: ADMIN, body: { password: 'BrandNew12345' } });
  assert.equal(res.status, 200);
  assert.equal((await call('POST', '/api/auth/login', { body: { email: 'viewer@test', password: 'BrandNew12345' } })).status, 200);
  assert.equal((await call('POST', '/api/auth/login', { body: { email: 'viewer@test', password: 'Viewer12345' } })).status, 401);
});

test('disabling an account kills the session it already had', async () => {
  const created = await call('POST', '/api/users', { tok: ADMIN, body: { name: 'Temp Two', email: 'temp2@test', password: 'TempTwo12345', role: 'analyst' } });
  const id = created.data.user.id;
  const theirToken = token('analyst', 'temp2@test', id);
  assert.equal((await call('GET', '/api/auth/me', { tok: theirToken })).status, 200);

  await call('PATCH', `/api/users/${id}`, { tok: ADMIN, body: { active: false } });

  // the 7-day token is no longer good: the account is read from the database
  const after = await call('GET', '/api/auth/me', { tok: theirToken });
  assert.equal(after.status, 403);
  assert.match(after.data.message, /disabled/i);
});

test('lowering a role takes effect on the next request, not at the next login', async () => {
  const created = await call('POST', '/api/users', { tok: ADMIN, body: { name: 'Temp Three', email: 'temp3@test', password: 'TempThree1234', role: 'analyst' } });
  const id = created.data.user.id;
  const theirToken = token('analyst', 'temp3@test', id);
  assert.equal((await call('POST', '/api/agent/commands', { tok: theirToken, body: { endpoint_id: 'linux-01', action: 'block_access', target: '45.95.147.3' } })).status, 202);

  await call('PATCH', `/api/users/${id}`, { tok: ADMIN, body: { role: 'viewer' } });

  const after = await call('POST', '/api/agent/commands', { tok: theirToken, body: { endpoint_id: 'linux-01', action: 'block_access', target: '45.95.147.3' } });
  assert.equal(after.status, 403);
});
