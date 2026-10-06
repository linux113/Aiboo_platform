// Add a user (or reset one) WITHOUT wiping the database.
//
//   npm run add-user -- --email viewer@example.com --name Viewer --role viewer --password 'Viewer12345'
//   npm run add-user -- --email analyst@example.com --role analyst          (role change only)
//   npm run add-user -- --email viewer@example.com --disable
//
// Roles: admin (full access), analyst (investigate + respond), viewer (read only).
// The dashboard equivalent is Settings -> Users, which needs you to be an admin.
import mongoose from 'mongoose';
import dotenv from 'dotenv';

dotenv.config();

import User from './models/User.js';
import { validateNewPassword } from './utils/passwords.js';
import { ROLES } from './services/auth.service.js';

const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/aiboo';

function parseArgs(argv) {
  const out = { flags: {} };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (!a.startsWith('--')) continue;
    const key = a.slice(2);
    const next = argv[i + 1];
    if (next === undefined || next.startsWith('--')) out.flags[key] = true;
    else { out.flags[key] = next; i += 1; }
  }
  return out.flags;
}

async function main() {
  const f = parseArgs(process.argv.slice(2));
  const email = String(f.email || '').trim().toLowerCase();
  if (!email && !f.list) {
    console.log('Usage: npm run add-user -- --email <email> [--name <name>] [--role admin|analyst|viewer]');
    console.log('                          [--password <password>] [--disable | --enable] [--list]');
    process.exit(1);
  }
  await mongoose.connect(MONGO_URI, { serverSelectionTimeoutMS: 5000 });

  if (f.list) {
    const users = await User.find().select('-password').sort({ createdAt: 1 });
    for (const u of users) {
      console.log(`${(u.active === false ? 'OFF ' : 'ON  ')}${String(u.role).padEnd(8)} ${u.email}   ${u.name || ''}`);
    }
    process.exit(0);
  }

  let user = await User.findOne({ email });

  if (!user) {
    const role = String(f.role || 'viewer').toLowerCase();
    if (!ROLES.includes(role)) {
      console.error(`❌ --role must be one of: ${ROLES.join(', ')}`);
      process.exit(1);
    }
    const password = f.password ? String(f.password) : '';
    if (!password) {
      console.error('❌ --password is required when creating a new user');
      process.exit(1);
    }
    const problem = validateNewPassword(password);
    if (problem) { console.error(`❌ ${problem}`); process.exit(1); }
    user = await User.create({ name: String(f.name || role).trim(), email, password, role });
    console.log(`✅ Created ${role} account: ${email}`);
  } else {
    if (f.role) {
      const role = String(f.role).toLowerCase();
      if (!ROLES.includes(role)) { console.error(`❌ --role must be one of: ${ROLES.join(', ')}`); process.exit(1); }
      user.role = role;
      console.log(`✅ ${email} is now ${role}`);
    }
    if (f.password) {
      const problem = validateNewPassword(String(f.password));
      if (problem) { console.error(`❌ ${problem}`); process.exit(1); }
      user.password = String(f.password);
      console.log(`✅ Password reset for ${email}`);
    }
    if (f.disable) { user.active = false; console.log(`✅ ${email} disabled`); }
    if (f.enable) { user.active = true; console.log(`✅ ${email} enabled`); }
    if (f.name) user.name = String(f.name);
    await user.save();
  }

  const all = await User.find().select('-password').sort({ createdAt: 1 });
  console.log('\nAccounts now able to log in:');
  for (const u of all) {
    console.log(`   ${(u.active === false ? 'OFF ' : 'ON  ')}${String(u.role).padEnd(8)} ${u.email}`);
  }
  process.exit(0);
}

main().catch((e) => {
  console.error('❌ Failed:', e.message);
  console.error('   Is MongoDB running and MONGO_URI in backend/.env correct?');
  process.exit(1);
});
