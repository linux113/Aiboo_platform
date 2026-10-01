import mongoose from 'mongoose';
import dotenv from 'dotenv';
import bcrypt from 'bcryptjs';

dotenv.config();

import User from './models/User.js';
import { generatePassword, validateNewPassword } from './utils/passwords.js';

const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/aiboo';

// Passwords come from backend/.env (SEED_ADMIN_PASSWORD / SEED_ANALYST_PASSWORD).
// If they are not set, a random password is generated and printed ONCE below.
// There are no built-in default passwords any more.
function pickPassword(envName) {
  const fromEnv = process.env[envName];
  if (fromEnv) {
    const problem = validateNewPassword(fromEnv);
    if (problem) {
      console.error(`❌ ${envName} rejected: ${problem}`);
      process.exit(1);
    }
    return { password: fromEnv, source: `from ${envName} in .env` };
  }
  return { password: generatePassword(), source: 'randomly generated' };
}

async function seed() {
  const admin = pickPassword('SEED_ADMIN_PASSWORD');
  const analyst = pickPassword('SEED_ANALYST_PASSWORD');

  await mongoose.connect(MONGO_URI);
  console.log('✅ MongoDB Connected');
  console.log('🧹 Dropping database...');
  await mongoose.connection.db.dropDatabase();

  // ── Users (bypass pre-save hook to avoid double-hash) ──────────
  const adminHash = await bcrypt.hash(admin.password, 10);
  const analystHash = await bcrypt.hash(analyst.password, 10);
  await User.collection.insertMany([
    { name:'Admin',   email:'admin@example.com',   password:adminHash,   role:'admin',   createdAt:new Date(), updatedAt:new Date() },
    { name:'Analyst', email:'analyst@example.com', password:analystHash, role:'analyst', createdAt:new Date(), updatedAt:new Date() },
  ]);

  console.log('✅ Users only — no demo cameras, detections, or threats');
  console.log('\n🎉 SEEDING COMPLETE — login details (save them now, they are not shown again):');
  console.log(`   admin@example.com   / ${admin.password}   (${admin.source})`);
  console.log(`   analyst@example.com / ${analyst.password}   (${analyst.source})`);
  console.log('\n   Change a password later with:  npm run set-password -- <email> <new-password>');
  process.exit(0);
}

seed().catch(e => { console.error('❌ Seed failed:', e); process.exit(1); });
