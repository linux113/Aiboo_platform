import mongoose from 'mongoose';
import dotenv from 'dotenv';
import bcrypt from 'bcryptjs';

dotenv.config();

import User from './models/User.js';

const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/aiboo';

async function seed() {
  await mongoose.connect(MONGO_URI);
  console.log('✅ MongoDB Connected');
  console.log('🧹 Dropping database...');
  await mongoose.connection.db.dropDatabase();

  // ── Users (bypass pre-save hook to avoid double-hash) ──────────
  const adminHash  = await bcrypt.hash('admin123',  10);
  const analystHash = await bcrypt.hash('analyst123', 10);
  await User.collection.insertMany([
    { name:'Admin',   email:'admin@example.com',   password:adminHash,   role:'admin',   createdAt:new Date(), updatedAt:new Date() },
    { name:'Analyst', email:'analyst@example.com', password:analystHash, role:'analyst', createdAt:new Date(), updatedAt:new Date() },
  ]);
  console.log('✅ Users: admin@example.com/admin123 · analyst@example.com/analyst123');

  console.log('✅ Users only — no demo cameras, detections, or threats');

  console.log('\n🎉 SEEDING COMPLETE');
  console.log('   admin@example.com  / admin123');
  console.log('   analyst@example.com / analyst123');
  process.exit(0);
}

seed().catch(e => { console.error('❌ Seed failed:', e); process.exit(1); });
