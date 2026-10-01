// Change a user's password WITHOUT wiping the database.
//   npm run set-password -- admin@example.com MyNewPassw0rd
import mongoose from 'mongoose';
import dotenv from 'dotenv';

dotenv.config();

import User from './models/User.js';
import { validateNewPassword } from './utils/passwords.js';

const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/aiboo';

async function main() {
  const [email, newPassword] = process.argv.slice(2);
  if (!email || !newPassword) {
    console.log('Usage: npm run set-password -- <email> <new-password>');
    process.exit(1);
  }
  const problem = validateNewPassword(newPassword);
  if (problem) {
    console.error(`❌ ${problem}`);
    process.exit(1);
  }

  await mongoose.connect(MONGO_URI);
  const user = await User.findOne({ email: email.trim().toLowerCase() }) || await User.findOne({ email: email.trim() });
  if (!user) {
    console.error(`❌ No user with email ${email}`);
    process.exit(1);
  }
  user.password = newPassword; // hashed by the model's pre-save hook
  await user.save();
  console.log(`✅ Password changed for ${user.email}`);
  process.exit(0);
}

main().catch(e => { console.error('❌ Failed:', e.message); process.exit(1); });
