import 'dotenv/config';
import mongoose from 'mongoose';
import User from './models/User.js';
import { validateNewPassword } from './utils/passwords.js';

// One-time platform-admin bootstrap. Set the three environment variables only
// in the server's protected shell/environment; never pass secrets as arguments.
async function main() {
  const email = String(process.env.PLATFORM_ADMIN_EMAIL || '').trim().toLowerCase();
  const name = String(process.env.PLATFORM_ADMIN_NAME || '').trim();
  const password = process.env.PLATFORM_ADMIN_PASSWORD || '';
  if (!process.env.MONGO_URI || !email || !name || !password) {
    throw new Error('Set MONGO_URI, PLATFORM_ADMIN_EMAIL, PLATFORM_ADMIN_NAME and PLATFORM_ADMIN_PASSWORD in the server environment.');
  }
  const passwordError = validateNewPassword(password);
  if (passwordError) throw new Error(passwordError);

  await mongoose.connect(process.env.MONGO_URI);
  if (await User.exists({ role: 'super_admin' })) {
    throw new Error('A platform Super Admin already exists; bootstrap is one-time and will not create another.');
  }
  if (await User.exists({ email })) throw new Error('That email already belongs to an account; use a distinct platform-admin address.');

  await User.create({ name, email, password, role: 'super_admin', organization: null, active: true });
  console.log(`Platform Super Admin created for ${email}. The password was not displayed.`);
}

main()
  .catch((err) => {
    console.error(`Super Admin bootstrap failed: ${err.message}`);
    process.exitCode = 1;
  })
  .finally(async () => { await mongoose.disconnect().catch(() => {}); });
