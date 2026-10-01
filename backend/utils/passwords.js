// Password rules shared by login, change-password, seed and set-password.
import crypto from 'crypto';
import bcrypt from 'bcryptjs';

// Passwords that shipped with older versions or are too common to allow.
export const DEFAULT_PASSWORDS = [
  'admin123', 'analyst123', 'password', 'password123', 'admin', 'changeme', '12345678', '123456',
];

export const MIN_PASSWORD_LENGTH = 8;

export const isDefaultPassword = (plain) =>
  typeof plain === 'string' && DEFAULT_PASSWORDS.includes(plain.trim().toLowerCase());

/** Returns an error message, or null when the new password is acceptable. */
export function validateNewPassword(plain) {
  if (typeof plain !== 'string' || plain.length < MIN_PASSWORD_LENGTH) {
    return `Password must be at least ${MIN_PASSWORD_LENGTH} characters.`;
  }
  if (isDefaultPassword(plain)) {
    return 'That password is a known default/common password. Choose a different one.';
  }
  if (!/[A-Za-z]/.test(plain) || !/[0-9]/.test(plain)) {
    return 'Password must contain at least one letter and one number.';
  }
  return null;
}

/** Random password such as "Kq7m-P2xd-9RtB-w4Nz" for first-time seeding. */
export function generatePassword() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789';
  const bytes = crypto.randomBytes(16);
  let out = '';
  for (let i = 0; i < 16; i++) {
    if (i && i % 4 === 0) out += '-';
    out += chars[bytes[i] % chars.length];
  }
  // guarantee at least one digit and one letter for validateNewPassword()
  return /[0-9]/.test(out) && /[A-Za-z]/.test(out) ? out : generatePassword();
}

/**
 * Startup check: warn in the backend log about accounts that still use a
 * shipped default password. Only checks the first few accounts so start-up
 * stays fast.
 */
export async function warnAboutDefaultPasswords(User, logger) {
  try {
    const users = await User.find({}, { email: 1, password: 1 }).limit(20).lean();
    for (const u of users) {
      for (const pw of ['admin123', 'analyst123']) {
        if (u.password && (await bcrypt.compare(pw, u.password))) {
          logger.warn(
            `SECURITY: user ${u.email} still uses the default password "${pw}". ` +
            'Change it in the dashboard (Settings → Security → Change Password) ' +
            `or run: npm run set-password -- ${u.email} <new-password>`
          );
          break;
        }
      }
    }
  } catch (err) {
    logger.warn(`Default-password check skipped: ${err.message}`);
  }
}
