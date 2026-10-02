// Remove alerts from Alert Management (MongoDB) WITHOUT touching users,
// settings or compliance history.
//
//   npm run clear-alerts -- --old-noise   only the known junk (see below)
//   npm run clear-alerts -- --all         every alert (fresh start for testing)
//   add --dry-run to only count, nothing is deleted
//
// "--old-noise" = alerts made before the 2 Oct 2026 fixes:
//   * "identity mismatch (ZeroTrustAgent / IdentityAgent)" and
//     "insider threat (...)" findings re-sent from an old queue file
//   * finding alerts copied from Windows events (TriGate has its own alert)
//   * "[CORRELATED] ..." cards from the old correlation engine
import mongoose from 'mongoose';
import dotenv from 'dotenv';

dotenv.config();

import Alert from './models/Alert.js';
import { isOldNoiseAlert } from './services/alertStore.js';

const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/aiboo';

async function main() {
  const args = process.argv.slice(2);
  const all = args.includes('--all');
  const noise = args.includes('--old-noise');
  const dry = args.includes('--dry-run');
  if (all === noise) {
    console.log('Usage: npm run clear-alerts -- --old-noise   (only known junk alerts)');
    console.log('       npm run clear-alerts -- --all         (every alert)');
    console.log('       add --dry-run to only count');
    process.exit(1);
  }

  await mongoose.connect(MONGO_URI, { serverSelectionTimeoutMS: 5000 });
  const docs = await Alert.find({}, { alertId: 1, kind: 1, title: 1, description: 1 }).lean();
  const ids = docs.filter((a) => all || isOldNoiseAlert(a)).map((a) => a.alertId);

  if (dry) {
    console.log(`Would delete ${ids.length} of ${docs.length} alert(s). Nothing deleted (--dry-run).`);
  } else if (ids.length) {
    const r = await Alert.deleteMany({ alertId: { $in: ids } });
    console.log(`✅ Deleted ${r.deletedCount} of ${docs.length} alert(s). ${docs.length - r.deletedCount} kept.`);
    console.log('   Restart the backend (Ctrl+C, then npm run dev) so the dashboard forgets them too.');
  } else {
    console.log(`Nothing to delete (${docs.length} alert(s) checked).`);
  }
  await mongoose.disconnect();
  process.exit(0);
}

main().catch((e) => { console.error('❌ Failed:', e.message, '\n   Is MongoDB running and MONGO_URI in backend\\.env correct?'); process.exit(1); });
