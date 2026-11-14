import 'dotenv/config';
import mongoose from 'mongoose';
import Organization from './models/Organization.js';
import User from './models/User.js';
import Alert from './models/Alert.js';
import Threat from './models/Threat.js';
import Asset from './models/Asset.js';
import Camera from './models/Camera.js';
import CameraEvent from './models/CameraEvent.js';
import Detection from './models/Detection.js';
import Finding from './models/Finding.js';
import IdentityRisk from './models/IdentityRisk.js';
import ResponseAction from './models/ResponseAction.js';
import Vulnerability from './models/Vulnerability.js';
import Approval from './models/Approval.js';
import Playbook from './models/Playbook.js';
import PlaybookRun from './models/PlaybookRun.js';
import ResponseRule from './models/ResponseRule.js';
import RuleEvent from './models/RuleEvent.js';
import ComplianceReport from './models/ComplianceReport.js';

const models = [
  Alert, Threat, Asset, Camera, CameraEvent, Detection, Finding, IdentityRisk,
  ResponseAction, Vulnerability, Approval, Playbook, PlaybookRun, ResponseRule,
  RuleEvent, ComplianceReport,
];
const missingOrganization = {
  $or: [{ organization: null }, { organization: { $exists: false } }],
};
const apply = process.argv.includes('--apply');
const acknowledge = process.argv.includes('--i-understand-legacy-assignment');

async function main() {
  if (!process.env.MONGO_URI) throw new Error('MONGO_URI is required. No database was changed.');
  if (apply && !acknowledge) {
    throw new Error('For safety, --apply also requires --i-understand-legacy-assignment.');
  }
  await mongoose.connect(process.env.MONGO_URI);

  const userCount = await User.countDocuments(missingOrganization);
  const counts = [];
  for (const Model of models) {
    counts.push({ collection: Model.collection.collectionName, count: await Model.countDocuments(missingOrganization) });
  }
  let alertIndexes = [];
  try { alertIndexes = await Alert.collection.indexes(); } catch { /* collection may not exist on a fresh install */ }
  const oldAlertUnique = alertIndexes.filter((index) => index.unique &&
    Object.keys(index.key || {}).length === 1 && index.key.alertId === 1);
  const hasTenantAlertUnique = alertIndexes.some((index) => index.unique &&
    index.key?.organization === 1 && index.key?.alertId === 1);

  console.log('Legacy tenant migration preview (records without an organization):');
  console.log(JSON.stringify({
    users: userCount,
    collections: counts,
    alertIndexMigration: {
      oldGlobalUniqueIndexes: oldAlertUnique.map((index) => index.name),
      createTenantUniqueIndex: !hasTenantAlertUnique,
    },
  }, null, 2));

  if (!apply) {
    console.log('DRY RUN ONLY. No records or organization documents were changed.');
    console.log('After backup and review, add --apply --i-understand-legacy-assignment to migrate.');
    return;
  }

  const org = await Organization.findOneAndUpdate(
    { slug: 'legacy' },
    { $setOnInsert: {
      name: 'Internal Legacy Workspace',
      slug: 'legacy',
      billingEmail: process.env.LEGACY_BILLING_EMAIL || 'legacy@internal.invalid',
      status: 'legacy',
      isLegacy: true,
      legacyDataReviewRequired: true,
    } },
    { upsert: true, new: true, setDefaultsOnInsert: true, runValidators: true },
  );

  const userResult = await User.updateMany(missingOrganization, { $set: { organization: org._id } });
  const collectionResults = [];
  for (const Model of models) {
    const result = await Model.updateMany(missingOrganization, { $set: { organization: org._id } });
    collectionResults.push({
      collection: Model.collection.collectionName,
      matched: result.matchedCount ?? result.n ?? 0,
      modified: result.modifiedCount ?? result.nModified ?? 0,
    });
  }
  await Organization.updateOne({ _id: org._id }, { $set: { legacyDataReviewRequired: true } });
  for (const index of oldAlertUnique) {
    await Alert.collection.dropIndex(index.name);
  }
  await Alert.collection.createIndex(
    { organization: 1, alertId: 1 },
    { unique: true, name: 'organization_1_alertId_1' },
  );
  console.log(JSON.stringify({
    applied: true,
    legacyOrganizationId: String(org._id),
    usersModified: userResult.modifiedCount ?? userResult.nModified ?? 0,
    collections: collectionResults,
    note: 'Existing records remain in an internal workspace. Reassign them only after verifying ownership.',
  }, null, 2));
}

main()
  .catch((err) => {
    console.error(`Legacy migration stopped: ${err.message}`);
    process.exitCode = 1;
  })
  .finally(async () => {
    await mongoose.disconnect().catch(() => {});
  });
