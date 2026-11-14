import crypto from 'node:crypto';
import AgentCredential from '../models/AgentCredential.js';
import Organization from '../models/Organization.js';
import Subscription from '../models/Subscription.js';
import Plan from '../models/Plan.js';

const TOKEN_PREFIX = 'aiboo1';
const hashSecret = (secret) => crypto.createHash('sha256').update(secret, 'utf8').digest('hex');
const validEndpointId = (value) => {
  const s = String(value || '').trim();
  return s.length >= 1 && s.length <= 160 && /^[a-zA-Z0-9_.:@-]+$/.test(s);
};

/**
 * Issue a tenant-bound, endpoint-specific credential. Plaintext is returned
 * only once; only its SHA-256 digest is stored. The 256-bit random secret is
 * high entropy, so a slow password hash is unnecessary.
 */
export async function getAgentPlanFeatures(organizationId) {
  const now = new Date();
  const subscription = await Subscription.findOne({
    organization: organizationId,
    status: 'active',
    currentPeriodStart: { $lte: now },
    currentPeriodEnd: { $gt: now },
  }).select('plan');
  if (!subscription) return {};
  const plan = await Plan.findById(subscription.plan).select('features enabled');
  return plan && plan.enabled !== false ? (plan.features || {}) : {};
}

export async function issueAgentCredential({ organizationId, endpointId, label = '', platform = 'unknown', createdBy = null }) {
  if (!validEndpointId(endpointId)) throw new Error('Invalid endpoint ID');
  const organization = await Organization.findById(organizationId).select('_id status currentSubscription');
  if (!organization || organization.status !== 'active') {
    throw Object.assign(new Error('Only an active, paid company can enroll an agent'), { statusCode: 402 });
  }
  const subscription = await Subscription.findOne({
    organization: organization._id,
    status: 'active',
    currentPeriodStart: { $lte: new Date() },
    currentPeriodEnd: { $gt: new Date() },
  }).sort({ currentPeriodEnd: -1 });
  if (!subscription) {
    throw Object.assign(new Error('No active subscription is available for this company'), { statusCode: 402 });
  }
  const plan = await Plan.findById(subscription.plan).select('limits features enabled');
  if (!plan || plan.enabled === false) {
    throw Object.assign(new Error('The company subscription plan is unavailable'), { statusCode: 402 });
  }
  const os = String(platform || 'unknown').toLowerCase();
  if (!['windows', 'linux'].includes(os) || plan.features?.[`${os}Agent`] !== true) {
    throw Object.assign(new Error(`The ${os} agent is not included in this plan`), { statusCode: 403 });
  }
  const activeCount = await AgentCredential.countDocuments({ organization: organization._id, status: 'active' });
  if (Number.isFinite(plan.limits?.endpoints) && activeCount >= plan.limits.endpoints) {
    throw Object.assign(new Error('Endpoint limit reached for this subscription plan'), { statusCode: 409 });
  }
  const duplicate = await AgentCredential.exists({ organization: organization._id, endpointId: String(endpointId).trim(), status: 'active' });
  if (duplicate) {
    throw Object.assign(new Error('An active credential already exists for this endpoint name'), { statusCode: 409 });
  }

  const keyId = crypto.randomBytes(9).toString('base64url');
  const secret = crypto.randomBytes(32).toString('base64url');
  const token = `${TOKEN_PREFIX}_${keyId}.${secret}`;
  const secretHash = hashSecret(secret);

  const credential = await AgentCredential.create({
    organization: organization._id,
    endpointId: String(endpointId).trim(),
    label: String(label || '').trim().slice(0, 160),
    keyId,
    secretHash,
    platform: os,
    createdBy,
  });

  return {
    id: String(credential._id),
    keyId,
    token, // display once to the company admin; do not persist or log it
    endpointId: credential.endpointId,
    organizationId: String(credential.organization),
    createdAt: credential.createdAt,
  };
}

/** Return the credential's tenant and endpoint only after constant-time verification. */
export async function verifyAgentCredential(token, { allowExpired = false, includeEntitlements = false } = {}) {
  const raw = String(token || '');
  const match = /^aiboo1_([A-Za-z0-9_-]{8,32})\.([A-Za-z0-9_-]{40,64})$/.exec(raw);
  if (!match) return null;

  const [, keyId, secret] = match;
  const credential = await AgentCredential.findOne({ keyId, status: 'active' }).select('+secretHash');
  if (!credential?.secretHash) return null;

  const supplied = Buffer.from(hashSecret(secret), 'hex');
  const stored = Buffer.from(credential.secretHash, 'hex');
  if (supplied.length !== stored.length || !crypto.timingSafeEqual(supplied, stored)) return null;

  const organization = await Organization.findById(credential.organization).select('_id status subscriptionExpiresAt');
  if (!organization || !['active', 'past_due', 'expired'].includes(organization.status)) return null;
  const subscriptionActive = organization.status === 'active'
    && organization.subscriptionExpiresAt instanceof Date
    && organization.subscriptionExpiresAt.getTime() > Date.now();
  if (!subscriptionActive && !allowExpired) return null;

  return {
    credentialId: String(credential._id),
    organizationId: String(organization._id),
    endpointId: credential.endpointId,
    platform: credential.platform,
    subscriptionActive,
    subscriptionExpiresAt: organization.subscriptionExpiresAt || null,
    ...(includeEntitlements ? { features: subscriptionActive ? await getAgentPlanFeatures(organization._id) : {} } : {}),
  };
}

export async function touchAgentCredential(credentialId, { ip = '', platform = '' } = {}) {
  const patch = { lastSeenAt: new Date(), lastSeenIp: String(ip || '').slice(0, 64) };
  if (['windows', 'linux', 'darwin'].includes(String(platform).toLowerCase())) {
    patch.platform = String(platform).toLowerCase();
  }
  await AgentCredential.updateOne({ _id: credentialId, status: 'active' }, { $set: patch });
}

export async function revokeAgentCredential({ organizationId, credentialId }) {
  const result = await AgentCredential.updateOne(
    { _id: credentialId, organization: organizationId, status: 'active' },
    { $set: { status: 'revoked', revokedAt: new Date() } },
  );
  return (result.modifiedCount ?? result.nModified ?? 0) === 1;
}

export async function listAgentCredentials(organizationId) {
  return AgentCredential.find({ organization: organizationId })
    .select('-secretHash')
    .sort({ createdAt: -1 })
    .lean();
}
