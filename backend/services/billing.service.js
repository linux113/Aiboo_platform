import crypto from 'node:crypto';
import User from '../models/User.js';
import Organization from '../models/Organization.js';
import Plan from '../models/Plan.js';
import Subscription from '../models/Subscription.js';
import BillingWebhookEvent from '../models/BillingWebhookEvent.js';
import { isDefaultPassword, validateNewPassword } from '../utils/passwords.js';

const cleanEmail = (value) => String(value || '').trim().toLowerCase();
const slugBase = (value) => String(value || '').toLowerCase().normalize('NFKD')
  .replace(/[\u0300-\u036f]/g, '').replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 48) || 'company';
const settingError = () => Object.assign(new Error('Online billing is not configured. Contact the platform administrator.'), { statusCode: 503 });

function gatewayCredentials() {
  const keyId = process.env.RAZORPAY_KEY_ID;
  const keySecret = process.env.RAZORPAY_KEY_SECRET;
  if (!keyId || !keySecret) throw settingError();
  return { keyId, keySecret };
}

function signHmac(secret, text) {
  return crypto.createHmac('sha256', secret).update(text).digest();
}

function safeEqualHex(expected, supplied) {
  if (!/^[a-f0-9]{64}$/i.test(String(supplied || ''))) return false;
  const a = Buffer.from(expected, 'hex');
  const b = Buffer.from(supplied, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function razorpayApiBaseUrl() {
  const configured = String(process.env.RAZORPAY_API_BASE_URL || '').trim();
  const value = (configured || 'https://api.razorpay.com/v1').replace(/\/+$/, '');
  let parsed;
  try { parsed = new URL(value); } catch { throw settingError(); }
  // Payment credentials must never be sent over plain HTTP or embedded in a URL.
  if (parsed.protocol !== 'https:' || parsed.username || parsed.password || parsed.search || parsed.hash) {
    throw settingError();
  }
  return value;
}

async function razorpayRequest(path, { method = 'GET', body } = {}) {
  const { keyId, keySecret } = gatewayCredentials();
  const auth = Buffer.from(`${keyId}:${keySecret}`).toString('base64');
  const baseUrl = razorpayApiBaseUrl();
  const response = await fetch(`${baseUrl}${path}`, {
    method,
    redirect: 'error',
    headers: { Authorization: `Basic ${auth}`, ...(body ? { 'Content-Type': 'application/json' } : {}) },
    ...(body ? { body: JSON.stringify(body) } : {}),
    signal: AbortSignal.timeout(12000),
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const detail = String(data?.error?.description || 'Payment provider request failed').slice(0, 180);
    throw Object.assign(new Error(detail), { statusCode: response.status >= 500 ? 502 : 400 });
  }
  return data;
}

export const listPublicPlans = async () => Plan.find({ enabled: true, publicSignup: true })
  .select('code name description currency monthlyAmountPaise yearlyAmountPaise limits features customPricing')
  .sort({ monthlyAmountPaise: 1, code: 1 })
  .lean();

function amountFor(plan, billingCycle) {
  const amount = billingCycle === 'yearly' ? plan.yearlyAmountPaise : plan.monthlyAmountPaise;
  if (!Number.isSafeInteger(amount) || amount < 100) {
    throw Object.assign(new Error('This plan is not available for online checkout yet. Contact sales.'), { statusCode: 409 });
  }
  return amount;
}

async function createProviderOrder(subscription, amountPaise, email) {
  const receipt = `aiboo_${String(subscription._id).slice(-20)}`.slice(0, 40);
  const order = await razorpayRequest('/orders', {
    method: 'POST',
    body: {
      amount: amountPaise,
      currency: 'INR',
      receipt,
      notes: {
        organization_id: String(subscription.organization),
        subscription_id: String(subscription._id),
        billing_cycle: subscription.billingCycle,
        plan_code: subscription.planCode,
        billing_email: email,
      },
    },
  });
  subscription.providerOrderId = order.id;
  subscription.metadata = {
    ...(subscription.metadata || {}),
    expectedAmountPaise: amountPaise,
    currency: 'INR',
  };
  await subscription.save();
  return { order, keyId: gatewayCredentials().keyId };
}

async function findUniqueSlug(name) {
  const root = slugBase(name);
  for (let i = 0; i < 5; i += 1) {
    const suffix = crypto.randomBytes(3).toString('hex');
    const slug = `${root}-${suffix}`.slice(0, 64);
    if (!(await Organization.exists({ slug }))) return slug;
  }
  throw Object.assign(new Error('Could not allocate a workspace name. Please retry.'), { statusCode: 503 });
}

/** Public company self-signup creates a pending tenant and one owner account. */
export async function signupCompany({ companyName, name, email, password, planCode, billingCycle }) {
  const company = String(companyName || '').trim();
  const ownerName = String(name || '').trim();
  const mail = cleanEmail(email);
  const cycle = String(billingCycle || '').toLowerCase();
  const code = String(planCode || '').toLowerCase();
  if (company.length < 2 || company.length > 160 || ownerName.length < 2 || ownerName.length > 120 || !mail || mail.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(mail)) {
    throw Object.assign(new Error('Company name, contact name, and a valid email are required.'), { statusCode: 400 });
  }
  if (!['monthly', 'yearly'].includes(cycle)) throw Object.assign(new Error('Choose monthly or yearly billing.'), { statusCode: 400 });
  if (!['basic', 'business', 'enterprise'].includes(code)) throw Object.assign(new Error('Choose a valid plan.'), { statusCode: 400 });
  const passwordProblem = validateNewPassword(password);
  if (passwordProblem) throw Object.assign(new Error(passwordProblem), { statusCode: 400 });
  if (await User.exists({ email: mail })) throw Object.assign(new Error('That email already has an account.'), { statusCode: 409 });

  const plan = await Plan.findOne({ code, enabled: true, publicSignup: true });
  if (!plan) throw Object.assign(new Error('This plan is not currently available.'), { statusCode: 404 });
  const amountPaise = amountFor(plan, cycle);
  gatewayCredentials(); // fail before creating account records if not configured

  const organization = await Organization.create({
    name: company,
    slug: await findUniqueSlug(company),
    billingEmail: mail,
    status: 'pending_payment',
  });
  let user;
  let subscription;
  try {
    user = await User.create({ name: ownerName, email: mail, password, role: 'admin', organization: organization._id });
    organization.ownerUser = user._id;
    await organization.save();
    subscription = await Subscription.create({
      organization: organization._id,
      plan: plan._id,
      planCode: plan.code,
      billingCycle: cycle,
      status: 'pending_payment',
      metadata: { signup: true, expectedAmountPaise: amountPaise, currency: 'INR' },
    });
    const { order, keyId } = await createProviderOrder(subscription, amountPaise, mail);
    const token = (await import('jsonwebtoken')).default.sign(
      { id: user._id, role: user.role, email: user.email, name: user.name, organization: String(organization._id) },
      process.env.JWT_SECRET,
      { expiresIn: '7d' },
    );
    return {
      token,
      mustChangePassword: isDefaultPassword(password),
      user: { id: String(user._id), name: user.name, email: user.email, role: user.role, organization: String(organization._id) },
      checkout: { keyId, orderId: order.id, amount: order.amount, currency: order.currency, plan: plan.name, billingCycle: cycle },
    };
  } catch (err) {
    // Preserve the pending workspace/user for a retry if Razorpay had already
    // accepted the order; never silently delete customer records on an API error.
    throw err;
  }
}

export async function createCheckout({ organizationId, email, planCode, billingCycle }) {
  const cycle = String(billingCycle || '').toLowerCase();
  const code = String(planCode || '').toLowerCase();
  if (!['monthly', 'yearly'].includes(cycle) || !['basic', 'business', 'enterprise'].includes(code)) {
    throw Object.assign(new Error('Choose a valid plan and billing cycle.'), { statusCode: 400 });
  }
  const organization = await Organization.findById(organizationId);
  if (!organization || organization.isLegacy) throw Object.assign(new Error('Billing is not available for this workspace.'), { statusCode: 403 });
  const plan = await Plan.findOne({ code, enabled: true });
  if (!plan) throw Object.assign(new Error('This plan is unavailable.'), { statusCode: 404 });
  const amountPaise = amountFor(plan, cycle);
  const subscription = await Subscription.create({
    organization: organization._id,
    plan: plan._id,
    planCode: plan.code,
    billingCycle: cycle,
    status: 'pending_payment',
    metadata: { expectedAmountPaise: amountPaise, currency: 'INR', signup: false },
  });
  const { order, keyId } = await createProviderOrder(subscription, amountPaise, email || organization.billingEmail);
  return { keyId, orderId: order.id, amount: order.amount, currency: order.currency, plan: plan.name, billingCycle: cycle };
}

function subscriptionPeriodEnd(start, billingCycle) {
  const end = new Date(start);
  if (billingCycle === 'yearly') end.setUTCFullYear(end.getUTCFullYear() + 1);
  else {
    const day = end.getUTCDate();
    end.setUTCDate(1);
    end.setUTCMonth(end.getUTCMonth() + 1);
    const lastDay = new Date(Date.UTC(end.getUTCFullYear(), end.getUTCMonth() + 1, 0)).getUTCDate();
    end.setUTCDate(Math.min(day, lastDay));
  }
  return end;
}

async function activatePaidOrder({ orderId, paymentId, amount, currency }) {
  const subscription = await Subscription.findOne({ providerOrderId: orderId });
  if (!subscription) throw Object.assign(new Error('Payment order is not recognized.'), { statusCode: 404 });
  const expected = Number(subscription.metadata?.expectedAmountPaise);
  if (currency !== 'INR' || Number(amount) !== expected) {
    throw Object.assign(new Error('Payment amount does not match the order.'), { statusCode: 400 });
  }
  if (subscription.status === 'active' && subscription.lastPaymentId === paymentId) {
    return { ok: true, alreadyProcessed: true, subscriptionId: String(subscription._id) };
  }
  if (subscription.status !== 'pending_payment') {
    throw Object.assign(new Error('This payment order is no longer payable.'), { statusCode: 409 });
  }

  const now = new Date();
  const organization = await Organization.findById(subscription.organization);
  if (!organization || organization.isLegacy) throw Object.assign(new Error('Company workspace not found.'), { statusCode: 404 });
  const current = organization.currentSubscription
    ? await Subscription.findOne({ _id: organization.currentSubscription, organization: organization._id, status: 'active' })
    : null;
  const start = current?.currentPeriodEnd && current.currentPeriodEnd > now ? current.currentPeriodEnd : now;
  subscription.status = 'active';
  subscription.currentPeriodStart = start;
  subscription.currentPeriodEnd = subscriptionPeriodEnd(start, subscription.billingCycle);
  subscription.activatedAt = now;
  subscription.lastPaymentId = paymentId;
  await subscription.save();

  organization.currentSubscription = subscription._id;
  organization.subscriptionExpiresAt = subscription.currentPeriodEnd;
  organization.status = 'active';
  await organization.save();
  return { ok: true, alreadyProcessed: false, subscriptionId: String(subscription._id), currentPeriodEnd: subscription.currentPeriodEnd };
}

export async function verifyCheckoutPayment({ organizationId, orderId, paymentId, signature }) {
  const { keySecret } = gatewayCredentials();
  const subscription = await Subscription.findOne({ providerOrderId: String(orderId || ''), organization: organizationId });
  if (!subscription) throw Object.assign(new Error('Payment order not found for this workspace.'), { statusCode: 404 });
  const expectedSignature = signHmac(keySecret, `${orderId}|${paymentId}`).toString('hex');
  if (!safeEqualHex(expectedSignature, signature)) throw Object.assign(new Error('Payment signature could not be verified.'), { statusCode: 400 });

  // Confirm provider-side capture and amount before granting access. A signed
  // checkout result alone can represent an authorized-but-not-captured payment.
  const payment = await razorpayRequest(`/payments/${encodeURIComponent(paymentId)}`);
  if (payment.order_id !== orderId || payment.status !== 'captured') {
    throw Object.assign(new Error('Payment is not captured yet. Access will begin after the provider confirms capture.'), { statusCode: 409 });
  }
  return activatePaidOrder({ orderId, paymentId, amount: payment.amount, currency: payment.currency });
}

export async function processRazorpayWebhook({ rawBody, signature, eventId, eventType, payload }) {
  const secret = process.env.RAZORPAY_WEBHOOK_SECRET;
  if (!secret) throw settingError();
  if (!Buffer.isBuffer(rawBody)) throw Object.assign(new Error('Webhook request body is missing.'), { statusCode: 400 });
  const expected = signHmac(secret, rawBody).toString('hex');
  if (!safeEqualHex(expected, signature)) throw Object.assign(new Error('Invalid webhook signature.'), { statusCode: 400 });
  if (!eventId) throw Object.assign(new Error('Missing Razorpay event ID.'), { statusCode: 400 });

  let event;
  try {
    event = await BillingWebhookEvent.create({ provider: 'razorpay', providerEventId: eventId, eventType });
  } catch (err) {
    if (err?.code !== 11000) throw err;
    event = await BillingWebhookEvent.findOne({ provider: 'razorpay', providerEventId: eventId });
    if (event?.processed) return { ok: true, duplicate: true };
  }
  try {
    if (eventType === 'payment.captured') {
      const payment = payload?.payment?.entity;
      if (!payment?.order_id || !payment?.id) throw new Error('Captured payment payload is incomplete.');
      await activatePaidOrder({ orderId: payment.order_id, paymentId: payment.id, amount: payment.amount, currency: payment.currency });
    }
    event.processed = true;
    event.processedAt = new Date();
    event.failureReason = '';
    await event.save();
    return { ok: true, duplicate: false };
  } catch (err) {
    event.failureReason = String(err.message || 'Webhook processing failed').slice(0, 500);
    await event.save();
    throw err;
  }
}

export async function getBillingOverview(organizationId) {
  const organization = await Organization.findById(organizationId).select('name billingEmail status currentSubscription isLegacy');
  if (!organization) throw Object.assign(new Error('Workspace not found.'), { statusCode: 404 });
  const current = organization.currentSubscription
    ? await Subscription.findOne({ _id: organization.currentSubscription, organization: organization._id }).populate('plan', 'name code limits features')
    : null;
  const pending = await Subscription.findOne({ organization: organization._id, status: 'pending_payment' }).sort({ createdAt: -1 }).populate('plan', 'name code');
  const pendingAmount = Number(pending?.metadata?.expectedAmountPaise || 0);
  const now = new Date();
  const activeNow = current?.status === 'active' && current.currentPeriodEnd > now;
  const expiresAt = current?.currentPeriodEnd || null;
  const daysRemaining = expiresAt ? Math.ceil((expiresAt.getTime() - now.getTime()) / 86400000) : null;
  return {
    organization: { id: String(organization._id), name: organization.name, billingEmail: organization.billingEmail, status: organization.status },
    subscription: current ? {
      id: String(current._id), status: activeNow ? 'active' : (current.status === 'active' ? 'expired' : current.status),
      plan: current.plan, billingCycle: current.billingCycle, currentPeriodStart: current.currentPeriodStart,
      currentPeriodEnd: expiresAt, daysRemaining,
    } : null,
    pendingCheckout: pending ? {
      subscriptionId: String(pending._id), plan: pending.plan, billingCycle: pending.billingCycle,
      orderId: pending.providerOrderId || null, amount: pendingAmount, currency: pending.metadata?.currency || 'INR',
      keyId: process.env.RAZORPAY_KEY_ID || '',
    } : null,
    access: organization.isLegacy || activeNow,
    isLegacy: organization.isLegacy,
  };
}
