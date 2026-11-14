import mongoose from 'mongoose';
import Organization from '../models/Organization.js';
import Subscription from '../models/Subscription.js';
import Plan from '../models/Plan.js';

const loadOrganization = async (req, res) => {
  if (!req.user) {
    res.status(401).json({ message: 'Login required' });
    return false;
  }
  if (req.user.role === 'super_admin') {
    res.status(403).json({ message: 'Use an explicitly scoped platform-admin route' });
    return false;
  }
  if (!req.user.tenantVerified) {
    res.status(503).json({ message: 'Workspace could not be verified; try again when the database is available' });
    return false;
  }
  const organizationId = String(req.user.organization || '');
  if (!mongoose.Types.ObjectId.isValid(organizationId)) {
    res.status(403).json({ message: 'This account is not assigned to a company workspace' });
    return false;
  }
  const organization = await Organization.findById(organizationId)
    .select('_id name slug status isLegacy currentSubscription subscriptionExpiresAt');
  if (!organization) {
    res.status(403).json({ message: 'Company workspace not found' });
    return false;
  }
  req.organization = organization;
  req.organizationId = String(organization._id);
  return true;
};

/** Require a paid, non-expired company or the internal legacy workspace. */
export const requireOrganization = async (req, res, next) => {
  try {
    if (!(await loadOrganization(req, res))) return;
    const org = req.organization;
    if (org.isLegacy && org.status === 'legacy') return next();
    const paidAndCurrent = org.status === 'active'
      && org.subscriptionExpiresAt instanceof Date
      && org.subscriptionExpiresAt.getTime() > Date.now();
    if (!paidAndCurrent) {
      return res.status(402).json({ message: 'Company subscription is not active; open Billing to renew' });
    }
    return next();
  } catch (err) {
    return next(err);
  }
};

/** Enforce an active plan entitlement on a tenant dashboard operation. */
export const requirePlanFeature = (feature) => async (req, res, next) => {
  if (req.organization?.isLegacy) return next();
  try {
    const now = new Date();
    const subscription = await Subscription.findOne({
      organization: req.organizationId,
      status: 'active',
      currentPeriodStart: { $lte: now },
      currentPeriodEnd: { $gt: now },
    }).select('plan');
    const plan = subscription
      ? await Plan.findById(subscription.plan).select(`features enabled`)
      : null;
    if (!plan || plan.enabled === false || plan.features?.[feature] !== true) {
      return res.status(403).json({ message: `This subscription plan does not include ${feature}` });
    }
    return next();
  } catch (err) {
    return next(err);
  }
};

/** Authenticated tenant resolution for the billing/renewal area only. */
export const requireBillingOrganization = async (req, res, next) => {
  try {
    if (!(await loadOrganization(req, res))) return;
    return next();
  } catch (err) {
    return next(err);
  }
};

/** Always add this to a query created for a normal tenant user. */
export const tenantQuery = (req) => {
  if (!req?.organizationId) throw new Error('Tenant query requested without requireOrganization middleware');
  return { organization: new mongoose.Types.ObjectId(req.organizationId) };
};

/** Platform-only routes; no company admin is implicitly a platform admin here. */
export const requireSuperAdmin = (req, res, next) => {
  if (req.user?.role !== 'super_admin') {
    return res.status(403).json({ message: 'Platform Super Admin access required' });
  }
  next();
};
