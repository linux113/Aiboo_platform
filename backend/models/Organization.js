import mongoose from 'mongoose';

const organizationSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true, maxlength: 160 },
  slug: { type: String, required: true, trim: true, lowercase: true, unique: true, index: true },
  billingEmail: { type: String, required: true, trim: true, lowercase: true, maxlength: 254 },
  ownerUser: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null, index: true },
  status: {
    type: String,
    enum: ['pending_payment', 'active', 'past_due', 'expired', 'suspended', 'legacy'],
    default: 'pending_payment',
    index: true,
  },
  currentSubscription: { type: mongoose.Schema.Types.ObjectId, ref: 'Subscription', default: null },
  subscriptionExpiresAt: { type: Date, default: null, index: true },
  isLegacy: { type: Boolean, default: false, index: true },
  legacyDataReviewRequired: { type: Boolean, default: false },
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
}, { timestamps: true });

organizationSchema.index({ status: 1, createdAt: -1 });

export default mongoose.model('Organization', organizationSchema);
