import 'dotenv/config';
import mongoose from 'mongoose';
import Plan from './models/Plan.js';

// Inserts starter package definitions only. Prices deliberately remain unset
// until a Super Admin configures INR amounts and Razorpay plan IDs. Existing
// plan rows are never overwritten by this script.
const starterPlans = [
  {
    code: 'basic',
    name: 'Basic',
    description: 'Core endpoint monitoring, alerts, and standard reports.',
    currency: 'INR',
    limits: { endpoints: 5, users: 2 },
    features: {
      windowsAgent: true,
      linuxAgent: true,
      reports: true,
      playbooks: false,
      responseActions: false,
      customIntegrations: false,
    },
    customPricing: false,
    publicSignup: true,
  },
  {
    code: 'business',
    name: 'Business',
    description: 'Basic features plus approved response actions and playbooks.',
    currency: 'INR',
    limits: { endpoints: 25, users: 10 },
    features: {
      windowsAgent: true,
      linuxAgent: true,
      reports: true,
      playbooks: true,
      responseActions: true,
      customIntegrations: false,
    },
    customPricing: false,
    publicSignup: true,
  },
  {
    code: 'enterprise',
    name: 'Enterprise',
    description: 'Business features with custom limits and integrations.',
    currency: 'INR',
    limits: { endpoints: null, users: null },
    features: {
      windowsAgent: true,
      linuxAgent: true,
      reports: true,
      playbooks: true,
      responseActions: true,
      customIntegrations: true,
    },
    customPricing: true,
    publicSignup: true,
  },
];

async function main() {
  if (!process.env.MONGO_URI) {
    throw new Error('MONGO_URI is required; plans were not changed.');
  }
  await mongoose.connect(process.env.MONGO_URI);
  for (const plan of starterPlans) {
    await Plan.updateOne(
      { code: plan.code },
      { $setOnInsert: plan },
      { upsert: true, runValidators: true },
    );
  }
  console.log('Starter plans ensured. Prices and Razorpay plan IDs are still unset.');
}

main()
  .catch((err) => {
    console.error(`Plan seed failed: ${err.message}`);
    process.exitCode = 1;
  })
  .finally(async () => {
    await mongoose.disconnect().catch(() => {});
  });
