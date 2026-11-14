import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';

const Organization = (await import('../models/Organization.js')).default;
const Subscription = (await import('../models/Subscription.js')).default;
const Plan = (await import('../models/Plan.js')).default;
const AgentCredential = (await import('../models/AgentCredential.js')).default;
const service = await import('../services/agentCredential.service.js');

const query = (value) => ({ select() { return this; }, sort() { return this; }, lean() { return Promise.resolve(value); }, then(resolve, reject) { return Promise.resolve(value).then(resolve, reject); } });

test('endpoint keys are unique, returned once, stored as a hash, and stop verifying after expiry', async () => {
  const original = {
    organizationFind: Organization.findById,
    subscriptionFind: Subscription.findOne,
    planFind: Plan.findById,
    credentialCount: AgentCredential.countDocuments,
    credentialExists: AgentCredential.exists,
    credentialCreate: AgentCredential.create,
    credentialFind: AgentCredential.findOne,
  };
  let stored;
  let organization = { _id: '650000000000000000000111', status: 'active', subscriptionExpiresAt: new Date(Date.now() + 86400000) };
  Organization.findById = () => query(organization);
  Subscription.findOne = () => query({ _id: 'sub', plan: 'plan' });
  Plan.findById = () => query({ enabled: true, limits: { endpoints: 5 }, features: { windowsAgent: true, linuxAgent: true } });
  AgentCredential.countDocuments = async () => 0;
  AgentCredential.exists = async () => false;
  AgentCredential.create = async (fields) => { stored = { ...fields, _id: '650000000000000000000112', organization: organization._id, createdAt: new Date() }; return stored; };
  AgentCredential.findOne = () => query(stored);

  try {
    const issued = await service.issueAgentCredential({ organizationId: organization._id, endpointId: 'server-01', platform: 'linux' });
    assert.match(issued.token, /^aiboo1_[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
    assert.equal(stored.endpointId, 'server-01');
    assert.equal(stored.secretHash, crypto.createHash('sha256').update(issued.token.split('.')[1]).digest('hex'));
    assert.equal(JSON.stringify(stored).includes(issued.token), false);

    const verified = await service.verifyAgentCredential(issued.token);
    assert.equal(verified.endpointId, 'server-01');
    assert.equal(verified.organizationId, organization._id);
    assert.equal(verified.subscriptionActive, true);
    const entitled = await service.verifyAgentCredential(issued.token, { includeEntitlements: true });
    assert.equal(entitled.features.windowsAgent, true);
    assert.equal(entitled.features.responseActions, undefined);

    organization = { ...organization, subscriptionExpiresAt: new Date(Date.now() - 1000) };
    assert.equal(await service.verifyAgentCredential(issued.token), null);
    const heartbeat = await service.verifyAgentCredential(issued.token, { allowExpired: true });
    assert.equal(heartbeat.subscriptionActive, false);
    assert.equal(heartbeat.endpointId, 'server-01');
  } finally {
    Organization.findById = original.organizationFind;
    Subscription.findOne = original.subscriptionFind;
    Plan.findById = original.planFind;
    AgentCredential.countDocuments = original.credentialCount;
    AgentCredential.exists = original.credentialExists;
    AgentCredential.create = original.credentialCreate;
    AgentCredential.findOne = original.credentialFind;
  }
});
