import { test } from 'node:test';
import assert from 'node:assert/strict';

const mongoose = (await import('mongoose')).default;
const models = [
  (await import('../models/Approval.js')).default,
  (await import('../models/Playbook.js')).default,
  (await import('../models/PlaybookRun.js')).default,
  (await import('../models/ResponseRule.js')).default,
  (await import('../models/RuleEvent.js')).default,
];
const { store, withResponseOrganization } = await import('../services/pseudolock.service.js');
const ORG_A = '650000000000000000000101';
const ORG_B = '650000000000000000000102';

const makeQuery = (result) => ({
  sort() { return this; },
  limit() { return this; },
  lean() { return Promise.resolve(result); },
});

test('Mongo PseudoLock collections constrain every operation by the active organization', async () => {
  const priorReadyState = mongoose.connection.readyState;
  const originals = new Map();
  const calls = [];
  Object.defineProperty(mongoose.connection, 'readyState', { value: 1, configurable: true, writable: true });
  for (const Model of models) {
    originals.set(Model, Object.fromEntries(['findOne', 'find', 'findOneAndUpdate', 'deleteOne', 'countDocuments']
      .map((method) => [method, Model[method]])));
    Model.findOne = (query) => { calls.push({ method: 'findOne', query }); return makeQuery(null); };
    Model.find = (query) => { calls.push({ method: 'find', query }); return makeQuery([]); };
    Model.findOneAndUpdate = (query, update) => {
      calls.push({ method: 'findOneAndUpdate', query, update });
      return makeQuery({ id: query.id, organization: update.$set.organization });
    };
    Model.deleteOne = async (query) => { calls.push({ method: 'deleteOne', query }); return { deletedCount: 0 }; };
    Model.countDocuments = async (query) => { calls.push({ method: 'countDocuments', query }); return 0; };
  }

  try {
    const collections = store();
    await withResponseOrganization(ORG_A, async () => {
      const approvals = collections.approvals;
      await approvals.get('approval-A');
      await approvals.list({ status: 'pending' });
      await approvals.count({ status: 'pending' });
      await approvals.remove('approval-A');
      // A caller-supplied tenant field cannot override the verified request scope.
      await approvals.save({ id: 'approval-new', organization: ORG_B, status: 'pending' });
      await collections.playbooks.get('playbook-A');
      await collections.runs.list({ limit: 10 });
      await collections.rules.count();
      await collections.ruleEvents.remove('event-A');
    });

    assert.equal(calls.length, 9);
    for (const { query } of calls) assert.equal(String(query.organization), ORG_A);
    const update = calls.find((call) => call.method === 'findOneAndUpdate');
    assert.equal(String(update.update.$set.organization), ORG_A);

    calls.length = 0;
    await withResponseOrganization(null, async () => {
      await collections.approvals.get('legacy-approval');
      await collections.approvals.save({ id: 'legacy-new', organization: ORG_B, status: 'pending' });
      await collections.rules.list({ limit: 10 });
    });
    assert.equal(calls.length, 3);
    for (const { query } of calls) assert.equal(query.organization, null);
    const legacyUpdate = calls.find((call) => call.method === 'findOneAndUpdate');
    assert.equal(legacyUpdate.update.$set.organization, null);
  } finally {
    for (const [Model, methods] of originals) Object.assign(Model, methods);
    Object.defineProperty(mongoose.connection, 'readyState', { value: priorReadyState, configurable: true, writable: true });
  }
});
