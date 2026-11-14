import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  useMemoryStore, ingest, listAlerts, getAlert, changeStatus,
  saveCompliance, latestCompliance,
} from '../services/alertStore.js';

const ORG_A = '650000000000000000000001';
const ORG_B = '650000000000000000000002';

test('alerts with the same external ID remain isolated between organizations', async () => {
  useMemoryStore();
  const mapped = {
    alertId: 'external-event-1', kind: 'finding', source: 'endpoint-1', title: 'Test alert',
    description: '', severity: 'high', riskScore: 80, firstSeen: new Date().toISOString(),
  };
  await ingest(mapped, false, ORG_A);
  await ingest({ ...mapped, title: 'Other company alert' }, false, ORG_B);

  const a = await listAlerts({}, ORG_A);
  const b = await listAlerts({}, ORG_B);
  assert.equal(a.total, 1);
  assert.equal(b.total, 1);
  assert.equal(a.alerts[0].title, 'Test alert');
  assert.equal(b.alerts[0].title, 'Other company alert');
  assert.equal((await getAlert(mapped.alertId, ORG_A)).organization, ORG_A);

  await changeStatus(mapped.alertId, 'acknowledged', { name: 'Tenant A admin' }, {}, ORG_A);
  assert.equal((await getAlert(mapped.alertId, ORG_A)).status, 'acknowledged');
  assert.equal((await getAlert(mapped.alertId, ORG_B)).status, 'open');
});

test('compliance reports are filtered by organization', async () => {
  useMemoryStore();
  await saveCompliance('same-endpoint', { checked_at: new Date().toISOString(), score: 91 }, ORG_A);
  await saveCompliance('same-endpoint', { checked_at: new Date().toISOString(), score: 32 }, ORG_B);
  assert.equal((await latestCompliance(ORG_A))[0].score, 91);
  assert.equal((await latestCompliance(ORG_B))[0].score, 32);
});
