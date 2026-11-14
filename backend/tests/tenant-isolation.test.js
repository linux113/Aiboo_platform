import { test } from 'node:test';
import assert from 'node:assert/strict';
import Threat from '../models/Threat.js';
import Asset from '../models/Asset.js';
import Vulnerability from '../models/Vulnerability.js';
import Camera from '../models/Camera.js';
import Detection from '../models/Detection.js';
import IdentityRisk from '../models/IdentityRisk.js';
import * as threatService from '../services/threat.service.js';
import * as assetService from '../services/asset.service.js';
import * as cameraService from '../services/camera.service.js';
import * as identityService from '../services/identity.service.js';
import { queueCommand, takePendingCommands, finishCommand as finishQueuedCommand } from '../services/commandQueue.service.js';

const ORG_A = '650000000000000000000001';
const ORG_B = '650000000000000000000002';
const chain = (value) => {
  const q = {
    sort() { return q; }, skip() { return q; }, limit() { return q; },
    populate() { return q; }, select() { return q; },
    then(resolve, reject) { return Promise.resolve(value).then(resolve, reject); },
  };
  return q;
};

test('threat CRUD always constrains reads and writes to the verified organization', async () => {
  let querySeen;
  let createSeen;
  let updateSeen;
  Threat.find = (query) => { querySeen = query; return chain([]); };
  Threat.countDocuments = async (query) => { assert.deepEqual(query, querySeen); return 0; };
  Threat.create = async (doc) => { createSeen = doc; return doc; };
  Threat.findOne = async (query) => { querySeen = query; return { _id: 't1' }; };
  Threat.findOneAndUpdate = async (query, update) => { updateSeen = { query, update }; return { _id: 't1' }; };

  await threatService.listThreats({ status: 'open' }, { organizationId: ORG_A });
  assert.deepEqual(querySeen, { status: 'open', organization: ORG_A });
  await threatService.createThreat({ title: 'example', organization: ORG_B }, ORG_A);
  assert.equal(createSeen.organization, ORG_A, 'request body cannot choose its tenant');
  await threatService.getThreatById('t1', ORG_A);
  assert.deepEqual(querySeen, { _id: 't1', organization: ORG_A });
  await threatService.updateThreat('t1', { status: 'resolved', organization: ORG_B }, ORG_A);
  assert.deepEqual(updateSeen.query, { _id: 't1', organization: ORG_A });
  assert.equal(updateSeen.update.organization, ORG_A);
});

test('assets and vulnerabilities stay tenant-bound, including scan side effects', async () => {
  let querySeen;
  let vulnerabilitySeen;
  const asset = { _id: 'a1', vulnerabilities: [], async save() {} };
  Asset.find = (query) => { querySeen = query; return chain([]); };
  Asset.countDocuments = async (query) => { assert.deepEqual(query, querySeen); return 0; };
  Asset.create = async (doc) => doc;
  Asset.findOne = async (query) => { querySeen = query; return asset; };
  Vulnerability.find = (query) => { querySeen = query; return chain([]); };
  Vulnerability.countDocuments = async (query) => { assert.deepEqual(query, querySeen); return 0; };
  Vulnerability.create = async (doc) => { vulnerabilitySeen = doc; return doc; };

  await assetService.listAssets({}, { organizationId: ORG_A });
  assert.deepEqual(querySeen, { organization: ORG_A });
  await assetService.listVulnerabilities({}, { organizationId: ORG_A });
  assert.deepEqual(querySeen, { organization: ORG_A });
  await assetService.runScan('a1', ORG_A);
  assert.deepEqual(querySeen, { _id: 'a1', organization: ORG_A });
  assert.equal(vulnerabilitySeen.organization, ORG_A);
});

test('camera and detection queries, creates, updates and deletes are tenant-scoped', async () => {
  let querySeen;
  let updateSeen;
  let detectionSeen;
  Camera.find = (query) => { querySeen = query; return chain([]); };
  Camera.countDocuments = async (query) => { assert.deepEqual(query, querySeen); return 0; };
  Camera.create = async (doc) => doc;
  Camera.findOne = async (query) => { querySeen = query; return { _id: 'c1', enabled: true, name: 'Cam', location: 'HQ', zone: 'A' }; };
  Camera.findOneAndUpdate = async (query, update) => { updateSeen = { query, update }; return { _id: 'c1' }; };
  Camera.findOneAndDelete = async (query) => { querySeen = query; return { _id: 'c1' }; };
  Detection.find = (query) => { querySeen = query; return chain([]); };
  Detection.create = async (doc) => { detectionSeen = doc; return doc; };
  Detection.findOneAndUpdate = async (query, update) => { updateSeen = { query, update }; return { _id: 'd1' }; };

  await cameraService.listCameras({}, { organizationId: ORG_A });
  assert.deepEqual(querySeen, { organization: ORG_A });
  await cameraService.updateCamera('c1', { name: 'Changed', organization: ORG_B }, ORG_A);
  assert.deepEqual(updateSeen.query, { _id: 'c1', organization: ORG_A });
  assert.equal(updateSeen.update.organization, ORG_A);
  await cameraService.deleteCamera('c1', ORG_A);
  assert.deepEqual(querySeen, { _id: 'c1', organization: ORG_A });
  await cameraService.listDetections({}, 30, ORG_A);
  assert.deepEqual(querySeen, { organization: ORG_A });
  await cameraService.createDetection({ type: 'person', organization: ORG_B }, ORG_A);
  assert.equal(detectionSeen.organization, ORG_A);
  await cameraService.acknowledgeDetection('d1', ORG_A);
  assert.deepEqual(updateSeen.query, { _id: 'd1', organization: ORG_A });
});

test('REST command polling and acknowledgements stay bound to tenant plus endpoint', async () => {
  const a = queueCommand('same-host', 'block_access', '192.0.2.1', {}, { organization: ORG_A });
  const b = queueCommand('same-host', 'block_access', '198.51.100.1', {}, { organization: ORG_B });
  const mine = takePendingCommands('same-host', ORG_A);
  assert.deepEqual(mine.map((command) => command.cmd_id), [a.cmd_id]);
  assert.equal(finishQueuedCommand(b.cmd_id, 'executed', null, {}, ORG_A, 'same-host'), null);
  assert.ok(finishQueuedCommand(b.cmd_id, 'executed', null, {}, ORG_B, 'same-host'));
});

test('identity-risk data and mutations are tenant-scoped', async () => {
  let querySeen;
  let updateSeen;
  IdentityRisk.find = (query) => { querySeen = query; return chain([]); };
  IdentityRisk.countDocuments = async (query) => { assert.deepEqual(query, querySeen); return 0; };
  IdentityRisk.findOne = (query) => { querySeen = query; return chain({ _id: 'i1' }); };
  IdentityRisk.findOneAndUpdate = async (query, update) => { updateSeen = { query, update }; return { _id: 'i1' }; };

  await identityService.listIdentities({}, { organizationId: ORG_A });
  assert.deepEqual(querySeen, { organization: ORG_A });
  await identityService.getIdentity('i1', ORG_A);
  assert.deepEqual(querySeen, { _id: 'i1', organization: ORG_A });
  await identityService.updateIdentity('i1', { flagged: true, organization: ORG_B }, ORG_A);
  assert.deepEqual(updateSeen.query, { _id: 'i1', organization: ORG_A });
  assert.equal(updateSeen.update.organization, ORG_A);
});
