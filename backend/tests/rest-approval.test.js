// Approvals / playbook actions on an agent that has NO Socket.IO connection
// (the Linux Sentinel polls over HTTPS). Before this, pressing Approve on a
// Linux endpoint answered "PC is not connected" and nothing reached the agent.
import test from 'node:test';
import assert from 'node:assert/strict';

process.env.NODE_ENV = 'test';
const { useMemoryStore } = await import('../services/alertStore.js');
useMemoryStore();
const pq = await import('../services/pseudolock.service.js');
const cq = await import('../services/commandQueue.service.js');

const drain = (endpoint) => cq.takePendingCommands(endpoint);

test('an approval for a REST agent is queued and completes when the agent acks', async () => {
  const pending = pq.executeAction({
    endpoint: 'linux-01', action: 'block_access', target: '45.95.147.3', by: 'test',
  });
  const queued = drain('linux-01');
  assert.equal(queued.length, 1, 'the command must be queued for the polling agent');
  assert.equal(queued[0].action, 'block_access');
  assert.equal(queued[0].target, '45.95.147.3');

  cq.finishCommand(queued[0].cmd_id, 'executed', null, { message: 'blocked 45.95.147.3 with iptables' });
  const out = await pending;
  assert.equal(out.ok, true);
  assert.equal(out.status, 'executed');
  assert.equal(out.result.message, 'blocked 45.95.147.3 with iptables');
});

test('a Linux action keeps its parameters (lock for 30 minutes)', async () => {
  const pending = pq.executeAction({
    endpoint: 'linux-01', action: 'restrict_identity', target: 'deploy',
    params: { minutes: 30 }, by: 'test',
  });
  const queued = drain('linux-01');
  assert.equal(queued[0].params.minutes, 30);
  cq.finishCommand(queued[0].cmd_id, 'failed', 'account is a system account', null);
  const out = await pending;
  assert.equal(out.ok, false);
  assert.equal(out.status, 'failed');
  assert.match(out.error, /system account/);
});

test('a command nobody answers times out instead of hanging forever', async () => {
  const res = await cq.waitForCommand('cmd_does_not_exist', 1200, 200);
  assert.equal(res.ok, false);
  assert.equal(res.status, 'timeout');
  assert.match(res.error, /No answer/);
});

test('commands for other endpoints are never handed to the wrong agent', () => {
  cq.queueCommand('windows-pc', 'block_access', '1.2.3.4');
  cq.queueCommand('linux-01', 'block_access', '5.6.7.8');
  const mine = drain('linux-01');
  assert.equal(mine.length, 1);
  assert.equal(mine[0].target, '5.6.7.8');
  const other = drain('windows-pc');
  assert.equal(other.length, 1);
  assert.equal(other[0].target, '1.2.3.4');
});

test('buttons are named the way the operating system does it', () => {
  assert.equal(pq.actionLabel('block_access', 'linux'), 'Block IP (Linux firewall / fail2ban)');
  assert.equal(pq.actionLabel('block_access', 'windows'), 'Block IP (Windows Firewall)');
  assert.equal(pq.actionLabel('restrict_identity', 'linux'), 'Lock the account for N minutes');
  assert.equal(pq.actionLabel('restrict_identity', 'windows'), 'Disable account for N minutes');
  assert.equal(pq.actionLabel('block_access', ''), 'Block IP (Windows Firewall)');   // old agents
});
