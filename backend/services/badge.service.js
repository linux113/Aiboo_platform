// backend/services/badge.service.js
// Freeze Badge: AiBoO cannot reach a door / badge controller itself. If the
// company's access-control system (or n8n / Zapier / Power Automate in front
// of it) gives a webhook URL, put it in backend/.env:
//   BADGE_WEBHOOK_URL=https://...      BADGE_WEBHOOK_TOKEN=optional-secret
// and we POST {action:'freeze_badge', badge_id, reason, requested_by, requested_at}.
// Used by the one-click playbook (routes/agent.routes.js) and by multi-step
// playbooks (services/pseudolock.service.js).
export const badgeConfigured = () => Boolean(process.env.BADGE_WEBHOOK_URL);

/** Returns { ok, httpStatus, notConfigured, error, message, detail, requestedAt }. */
export async function freezeBadge({ badgeId, reason = '', by = 'analyst' }) {
  const url = process.env.BADGE_WEBHOOK_URL;
  const id = String(badgeId || '').trim().slice(0, 120);
  const why = String(reason || '').trim().slice(0, 300);
  const requestedAt = new Date().toISOString();
  if (!id) return { ok: false, httpStatus: 400, error: 'badge_id (badge number or employee ID) is required', requestedAt };
  if (!url) {
    return {
      ok: false, httpStatus: 501, notConfigured: true, requestedAt,
      error: 'No badge system connected. Add BADGE_WEBHOOK_URL (and optional BADGE_WEBHOOK_TOKEN) to backend/.env and restart the backend.',
    };
  }
  const body = { action: 'freeze_badge', badge_id: id, reason: why, requested_by: by, requested_at: requestedAt };
  try {
    const headers = { 'Content-Type': 'application/json' };
    if (process.env.BADGE_WEBHOOK_TOKEN) headers.Authorization = `Bearer ${process.env.BADGE_WEBHOOK_TOKEN}`;
    const resp = await fetch(url, { method: 'POST', headers, body: JSON.stringify(body), signal: AbortSignal.timeout(8000) });
    const detail = (await resp.text()).slice(0, 300);
    if (!resp.ok) return { ok: false, httpStatus: 502, error: `Badge system answered HTTP ${resp.status}`, detail, remoteStatus: resp.status, requestedAt };
    return { ok: true, httpStatus: 200, message: `Badge ${id} freeze request accepted by the badge system`, detail, remoteStatus: resp.status, requestedAt };
  } catch (err) {
    return {
      ok: false, httpStatus: 502, requestedAt, networkError: true,
      error: `Could not reach the badge system: ${err.name === 'TimeoutError' ? 'no answer in 8 seconds' : err.message}`,
    };
  }
}
