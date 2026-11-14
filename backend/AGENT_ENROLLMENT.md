# Company endpoint enrollment

Company admins can issue one credential per endpoint from **Endpoints → Enroll an endpoint**. Credential management is tenant-scoped; a key belongs to one company and one endpoint. Revoke it from the same panel if the endpoint is retired or the key is exposed.

## Issue and install

1. Sign in to the company workspace and open **Endpoints**.
2. Enter the endpoint ID, platform, and optional label, then choose **Issue key**.
3. Copy the one-time key. It is not stored as plaintext and cannot be shown again. Store it only in the endpoint's local agent configuration; do not include it in a command, ticket, screenshot, or chat.
4. Enter the backend's plain-HTTP address in the enrollment panel's **Server address** field.
5. Use the displayed setup command on the endpoint:
   - **Windows:** run `configure.ps1 -EndpointName "<endpoint-id>"` from the extracted agent installer folder. Paste the key at the hidden prompt.
   - **Linux:** from the extracted `linux-agent` folder, run the displayed `install.sh` command. Paste the key at the hidden prompt.

The endpoint ID must match the value issued in the dashboard. Linux passes it through `--name`; Windows passes it to `configure.ps1 -EndpointName`. The endpoint configuration contains the key and should remain readable only by the local account that runs the agent.

## License behavior

Tenant agent credentials use `/api/agent/license-heartbeat` for the minimal licensing check. Windows checks every 15 seconds and Linux checks at most every 15 seconds. After an inactive response or heartbeat failure, the agents fail closed: they suppress new detection events/reports and automatic response; Windows event-log polling pauses, Linux skips its scan loop, and queued Windows reports are not sent until access is active again. The backend independently rejects tenant reports and actions as soon as the paid term is inactive, so the heartbeat interval does not extend server access. Only the licensing heartbeat remains available for an expired credential. Revocation blocks that credential immediately.

Tenant endpoints use the REST command queue (not the legacy shared Socket.IO channel). Dashboard commands are delivered only to the matching endpoint within the same organization and are accepted only while the subscription is active and its plan enables `responseActions` (Business/Enterprise by default). Basic-plan agents continue monitoring but do not poll for or execute response commands. Windows and Linux tenant agents poll over the configured HTTP backend address.
