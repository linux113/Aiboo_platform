# Billing setup (Razorpay)

Billing uses prepaid monthly or yearly periods. A renewal payment is required to extend access; automatic recurring card charges are not configured in this stage. Card details are handled by Razorpay Checkout and are never stored by AiBoO.

## Server configuration

1. Add `RAZORPAY_KEY_ID`, `RAZORPAY_KEY_SECRET`, and `RAZORPAY_WEBHOOK_SECRET` to the backend's protected environment. Keep the secret and webhook secret server-side; only the public key ID is returned to the browser. `RAZORPAY_API_BASE_URL` is an optional HTTPS override (include `/v1`); blank uses Razorpay's official API URL. In the frontend build environment, `VITE_RAZORPAY_CHECKOUT_SCRIPT_URL` is an optional checkout script URL override; blank uses Razorpay's official `checkout.js`. Both URL settings are blank in the example files, and the frontend URL is public configuration, not a secret.
2. Set `MONGO_URI`, `PLATFORM_ADMIN_EMAIL`, `PLATFORM_ADMIN_NAME`, and `PLATFORM_ADMIN_PASSWORD` in that environment, then run `npm run bootstrap:super-admin` once from `backend/`. The script does not print the password and refuses a second platform Super Admin.
3. Run `npm run plans:seed` from `backend/` to create Basic, Business, and Enterprise package rows. This does not choose prices.
4. Sign in with the platform Super Admin account and enter monthly/yearly INR prices in the platform-only pricing screen. Prices are stored as paise. Blank prices disable online checkout for that billing cycle.
5. Configure a Razorpay webhook to send `payment.captured` events to `/api/billing/webhooks/razorpay`, using the same webhook secret configured in step 1.

Company signup creates a pending workspace and its first admin. The workspace activates only after Razorpay confirms a captured payment. On expiry, protected workspace APIs, agent credentials, and dashboard sockets are denied; the authenticated Billing screen remains available for renewal. The agent license-heartbeat endpoint remains available to tenant-bound agent credentials and returns `active: false` when expired.

## HTTP constraint

AiBoO does not automatically enable TLS or change the hosting scheme. Razorpay Checkout or its production policies may require an HTTPS origin; if so, payment checkout cannot be completed over the requested plain-HTTP deployment. Use Razorpay test keys and an approved local/test setup before any live payment attempt. No payment has been processed or tested by this implementation.
