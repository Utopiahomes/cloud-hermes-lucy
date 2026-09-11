# Utopia R1 activation checkpoint

Status: activation preparation complete; customer-facing activation is blocked on the
exact public/private ingress and customer identity choices below. Transcript capture
remains disabled.

## Completed preparation

- R1-0 through R1-5 technical acceptance passed at commit
  `d43f7e67cb5cd9e26a4ce1eafa5009d20671260d`.
- A fail-closed activation manifest, validator, template, and seven focused tests were
  added at commit `9724b220dfdd0f5ccf1dcc78a6c8f95bfc724d6f`.
- The validator requires exact source/rollback/image/schema/AWS pins, exact HTTPS
  origins, distinct public/private hostnames, a pinned customer IdP and strong-auth
  claim, bounded rates, an approved public snapshot, and complete provider-cost limits
  if paid inference is enabled. It cannot authorize transcript capture.
- A quarantined rollout attempt confirmed the operational fence: Render built the exact
  candidate, but the ordinary runtime correctly refused admission while PostgreSQL was
  quarantined. Cleanup re-suspended all four ordinary services. The PostgreSQL public
  allow-list remained empty and no capture, provider call, public route, or data change
  occurred.
- Read-only inspection of `C:\Users\Forti\Projects\utopia-homes-web` found a public
  Vercel/Next.js site with no implemented Clerk, Auth0, Cognito, Entra, Auth.js, or other
  customer login. Its local `NEXT_PUBLIC_SITE_URL` remains `http://localhost:3000`;
  production DNS is intentionally outside that repository's committed configuration.

## Owner inputs still required

1. Choose the first live scope: public website Lucy only, or public plus authenticated
   private Lucy. Public-first is the recommended smallest activation.
2. Confirm the exact public hostname/path. The recommended default is the existing
   Utopia Homes production hostname with a same-origin `/api/lucy` proxy; this avoids a
   new browser-to-Render cross-origin trust boundary. The actual production hostname is
   not recorded in source and must be confirmed.
3. For private Lucy, choose/provide the customer identity provider, issuer, audience,
   stable owner subject, and strong-auth claim. AWS operator SSO cannot substitute.
4. Approve the first public content snapshot. The recommended seed is only the existing
   approved version-controlled Utopia Homes public content; private forms/submissions,
   email configuration, unpublished facts, and operational records stay excluded.
5. Choose whether OpenRouter paid inference is part of the first launch. The recommended
   first deployment keeps it off until exact model/rate and dollar caps are approved.

## Exact next action

After those inputs are recorded, populate the private manifest, validate it, build the
same-origin website proxy/widget in the Utopia Homes workspace, deploy the exact Lucy
revision under quarantine, prove negative ingress/auth/cross-realm controls, perform the
protected activation handoff, then resume only the selected services. Any failure returns
the realm to quarantine and suspension.
