# Bloch Bridge website

English static project hub for blochbridge.com. Cloudflare Pages project:
`blochbridge`, production branch `main`. Publish only this directory; it
contains no application runtime or asset transfer interface.

The site describes tested reference components and pending production
integration accurately. Deposits and withdrawals remain disabled.

Deploy with `wrangler pages deploy site --project-name blochbridge --branch main`.
Custom domain `blochbridge.com` is connected. The owner configured DNS on
2026-09-10; HTTPS and the expected English page were verified afterward.
Preserve the Pages association and DNS records during future deployments.

Validation: internal fragment and local asset checks passed. Production Pages
content was checked over HTTPS. No visual browser inspection was available.
