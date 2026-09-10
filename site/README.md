# Bloch Bridge website

English static project hub for blochbridge.com. Cloudflare Pages project:
`blochbridge`, production branch `main`. Publish only this directory; it
contains no application runtime or asset transfer interface.

The site describes tested reference components and pending production
integration accurately. Deposits and withdrawals remain disabled.

Deploy with `wrangler pages deploy site --project-name blochbridge --branch main`.
Custom domain association exists. Complete DNS with a proxied CNAME at
`blochbridge.com` pointing to `blochbridge.pages.dev`, then confirm Pages domain
validation and HTTPS. Preserve unrelated DNS records.

Validation: internal fragment and local asset checks passed. Production Pages
content was checked over HTTPS. No visual browser inspection was available.
