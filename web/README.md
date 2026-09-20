# Bloch Bridge development portal

Static publication source for `https://blochbridge.com/`. The visual styles and
favicon preserve the previously published portal. Content describes the initial
Ethereum mainnet USDC to native Bloch L1 bUSDC route, including outstanding
custody, source deployment, activation and finality work.

There is no JavaScript, wallet connection, approval, deposit address, RPC call,
analytics or transfer endpoint. The DEX link is explicitly a separate testnet.
No source configuration, token holdings or real bridge deployment is inferred
from the site being online. Public transfers remain disabled.

Publish only `index.html`, `style.css`, `favicon.svg`, and `_headers` to the
confirmed existing Cloudflare Pages project. Do not upload the whole repository,
keys or environment files. This README is development documentation and need
not be included in the site artifact. The exact Pages project must be confirmed
from its custom-domain association before deployment.

Before publication, preview desktop and narrow mobile widths; check all local
assets and section links, preserve the CSP headers, and verify the published
content still says USDC/bUSDC transfers are not enabled. External repository links
point to the actual project roots; no uncommitted file URLs or invented contract
addresses are presented.

## Publication on 15 September 2026

Republished the four reviewed public files to the existing `blochbridge` Pages
project with user authorization. Deployment: `4b5735df.blochbridge.pages.dev`.
The files already matched Cloudflare's asset store; this is a verified
republication, not new bridge activation. Desktop/mobile browser checks,
anchors and published styles/favicon passed. Transfers remain disabled.
Previous deployment for rollback: `5f9a35c9-9a4a-4250-8b36-9bc11a44af13`.

## Publication on 20 September 2026

Published the four reviewed public files from commit `ee010dc` to the existing
`blochbridge` Pages project. Deployment: `e669c488.blochbridge.pages.dev`.
The custom domain returned the exact reviewed `index.html` SHA-256
`3b52b254af8e9e893762abfb40c8877e0577ca4753604913ccb3fa1922aa2d60`
with the CSP, permissions, referrer and content-type protections intact. The
copy now reflects the selected Ethereum USDC to Bloch L1 bUSDC qualification
path. It still exposes no wallet or transfer flow and explicitly says transfers
are not enabled. Previous deployment for rollback: `4b5735df.blochbridge.pages.dev`.

Republished the four-file artifact after pinning both public source links to the
reviewed paused-vault commit `29a9aea`. Deployment:
`b41f738e.blochbridge.pages.dev`. Both the deployment URL and custom domain
returned the exact reviewed `index.html` SHA-256
`dde99b69be5e72e38ece76f48851c7fef177c84a9542dc732b35d9bd8ff1902b`
with the required CSP, permissions, referrer and content-type protections. The
site still contains no wallet, approval or transfer endpoint. Previous
deployment for rollback: `e669c488.blochbridge.pages.dev`.
