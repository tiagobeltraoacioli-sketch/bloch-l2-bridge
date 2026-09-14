# Bloch Bridge development portal

Static publication source for `https://blochbridge.com/`. The visual styles and
favicon preserve the previously published portal. Content now describes the
planned Ethereum ERC-20 and TRON TRC-20 USDT routes to native Bloch L1, including
outstanding source deployment, activation and finality work.

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
content still says USDT transfers are not enabled. External repository links
point to the actual project roots; no uncommitted file URLs or invented contract
addresses are presented.
