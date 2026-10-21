#!/usr/bin/env bash
# Cross-repo e2e: deploy via the CLI (authfly/cli) → widgets (authfly/authkit) → Stalwart adapter (authfly/authfly)
# → magic link. Every sibling repo comes from deps.lock (.deps/), nothing is copied.
#   tools/e2e-cross.sh [dir]      default dir: /tmp/authfly-xrepo (docker target, gdpr pack, ports 4000/8080/4500)
# Steps:
#   1. tools/deps.sh; release $XREPO_VERSION (default 0.4.0) from this checkout + .deps/stalwart (Console)
#   2. authfly init -y (provider stalwart) + deploy + doctor (0 FAIL)
#   3. /api/v1/capabilities → @authfly/core widgetProps; the hosted sign-in page renders authkit's templ block
#      (data-testid=authfly-sign-in) and the React demo bundle is built from authkit's React blocks
#   4. @authfly/contract-tests with @authfly/provider-stalwart against the deploy: sign-up, verify, magic link
#      (sent, read from the Stalwart mailbox over JMAP, verified, single use), reset, session, export, delete
#   5. the flow suite (hosted pages + OIDC into the React demo + the Python/PHP SDKs from .deps/authfly)
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd); cd "$root"
dir=${1:-/tmp/authfly-xrepo}; v=${XREPO_VERSION:-0.4.0}
AF="sudo -n $root/dist/$v/authfly-linux-amd64"
step() { echo; echo "### $*"; }
step "1. deps + release $v"
bash tools/deps.sh
DOCKER="${DOCKER:-sudo -n docker}" bash tools/release.sh "$v" | tail -1
step "2. authfly init + deploy (docker, gdpr, provider stalwart)"
sudo -n mkdir -p "$dir" && cd "$dir"
$AF init -y --force --name xrepo --target docker --provider stalwart --runtime react --adapter node --policy gdpr \
  --operator "Auth Fly Test" --domain authfly.test --public-url http://localhost:4000 --tls off --http-port 4000 \
  --smtp-port 2525 --submissions-port 4465 --imaps-port 9993 --signin magic,password,username \
  --client "demo-react:Demo app (React)=http://localhost:5173/callback;adapters:Adapter test=http://localhost:9999/callback" \
  --channel "$root/dist/channel.json"
sudo -n sed -i "s/^    version: \"\"/    version: $v/" authfly.yaml
grep -q '^provider: stalwart' authfly.yaml
$AF deploy | tail -3
fails=$($AF doctor | grep -c '^FAIL' || true); echo "doctor FAIL: $fails"; [ "$fails" = 0 ]
cd "$root"
step "3. capabilities → widgets"
caps=$(curl -sf localhost:4000/api/v1/capabilities); echo "capabilities: $caps"
(cd .deps/authfly && bun install >/dev/null 2>&1 && bun -e "
import { widgetProps } from '@authfly/core';
const p = widgetProps($caps);
if (p.signIn.method !== 'password' || !p.signIn.magicLink) throw new Error('widgetProps ' + JSON.stringify(p));
console.log('widgetProps.signIn', JSON.stringify(p.signIn));")
curl -sf localhost:4000/auth/sign-in | grep -q 'data-testid="authfly-sign-in"' && echo "hosted sign-in renders the authkit templ block @ $(awk '$1=="authkit"{print substr($3,1,7)}' deps.lock)"
(bun install >/dev/null 2>&1 && cd apps/demo-react && bunx vite build >/dev/null && grep -l "authfly-account" dist/assets/*.js >/dev/null) && echo "React demo bundle built from authkit React blocks"
step "4. contract suite: @authfly/provider-stalwart against the deploy (incl. magic link)"
sec() { sudo -n cat "$dir/.authfly/secrets/$1"; }
(cd .deps/authfly && AUTHFLY_URL=http://localhost:4000 STALWART_URL=http://localhost:8080 AUTHFLY_DOMAIN=authfly.test bun tests/contract.ts)
step "5. flow suite (hosted pages, magic link, OIDC into the demo, SDKs)"
E2E_REBUILD=1 E2E_SUITES=flow E2E_TAIL=${E2E_TAIL:-25} bash tools/e2e-deploy.sh "$dir"
echo; echo "cross-repo e2e: PASS"
