#!/usr/bin/env bash
# Run the e2e suites (flow, security, gdpr) against an `authfly deploy` install.
#   tools/e2e-deploy.sh <deploy dir with authfly.yaml>
# Reads the generated secrets as root (they are 0600 root) into the test environment only; nothing is printed.
# Starts the React demo app on :5173 on the host (it is the OIDC relying party of the flow test).
set -euo pipefail
dir=$(cd "$1" && pwd)
root=$(cd "$(dirname "$0")/.." && pwd)
y=$dir/authfly.yaml
val() { sed -n "s/^$1: *//p" "$y" | tr -d '"'; }   # top-level keys of authfly.yaml
name=$(val name); target=$(val target); domain=$(val domain)
sec() { sudo -n cat "$dir/.authfly/secrets/$1"; }
export AUTHFLY_URL=http://localhost:4000 STALWART_URL=http://localhost:8080 CONSOLE_URL=http://localhost:4500 AUTHFLY_DOMAIN=$domain
export STALWART_ADMIN="admin:$(sec stalwart_admin_password)" CONSOLE_ADMIN="console:$(sec console_password)" AUTHFLY_SERVICE="authfly-svc@$domain:$(sec service_password)"
if [ "$target" = incus ]; then export E2E_EXEC="sudo -n incus exec $name-authfly --" E2E_DATA=/var/lib/authfly
else export E2E_EXEC="sudo -n docker compose -p authfly-$name -f $dir/.authfly/compose.yml exec -T authfly" E2E_DATA=/data; fi
cd "$root/apps/demo-react"
[ -d dist ] || bunx vite build >/dev/null
AUTHFLY_URL=http://localhost:4000 STALWART_URL=http://localhost:4000 OIDC_CLIENT_ID=demo-react OIDC_REDIRECT_URI=http://localhost:5173/callback \
  SESSION_SECRET=$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n') bun server.ts >/tmp/demo-react.log 2>&1 &
demo=$!
trap 'kill $demo 2>/dev/null' EXIT
for i in $(seq 30); do curl -s -o /dev/null localhost:5173 && break; sleep 1; done
cd "$root"
fail=0
for t in flow security gdpr; do
  echo "== $t ($name, $target)"
  bun "e2e/$t.test.ts" 2>&1 | tail -${E2E_TAIL:-40} || fail=1
done
exit $fail
