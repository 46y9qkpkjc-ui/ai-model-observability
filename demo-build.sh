#!/usr/bin/env bash
# demo-build.sh — one-shot provisioning of the simulated dev project and its
# CI/CD pipeline for the recording. Run once per snapshot AS the developer:
#
#   ./demo-build.sh
#
# Creates:
#   ~/work/ml-serving/            the developer's project (build.sh = npm run build)
#   ~/work/ml-serving-origin.git  local "origin" whose post-receive hook
#                                 simulates the CI/CD pipeline on every push
set -euo pipefail

PROJ="$HOME/work/ml-serving"
ORIGIN="$HOME/work/ml-serving-origin.git"

rm -rf "$PROJ" "$ORIGIN"
mkdir -p "$PROJ/src"

cat > "$PROJ/package.json" <<'EOF'
{
  "name": "ml-serving",
  "version": "1.8.2",
  "private": true,
  "description": "Inference serving layer for fraud/churn models",
  "scripts": {
    "build": "bash build.sh"
  },
  "devDependencies": {
    "ai-model-observability": "^1.0.0"
  }
}
EOF

cat > "$PROJ/src/server.mjs" <<'EOF'
import http from 'node:http';
const port = process.env.PORT || 8080;
http.createServer((req, res) => {
  if (req.url === '/healthz') { res.end('ok'); return; }
  res.setHeader('content-type', 'application/json');
  res.end(JSON.stringify({ model: 'fraud-gbdt-17', score: 0.82 }));
}).listen(port, () => console.log(`ml-serving listening on :${port}`));
EOF

cat > "$PROJ/src/predict.mjs" <<'EOF'
export function score(features) {
  const w = [0.42, -0.17, 0.91];
  const z = features.reduce((s, x, i) => s + x * w[i], 0);
  return 1 / (1 + Math.exp(-z));
}
EOF

cat > "$PROJ/tsconfig.json" <<'EOF'
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "NodeNext",
    "strict": true,
    "outDir": "dist"
  },
  "include": ["src/**/*"]
}
EOF

cat > "$PROJ/.gitignore" <<'EOF'
node_modules/
dist/
EOF

cat > "$PROJ/README.md" <<'EOF'
# ml-serving

Inference serving layer for the fraud/churn models.

```bash
npm run build   # typecheck + bundle + push -> triggers CI/CD
node dist/server.mjs
```

Observability (drift + inference telemetry) via `ai-model-observability`.
EOF

cat > "$PROJ/build.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
STAMP=$(date +%Y%m%d-%H%M)
REV=$(git rev-parse --short HEAD 2>/dev/null || echo '--------')

echo "[build] ml-serving 1.8.2 · rev $REV · node $(node -v)"
echo "[build] restoring dependencies ... up to date (214 packages, 1.3s)"
echo "[build] typecheck (tsc --noEmit) ..."
for f in src/*.mjs; do node --check "$f"; done
echo "[build] typecheck ok — 0 errors (0.8s)"

rm -rf dist && mkdir -p dist
cp src/* dist/
N=$(find dist -type f | wc -l | tr -d ' ')
echo "[build] bundle -> dist/ ($N files, 640 KB)"
echo "[build] unit tests: 138 passed, 0 failed (2.1s)"

git add -A
git commit -q -m "build: release 1.8.2 ($STAMP)" --allow-empty
echo "[build] artifacts packaged — ml-serving:1.8.2 pushed to registry.acme.internal"
echo "[ci] POST https://ci.acme.internal/api/v1/pipelines (repo=ml-serving, ref=main)"
git push -q origin HEAD:main
echo "BUILD SUCCESS — pipeline #4721 completed on jenkins-worker-03"
EOF
chmod +x "$PROJ/build.sh"

# local origin whose post-receive hook plays the CI/CD runner
git init -q --bare -b main "$ORIGIN"
cat > "$ORIGIN/hooks/post-receive" <<'EOF'
#!/usr/bin/env bash
echo "[ci] pipeline #4721 queued on jenkins-worker-03"
echo "[ci] stage lint     ok   (0.4s)"
echo "[ci] stage typecheck ok   (0.8s)"
echo "[ci] stage test      ok   138 passed (2.1s)"
echo "[ci] stage package   ok   ml-serving:1.8.2 -> registry.acme.internal"
echo "[ci] stage deploy    ok   https://ml-serving.dev.acme.internal"
echo "[ci] BUILD SUCCESS — pipeline #4721"
EOF
chmod +x "$ORIGIN/hooks/post-receive"

git -C "$PROJ" init -q -b main
git -C "$PROJ" config user.name 'arjun.das'
git -C "$PROJ" config user.email 'arjun.das@acme.internal'
git -C "$PROJ" remote add origin "$ORIGIN"
git -C "$PROJ" add -A
git -C "$PROJ" commit -q -m 'initial import'
git -C "$PROJ" push -q -u origin main

echo "demo-build ready:"
echo "  project : $PROJ"
echo "  origin  : $ORIGIN (CI hook installed)"
echo "  record  : cd $PROJ && npmi install ai-model-observability && npm run build"
