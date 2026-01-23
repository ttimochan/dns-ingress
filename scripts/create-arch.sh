#!/bin/bash
set -e

VERSION=$1

mkdir -p pkgdir/{usr/bin,etc/dns-ingress,usr/lib/systemd/system}
cp target/release/dns-ingress pkgdir/usr/bin/
cp CHANGELOG.md pkgdir/usr/share/doc/dns-ingress/ 2>/dev/null || true

cat > pkgdir/usr/lib/systemd/system/dns-ingress.service <<'EOF'
[Unit]
Description=DNS Proxy Server with SNI Routing
After=network.target

[Service]
Type=simple
User=dns-ingress
Group=dns-ingress
ExecStart=/usr/bin/dns-ingress
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

tar -C pkgdir -cf dns-ingress-${VERSION}-x86_64.tar .
zstd -19 -T0 dns-ingress-${VERSION}-x86_64.tar -o dist/dns-ingress-${VERSION}-x86_64.pkg.tar.zst

echo "Created: dist/dns-ingress-${VERSION}-x86_64.pkg.tar.zst"
