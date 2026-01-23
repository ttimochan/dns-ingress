#!/bin/bash
set -e

BINARY_PATH=$1
VERSION=$2

mkdir -p pkgdir/{usr/bin,etc/dns-ingress,usr/lib/systemd/system}
cp "$BINARY_PATH" pkgdir/usr/bin/dns-ingress
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

BASENAME=$(basename "$BINARY_PATH")
tar -C pkgdir -cf "dist/${BASENAME}.tar" .
zstd -19 -T0 "dist/${BASENAME}.tar" -o "dist/${BASENAME}.pkg.tar.zst"
rm "dist/${BASENAME}.tar"

echo "Created: dist/${BASENAME}.pkg.tar.zst"
