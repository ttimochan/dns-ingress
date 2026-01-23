#!/bin/bash
set -e

ARCH=$1
TARGET=$2
BINARY_PATH=$3
VERSION=$4

mkdir -p debian-pkg/DEBIAN
mkdir -p debian-pkg/usr/bin
mkdir -p debian-pkg/etc/dns-ingress
mkdir -p debian-pkg/usr/lib/systemd/system

cp "$BINARY_PATH" debian-pkg/usr/bin/dns-ingress

cat > debian-pkg/DEBIAN/control <<EOF
Package: dns-ingress
Version: $VERSION
Section: net
Priority: optional
Architecture: $ARCH
Depends: libssl3, libc6
Maintainer: ttimochan <ttimochan@example.com>
Description: DNS Proxy Server with SNI Routing
 A high-performance DNS proxy server supporting DoT, DoH, DoQ, and DoH3.
Homepage: https://github.com/ttimochan/dns-ingress
EOF

cat > debian-pkg/DEBIAN/postinst <<EOF
#!/bin/bash
if ! id dns-ingress &>/dev/null; then
    useradd --system --no-create-home --shell /usr/sbin/nologin dns-ingress 2>/dev/null || true
fi
mkdir -p /etc/dns-ingress
mkdir -p /var/log/dns-ingress
echo "DNS Ingress installed. Please edit /etc/dns-ingress/config.toml"
EOF
chmod +x debian-pkg/DEBIAN/postinst

cat > debian-pkg/usr/lib/systemd/system/dns-ingress.service <<EOF
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

dpkg-deb --build debian-pkg dist/dns-ingress_${VERSION}_${ARCH}.deb
echo "Created: dist/dns-ingress_${VERSION}_${ARCH}.deb"
