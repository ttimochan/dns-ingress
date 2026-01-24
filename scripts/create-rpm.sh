#!/bin/bash
set -e

ARCH=$1
TARGET=$2
BINARY_PATH=$3
VERSION=$4

# RPM doesn't allow '-' in version, replace with '.'
RPM_VERSION=$(echo "$VERSION" | tr '-' '.')

# Get absolute path to binary
BINARY_ABS=$(realpath "$BINARY_PATH")

# Create spec file with proper escaping
CHANGELOG_DATE=$(date '+%a %b %d %Y')

cat > /tmp/dns-ingress.spec <<SPEC
Name:           dns-ingress
Version:        $RPM_VERSION
Release:        1
Summary:        DNS Proxy Server with SNI Routing
License:        AGPL-3.0
URL:            https://github.com/ttimochan/dns-ingress
BuildArch:      $(echo $TARGET | cut -d'-' -f1)

%description
A high-performance DNS proxy server supporting DoT, DoH, DoQ, and DoH3 protocols.

%install
mkdir -p %{buildroot}/usr/bin
mkdir -p %{buildroot}/etc/dns-ingress
mkdir -p %{buildroot}/usr/lib/systemd/system
cp $BINARY_ABS %{buildroot}/usr/bin/dns-ingress

cat > %{buildroot}/usr/lib/systemd/system/dns-ingress.service <<'SERVICE'
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
SERVICE

%pre
groupadd -r dns-ingress 2>/dev/null || true
useradd -r -g dns-ingress -s /sbin/nologin dns-ingress 2>/dev/null || true

%files
%defattr(-,root,root,-)
%dir /etc/dns-ingress
/usr/lib/systemd/system/dns-ingress.service
%attr(755,root,root) %{_bindir}/dns-ingress

%changelog
* $CHANGELOG_DATE - ttimochan - $VERSION
- Release $VERSION
SPEC

# Initialize RPM database
rpm --initdb --dbpath /root/.rpmdb 2>/dev/null || true

# Build RPM
rpmbuild -bb /tmp/dns-ingress.spec \
  --define "_topdir $(pwd)/rpmbuild" \
  --define "_rpmdbpath /root/.rpmdb"

# Move result to dist
mkdir -p dist
find rpmbuild/RPMS -name "*.rpm" -exec cp {} dist/ \;

echo "Created RPM packages in dist/"
