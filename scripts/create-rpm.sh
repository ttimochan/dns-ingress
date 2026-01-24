#!/bin/bash
set -e

ARCH=$1
TARGET=$2
BINARY_PATH=$3
VERSION=$4
WORKSPACE=${GITHUB_WORKSPACE:-$(pwd)}

# RPM doesn't allow '-' in version, replace with '.'
RPM_VERSION=$(echo "$VERSION" | tr '-' '.')

mkdir -p "$WORKSPACE/rpmbuild/SPECS"

# Create spec file
cat > "$WORKSPACE/rpmbuild/SPECS/dns-ingress.spec" <<'EOFSPEC'
Name:           dns-ingress
Version:        VERSION_PLACEHOLDER
Release:        1
Summary:        DNS Proxy Server with SNI Routing
License:        AGPL-3.0
URL:            https://github.com/ttimochan/dns-ingress
BuildArch:      TARGET_PLACEHOLDER

%description
A high-performance DNS proxy server supporting DoT, DoH, DoQ, and DoH3 protocols.

%install
mkdir -p %{buildroot}/usr/bin
mkdir -p %{buildroot}/etc/dns-ingress
mkdir -p %{buildroot}/usr/lib/systemd/system
cp BINARY_PATH %{buildroot}/usr/bin/dns-ingress

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
* $(date '+%a %b %d %Y') - ttimochan - VERSION_PLACEHOLDER
- Release VERSION_PLACEHOLDER
EOFSPEC

# Replace placeholders
sed -i "s/VERSION_PLACEHOLDER/$RPM_VERSION/g" "$WORKSPACE/rpmbuild/SPECS/dns-ingress.spec"
sed -i "s/TARGET_PLACEHOLDER/$(echo $TARGET | cut -d'-' -f1)/g" "$WORKSPACE/rpmbuild/SPECS/dns-ingress.spec"
sed -i "s|BINARY_PATH|$BINARY_PATH|g" "$WORKSPACE/rpmbuild/SPECS/dns-ingress.spec"
sed -i "s|VERSION_PLACEHOLDER|$VERSION|g" "$WORKSPACE/rpmbuild/SPECS/dns-ingress.spec"

# Initialize RPM database
HOME=/root rpm --initdb --dbpath /root/.rpmdb 2>/dev/null || true

# Build RPM
cd "$WORKSPACE"
HOME=/root rpmbuild -bb "$WORKSPACE/rpmbuild/SPECS/dns-ingress.spec" \
  --define "_topdir $WORKSPACE/rpmbuild" \
  --define "_rpmdbpath /root/.rpmdb"

find "$WORKSPACE/rpmbuild/RPMS" -name "*.rpm" -exec cp {} dist/ \;

echo "Created RPM packages in dist/"
