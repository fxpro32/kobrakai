#!/bin/bash
#####################################################################
# GeoLite2 Database Download Script for KobraKai
#####################################################################
#
# This script downloads the MaxMind GeoLite2 Country database
# required for geo-blocking functionality.
#
# INSTRUCTIONS:
# 1. Register for a FREE account at: https://www.maxmind.com/en/geolite2/signup
# 2. After registration, go to: Account > Manage License Keys
# 3. Click "Generate New License Key"
# 4. Run this script with your license key:
#    ./download-geoip.sh YOUR_LICENSE_KEY
#
#####################################################################

set -e

if [ -z "$1" ]; then
    echo "=========================================="
    echo "GeoLite2 Database Downloader for KobraKai"
    echo "=========================================="
    echo ""
    echo "Usage: $0 <LICENSE_KEY>"
    echo ""
    echo "To get your FREE license key:"
    echo "1. Sign up at: https://www.maxmind.com/en/geolite2/signup"
    echo "2. Go to: Account > Manage License Keys"
    echo "3. Generate a new license key"
    echo ""
    exit 1
fi

LICENSE_KEY="$1"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEST_DIR="${SCRIPT_DIR}"

echo "Downloading GeoLite2-Country database..."
echo "Destination: ${DEST_DIR}"

cd "$DEST_DIR"

# Download the database
if ! wget -q -O GeoLite2-Country.tar.gz "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country&license_key=${LICENSE_KEY}&suffix=tar.gz"; then
    echo "ERROR: Download failed. Please check your license key."
    rm -f GeoLite2-Country.tar.gz
    exit 1
fi

# Verify download
if [ ! -s GeoLite2-Country.tar.gz ]; then
    echo "ERROR: Downloaded file is empty. Please check your license key."
    rm -f GeoLite2-Country.tar.gz
    exit 1
fi

# Extract the database
echo "Extracting database..."
tar -xzf GeoLite2-Country.tar.gz

# Move the mmdb file to the destination
mv GeoLite2-Country_*/GeoLite2-Country.mmdb .

# Cleanup
rm -rf GeoLite2-Country_* GeoLite2-Country.tar.gz

if [ -f "GeoLite2-Country.mmdb" ]; then
    echo ""
    echo "=========================================="
    echo "SUCCESS!"
    echo "=========================================="
    echo "Database installed: ${DEST_DIR}/GeoLite2-Country.mmdb"
    echo ""
    echo "To enable geo-blocking, update your config:"
    echo '  "geoip_enabled": true,'
    echo '  "allowed_countries": ["AU"],'
    echo ""
    echo "Change 'AU' to your country's ISO code."
    echo "Common codes: US, GB, CA, NZ, DE, FR, etc."
    echo ""
else
    echo "ERROR: Database file not found after extraction."
    exit 1
fi
