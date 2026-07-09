#!/bin/bash
# ==========================================
# central-idp — credential rotation script
# ==========================================
# Demonstrates the two rotation procedures documented in
# ems-docs/security-and-compliance.md, implemented concretely for this
# service.
#
# Usage:
#   ./rotate-secrets.sh jwt      Rotate the JWT signing key (zero-downtime)
#   ./rotate-secrets.sh db       Rotate the database password (requires restart)
# ==========================================

set -e

ENV_FILE=".env"

if [ ! -f "$ENV_FILE" ]; then
    echo "Error: $ENV_FILE not found in current directory."
    exit 1
fi

generate_secret() {
    openssl rand -base64 48 | tr -d '\n'
}

rotate_jwt() {
    echo "== Rotating JWT signing key =="

    CURRENT_ID=$(grep '^JWT_CURRENT_KEY_ID=' "$ENV_FILE" | cut -d '=' -f2-)
    CURRENT_SECRET=$(grep '^JWT_CURRENT_KEY_SECRET=' "$ENV_FILE" | cut -d '=' -f2-)

    if [ -z "$CURRENT_ID" ]; then
        CURRENT_ID="key-1"
    fi

    # New key id — increment the numeric suffix (key-1 -> key-2, etc.)
    NEXT_NUM=$(( $(echo "$CURRENT_ID" | grep -oE '[0-9]+$' || echo 0) + 1 ))
    NEW_ID="key-${NEXT_NUM}"
    NEW_SECRET=$(generate_secret)

    echo "Current key ($CURRENT_ID) will become the 'previous' key — still valid for"
    echo "validating tokens issued before this rotation, until the next rotation."
    echo "New current key: $NEW_ID"

    # Move current -> previous, set new current
    sed -i \
        -e "s|^JWT_PREVIOUS_KEY_ID=.*|JWT_PREVIOUS_KEY_ID=${CURRENT_ID}|" \
        -e "s|^JWT_PREVIOUS_KEY_SECRET=.*|JWT_PREVIOUS_KEY_SECRET=${CURRENT_SECRET}|" \
        -e "s|^JWT_CURRENT_KEY_ID=.*|JWT_CURRENT_KEY_ID=${NEW_ID}|" \
        -e "s|^JWT_CURRENT_KEY_SECRET=.*|JWT_CURRENT_KEY_SECRET=${NEW_SECRET}|" \
        "$ENV_FILE"

    # If the PREVIOUS_KEY lines didn't exist yet, append them
    grep -q '^JWT_PREVIOUS_KEY_ID=' "$ENV_FILE" || echo "JWT_PREVIOUS_KEY_ID=${CURRENT_ID}" >> "$ENV_FILE"
    grep -q '^JWT_PREVIOUS_KEY_SECRET=' "$ENV_FILE" || echo "JWT_PREVIOUS_KEY_SECRET=${CURRENT_SECRET}" >> "$ENV_FILE"

    echo ""
    echo "Done. Restart central-idp to apply."
    echo "Tokens signed with '${CURRENT_ID}' remain valid until you rotate again and it ages out."
    echo "Remember to log this rotation in ems-docs/security-and-compliance.md."
}

rotate_db_password() {
    echo "== Rotating database password =="
    echo "This requires a MySQL admin step this script does NOT perform automatically —"
    echo "changing a live password blind could lock you out. Follow these steps:"
    echo ""
    NEW_PASSWORD=$(generate_secret)
    echo "1. Generated new password (save this securely): ${NEW_PASSWORD}"
    echo "2. Run in MySQL, as an admin:"
    echo "   ALTER USER 'root'@'localhost' IDENTIFIED BY '${NEW_PASSWORD}';"
    echo "3. Once confirmed working, update this service's .env:"
    echo "   DB_PASSWORD=${NEW_PASSWORD}"
    echo "4. Restart central-idp."
    echo "5. Log this rotation in ems-docs/security-and-compliance.md."
}

case "$1" in
    jwt)
        rotate_jwt
        ;;
    db)
        rotate_db_password
        ;;
    *)
        echo "Usage: $0 {jwt|db}"
        exit 1
        ;;
esac
