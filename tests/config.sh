# shellcheck shell=sh
# Settings for running generate.sh against the fixture feeds.
# Sourced by generate.sh via BLOCKLIST_CONFIG; expects TESTS_DIR to be set.
# shellcheck disable=SC2034  # variables are used by generate.sh

FEEDS_DIR="$TESTS_DIR/fixtures"
RETRY_PASS_DELAY=0

FEEDS=$(cat <<'EOF'
s|drop|5|Fixture DROP|https://example.invalid/drop
s|dshield|2|Fixture DShield|https://example.invalid/dshield
s|threatfox|2|Fixture ThreatFox|https://example.invalid/threatfox
l|cins|3|Fixture CINS|https://example.invalid/cins
xl|ipsum|2|Fixture IPsum|https://example.invalid/ipsum
EOF
)

LISTS=$(cat <<'EOF'
blocklist|blocklist_ga|s|10|100
blocklist_l|blocklist_ga_l|s l|10|100
blocklist_xl|blocklist_ga_xl|s l xl|10|100
EOF
)

WHITELIST="52.113.194.132 35.186.224.25"

# Tiny JSON blocks, so the fixtures span several blocks and first-octet
# objects continue across block boundaries.
JSON_BLOCK=200
