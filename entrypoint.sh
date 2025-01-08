#!/bin/sh
set -e

CRYPTD="/usr/local/bin/custom-cryptd"

# Default envs
MODE=${MODE:-server}
KEY_DIR=${KEY_DIR:-/keys}

case "$MODE" in
    "generate")
        FILENAME=$KEY_DIR/key_$(date +"%Y%m%d%H%M%S").key
        echo "Generating a new key in $FILENAME..."
        $CRYPTD -g $FILENAME
        echo "Key generation complete. Exiting."
        ;;
    "server")
        echo "Starting cryptd with all keys in $KEY_DIR..."
        KEYS=$(find "$KEY_DIR" -type f -name "key_*.key" | sort)
        if [ -z "$KEYS" ]; then
            echo "No keys found in $KEY_DIR. Exiting."
            exit 1
        fi
        echo "Loading keys:"
        echo "$KEYS"
        $CRYPTD $KEYS
        ;;
    *)
        echo "Invalid mode: $MODE"
        echo "Available modes:"
        echo "  generate - Generate a new key and exit"
        echo "  server   - Start the server and load all keys in the specified directory"
        exit 1
        ;;
esac