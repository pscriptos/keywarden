#!/bin/sh
# Keywarden Docker Entrypoint
# Ensures data directories exist with correct ownership before
# dropping privileges to the keywarden user.

set -e

# Configure timezone if TZ is set (requires tzdata package)
if [ -n "$TZ" ] && [ -f "/usr/share/zoneinfo/$TZ" ]; then
  ln -sf "/usr/share/zoneinfo/$TZ" /etc/localtime
  echo "$TZ" > /etc/timezone
fi

# Create data directories (bind-mount from host may be owned by root)
mkdir -p /data/keys /data/master /data/avatars

# Fix ownership so the unprivileged keywarden user can write
chown -R keywarden:keywarden /data

# Drop privileges and exec the application
exec su-exec keywarden ./keywarden "$@"
