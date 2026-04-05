#!/bin/sh
# Keywarden Docker Entrypoint
# Ensures data directories exist with correct ownership before
# dropping privileges to the keywarden user.

set -e

# Create data directories (bind-mount from host may be owned by root)
mkdir -p /data/keys /data/master /data/avatars

# Fix ownership so the unprivileged keywarden user can write
chown -R keywarden:keywarden /data

# Drop privileges and exec the application
exec su-exec keywarden ./keywarden "$@"
