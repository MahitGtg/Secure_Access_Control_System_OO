#!/usr/bin/env bash

# DO NOT SUBMIT THIS FILE
#
# When submitting your assignment, this file will be overwritten
# by the automated build and test system.

# Takes a list of `apt` packages to install on standard input.
# Whitespace and commented lines (`#`) will be ignored.

if [ "$(id -u)" -ne 0 ]; then
  echo "This script must be run as root (use sudo)." >&2
  exit 1
fi

LAST_UPDATE=$(stat -c %Y /var/lib/apt/lists 2>/dev/null || echo 0)
CURRENT_TIME=$(date +%s)
TIME_DIFF=$(( CURRENT_TIME - LAST_UPDATE ))
SECS_PER_DAY=$((24 * 60 * 60))

if [ "$TIME_DIFF" -gt "$SECS_PER_DAY" ]; then
  echo "Running apt-get update (last run was more than a day ago)..."
  apt-get update
else
  echo "Skipping apt-get update (last run was within the last 24 hours)."
fi

echo "Installing dependencies..."

while IFS= read -r pkg; do
  # Skip empty lines and comments
  if [[ -z "$pkg" || "$pkg" =~ ^# ]]; then
    continue
  fi
  
  echo "Installing $pkg..."
  apt-get install -y --no-install-recommends "$pkg" || {
    echo "Failed to install $pkg" >&2
    exit 1
  }
done

echo "dependencies installed."

