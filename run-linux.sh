#!/usr/bin/env bash
set -eu

cd -- "$(dirname -- "$(readlink -f -- "$0")")"

if ! command -v node >/dev/null 2>&1; then
  echo "Node.js 18 or newer is required. Install Node.js and try again." >&2
  exit 1
fi

if ! command -v npm >/dev/null 2>&1; then
  echo "npm was not found. Install npm and try again." >&2
  exit 1
fi

node_version="$(node -p "Number(process.versions.node.split('.')[0])")"
if [ "$node_version" -lt 18 ]; then
  echo "Node.js 18 or newer is required (found $(node --version))." >&2
  exit 1
fi

if [ ! -d node_modules ]; then
  echo "Installing dependencies for the first run..."
  npm ci
fi

echo "Starting Free GST Billing. Keep this terminal open while using the app."
npm start
