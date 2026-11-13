#!/usr/bin/env bash
set -euo pipefail

# Pocket Nutrition Vault — First-time setup
# Usage: ./setup.sh

echo "=== Pocket Nutrition Vault Setup ==="

# Work from the repository root, wherever the script is called from
cd "$(dirname "${BASH_SOURCE[0]}")"

# Check prerequisites
command -v python3.12 >/dev/null 2>&1 || { echo "Error: python3.12 is required."; exit 1; }

# Virtual environment
if [ ! -d .venv ]; then
  echo "Creating virtual environment..."
  python3.12 -m venv .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate

# Environment
if [ ! -f .env ]; then
  cp .env.example .env
  echo "Created .env from .env.example — Docker reads it (--env-file); the server itself does not"
fi

# Dependencies
echo "Installing dependencies..."
pip install --upgrade pip >/dev/null
pip install -r requirements-dev.txt

echo ""
echo "=== Setup complete! ==="
echo ""
echo "Next steps:"
echo "  1. Activate the virtual environment: source .venv/bin/activate"
echo "  2. Run the server (SQLite, nothing to configure):"
echo "       VAULT_ADMIN_TOKEN=dev uvicorn app.main:build --factory --reload"
echo "  3. Check it: curl localhost:8000/healthz"
echo "  4. Create an owner account (the API key is shown once):"
echo "       curl -X POST localhost:8000/admin/accounts -H 'Authorization: Bearer dev'"
echo "  5. Run tests: pytest"
echo "  6. Running the container image? Edit .env first (database URL, secrets): see README.md"
echo "  7. Using Claude Code? CLAUDE.md has all the context."
