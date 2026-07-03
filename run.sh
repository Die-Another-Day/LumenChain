#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"

if [ ! -d ".venv" ]; then
  echo "Creating virtual environment..."
  python3 -m venv .venv
fi

source .venv/bin/activate
pip install -q -r requirements.txt

echo ""
echo "LUMENCHAIN starting at http://localhost:8420"
echo "(Set ANTHROPIC_API_KEY as an env var first if you want AI-phrased narrative summaries;"
echo " otherwise deterministic template summaries are used automatically.)"
echo ""

cd backend
uvicorn main:app --host 0.0.0.0 --port 8420
