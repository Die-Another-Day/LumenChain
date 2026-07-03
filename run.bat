@echo off
cd /d "%~dp0"

if not exist ".venv" (
  echo Creating virtual environment...
  python -m venv .venv
)

call .venv\Scripts\activate.bat
pip install -q -r requirements.txt

echo.
echo LUMENCHAIN starting at http://localhost:8420
echo (Set ANTHROPIC_API_KEY as an env var first if you want AI-phrased narrative summaries;
echo  otherwise deterministic template summaries are used automatically.)
echo.

cd backend
uvicorn main:app --host 0.0.0.0 --port 8420
