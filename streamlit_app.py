"""Streamlit Community Cloud entrypoint.

The main application lives in src/app.py. Keeping this thin wrapper in the
repository root makes cloud deployment easier because the entrypoint is obvious.
"""

from pathlib import Path
import runpy


APP_PATH = Path(__file__).parent / "src" / "app.py"
runpy.run_path(str(APP_PATH), run_name="__main__")
