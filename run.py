from dotenv import load_dotenv
import os
import json
from pathlib import Path

# Load .flaskenv before importing app
load_dotenv('.flaskenv')

from app import app

def get_debug_mode():
    """Read environment from master_config.json to determine debug mode"""
    config_path = os.path.join(os.path.dirname(__file__), 'instance', 'master_config.json')
    try:
        with open(config_path) as f:
            config = json.load(f)
            return config.get('system', {}).get('environment', 'production') == 'development'
    except (FileNotFoundError, json.JSONDecodeError):
        return False  # Default to production (debug=False) if config not found

if __name__ == "__main__":
    debug = get_debug_mode()

    # Collect template files for auto-reload in debug mode
    extra_files = []
    if debug:
        templates_dir = Path('app/templates')
        if templates_dir.exists():
            for template_file in templates_dir.rglob('*.html'):
                extra_files.append(str(template_file))

    # Security: Bind to localhost only - Core should not be exposed externally
    # Access via Nexus proxy at https://localhost:443/core
    app.run(
        host='127.0.0.1',
        port=5000,
        debug=debug,
        extra_files=extra_files if extra_files else None
    )
