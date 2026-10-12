import sys

if sys.version_info < (3, 11):
    sys.exit(f"aws-analyzer needs Python 3.11 or newer (this is {sys.version.split()[0]}). "
             "On macOS try: python3.12 -m analyzer ... (brew install python) or use conda/pyenv.")

from .cli import main  # noqa: E402

sys.exit(main())
