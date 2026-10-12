# The test suite never reads the developer's real ~/.aws/cli/alias (awscli.py checks it before starting aws); tests
# that exercise the alias check point awscli._ALIAS_FILE at a file of their own and restore this value.
from pathlib import Path

import analyzer.awscli as _awscli

NO_ALIAS_FILE = str(Path(__file__).resolve().parent / "no-such-dir" / "alias")
_awscli._ALIAS_FILE = NO_ALIAS_FILE
