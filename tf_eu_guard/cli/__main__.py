"""Allow the CLI package to run with ``python -m tf_eu_guard.cli``."""

import sys

from tf_eu_guard.cli import main

if __name__ == "__main__":
    sys.exit(main())
