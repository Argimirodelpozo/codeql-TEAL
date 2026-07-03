import sys

from .main import main

if __name__ == "__main__":
    # Propagate the exit code: `python -m tealql.cli` must behave like the `tealql`
    # console script (0 clean / 1 findings / 2 error), not always exit 0.
    sys.exit(main())
