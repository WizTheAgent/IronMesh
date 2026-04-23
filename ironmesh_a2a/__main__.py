"""``python -m ironmesh_a2a`` shim."""

import sys

from ironmesh_a2a.server import main

if __name__ == "__main__":
    sys.exit(main())
