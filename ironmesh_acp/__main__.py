"""``python -m ironmesh_acp`` shim."""

import sys

from ironmesh_acp.server import main

if __name__ == "__main__":
    sys.exit(main())
