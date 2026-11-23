"""An acceptance probe (not a test): connect over a socket as admin, run one statement, print its rows.
Exit 0 with the rows, or 1 with the driver's error (sys.argv: socket path, password, statement)."""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import imagedb  # noqa: E402

try:
    conn = imagedb.connect(socket=sys.argv[1], user="admin", password=sys.argv[2], timeout=10, connect_timeout=10)
    cur = conn.cursor()
    cur.execute(sys.argv[3])
    print(cur.fetchall())
    conn.close()
except Exception as ex:  # the probe reports whatever the driver raised
    print("REFUSED: %s: %s" % (type(ex).__name__, ex))
    sys.exit(1)
