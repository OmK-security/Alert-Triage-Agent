"""Tests the MCP server's own containment policy, with no agent and no model involved."""
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ["QUEUE_FILE"] = str(Path(tempfile.mkdtemp()) / "queue.jsonl")
os.environ["QUEUE_BACKEND"] = "file"

import mcp_server as s


def status(action, target):
    return s.request_containment(action, target, "test")["status"]


BAD = [
    ("block_ip", "8.8.8.8"),          # protected IP
    ("block_ip", "10.77.77.77"),      # valid IP, but in no alert
    ("block_ip", "127.0.0.1"),        # loopback
    ("block_ip", "203.0.113.0/24"),   # a range, not one IP
    ("isolate_host", "dc-01"),        # protected host
    ("isolate_host", "bad host!"),    # invalid hostname
    ("isolate_host", "ghost-99"),     # valid name, but in no alert
]
for action, target in BAD:
    assert status(action, target) == "rejected_by_server_policy", (action, target)

assert status("delete_all", "203.0.113.45") == "rejected"            # unknown action
assert status("block_ip", "203.0.113.45") == "queued_for_human_approval"   # legitimate
assert status("block_ip", "203.0.113.45") == "duplicate"             # same request again
print("server policy tests passed: %d bad requests rejected, 1 legit queued, 1 duplicate stopped" % len(BAD))
