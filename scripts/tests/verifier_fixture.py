"""Fixture of the custody verifier tests (agent 403, round 19): the built verifier as a private copy.

cargo creates `target/debug/<bin>` under the process umask, so under umask 002 (a shared build host) the binary is
0775, and every tool rightly refuses a verifier that group or others can write (`_stage_verifier`: "immutable regular
... verifier required"). The tests therefore hand the tools a copy with an explicit mode in a directory of their own:
the result no longer depends on the umask of whoever runs the suite. The rule itself is not touched and is pinned by
`test_custody_deployment_ancestry.py::test_a_group_or_other_writable_verifier_is_refused`.
"""
from pathlib import Path
import tempfile


def private_copy(cls, built, mode=0o500):
    """Copy `built` into a fresh 0700 directory with `mode`; the directory is removed with the test class."""
    directory = tempfile.TemporaryDirectory(prefix="custody-verifier-")
    cls.addClassCleanup(directory.cleanup)
    Path(directory.name).chmod(0o700)
    staged = Path(directory.name) / Path(built).name
    staged.write_bytes(Path(built).read_bytes())
    staged.chmod(mode)
    return staged
