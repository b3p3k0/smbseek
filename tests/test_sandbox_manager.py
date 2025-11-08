import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from gui.utils.sandbox_manager import SandboxManager, SandboxUnavailable


class SandboxManagerTests(unittest.TestCase):
    def test_build_command_includes_runner_and_target(self):
        manager = SandboxManager(runner="podman", image="alpine:latest")
        cmd = manager._build_command("10.0.0.5", "guest", "")
        self.assertEqual(cmd[0], "podman")
        self.assertIn("//10.0.0.5", cmd[-1])
        self.assertIn("-e", cmd)

    def test_build_script_handles_anonymous(self):
        script = SandboxManager._build_script("1.2.3.4", "")
        self.assertIn("-N", script)
        self.assertNotIn("$SMB_USER", script.split("-N")[-1])

    def test_unavailable_manager_raises(self):
        manager = SandboxManager(runner=None)
        with self.assertRaises(SandboxUnavailable):
            manager.list_shares("10.0.0.1", "", "")


if __name__ == "__main__":
    unittest.main()
