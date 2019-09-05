"""
Tests end-user scenarios for sedcli binary.
This suite needs to be run against Python 3.x and the sedcli binary must be
in your $PATH.

Copyright (C) 2018-2019 Intel Corporation

SPDX-License-Identifier: GPL-2.0-or-later
"""
import os
import unittest
import subprocess

sedcli_version = b"v0.1"

class TestSedCLI(unittest.TestCase):
    def test_noargs(self):
        """
        Tests for: sedcli
        """
        cp = subprocess.run(["sedcli"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(cp.returncode, 1,
                        "Expected sedcli with no args to return exit code of 1.")
        self.assertEqual(cp.stderr,
                        b"No command given.\n",
                        "Received an unexpected error message when no args provided.")

    def test_version(self):
        """
        Tests for: sedcli --version
        """
        for good in [["--version"],
                     ["-V"]]:
            cp = subprocess.run(["sedcli"] + good, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.assertEqual(cp.returncode, 0,
                            "Expected sedcli with version flag to return exit code of 0.")
            self.assertEqual(len(cp.stderr), 0,
                            "sedcli version shouldn't generate any error output.")
            self.assertEqual(cp.stdout.strip(), b'sedcli %b\n' % (sedcli_version),
                            "sedcli version didn't generate expected output.")

        for bad in [[b"bad", b"--version"],
                    [b"--VERSION"],
                    [b"-v"],
		    [b"-version"]]:
            cp = subprocess.run(["sedcli"] + bad,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.assertEqual(cp.returncode, 1,
                             "Expected sedcli with no args to return exit code of 1 (%s)." % str(bad))
            self.assertEqual(cp.stderr,
                             b"Unrecognized command " + bad[0] + b"\n",
                             "Received an unexpected error message when no args provided.")
            self.assertEqual(cp.stdout,
                             b"Try `sedcli --help | -H' for more information.\n",
                             "sedcli didn't suggest running 'help' arg.")

    def test_help(self):
        """
        Tests for: sedcli --help
        """
        for good in [["--help"],
                     ["-H"]]:
            cp = subprocess.run(["sedcli"] + good,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.assertEqual(cp.returncode, 0,
                             "Expected sedcli help to return exit code of 0.")
            self.assertEqual(len(cp.stderr), 0,
                             "Received an unexpected error message when help args provided.")
            self.assertEqual(len(cp.stdout), 924,
			     "sedcli --help didn't generate expected output.")
        for bad in [[b"bad", b"--help"],
                    [b"--HELP"],
                    [b"-h"],
		    [b"-help"]]:
            cp = subprocess.run(["sedcli"] + bad,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.assertEqual(cp.returncode, 1,
                             "Expected sedcli help with bad args to return exit code of 1 (%s)." % str(bad))
            self.assertEqual(cp.stderr,
                             b"Unrecognized command " + bad[0] + b"\n",
                             "Received an unexpected error message.")
            self.assertEqual(cp.stdout,
			     b"Try `sedcli --help | -H' for more information.\n",
			     "sedcli didn't suggest running 'help' arg.")

    # Tests for help on commands
    def test_sed_ownership_help(self):
        """
        Tests for: sedcli --ownership --help
        """
        for good in [["--ownership"],
		     ["-O"]]:
            cp = subprocess.run(["sedcli"] + good + ["--help"],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.assertEqual(cp.returncode, 0,
                             "Expected sedcli ownership to return exit code of 0.")
            self.assertEqual(len(cp.stderr), 0,
                             "Received an unexpected error message when ownership args provided.")
            self.assertEqual(len(cp.stdout), 340,
                                 "sedcli --ownership --help didn't generate expected output.")

        for bad in [[b"bad", b"--ownership"],
		    [b"-o"],
		    [b"--OWNERSHIP"],
		    [b"-ownership"]]:
            cp =  subprocess.run(["sedcli"] + bad + ["--help"],
			         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.assertEqual(cp.returncode, 1,
                             "Expected sedcli --ownership --help with bad args to return exit code of 1 (%s)." % str(bad))
            self.assertEqual(cp.stderr,
                             b"Unrecognized command " + bad[0] + b"\n",
                             "Received an unexpected error message.")
            self.assertEqual(cp.stdout,
                             b"Try `sedcli --help | -H' for more information.\n",
                             "sedcli didn't suggest running 'help' arg.")

    def test_sed_activate_lsp_help(self):
        """
        Tests for: sedcli --activate-lsp --help
        """
        for good in [["--activate-lsp"],
                     ["-A"]]:
            cp = subprocess.run(["sedcli"] + good + ["--help"],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.assertEqual(cp.returncode, 0,
                             "Expected sedcli activte-lsp to return exit code of 0.")
            self.assertEqual(len(cp.stderr), 0,
                             "Received an unexpected error message when activate-lsp args provided.")
            self.assertEqual(len(cp.stdout), 398,
                             "sedcli --activate-lsp --help didn't generate expected output.")

        for bad in [[b"bad", b"--activate-lsp"],
                    [b"-a"],
                    [b"--ACTIVATE-LSP"],
                    [b"-activate-lsp"]]:
            cp =  subprocess.run(["sedcli"] + bad + ["--help"],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.assertEqual(cp.returncode, 1,
                             "Expected sedcli --activate-lsp --help with bad args to return exit code of 1 (%s)." % str(bad))
            self.assertEqual(cp.stderr,
                             b"Unrecognized command " + bad[0] + b"\n",
                             "Received an unexpected error message.")
            self.assertEqual(cp.stdout,
                             b"Try `sedcli --help | -H' for more information.\n",
                             "sedcli didn't suggest running 'help' arg.")

    def test_sed_revert_help(self):
        """
        Tests for: sedcli --revert --help
        """
        for good in [["--revert"],
                     ["-R"]]:
            cp = subprocess.run(["sedcli"] + good + ["--help"],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.assertEqual(cp.returncode, 0,
                             "Expected sedcli revert to return exit code of 0.")
            self.assertEqual(len(cp.stderr), 0,
                             "Received an unexpected error message when revert args provided.")
            self.assertEqual(len(cp.stdout), 446,
                             "sedcli --revert --help didn't generate expected output.")

        for bad in [[b"bad", b"--revert"],
                    [b"-r"],
                    [b"--REVERT"],
                    [b"-revert"]]:
            cp =  subprocess.run(["sedcli"] + bad + ["--help"],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.assertEqual(cp.returncode, 1,
                             "Expected sedcli --revert --help with bad args to return exit code of 1 (%s)." % str(bad))
            self.assertEqual(cp.stderr,
                             b"Unrecognized command " + bad[0] + b"\n",
                             "Received an unexpected error message.")
            self.assertEqual(cp.stdout,
                             b"Try `sedcli --help | -H' for more information.\n",
                             "sedcli didn't suggest running 'help' arg.")

    def test_sed_lock_unlock_help(self):
        """
        Tests for: sedcli --lock-unlock --help
        """
        for good in [["--lock-unlock"],
                     ["-L"]]:
            cp = subprocess.run(["sedcli"] + good + ["--help"],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.assertEqual(cp.returncode, 0,
                             "Expected sedcli lock-unlock to return exit code of 0.")
            self.assertEqual(len(cp.stderr), 0,
                             "Received an unexpected error message when lock-unlock args provided.")
            self.assertEqual(len(cp.stdout), 456,
                             "sedcli --lock-unlock --help didn't generate expected output.")

        for bad in [[b"bad", b"--lock-unlock"],
                    [b"-l"],
                    [b"--LOCK-UNLOCK"],
                    [b"-lock-unlock"]]:
            cp =  subprocess.run(["sedcli"] + bad + ["--help"],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.assertEqual(cp.returncode, 1,
                            "Expected sedcli --lock-unlock --help with bad args to return exit code of 1 (%s)." % str(bad))
            self.assertEqual(cp.stderr,
                             b"Unrecognized command " + bad[0] + b"\n",
                             "Received an unexpected error message.")
            self.assertEqual(cp.stdout,
                             b"Try `sedcli --help | -H' for more information.\n",
                             "sedcli didn't suggest running 'help' arg.")

    def test_sed_setup_global_range_help(self):
        """
        Tests for: sedcli --setup-global-range --help
        """
        for good in [["--setup-global-range"],
                     ["-S"]]:
            cp = subprocess.run(["sedcli"] + good + ["--help"],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.assertEqual(cp.returncode, 0,
                            "Expected sedcli setup-global-range to return exit code of 0.")
            self.assertEqual(len(cp.stderr), 0,
                             "Received an unexpected error message when setup-global-range args provided.")
            self.assertEqual(len(cp.stdout), 383,
                             "sedcli --setup-global-range --help didn't generate expected output.")

        for bad in [[b"bad", b"--setup-global-range"],
                    [b"-s"],
                    [b"--SETUP-GLOBAL-RANGE"],
                    [b"-setup-global-range"]]:
            cp =  subprocess.run(["sedcli"] + bad + ["--help"],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.assertEqual(cp.returncode, 1,
                             "Expected sedcli --setup-global-range --help with bad args to return exit code of 1 (%s)." % str(bad))
            self.assertEqual(cp.stderr,
                             b"Unrecognized command " + bad[0] + b"\n",
                             "Received an unexpected error message.")
            self.assertEqual(cp.stdout,
                             b"Try `sedcli --help | -H' for more information.\n",
                             "sedcli didn't suggest running 'help' arg.")

    def test_sed_set_password_help(self):
        """
        Tests for: sedcli --set-password --help
        """
        for good in [["--set-password"],
                     ["-P"]]:
            cp = subprocess.run(["sedcli"] + good + ["--help"],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.assertEqual(cp.returncode, 0,
                             "Expected sedcli set-password to return exit code of 0.")
            self.assertEqual(len(cp.stderr), 0,
                            "Received an unexpected error message when setup-global-range args provided.")
            self.assertEqual(len(cp.stdout), 445,
                             "sedcli --set-password --help didn't generate expected output.")

        for bad in [[b"bad", b"--set-password"],
                    [b"-p"],
                    [b"--SET-PASSWORD"],
                    [b"-set-password"]]:
            cp =  subprocess.run(["sedcli"] + bad + ["--help"],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.assertEqual(cp.returncode, 1,
                            "Expected sedcli --set-password --help with bad args to return exit code of 1 (%s)." % str(bad))
            self.assertEqual(cp.stderr,
                             b"Unrecognized command " + bad[0] + b"\n",
                             "Received an unexpected error message.")
            self.assertEqual(cp.stdout,
                             b"Try `sedcli --help | -H' for more information.\n",
                             "sedcli didn't suggest running 'help' arg.")

# -----------------------------------------------------------------------------
if __name__ == '__main__':
    unittest.main()
