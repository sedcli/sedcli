# Copyright (C) 2018-2019 Intel Corporation
#
# SPDX-License-Identifier: GPL-2.0-or-later

"""
Tests end-user scenarios for sedcli binary.
This suite needs to be run against Python 3.x and the sedcli binary must be
in your $PATH.
"""

import os
import sys
import unittest
import subprocess
import random
import string

class TestSedcliBasic(unittest.TestCase):

	NVME_DEV_PATH = '/dev/nvme0n1'

	def __init__(self, *args, **kwargs):
		super(TestSedcliBasic, self).__init__(*args, **kwargs)

		letters = string.ascii_lowercase
		self.nvme_sid_key =  ''.join(random.choice(letters) for i in range(32)).encode('ascii')

	def test_initial_setup(self):
		"""
		Tests for: sedcli intial provision of drive (that is take ownerhisp,
		activate Locking SP and setup global locking range)
		"""

		print("Key used to initial provision drive:" + str(self.nvme_sid_key))

		pipe = subprocess.Popen(["sedcli", "--ownership", "--device", self.NVME_DEV_PATH], stdout = subprocess.PIPE, stdin = subprocess.PIPE, stderr = subprocess.PIPE)
		pipe.stdin.write(self.nvme_sid_key + b'\n' + self.nvme_sid_key + b'\n')
		outs, errs = pipe.communicate()
		pipe.stdin.close()

		# Test taking ownership (test is assuming that drive is in Manufactured-inactive state)
		self.assertEqual(pipe.returncode, 0, "sedcli returned error while taking ownership of the drive:\n" + str(errs))
		self.assertEqual(len(errs), 0, "sedcli returned success code but error message has been printed on stderr:\n" + str(errs))

		# Activate Locking SP
		pipe = subprocess.Popen(["sedcli", "--activate-lsp", "--device", self.NVME_DEV_PATH], stdout = subprocess.PIPE, stdin = subprocess.PIPE, stderr = subprocess.PIPE)
		pipe.stdin.write(self.nvme_sid_key + b'\n')
		outs, errs = pipe.communicate()
		pipe.stdin.close()

		self.assertEqual(pipe.returncode, 0, "sedcli returned error while activating Locking SP:\n" + str(errs))
		self.assertEqual(len(errs), 0, "sedcli returned success code but error message has been printed on stderr:\n" + str(errs))

		# Set RLE and WLE on global locking range
		pipe = subprocess.Popen(["sedcli", "--setup-global-range", "--device", self.NVME_DEV_PATH], stdout = subprocess.PIPE, stdin = subprocess.PIPE, stderr = subprocess.PIPE)
		pipe.stdin.write(self.nvme_sid_key + b'\n')
		outs, errs = pipe.communicate()
		pipe.stdin.close()

		self.assertEqual(pipe.returncode, 0, "sedcli returned error while setting RLE and WLE on global range:\n" + str(errs))
		self.assertEqual(len(errs), 0, "sedcli returned success code but error message has been printed on stderr:\n" + str(errs))

# -----------------------------------------------------------------------------
if __name__ == '__main__':
	if len(sys.argv) > 1:
		TestSedcliBasic.NVME_DEV_PATH = sys.argv.pop()
	unittest.main()
