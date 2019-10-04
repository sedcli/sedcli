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

def run_cmd(cmd_params, stdin_bytes):
	global pipe
	pipe = subprocess.Popen(cmd_params, stdout = subprocess.PIPE, stdin = subprocess.PIPE, stderr = subprocess.PIPE)
	pipe.stdin.write(stdin_bytes)
	outs, errs = pipe.communicate()
	pipe.stdin.close()
	return outs, errs

def gen_rand_key(key_len):
	letters = string.ascii_lowercase
	return  ''.join(random.choice(letters) for i in range(key_len)).encode('ascii')

class TestSedcliBasic(unittest.TestCase):

	NVME_DEV_PATH = '/dev/nvme0n1'

	def __init__(self, *args, **kwargs):
		super(TestSedcliBasic, self).__init__(*args, **kwargs)

		self.nvme_sid_key = gen_rand_key(32)

	def test_initial_setup(self):
		"""
		Tests for: sedcli intial provision of drive (that is take ownerhisp,
		activate Locking SP and setup global locking range)
		"""
		print("Key used to initial provision drive:" + str(self.nvme_sid_key))

		# Test taking ownership (test is assuming that drive is in Manufactured-inactive state)
		outs, errs = run_cmd(["sedcli", "--ownership", "--device", self.NVME_DEV_PATH], self.nvme_sid_key + b'\n' + self.nvme_sid_key + b'\n')

		self.assertEqual(pipe.returncode, 0, "sedcli returned error while taking ownership of the drive:\n" + str(errs))
		self.assertEqual(len(errs), 0, "sedcli returned success code but error message has been printed on stderr:\n" + str(errs))

		# Activate Locking SP
		outs, errs = run_cmd(["sedcli", "--activate-lsp", "--device", self.NVME_DEV_PATH], self.nvme_sid_key + b'\n')

		self.assertEqual(pipe.returncode, 0, "sedcli returned error while activating Locking SP:\n" + str(errs))
		self.assertEqual(len(errs), 0, "sedcli returned success code but error message has been printed on stderr:\n" + str(errs))

		# Set RLE and WLE on global locking range
		outs, errs = run_cmd(["sedcli", "--setup-global-range", "--device", self.NVME_DEV_PATH], self.nvme_sid_key + b'\n')

		self.assertEqual(pipe.returncode, 0, "sedcli returned error while setting RLE and WLE on global range:\n" + str(errs))
		self.assertEqual(len(errs), 0, "sedcli returned success code but error message has been printed on stderr:\n" + str(errs))

# -----------------------------------------------------------------------------
if __name__ == '__main__':
	if len(sys.argv) > 1:
		TestSedcliBasic.NVME_DEV_PATH = sys.argv.pop()
	unittest.main()
