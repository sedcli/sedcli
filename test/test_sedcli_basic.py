# Copyright (C) 2018-2019 Intel Corporation
#
# SPDX-License-Identifier: GPL-2.0-or-later

"""
Tests end-user scenarios for sedcli binary.
This suite needs to be run against Python 3.x and the sedcli binary must be
in your $PATH.
The user must provide:
	1. Device Path
	2. Device PSID
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

def read_opal_drive(device_path):
	# Read from the disk
	pipe = subprocess.Popen(["dd", "if=" + device_path, "of=/dev/null", "bs=4k", "count=100", "iflag=direct"], stdout = subprocess.PIPE, stdin = subprocess.PIPE, stderr = subprocess.PIPE)
	err = pipe.communicate()
	return pipe.returncode

def write_opal_drive(device_path):
	# Write to the disk
	pipe = subprocess.Popen(["dd", "if=/dev/zero", "of=" + device_path, "bs=4k", "count=100", "oflag=direct"], stdout = subprocess.PIPE, stdin = subprocess.PIPE, stderr = subprocess.PIPE)
	err = pipe.communicate()
	return pipe.returncode

nvme_sid_key = gen_rand_key(32)
print("\nKey used to initial provision drive:" + str(nvme_sid_key) + "\n")
f = open("random_pswd.txt", "w+")
f.write("Randomly Generated SID password to initially provision drive: " + str(nvme_sid_key) + "\n")

class TestSedcliBasic(unittest.TestCase):

	NVME_DEV_PATH = '/dev/nvme0n1'

	def __init__(self, *args, **kwargs):
		super(TestSedcliBasic, self).__init__(*args, **kwargs)

	def test_initial_setup(self):
		"""
		Tests for: sedcli intial provision of drive (that is take ownerhisp,
		activate Locking SP and setup global locking range)
		"""
		# Test taking ownership (test is assuming that drive is in Manufactured-inactive state)
		outs, errs = run_cmd(["sedcli", "--ownership", "--device", self.NVME_DEV_PATH], nvme_sid_key + b'\n' + nvme_sid_key + b'\n')

		self.assertEqual(pipe.returncode, 0, "sedcli returned error while taking ownership of the drive:\n" + str(errs))
		self.assertEqual(len(errs), 0, "sedcli returned success code but error message has been printed on stderr:\n" + str(errs))

		# Activate Locking SP
		outs, errs = run_cmd(["sedcli", "--activate-lsp", "--device", self.NVME_DEV_PATH], nvme_sid_key + b'\n')

		self.assertEqual(pipe.returncode, 0, "sedcli returned error while activating Locking SP:\n" + str(errs))
		self.assertEqual(len(errs), 0, "sedcli returned success code but error message has been printed on stderr:\n" + str(errs))

		# Set RLE and WLE on global locking range
		outs, errs = run_cmd(["sedcli", "--setup-global-range", "--device", self.NVME_DEV_PATH], nvme_sid_key + b'\n')

		self.assertEqual(pipe.returncode, 0, "sedcli returned error while setting RLE and WLE on global range:\n" + str(errs))
		self.assertEqual(len(errs), 0, "sedcli returned success code but error message has been printed on stderr:\n" + str(errs))

	def test_locking_range_test(self):
		# Read Lock Disk
		outs, errs = run_cmd(["sedcli", "--lock-unlock", "--device", self.NVME_DEV_PATH, "--accesstype", "RO"], nvme_sid_key + b'\n')

		self.assertEqual(pipe.returncode, 0, "sedcli returned error while Read-Only locking the disk:\n" + str(errs))
		self.assertEqual(len(errs), 0, "sedcli returned success code but error message has been printed on stderr:\n" + str(errs))

		read = read_opal_drive(TestSedcliBasic.NVME_DEV_PATH)
		self.assertEqual(read, 0, "Unable to read data from the disk when the user is supposed to: " + str(errs))

		write = write_opal_drive(TestSedcliBasic.NVME_DEV_PATH)
		self.assertEqual(write, 1, "Able to write data to the disk when the user is NOT supposed to: " + str(errs))

		# ReadWrite Lock Disk
		outs, errs = run_cmd(["sedcli", "--lock-unlock", "--device", self.NVME_DEV_PATH, "--accesstype", "RW"], nvme_sid_key + b'\n')

		self.assertEqual(pipe.returncode, 0, "sedcli returned error while Read-Write locking the disk:\n" + str(errs))
		self.assertEqual(len(errs), 0, "sedcli returned success code but error message has been printed on stderr:\n" + str(errs))

		read = read_opal_drive(TestSedcliBasic.NVME_DEV_PATH)
		self.assertEqual(read, 0, "Unable to read data from the disk when the user is supposed to: " + str(errs))

		write = write_opal_drive(TestSedcliBasic.NVME_DEV_PATH)
		self.assertEqual(write, 0, "Unable to write data to the disk when the user is supposed to: " + str(errs))

		# Lock Disk
		outs, errs = run_cmd(["sedcli", "--lock-unlock", "--device", self.NVME_DEV_PATH, "--accesstype", "LK"], nvme_sid_key + b'\n')

		self.assertEqual(pipe.returncode, 0, "sedcli returned error while Locking the disk:\n" + str(errs))
		self.assertEqual(len(errs), 0, "sedcli returned success code but error message has been printed on stderr:\n" + str(errs))

		read = read_opal_drive(TestSedcliBasic.NVME_DEV_PATH)
		self.assertEqual(read, 1, "Able to read data from the disk when the user is NOT supposed to: " + str(errs))

		write = write_opal_drive(TestSedcliBasic.NVME_DEV_PATH)
		self.assertEqual(write, 1, "Able to write data to the disk when the user is NOT supposed to: " + str(errs))

		# Randomly generate the new amin1 password
		self.new_admin1_paswd = gen_rand_key(32)
		f.write("Radomly generated new Admin-1 Passwd: " + str(self.new_admin1_paswd) + "\n")
		f.close()

		# Set password (Update/Change password for Admin1 authority in Locking SP)
		outs, errs = run_cmd(["sedcli", "--set-password", "--device", self.NVME_DEV_PATH], nvme_sid_key + b'\n' + self.new_admin1_paswd + b'\n' + self.new_admin1_paswd + b'\n')

		self.assertEqual(pipe.returncode, 0, "sedcli returned error while Setting new password for the disk:\n" + str(errs))
		self.assertEqual(len(errs), 0, "sedcli returned success code but error message has been printed on stderr:\n" + str(errs))

		# Now check if the newly set password works fine
		# 1. Try to Set RLE and WLE on global locking range using old Admin-1 password
		outs, errs = run_cmd(["sedcli", "--setup-global-range", "--device", self.NVME_DEV_PATH], nvme_sid_key + b'\n')

		self.assertEqual(pipe.returncode, 1, "Able to access LSP using the old admin-1 password: " + str(errs))

		# 2. Try to Set RLE and WLE on global locking range usign new Admin-1 password
		outs, errs = run_cmd(["sedcli", "--setup-global-range", "--device", self.NVME_DEV_PATH], self.new_admin1_paswd + b'\n')

		self.assertEqual(pipe.returncode, 0, "sedcli returned error while setting RLE and WLE on global range with new admin-1 password:\n" + str(errs))
		self.assertEqual(len(errs), 0, "sedcli returned success code but error message has been printed on stderr:\n" + str(errs))

	def test_revert_drive(self):
		# Revert the TPer with SID authority
		outs, errs = run_cmd(["sedcli", "--revert", "--device", self.NVME_DEV_PATH], nvme_sid_key + b'\n')

		self.assertEqual(pipe.returncode, 0, "sedcli returned error while Reverting TPer using SID authority:\n" + str(errs))
		self.assertEqual(len(errs), 0, "sedcli returned success code but error message has been printed on stderr:\n" + str(errs))

		# Revert the TPer with PSID authority
		outs, errs = run_cmd(["sedcli", "--revert", "--device", self.NVME_DEV_PATH, "--psid"], TestSedcliBasic.NVME_DEV_PSID + b'\n')

		self.assertEqual(pipe.returncode, 0, "sedcli returned error while Reverting TPer using PSID authority:\n" + str(errs))
		self.assertEqual(len(errs), 0, "sedcli returned success code but error message has been printed on stderr:\n" + str(errs))

# -----------------------------------------------------------------------------
if __name__ == '__main__':
	if len(sys.argv) == 3:
		TestSedcliBasic.NVME_DEV_PSID = bytes(sys.argv.pop(), 'utf-8')
		TestSedcliBasic.NVME_DEV_PATH = sys.argv.pop()
		print("Provided Device-Path: " + TestSedcliBasic.NVME_DEV_PATH)
		print(b'Provided Device-PSID: ' + TestSedcliBasic.NVME_DEV_PSID)
		unittest.main()
	else:
		print("The user must provide\n\t1. Device Path\n\t2. Device PSID\n")
