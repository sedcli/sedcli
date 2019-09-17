# sedcli and libsed

TCG Opal is an industry standard allowing Self-Encrypting Drives management,
i.e. enable locking, configuring users, locking ranges etc.

Sedcli is an utility for managing NVMe SEDs that are TCG Opal complaint.

Libsed is a library allowing to programatically manage NVMe SEDs that are TCG
Opal complaint.

## Getting started

In order to get started use following steps (<sedcli> denotes top level
directory for sedcli):

```
# download sedcli sources
git clone https://github.com/sedcli/sedcli.git

# navigate to source directory
cd <sedcli>/src

# perform build environment configuration and run compilation
./configure
make
make install

# invoke sedcli help to available commands and its syntax
sedcli -H

# alterntively read sedcli man page
man sedcli

```

## Contributing

We encourage contributions! Patches are accepted via pull request:
* Contributions into sedcli are accepted on GPL-2.0-or-later license
* Contributions into libsed are accepted on LGPL-2.1-or-later license
* Patches must be signedoff by the developer. This indicates that submitter
agrees to the **Developer Certificate of Origin**
[DCO](https://developercertificate.org)
