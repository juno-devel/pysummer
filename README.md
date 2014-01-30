pysummer
========

Multi hash generator / verificator in python

Goal :

* standalone application that can recursively scan entire directory
 trees and then compute a cryptographic hash again each file found
* compatible with GNU command-line utilities like md5sum, sha(X)sum



Limitations :

* SHA-3 (Keccak) is not yet supported as it is not available in all Python versions