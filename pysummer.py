#-*- coding:utf-8 -*-

## Author : JEANNENOT Stephane
## Mail : stephane.jeannenot@gmail.com
## Date : 13 May 2009 - First released on pypi (http://pypi.python.org/pypi)
## Date : 01 Feb 2013 - Some improvements and released on Google Code
## Date : 30 Jan 2014 - Release on Github

## This code is placed under the simplified BSD license : see below

## Copyright (c) 2009-2014, JEANNENOT Stephane
## All rights reserved.
##
## Redistribution and use in source and binary forms, with or without
## modification, are permitted provided that the following conditions are met:
##
##    1 Redistributions of source code must retain the above copyright notice,
##      this list of conditions and the following disclaimer.
##    2 Redistributions in binary form must reproduce the above copyright
##      notice, this list of conditions and the following disclaimer in the
##      documentation and/or other materials provided with the distribution.
##
## THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
## AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
## IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
## ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
## LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
## CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
## SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
## INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
## CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
## ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
## THE POSSIBILITY OF SUCH DAMAGE.


# Conditional imports
import sys
if sys.version_info[0] < 3:
    from exceptions import NotImplementedError, ValueError, IOError
if(sys.version_info[0] < 2 or
       (sys.version_info[0] == 2 and sys.version_info[1] < 5)):
    print("Please consider upgrading your interpreter\nThis script needs at least python >= 2.5")
    sys.exit(1)

import os
import re
import hashlib
#import logging
# TODO : replace optparse with argparse : will brake compatibility with Python < 2.7
from optparse import OptionParser

version = '1.0'
hash_pattern = re.compile("(\w{32,128})\s+[*]{0,1}(.*)")


class Worker():
    def __init__(self, hashname, rmode='rb', bufsize=8192, name=""):
        self.hash_known = ['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512']
        self.hash_length = {32: "md5", 40: "sha1", 56: "sha224", 64: "sha256", 96: "sha384", 128: "sha512"}
        self.rmode = rmode
        self.bufsize = bufsize
        self.hashname = hashname
        self.hashdata = None
        if len(name) > 0:
            self.name = name
        else:
            self.name = "worker-%s" % self.hashname

        if self.hashname in self.hash_known:
            if self.hashname == 'md5':
                #~ self.hashdata = hashlib.md5()
                print("# %s : md5 hash algorithm selected" % (self.name))
            if self.hashname == 'sha1':
                #~ self.hashdata = hashlib.sha1()
                print("# %s : sha1 hash algorithm selected" % (self.name))
            if self.hashname == 'sha224':
                #~ self.hashdata = hashlib.sha224()
                print("# %s : sha224 hash algorithm selected" % (self.name))
            if self.hashname == 'sha256':
                #~ self.hashdata = hashlib.sha256()
                print("# %s : sha256 hash algorithm selected" % (self.name))
            if self.hashname == 'sha384':
                #~ self.hashdata = hashlib.sha384()
                print("# %s : sha384 hash algorithm selected" % (self.name))
            if self.hashname == 'sha512':
                #~ self.hashdata = hashlib.sha512()
                print("# %s : sha512 hash algorithm selected" % (self.name))
        elif self.hashname == 'auto':
            print("# %s : auto hash algorithm selected" % (self.name))
        else:
            print("# %s : hash algorithm [ %s ] not implemented" % (self.name, self.hashname))

    def compute(self, fname):
        try:
            self.hashdata = hashlib.new(self.hashname)
        except ValueError:
            raise NotImplementedError("# %s : hash algorithm [ %s ] not implemented" % (self.name, self.hashname))

        fhandle = open(fname, self.rmode)
        data = fhandle.read(self.bufsize)
        while(data):
            self.hashdata.update(data)
            data = fhandle.read(self.bufsize)
        fhandle.close()
        return self.hashdata.hexdigest()

    def guess_hash(self, hexdigest):
        length = len(hexdigest)
        if length in self.hash_length:
            return self.hash_length[length]
        else:
            return None


def main():
    usage = "usage: %prog [options] arg"
    parser = OptionParser(usage=usage)
    parser.add_option("-r", dest="recursive", action="store_true", default=False, help="recursively calculate checksums")
    parser.add_option("-c", dest="check", action="store_true", default=False, help="check sums")
    parser.add_option("--hash", dest="hashname", default="auto", help="select hash algorithm")
    (options, args) = parser.parse_args()

    print("# generated by pysummer version %s" % (version))
    print("#     recursive option : %s" % ("True" if options.recursive else "False"))
    print("#     action : %s sums" % ("checking" if options.check else "generating"))

    if args:
        arg0 = args[0]
        if not options.check:
# generate sums
            if options.hashname == "auto":
                options.hashname = "sha1"
                print("#     WARNING : 'auto' as hash selected, so defaulting to 'sha1'")
            w = Worker(options.hashname)
            if os.path.isfile(arg0):
                hw = w.compute(arg0)
                print("%s *%s" % (hw, arg0))
            elif os.path.isdir(arg0):
                topdir = os.path.abspath(arg0)
                if options.recursive:
                    for root, dirs, files in os.walk(topdir):
                        for fname in files:
                            fullpath = os.path.abspath(os.path.join(root, fname))
                            relpath = fullpath[len(os.path.dirname(topdir)):].lstrip("\/")
                            relpath = os.path.normpath(relpath)  # OS independance
                            hw = w.compute(fullpath)
                            print("%s *%s" % (hw, relpath))
                else:
                    for item in os.listdir(topdir):
                        if os.path.isfile(item):
                            hw = w.compute(item)
                            item = os.path.normpath(item)  # OS independance
                            print("%s *%s" % (hw, item))
            else:
                raise IOError("Specified file or directory not found")
        else:
# verify sums
            if os.path.isfile(arg0):
                fhandle = open(arg0, 'r')
                fenum = enumerate(fhandle)
                filechk = list()
                for ldata in fenum:
                    mp = hash_pattern.match(ldata[1])
                    if(mp):
                        filechk.append(mp.groups())
                fhandle.close()
                w = Worker(options.hashname)
                if options.hashname == "auto":
                    print("#     guessing hash algorithm for each line")
                for item in filechk:
                    if options.hashname == "auto":
                        w.hashname = w.guess_hash(item[0])
                    try:
                        hw = w.compute(item[1])
                        if item[0] == hw:
                            print("[%s] %s : OK" % (w.hashname, item[1]))
                        else:
                            print("[%s] %s : FAILED" % (w.hashname, item[1]))
                    except IOError:
                        print("[%s] %s : EXCEPTION : IOError" % (w.hashname, item[1]))
    else:
        raise IOError("Argument missing : use -h flag to get help")


if __name__ == "__main__":
    main()
