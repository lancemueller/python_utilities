#!/usr/bin/python
# coding: utf-8


# Author:

  # Lance Mueller
  # Website: www.forensickb.com
  # Twitter: @lancemueller

# Usage:

  # Provide directory with encoded keylog files

# License:

  # Copyright (c) 2017 Lance Mueller

  # Permission is hereby granted, free of charge, to any person obtaining a copy
  # of this software and associated documentation files (the "Software"), to deal
  # in the Software without restriction, including without limitation the rights
  # to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  # copies of the Software, and to permit persons to whom the Software is
  # furnished to do so, subject to the following conditions:

  # The above copyright notice and this permission notice shall be included in all
  # copies or substantial portions of the Software.

  # THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  # IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  # FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  # AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  # LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  # OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
  # SOFTWARE.



import operator
import os
import sys

def main(argv):
    f=open(argv, 'rb')
    infile = f.read()
    f.close
    f=open(argv + '_decoded.txt', 'wb')

    cleartext_string = ""
    for k in range(0, len(infile)):
        ciphertext_char = ord(infile[k])
        ciphertext_char = ciphertext_char - 0x24
        if ciphertext_char < 0:
            ciphertext_char = int(hex(ciphertext_char & 0xffff)[-2:],16)
        cleartext_char = operator.xor(ciphertext_char, 0x9D)
        cleartext_string += chr(cleartext_char)
    f.write(cleartext_string)   
    f.close
#
if __name__ == "__main__":
    if len(sys.argv) == 2:
        for root, subFolders, files in os.walk(sys.argv[1]):
            for file in files:
                if '.txt' not in file:
                    print "Processing..." + os.path.join(root,file)
                    main(os.path.join(root,file))
    
    else:
        print "\n" + sys.argv[0] + " <dir containing keylog files>"