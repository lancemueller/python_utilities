#Based on code from Hexacorn and Optiv
#https://github.com/brad-accuvant/cuckoo-modified/blob/master/lib/cuckoo/common/quarantine.py
#http://www.hexacorn.com/blog/2016/03/11/dexray/

import sys
import struct
from binascii import crc32

def bytearray_xor(data, key):
    for i in xrange(len(data)):
        data[i] ^= key
    return data

def read_trend_tag(data, offset):
    """ @return a code byte and data tuple
    """
    code, length = struct.unpack("<BH", data[offset:offset+3])
    return code, bytes(data[offset+3:offset+3+length])


def trend_unquarantine(f):
    with open(f, "rb") as quarfile:
        qdata = quarfile.read()

    data = bytearray_xor(bytearray(qdata), 0xff)

    magic, dataoffset, numtags = struct.unpack("<IIH", data[:10])
    if magic != 0x58425356: # VSBX
        return None
    origpath = "C:\\"
    origname = "UnknownTrendFile.bin"
    platform = "Unknown"
    attributes = 0x00000000
    unknownval = 0
    basekey = 0x00000000
    encmethod = 0

    if numtags > 15:
        return None

    dataoffset += 10
    offset = 10
    for i in xrange(numtags):
        code, tagdata = read_trend_tag(data, offset)
        if code == 1: # original pathname
            origpath = unicode(tagdata, encoding="utf16").encode("utf8", "ignore").rstrip("\0")
        elif code == 2: # original filename
            origname = unicode(tagdata, encoding="utf16").encode("utf8", "ignore").rstrip("\0")
        elif code == 3: # platform
            platform = str(tagdata)
        elif code == 4: # file attributes
            attributes = struct.unpack("<I", tagdata)[0]
        elif code == 5: # unknown, generally 1
            unknownval = struct.unpack("<I", tagdata)[0]
        elif code == 6: # base key
            basekey = struct.unpack("<I", tagdata)[0]
        elif code == 7: # encryption method: 1 == xor FF, 2 = CRC method
            encmethod = struct.unpack("<I", tagdata)[0]
        offset += 3 + len(tagdata)

    print "Original Path: %s" % origpath
    print "Original Name: %s" % origname

    if encmethod != 2:
        return store_temp_file(data[dataoffset:], origname)

    bytesleft = len(data) - dataoffset
    unaligned = dataoffset % 4
    firstiter = True
    curoffset = dataoffset
    while bytesleft:
        off = curoffset
        if firstiter:
            off = curoffset - unaligned
            firstiter = False
        keyval = basekey + off
        buf = struct.pack("<I", keyval)
        crc = crc32(buf) & 0xffffffff
        crcbuf = bytearray(struct.pack("<I", crc))

        for i in xrange(unaligned, 4):
            if not bytesleft:
                break
            data[curoffset] ^= crcbuf[i]
            curoffset += 1
            bytesleft -= 1

        unaligned = 0

    return (data[dataoffset:], origname)

if __name__ == "__main__":
    data,name = trend_unquarantine(sys.argv[1])
    with open(name + ".malware", 'wb') as f:
        f.write(data)
    print "file: " + name + ".malware created."