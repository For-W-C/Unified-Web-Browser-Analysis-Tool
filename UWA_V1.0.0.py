#!/usr/bin/python
# -*- coding: utf-8 -*-
import sys
reload(sys)
sys.setdefaultencoding('utf-8')
"""
BoB Project Team For W.C

This Program is Unified Web Browser Analysis Tool

pm : Hanrim Choi
member : Suwon Kim jihwan Lee, Dongwoo Kim
last edited : Nov, 2015
"""

from struct import pack, unpack, calcsize

class Structure:
    """ sublcasses can define commonHdr and/or structure.
        each of them is an tuple of either two: (fieldName, format) or three: (fieldName, ':', class) fields.
        [it can't be a dictionary, because order is important]
        
        where format specifies how the data in the field will be converted to/from bytes (string)
        class is the class to use when unpacking ':' fields.

        each field can only contain one value (or an array of values for *)
           i.e. struct.pack('Hl',1,2) is valid, but format specifier 'Hl' is not (you must use 2 dfferent fields)

        format specifiers:
          specifiers from module pack can be used with the same format 
          see struct.__doc__ (pack/unpack is finally called)
            x       [padding byte]
            c       [character]
            b       [signed byte]
            B       [unsigned byte]
            h       [signed short]
            H       [unsigned short]
            l       [signed long]
            L       [unsigned long]
            i       [signed integer]
            I       [unsigned integer]
            q       [signed long long (quad)]
            Q       [unsigned long long (quad)]
            s       [string (array of chars), must be preceded with length in format specifier, padded with zeros]
            p       [pascal string (includes byte count), must be preceded with length in format specifier, padded with zeros]
            f       [float]
            d       [double]
            =       [native byte ordering, size and alignment]
            @       [native byte ordering, standard size and alignment]
            !       [network byte ordering]
            <       [little endian]
            >       [big endian]

          usual printf like specifiers can be used (if started with %) 
          [not recommeneded, there is no why to unpack this]

            %08x    will output an 8 bytes hex
            %s      will output a string
            %s\\x00  will output a NUL terminated string
            %d%d    will output 2 decimal digits (against the very same specification of Structure)
            ...

          some additional format specifiers:
            :       just copy the bytes from the field into the output string (input may be string, other structure, or anything responding to __str__()) (for unpacking, all what's left is returned)
            z       same as :, but adds a NUL byte at the end (asciiz) (for unpacking the first NUL byte is used as terminator)  [asciiz string]
            u       same as z, but adds two NUL bytes at the end (after padding to an even size with NULs). (same for unpacking) [unicode string]
            w       DCE-RPC/NDR string (it's a macro for [  '<L=(len(field)+1)/2','"\\x00\\x00\\x00\\x00','<L=(len(field)+1)/2',':' ]
            ?-field length of field named 'field', formated as specified with ? ('?' may be '!H' for example). The input value overrides the real length
            ?1*?2   array of elements. Each formated as '?2', the number of elements in the array is stored as specified by '?1' (?1 is optional, or can also be a constant (number), for unpacking)
            'xxxx   literal xxxx (field's value doesn't change the output. quotes must not be closed or escaped)
            "xxxx   literal xxxx (field's value doesn't change the output. quotes must not be closed or escaped)
            _       will not pack the field. Accepts a third argument, which is an unpack code. See _Test_UnpackCode for an example
            ?=packcode  will evaluate packcode in the context of the structure, and pack the result as specified by ?. Unpacking is made plain
            ?&fieldname "Address of field fieldname".
                        For packing it will simply pack the id() of fieldname. Or use 0 if fieldname doesn't exists.
                        For unpacking, it's used to know weather fieldname has to be unpacked or not, i.e. by adding a & field you turn another field (fieldname) in an optional field.
            
    """
    commonHdr = ()
    structure = ()
    debug = 0

    def __init__(self, data = None, alignment = 0):
        if not hasattr(self, 'alignment'):
            self.alignment = alignment

        self.fields    = {}
        self.rawData   = data
        if data is not None:
            self.fromString(data)
        else:
            self.data = None

    @classmethod
    def fromFile(self, file):
        answer = self()
        answer.fromString(file.read(len(answer)))
        return answer

    def setAlignment(self, alignment):
        self.alignment = alignment

    def setData(self, data):
        self.data = data

    def packField(self, fieldName, format = None):
        if self.debug:
            print "packField( %s | %s )" % (fieldName, format)

        if format is None:
            format = self.formatForField(fieldName)

        if self.fields.has_key(fieldName):
            ans = self.pack(format, self.fields[fieldName], field = fieldName)
        else:
            ans = self.pack(format, None, field = fieldName)

        if self.debug:
            print "\tanswer %r" % ans

        return ans

    def getData(self):
        if self.data is not None:
            return self.data
        data = ''
        for field in self.commonHdr+self.structure:
            try:
                data += self.packField(field[0], field[1])
            except Exception, e:
                if self.fields.has_key(field[0]):
                    e.args += ("When packing field '%s | %s | %r' in %s" % (field[0], field[1], self[field[0]], self.__class__),)
                else:
                    e.args += ("When packing field '%s | %s' in %s" % (field[0], field[1], self.__class__),)
                raise
            if self.alignment:
                if len(data) % self.alignment:
                    data += ('\x00'*self.alignment)[:-(len(data) % self.alignment)]
            
        #if len(data) % self.alignment: data += ('\x00'*self.alignment)[:-(len(data) % self.alignment)]
        return data

    def fromString(self, data):
        self.rawData = data
        for field in self.commonHdr+self.structure:
            if self.debug:
                print "fromString( %s | %s | %r )" % (field[0], field[1], data)
            size = self.calcUnpackSize(field[1], data, field[0])
            if self.debug:
                print "  size = %d" % size
            dataClassOrCode = str
            if len(field) > 2:
                dataClassOrCode = field[2]
            try:
                self[field[0]] = self.unpack(field[1], data[:size], dataClassOrCode = dataClassOrCode, field = field[0])
            except Exception,e:
                e.args += ("When unpacking field '%s | %s | %r[:%d]'" % (field[0], field[1], data, size),)
                raise

            size = self.calcPackSize(field[1], self[field[0]], field[0])
            if self.alignment and size % self.alignment:
                size += self.alignment - (size % self.alignment)
            data = data[size:]

        return self
        
    def __setitem__(self, key, value):
        self.fields[key] = value
        self.data = None        # force recompute

    def __getitem__(self, key):
        return self.fields[key]

    def __delitem__(self, key):
        del self.fields[key]
        
    def __str__(self):
        return self.getData()

    def __len__(self):
        # XXX: improve
        return len(self.getData())

    def pack(self, format, data, field = None):
        if self.debug:
            print "  pack( %s | %r | %s)" %  (format, data, field)

        if field:
            addressField = self.findAddressFieldFor(field)
            if (addressField is not None) and (data is None):
                return ''

        # void specifier
        if format[:1] == '_':
            return ''

        # quote specifier
        if format[:1] == "'" or format[:1] == '"':
            return format[1:]

        # code specifier
        two = format.split('=')
        if len(two) >= 2:
            try:
                return self.pack(two[0], data)
            except:
                fields = {'self':self}
                fields.update(self.fields)
                return self.pack(two[0], eval(two[1], {}, fields))

        # address specifier
        two = format.split('&')
        if len(two) == 2:
            try:
                return self.pack(two[0], data)
            except:
                if (self.fields.has_key(two[1])) and (self[two[1]] is not None):
                    return self.pack(two[0], id(self[two[1]]) & ((1<<(calcsize(two[0])*8))-1) )
                else:
                    return self.pack(two[0], 0)

        # length specifier
        two = format.split('-')
        if len(two) == 2:
            try:
                return self.pack(two[0],data)
            except:
                return self.pack(two[0], self.calcPackFieldSize(two[1]))

        # array specifier
        two = format.split('*')
        if len(two) == 2:
            answer = ''
            for each in data:
                answer += self.pack(two[1], each)
            if two[0]:
                if two[0].isdigit():
                    if int(two[0]) != len(data):
                        raise Exception, "Array field has a constant size, and it doesn't match the actual value"
                else:
                    return self.pack(two[0], len(data))+answer
            return answer

        # "printf" string specifier
        if format[:1] == '%':
            # format string like specifier
            return format % data

        # asciiz specifier
        if format[:1] == 'z':
            return str(data)+'\0'

        # unicode specifier
        if format[:1] == 'u':
            return str(data)+'\0\0' + (len(data) & 1 and '\0' or '')

        # DCE-RPC/NDR string specifier
        if format[:1] == 'w':
            if len(data) == 0:
                data = '\0\0'
            elif len(data) % 2:
                data += '\0'
            l = pack('<L', len(data)/2)
            return '%s\0\0\0\0%s%s' % (l,l,data)
                    
        if data is None:
            raise Exception, "Trying to pack None"
        
        # literal specifier
        if format[:1] == ':':
            return str(data)

        # struct like specifier
        return pack(format, data)

    def unpack(self, format, data, dataClassOrCode = str, field = None):
        if self.debug:
            print "  unpack( %s | %r )" %  (format, data)

        if field:
            addressField = self.findAddressFieldFor(field)
            if addressField is not None:
                if not self[addressField]:
                    return

        # void specifier
        if format[:1] == '_':
            if dataClassOrCode != str:
                fields = {'self':self, 'inputDataLeft':data}
                fields.update(self.fields)
                return eval(dataClassOrCode, {}, fields)
            else:
                return None

        # quote specifier
        if format[:1] == "'" or format[:1] == '"':
            answer = format[1:]
            if answer != data:
                raise Exception, "Unpacked data doesn't match constant value '%r' should be '%r'" % (data, answer)
            return answer

        # address specifier
        two = format.split('&')
        if len(two) == 2:
            return self.unpack(two[0],data)

        # code specifier
        two = format.split('=')
        if len(two) >= 2:
            return self.unpack(two[0],data)

        # length specifier
        two = format.split('-')
        if len(two) == 2:
            return self.unpack(two[0],data)

        # array specifier
        two = format.split('*')
        if len(two) == 2:
            answer = []
            sofar = 0
            if two[0].isdigit():
                number = int(two[0])
            elif two[0]:
                sofar += self.calcUnpackSize(two[0], data)
                number = self.unpack(two[0], data[:sofar])
            else:
                number = -1

            while number and sofar < len(data):
                nsofar = sofar + self.calcUnpackSize(two[1],data[sofar:])
                answer.append(self.unpack(two[1], data[sofar:nsofar], dataClassOrCode))
                number -= 1
                sofar = nsofar
            return answer

        # "printf" string specifier
        if format[:1] == '%':
            # format string like specifier
            return format % data

        # asciiz specifier
        if format == 'z':
            if data[-1] != '\x00':
                raise Exception, ("%s 'z' field is not NUL terminated: %r" % (field, data))
            return data[:-1] # remove trailing NUL

        # unicode specifier
        if format == 'u':
            if data[-2:] != '\x00\x00':
                raise Exception, ("%s 'u' field is not NUL-NUL terminated: %r" % (field, data))
            return data[:-2] # remove trailing NUL

        # DCE-RPC/NDR string specifier
        if format == 'w':
            l = unpack('<L', data[:4])[0]
            return data[12:12+l*2]

        # literal specifier
        if format == ':':
            return dataClassOrCode(data)

        # struct like specifier
        return unpack(format, data)[0]

    def calcPackSize(self, format, data, field = None):
#        # print "  calcPackSize  %s:%r" %  (format, data)
        if field:
            addressField = self.findAddressFieldFor(field)
            if addressField is not None:
                if not self[addressField]:
                    return 0

        # void specifier
        if format[:1] == '_':
            return 0

        # quote specifier
        if format[:1] == "'" or format[:1] == '"':
            return len(format)-1

        # address specifier
        two = format.split('&')
        if len(two) == 2:
            return self.calcPackSize(two[0], data)

        # code specifier
        two = format.split('=')
        if len(two) >= 2:
            return self.calcPackSize(two[0], data)

        # length specifier
        two = format.split('-')
        if len(two) == 2:
            return self.calcPackSize(two[0], data)

        # array specifier
        two = format.split('*')
        if len(two) == 2:
            answer = 0
            if two[0].isdigit():
                    if int(two[0]) != len(data):
                        raise Exception, "Array field has a constant size, and it doesn't match the actual value"
            elif two[0]:
                answer += self.calcPackSize(two[0], len(data))

            for each in data:
                answer += self.calcPackSize(two[1], each)
            return answer

        # "printf" string specifier
        if format[:1] == '%':
            # format string like specifier
            return len(format % data)

        # asciiz specifier
        if format[:1] == 'z':
            return len(data)+1

        # asciiz specifier
        if format[:1] == 'u':
            l = len(data)
            return l + (l & 1 and 3 or 2)

        # DCE-RPC/NDR string specifier
        if format[:1] == 'w':
            l = len(data)
            return 12+l+l % 2

        # literal specifier
        if format[:1] == ':':
            return len(data)

        # struct like specifier
        return calcsize(format)

    def calcUnpackSize(self, format, data, field = None):
        if self.debug:
            print "  calcUnpackSize( %s | %s | %r)" %  (field, format, data)

        # void specifier
        if format[:1] == '_':
            return 0

        addressField = self.findAddressFieldFor(field)
        if addressField is not None:
            if not self[addressField]:
                return 0

        try:
            lengthField = self.findLengthFieldFor(field)
            return self[lengthField]
        except:
            pass

        # XXX: Try to match to actual values, raise if no match
        
        # quote specifier
        if format[:1] == "'" or format[:1] == '"':
            return len(format)-1

        # address specifier
        two = format.split('&')
        if len(two) == 2:
            return self.calcUnpackSize(two[0], data)

        # code specifier
        two = format.split('=')
        if len(two) >= 2:
            return self.calcUnpackSize(two[0], data)

        # length specifier
        two = format.split('-')
        if len(two) == 2:
            return self.calcUnpackSize(two[0], data)

        # array specifier
        two = format.split('*')
        if len(two) == 2:
            answer = 0
            if two[0]:
                if two[0].isdigit():
                    number = int(two[0])
                else:
                    answer += self.calcUnpackSize(two[0], data)
                    number = self.unpack(two[0], data[:answer])

                while number:
                    number -= 1
                    answer += self.calcUnpackSize(two[1], data[answer:])
            else:
                while answer < len(data):
                    answer += self.calcUnpackSize(two[1], data[answer:])
            return answer

        # "printf" string specifier
        if format[:1] == '%':
            raise Exception, "Can't guess the size of a printf like specifier for unpacking"

        # asciiz specifier
        if format[:1] == 'z':
            return data.index('\x00')+1

        # asciiz specifier
        if format[:1] == 'u':
            l = data.index('\x00\x00')
            return l + (l & 1 and 3 or 2)

        # DCE-RPC/NDR string specifier
        if format[:1] == 'w':
            l = unpack('<L', data[:4])[0]
            return 12+l*2

        # literal specifier
        if format[:1] == ':':
            return len(data)

        # struct like specifier
        return calcsize(format)

    def calcPackFieldSize(self, fieldName, format = None):
        if format is None:
            format = self.formatForField(fieldName)

        return self.calcPackSize(format, self[fieldName])

    def formatForField(self, fieldName):
        for field in self.commonHdr+self.structure:
            if field[0] == fieldName:
                return field[1]
        raise Exception, ("Field %s not found" % fieldName)

    def findAddressFieldFor(self, fieldName):
        descriptor = '&%s' % fieldName
        l = len(descriptor)
        for field in self.commonHdr+self.structure:
            if field[1][-l:] == descriptor:
                return field[0]
        return None
        
    def findLengthFieldFor(self, fieldName):
        descriptor = '-%s' % fieldName
        l = len(descriptor)
        for field in self.commonHdr+self.structure:
            if field[1][-l:] == descriptor:
                return field[0]
        return None
        
    def zeroValue(self, format):
        two = format.split('*')
        if len(two) == 2:
            if two[0].isdigit():
                return (self.zeroValue(two[1]),)*int(two[0])
                        
        if not format.find('*') == -1: return ()
        if 's' in format: return ''
        if format in ['z',':','u']: return ''
        if format == 'w': return '\x00\x00'

        return 0

    def clear(self):
        for field in self.commonHdr + self.structure:
            self[field[0]] = self.zeroValue(field[1])

    def dump(self, msg = None, indent = 0):
        import types
        if msg is None: msg = self.__class__.__name__
        ind = ' '*indent
        print "\n%s" % (msg)
        fixedFields = []
        for field in self.commonHdr+self.structure:
            i = field[0] 
            if i in self.fields:
                fixedFields.append(i)
                if isinstance(self[i], Structure):
                    self[i].dump('%s%s:{' % (ind,i), indent = indent + 4)
                    print "%s}" % ind
                else:
                    print "%s%s: {%r}" % (ind,i,self[i])
        # Do we have remaining fields not defined in the structures? let's 
        # print them
        remainingFields = list(set(self.fields) - set(fixedFields))
        for i in remainingFields:
            if isinstance(self[i], Structure):
                self[i].dump('%s%s:{' % (ind,i), indent = indent + 4)
                print "%s}" % ind
            else:
                print "%s%s: {%r}" % (ind,i,self[i])

#Webcache Parser Start
import logging
try:
    from collections import OrderedDict
except:
    try:
        from ordereddict.ordereddict import OrderedDict
    except:
        from ordereddict import OrderedDict

# Constants
FILE_TYPE_DATABASE       = 0
FILE_TYPE_STREAMING_FILE = 1

# Database state
JET_dbstateJustCreated    = 1
JET_dbstateDirtyShutdown  = 2
JET_dbstateCleanShutdown  = 3
JET_dbstateBeingConverted = 4
JET_dbstateForceDetach    = 5

# Page Flags
FLAGS_ROOT         = 1
FLAGS_LEAF         = 2
FLAGS_PARENT       = 4
FLAGS_EMPTY        = 8
FLAGS_SPACE_TREE   = 0x20
FLAGS_INDEX        = 0x40
FLAGS_LONG_VALUE   = 0x80
FLAGS_NEW_FORMAT   = 0x2000
FLAGS_NEW_CHECKSUM = 0x2000

# Tag Flags
TAG_UNKNOWN = 0x1
TAG_DEFUNCT = 0x2
TAG_COMMON  = 0x4

# Fixed Page Numbers
DATABASE_PAGE_NUMBER           = 1
CATALOG_PAGE_NUMBER            = 4
CATALOG_BACKUP_PAGE_NUMBER     = 24

# Fixed FatherDataPages
DATABASE_FDP         = 1
CATALOG_FDP          = 2
CATALOG_BACKUP_FDP   = 3

# Catalog Types
CATALOG_TYPE_TABLE        = 1
CATALOG_TYPE_COLUMN       = 2
CATALOG_TYPE_INDEX        = 3
CATALOG_TYPE_LONG_VALUE   = 4
CATALOG_TYPE_CALLBACK     = 5

# Column Types
JET_coltypNil          = 0
JET_coltypBit          = 1
JET_coltypUnsignedByte = 2
JET_coltypShort        = 3
JET_coltypLong         = 4
JET_coltypCurrency     = 5
JET_coltypIEEESingle   = 6
JET_coltypIEEEDouble   = 7
JET_coltypDateTime     = 8
JET_coltypBinary       = 9
JET_coltypText         = 10
JET_coltypLongBinary   = 11
JET_coltypLongText     = 12
JET_coltypSLV          = 13
JET_coltypUnsignedLong = 14
JET_coltypLongLong     = 15
JET_coltypGUID         = 16
JET_coltypUnsignedShort= 17
JET_coltypMax          = 18

ColumnTypeToName = {
    JET_coltypNil          : 'NULL',
    JET_coltypBit          : 'Boolean',
    JET_coltypUnsignedByte : 'Signed byte',
    JET_coltypShort        : 'Signed short',
    JET_coltypLong         : 'Signed long',
    JET_coltypCurrency     : 'Currency',
    JET_coltypIEEESingle   : 'Single precision FP',
    JET_coltypIEEEDouble   : 'Double precision FP',
    JET_coltypDateTime     : 'DateTime',
    JET_coltypBinary       : 'Binary',
    JET_coltypText         : 'Text',
    JET_coltypLongBinary   : 'Long Binary',
    JET_coltypLongText     : 'Long Text',
    JET_coltypSLV          : 'Obsolete',
    JET_coltypUnsignedLong : 'Unsigned long',
    JET_coltypLongLong     : 'Long long',
    JET_coltypGUID         : 'GUID',
    JET_coltypUnsignedShort: 'Unsigned short',
    JET_coltypMax          : 'Max',
}

ColumnTypeSize = {
    JET_coltypNil          : None,
    JET_coltypBit          : (1,'B'),
    JET_coltypUnsignedByte : (1,'B'),
    JET_coltypShort        : (2,'<h'),
    JET_coltypLong         : (4,'<l'),
    JET_coltypCurrency     : (8,'<Q'),
    JET_coltypIEEESingle   : (4,'<f'),
    JET_coltypIEEEDouble   : (8,'<d'),
    JET_coltypDateTime     : (8,'<Q'),
    JET_coltypBinary       : None,
    JET_coltypText         : None, 
    JET_coltypLongBinary   : None,
    JET_coltypLongText     : None,
    JET_coltypSLV          : None,
    JET_coltypUnsignedLong : (4,'<L'),
    JET_coltypLongLong     : (8,'<Q'),
    JET_coltypGUID         : (16,'16s'),
    JET_coltypUnsignedShort: (2,'<H'),
    JET_coltypMax          : None,
}

# Tagged Data Type Flags
TAGGED_DATA_TYPE_VARIABLE_SIZE = 1
TAGGED_DATA_TYPE_COMPRESSED    = 2
TAGGED_DATA_TYPE_STORED        = 4
TAGGED_DATA_TYPE_MULTI_VALUE   = 8
TAGGED_DATA_TYPE_WHO_KNOWS     = 10

# Code pages
CODEPAGE_UNICODE = 1200
CODEPAGE_ASCII   = 20127
CODEPAGE_WESTERN = 1252

StringCodePages = {
    CODEPAGE_UNICODE : 'utf-16le', 
    CODEPAGE_ASCII   : 'ascii',
    CODEPAGE_WESTERN : 'ascii',
}

# Structures

TABLE_CURSOR = {
    'TableData' : '',
    'FatherDataPageNumber': 0,
    'CurrentPageData' : '',
    'CurrentTag' : 0,
}

class ESENT_JET_SIGNATURE(Structure):
    structure = (
        ('Random','<L=0'),
        ('CreationTime','<Q=0'),
        ('NetBiosName','16s=""'),
    )

class ESENT_DB_HEADER(Structure):
    structure = (
        ('CheckSum','<L=0'),
        ('Signature','"\xef\xcd\xab\x89'),
        ('Version','<L=0'),
        ('FileType','<L=0'),
        ('DBTime','<Q=0'),
        ('DBSignature',':',ESENT_JET_SIGNATURE),
        ('DBState','<L=0'),
        ('ConsistentPosition','<Q=0'),
        ('ConsistentTime','<Q=0'),
        ('AttachTime','<Q=0'),
        ('AttachPosition','<Q=0'),
        ('DetachTime','<Q=0'),
        ('DetachPosition','<Q=0'),
        ('LogSignature',':',ESENT_JET_SIGNATURE),
        ('Unknown','<L=0'),
        ('PreviousBackup','24s=""'),
        ('PreviousIncBackup','24s=""'),
        ('CurrentFullBackup','24s=""'),
        ('ShadowingDisables','<L=0'),
        ('LastObjectID','<L=0'),
        ('WindowsMajorVersion','<L=0'),
        ('WindowsMinorVersion','<L=0'),
        ('WindowsBuildNumber','<L=0'),
        ('WindowsServicePackNumber','<L=0'),
        ('FileFormatRevision','<L=0'),
        ('PageSize','<L=0'),
        ('RepairCount','<L=0'),
        ('RepairTime','<Q=0'),
        ('Unknown2','28s=""'),
        ('ScrubTime','<Q=0'),
        ('RequiredLog','<Q=0'),
        ('UpgradeExchangeFormat','<L=0'),
        ('UpgradeFreePages','<L=0'),
        ('UpgradeSpaceMapPages','<L=0'),
        ('CurrentShadowBackup','24s=""'),
        ('CreationFileFormatVersion','<L=0'),
        ('CreationFileFormatRevision','<L=0'),
        ('Unknown3','16s=""'),
        ('OldRepairCount','<L=0'),
        ('ECCCount','<L=0'),
        ('LastECCTime','<Q=0'),
        ('OldECCFixSuccessCount','<L=0'),
        ('ECCFixErrorCount','<L=0'),
        ('LastECCFixErrorTime','<Q=0'),
        ('OldECCFixErrorCount','<L=0'),
        ('BadCheckSumErrorCount','<L=0'),
        ('LastBadCheckSumTime','<Q=0'),
        ('OldCheckSumErrorCount','<L=0'),
        ('CommittedLog','<L=0'),
        ('PreviousShadowCopy','24s=""'),
        ('PreviousDifferentialBackup','24s=""'),
        ('Unknown4','40s=""'),
        ('NLSMajorVersion','<L=0'),
        ('NLSMinorVersion','<L=0'),
        ('Unknown5','148s=""'),
        ('UnknownFlags','<L=0'),
    )

class ESENT_PAGE_HEADER(Structure):
    structure_2003_SP0 = (
        ('CheckSum','<L=0'),
        ('PageNumber','<L=0'),
    )
    structure_0x620_0x0b = (
        ('CheckSum','<L=0'),
        ('ECCCheckSum','<L=0'),
    )
    structure_win7 = (
        ('CheckSum','<Q=0'),
    )
    common = (
        ('LastModificationTime','<Q=0'),
        ('PreviousPageNumber','<L=0'),
        ('NextPageNumber','<L=0'),
        ('FatherDataPage','<L=0'),
        ('AvailableDataSize','<H=0'),
        ('AvailableUncommittedDataSize','<H=0'),
        ('FirstAvailableDataOffset','<H=0'),
        ('FirstAvailablePageTag','<H=0'),
        ('PageFlags','<L=0'),
    )
    extended_win7 = (
        ('ExtendedCheckSum1','<Q=0'),
        ('ExtendedCheckSum2','<Q=0'),
        ('ExtendedCheckSum3','<Q=0'),
        ('PageNumber','<Q=0'),
        ('Unknown','<Q=0'),
    )
    def __init__(self, version, revision, pageSize=8192, data=None):
        if (version < 0x620) or (version == 0x620 and revision < 0x0b):
            # For sure the old format
            self.structure = self.structure_2003_SP0 + self.common
        elif (version == 0x620 and revision < 0x11):
            # Exchange 2003 SP1 and Windows Vista and later
            self.structure = self.structure_0x620_0x0b + self.common
        else:
            # Windows 7 and later
            self.structure = self.structure_win7 + self.common
            if pageSize > 8192:
                self.structure += self.extended_win7

        return Structure.__init__(self,data)

class ESENT_ROOT_HEADER(Structure):
    structure = (
        ('InitialNumberOfPages','<L=0'),
        ('ParentFatherDataPage','<L=0'),
        ('ExtentSpace','<L=0'),
        ('SpaceTreePageNumber','<L=0'),
    )

class ESENT_BRANCH_HEADER(Structure):
    structure = (
        ('CommonPageKey',':'),
    )

class ESENT_BRANCH_ENTRY(Structure):
    common = (
        ('CommonPageKeySize','<H=0'),
    )
    structure = (
        ('LocalPageKeySize','<H=0'),
        ('_LocalPageKey','_-LocalPageKey','self["LocalPageKeySize"]'),
        ('LocalPageKey',':'),
        ('ChildPageNumber','<L=0'),
    )
    def __init__(self, flags, data=None):
        if flags & TAG_COMMON > 0:
            # Include the common header
            self.structure = self.common + self.structure
        return Structure.__init__(self,data)

class ESENT_LEAF_HEADER(Structure):
    structure = (
        ('CommonPageKey',':'),
    )

class ESENT_LEAF_ENTRY(Structure):
    common = (
        ('CommonPageKeySize','<H=0'),
    )
    structure = (
        ('LocalPageKeySize','<H=0'),
        ('_LocalPageKey','_-LocalPageKey','self["LocalPageKeySize"]'),
        ('LocalPageKey',':'),
        ('EntryData',':'),
    )
    def __init__(self, flags, data=None):
        if flags & TAG_COMMON > 0:
            # Include the common header
            self.structure = self.common + self.structure
        return Structure.__init__(self,data)

class ESENT_SPACE_TREE_HEADER(Structure):
    structure = (
        ('Unknown','<Q=0'),
    )

class ESENT_SPACE_TREE_ENTRY(Structure):
    structure = (
        ('PageKeySize','<H=0'),
        ('LastPageNumber','<L=0'),
        ('NumberOfPages','<L=0'),
    )

class ESENT_INDEX_ENTRY(Structure):
    structure = (
        ('RecordPageKey',':'),
    )

class ESENT_DATA_DEFINITION_HEADER(Structure):
    structure = (
        ('LastFixedSize','<B=0'),
        ('LastVariableDataType','<B=0'),
        ('VariableSizeOffset','<H=0'),
    )

class ESENT_CATALOG_DATA_DEFINITION_ENTRY(Structure):
    fixed = (
        ('FatherDataPageID','<L=0'),
        ('Type','<H=0'),
        ('Identifier','<L=0'),
    )

    column_stuff = (
        ('ColumnType','<L=0'),
        ('SpaceUsage','<L=0'),
        ('ColumnFlags','<L=0'),
        ('CodePage','<L=0'),
    )

    other = (
        ('FatherDataPageNumber','<L=0'),
    )

    table_stuff = (
        ('SpaceUsage','<L=0'),
#        ('TableFlags','<L=0'),
#        ('InitialNumberOfPages','<L=0'),
    )

    index_stuff = (
        ('SpaceUsage','<L=0'),
        ('IndexFlags','<L=0'),
        ('Locale','<L=0'),
    )

    lv_stuff = (
        ('SpaceUsage','<L=0'),
#        ('LVFlags','<L=0'),
#        ('InitialNumberOfPages','<L=0'),
    )
    common = (
#        ('RootFlag','<B=0'),
#        ('RecordOffset','<H=0'),
#        ('LCMapFlags','<L=0'),
#        ('KeyMost','<H=0'),
        ('Trailing',':'),
    )

    def __init__(self,data):
        # Depending on the type of data we'll end up building a different struct
        dataType = unpack('<H', data[4:][:2])[0]
        self.structure = self.fixed

        if dataType == CATALOG_TYPE_TABLE:
            self.structure += self.other + self.table_stuff
        elif dataType == CATALOG_TYPE_COLUMN:
            self.structure += self.column_stuff
        elif dataType == CATALOG_TYPE_INDEX:
            self.structure += self.other + self.index_stuff
        elif dataType == CATALOG_TYPE_LONG_VALUE:
            self.structure += self.other + self.lv_stuff
        elif dataType == CATALOG_TYPE_CALLBACK:
            logging.error('CallBack types not supported!')
            raise
        else:
            logging.error('Unknown ttype 0x%x' % dataType)
            self.structure = ()
            return Structure.__init__(self,data)

        self.structure += self.common

        return Structure.__init__(self,data)

import string
def pretty_print(x):
    if x in '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~ ':
       return x
    else:
       return '.'

def hexdump(data):
    x=str(data)
    strLen = len(x)
    i = 0
    while i < strLen:
        print "%04x  " % i,
        for j in range(16):
            if i+j < strLen:
                print "%02X" % ord(x[i+j]),
            else:
                print "  ",
            if j%16 == 7:
                print "",
        print " ",
        print ''.join(pretty_print(x) for x in x[i:i+16] )
        i += 16

def getUnixTime(t):
    t -= 116444736000000000
    t /= 10000000
    return t

class ESENT_PAGE():
    def __init__(self, db, data=None):
        self.__DBHeader = db
        self.data = data
        self.record = None
        if data is not None:
            self.record = ESENT_PAGE_HEADER(self.__DBHeader['Version'], self.__DBHeader['FileFormatRevision'], self.__DBHeader['PageSize'], data)

    def printFlags(self):
        flags = self.record['PageFlags']
        if flags & FLAGS_EMPTY:
            print "\tEmpty"
        if flags & FLAGS_INDEX:
            print "\tIndex"
        if flags & FLAGS_LEAF:
            print "\tLeaf"
        else:
            print "\tBranch"
        if flags & FLAGS_LONG_VALUE:
            print "\tLong Value"
        if flags & FLAGS_NEW_CHECKSUM:
            print "\tNew Checksum"
        if flags & FLAGS_NEW_FORMAT:
            print "\tNew Format"
        if flags & FLAGS_PARENT:
            print "\tParent"
        if flags & FLAGS_ROOT:
            print "\tRoot"
        if flags & FLAGS_SPACE_TREE:
            print "\tSpace Tree"

    def dump(self):
        baseOffset = len(self.record)
        self.record.dump()
        tags = self.data[-4*self.record['FirstAvailablePageTag']:]

        print "FLAGS: "
        self.printFlags()

        print

        for i in range(self.record['FirstAvailablePageTag']):
            tag = tags[-4:]
            if self.__DBHeader['Version'] == 0x620 and self.__DBHeader['FileFormatRevision'] > 11 and self.__DBHeader['PageSize'] > 8192:
                valueSize = unpack('<H', tag[:2])[0] & 0x7fff
                valueOffset = unpack('<H',tag[2:])[0] & 0x7fff
                hexdump((self.data[baseOffset+valueOffset:][:6]))
                pageFlags = ord(self.data[baseOffset+valueOffset:][1]) >> 5
                #print "TAG FLAG: 0x%x " % (unpack('<L', self.data[baseOffset+valueOffset:][:4]) ) >> 5
                #print "TAG FLAG: 0x " , ord(self.data[baseOffset+valueOffset:][0])
            else:
                valueSize = unpack('<H', tag[:2])[0] & 0x1fff
                pageFlags = (unpack('<H', tag[2:])[0] & 0xe000) >> 13
                valueOffset = unpack('<H',tag[2:])[0] & 0x1fff
                
            print "TAG %-8d offset:0x%-6x flags:0x%-4x valueSize:0x%x" % (i,valueOffset,pageFlags,valueSize)
            #hexdump(self.getTag(i)[1])
            tags = tags[:-4]

        if self.record['PageFlags'] & FLAGS_ROOT > 0:
            rootHeader = ESENT_ROOT_HEADER(self.getTag(0)[1])
            rootHeader.dump()
        elif self.record['PageFlags'] & FLAGS_LEAF == 0:
            # Branch Header
            flags, data = self.getTag(0)
            branchHeader = ESENT_BRANCH_HEADER(data)
            branchHeader.dump()
        else:
            # Leaf Header
            flags, data = self.getTag(0)
            if self.record['PageFlags'] & FLAGS_SPACE_TREE > 0:
                # Space Tree
                spaceTreeHeader = ESENT_SPACE_TREE_HEADER(data)
                spaceTreeHeader.dump()
            else:
                leafHeader = ESENT_LEAF_HEADER(data)
                leafHeader.dump()

        # Print the leaf/branch tags
        for tagNum in range(1,self.record['FirstAvailablePageTag']):
            flags, data = self.getTag(tagNum)
            if self.record['PageFlags'] & FLAGS_LEAF == 0:
                # Branch page
                branchEntry = ESENT_BRANCH_ENTRY(flags, data)
                branchEntry.dump()
            elif self.record['PageFlags'] & FLAGS_LEAF > 0:
                # Leaf page
                if self.record['PageFlags'] & FLAGS_SPACE_TREE > 0:
                    # Space Tree
                    spaceTreeEntry = ESENT_SPACE_TREE_ENTRY(data)
                    #spaceTreeEntry.dump()

                elif self.record['PageFlags'] & FLAGS_INDEX > 0:
                    # Index Entry
                    indexEntry = ESENT_INDEX_ENTRY(data)
                    #indexEntry.dump()
                elif self.record['PageFlags'] & FLAGS_LONG_VALUE > 0:
                    # Long Page Value
                    logging.error('Long value still not supported')
                    raise
                else:
                    # Table Value
                    leafEntry = ESENT_LEAF_ENTRY(flags, data)
                    dataDefinitionHeader = ESENT_DATA_DEFINITION_HEADER(leafEntry['EntryData'])
                    dataDefinitionHeader.dump()
                    catalogEntry = ESENT_CATALOG_DATA_DEFINITION_ENTRY(leafEntry['EntryData'][len(dataDefinitionHeader):])
                    catalogEntry.dump()
                    hexdump(leafEntry['EntryData'])

    def getTag(self, tagNum):
        if self.record['FirstAvailablePageTag'] < tagNum:
            logging.error('Trying to grab an unknown tag 0x%x' % tagNum)
            raise

        tags = self.data[-4*self.record['FirstAvailablePageTag']:]
        baseOffset = len(self.record)
        for i in range(tagNum):
            tags = tags[:-4]

        tag = tags[-4:]

        if self.__DBHeader['Version'] == 0x620 and self.__DBHeader['FileFormatRevision'] >= 17 and self.__DBHeader['PageSize'] > 8192:
            valueSize = unpack('<H', tag[:2])[0] & 0x7fff
            valueOffset = unpack('<H',tag[2:])[0] & 0x7fff
            tmpData = list(self.data[baseOffset+valueOffset:][:valueSize])
            pageFlags = ord(tmpData[1]) >> 5
            tmpData[1] = chr(ord(tmpData[1]) & 0x1f)
            tagData = "".join(tmpData)
        else:
            valueSize = unpack('<H', tag[:2])[0] & 0x1fff
            pageFlags = (unpack('<H', tag[2:])[0] & 0xe000) >> 13
            valueOffset = unpack('<H',tag[2:])[0] & 0x1fff
            tagData = self.data[baseOffset+valueOffset:][:valueSize]

        #return pageFlags, self.data[baseOffset+valueOffset:][:valueSize]
        return pageFlags, tagData

class ESENT_DB:
    def __init__(self, fileName, pageSize = 8192, isRemote = False):
        self.__fileName = fileName
        self.__pageSize = pageSize
        self.__DB = None
        self.__DBHeader = None
        self.__totalPages = None
        self.__tables = OrderedDict()
        self.__currentTable = None
        self.__isRemote = isRemote
        self.mountDB()

    def mountDB(self):
        logging.debug("Mounting DB...")
        if self.__isRemote is True:
            self.__DB = self.__fileName
            self.__DB.open()
        else:
            self.__DB = open(self.__fileName,"rb")
        mainHeader = self.getPage(-1)
        self.__DBHeader = ESENT_DB_HEADER(mainHeader)
        self.__pageSize = self.__DBHeader['PageSize']
        self.__DB.seek(0,2)
        self.__totalPages = (self.__DB.tell() / self.__pageSize) -2
        logging.debug("Database Version:0x%x, Revision:0x%x"% (self.__DBHeader['Version'], self.__DBHeader['FileFormatRevision']))
        logging.debug("Page Size: %d" % self.__pageSize)
        logging.debug("Total Pages in file: %d" % self.__totalPages)
        self.parseCatalog(CATALOG_PAGE_NUMBER)

    def DBCatalog(self):
        Catalog = {}

        print "CheckSum 0x%x" % (self.__DBHeader['CheckSum'])
        print "DBState 0x%x" % (self.__DBHeader['DBState'])
        print "FileType 0x%x" % (self.__DBHeader['FileType'])
        print "WindowMajorVersion 0x%x" % (self.__DBHeader['WindowsMajorVersion'])
        print "WindowsMinorVersion 0x%x" % (self.__DBHeader['WindowsMinorVersion'])
        print "WindowsBuildNumber 0x%x" % (self.__DBHeader['WindowsBuildNumber'])
        print "WindowsServicePackNumber 0x%x" % (self.__DBHeader['WindowsServicePackNumber'])
        print "CreationFileFormatVersion 0x%x" % (self.__DBHeader['CreationFileFormatVersion'])
        print "CreationFileFormatRevision 0x%x" % (self.__DBHeader['CreationFileFormatRevision'])
        print "Signature 0x89abcdef"
        print "Database version: 0x%x, 0x%x" % (self.__DBHeader['Version'], self.__DBHeader['FileFormatRevision'] )
        print "Page size: %d " % (self.__pageSize)
        print "Number of pages: %d" % self.__totalPages
        print "Catalog for %s" % self.__fileName
        
        Catalog[0] = self.__DBHeader['CheckSum']
        Catalog[1] = self.__DBHeader['FileType']
        Catalog[2] = self.__DBHeader['DBState']
        Catalog[3] = self.__DBHeader['Version']
        Catalog[4] = self.__DBHeader['FileFormatRevision']
        Catalog[5] = self.__pageSize
        Catalog[6] = self.__totalPages

        return Catalog

    def SearchTable(self):
        tablename = {}
        i=0
        for table in self.__tables.keys():
            tablename[i] = table
            i=i+1

        return tablename

    def SearchTableColumn(self, tableName):
        columnsname = {}
        i=0
        for column in self.__tables[tableName]['Columns'].keys():
            record = self.__tables[tableName]['Columns'][column]['Record']
            print "%-5d%-30s%s" % (record['Identifier'], column, ColumnTypeToName[record['ColumnType']])
            columnsname[i] = column
            i=i+1

        return columnsname

    def printCatalog(self):
        indent = '    '

        print "Database version: 0x%x, 0x%x" % (self.__DBHeader['Version'], self.__DBHeader['FileFormatRevision'] )
        print "Page size: %d " % (self.__pageSize)
        print "Number of pages: %d" % self.__totalPages
        print 
        print "Catalog for %s" % self.__fileName
        f = open("Catalog.txt", 'wb')
        data = {}
        tablename = {}
        i = 0
        for table in self.__tables.keys():
            data[0] = "%s" % table
            tablename[i] = data[0]
            data[1] = "%sColumns " % indent
            f.write(data[0])
            f.write(data[1])
            for column in self.__tables[table]['Columns'].keys():
                record = self.__tables[table]['Columns'][column]['Record']
                data[2] = "%s%-5d%-30s%s" % (indent*2, record['Identifier'], column,ColumnTypeToName[record['ColumnType']])
                f.write(data[2])
            data[3] = "%sIndexes"% indent
            f.write(data[3])
            for index in self.__tables[table]['Indexes'].keys():
                data[4] = "%s%s" % (indent*2, index)
                f.write(data[4])
            f.write("\n")
            i=i+1
        f.close()
        return tablename

    def __addItem(self, entry):
        dataDefinitionHeader = ESENT_DATA_DEFINITION_HEADER(entry['EntryData'])
        catalogEntry = ESENT_CATALOG_DATA_DEFINITION_ENTRY(entry['EntryData'][len(dataDefinitionHeader):])
        itemName = self.__parseItemName(entry)

        if catalogEntry['Type'] == CATALOG_TYPE_TABLE:
            self.__tables[itemName] = OrderedDict()
            self.__tables[itemName]['TableEntry'] = entry
            self.__tables[itemName]['Columns']    = OrderedDict()
            self.__tables[itemName]['Indexes']    = OrderedDict()
            self.__tables[itemName]['LongValues'] = OrderedDict()
            self.__currentTable = itemName
        elif catalogEntry['Type'] == CATALOG_TYPE_COLUMN:
            self.__tables[self.__currentTable]['Columns'][itemName] = entry
            self.__tables[self.__currentTable]['Columns'][itemName]['Header'] = dataDefinitionHeader
            self.__tables[self.__currentTable]['Columns'][itemName]['Record'] = catalogEntry
        elif catalogEntry['Type'] == CATALOG_TYPE_INDEX:
            self.__tables[self.__currentTable]['Indexes'][itemName] = entry
        elif catalogEntry['Type'] == CATALOG_TYPE_LONG_VALUE:
            self.__addLongValue(entry)
        else:
            logging.error('Unknown type 0x%x' % catalogEntry['Type'])
            raise

    def __parseItemName(self,entry):
        dataDefinitionHeader = ESENT_DATA_DEFINITION_HEADER(entry['EntryData'])

        if dataDefinitionHeader['LastVariableDataType'] > 127:
            numEntries =  dataDefinitionHeader['LastVariableDataType'] - 127
        else:
            numEntries =  dataDefinitionHeader['LastVariableDataType']

        itemLen = unpack('<H',entry['EntryData'][dataDefinitionHeader['VariableSizeOffset']:][:2])[0]
        itemName = entry['EntryData'][dataDefinitionHeader['VariableSizeOffset']:][2*numEntries:][:itemLen]
        return itemName

    def __addLongValue(self, entry):
        dataDefinitionHeader = ESENT_DATA_DEFINITION_HEADER(entry['EntryData'])
        catalogEntry = ESENT_CATALOG_DATA_DEFINITION_ENTRY(entry['EntryData'][len(dataDefinitionHeader):])
        lvLen = unpack('<H',entry['EntryData'][dataDefinitionHeader['VariableSizeOffset']:][:2])[0]
        lvName = entry['EntryData'][dataDefinitionHeader['VariableSizeOffset']:][7:][:lvLen]
        self.__tables[self.__currentTable]['LongValues'][lvName] = entry

    def parsePage(self, page):
        baseOffset = len(page.record)

        # Print the leaf/branch tags
        for tagNum in range(1,page.record['FirstAvailablePageTag']):
            flags, data = page.getTag(tagNum)
            if page.record['PageFlags'] & FLAGS_LEAF > 0:
                # Leaf page
                if page.record['PageFlags'] & FLAGS_SPACE_TREE > 0:
                    pass
                elif page.record['PageFlags'] & FLAGS_INDEX > 0:
                    pass
                elif page.record['PageFlags'] & FLAGS_LONG_VALUE > 0:
                    pass
                else:
                    # Table Value
                    leafEntry = ESENT_LEAF_ENTRY(flags, data)
                    self.__addItem(leafEntry)

    def parseCatalog(self, pageNum):
        # Parse all the pages starting at pageNum and commit table data
        page = self.getPage(pageNum)
        self.parsePage(page)

        for i in range(1, page.record['FirstAvailablePageTag']):
            flags, data = page.getTag(i)
            if page.record['PageFlags'] & FLAGS_LEAF == 0:
                # Branch page
                branchEntry = ESENT_BRANCH_ENTRY(flags, data)
                self.parseCatalog(branchEntry['ChildPageNumber'])


    def readHeader(self):
        logging.debug("Reading Boot Sector for %s" % self.__volumeName)

    def getPage(self, pageNum):
        logging.debug("Trying to fetch page %d (0x%x)" % (pageNum, (pageNum+1)*self.__pageSize))
        self.__DB.seek((pageNum+1)*self.__pageSize, 0)
        data = self.__DB.read(self.__pageSize)
        while len(data) < self.__pageSize:
            remaining = self.__pageSize - len(data)
            data += self.__DB.read(remaining)
        # Special case for the first page
        if pageNum <= 0:
            return data
        else:
            return ESENT_PAGE(self.__DBHeader, data)

    def close(self):
        self.__DB.close()

    def openTable(self, tableName):
        # Returns a cursos for later use
        
        if tableName in self.__tables:
            entry = self.__tables[tableName]['TableEntry']
            dataDefinitionHeader = ESENT_DATA_DEFINITION_HEADER(entry['EntryData'])
            catalogEntry = ESENT_CATALOG_DATA_DEFINITION_ENTRY(entry['EntryData'][len(dataDefinitionHeader):])
            
            # Let's position the cursor at the leaf levels for fast reading
            pageNum = catalogEntry['FatherDataPageNumber']
            done = False
            while done is False:
                page = self.getPage(pageNum)
                if page.record['FirstAvailablePageTag'] == 1:
                    # There are no records
                    done = True
                for i in range(1, page.record['FirstAvailablePageTag']):
                    flags, data = page.getTag(i)
                    if page.record['PageFlags'] & FLAGS_LEAF == 0:
                        # Branch page, move on to the next page
                        branchEntry = ESENT_BRANCH_ENTRY(flags, data)
                        pageNum = branchEntry['ChildPageNumber']
                        break
                    else:
                        done = True
                        break
                
            cursor = TABLE_CURSOR
            cursor['TableData'] = self.__tables[tableName]
            cursor['FatherDataPageNumber'] = catalogEntry['FatherDataPageNumber']
            cursor['CurrentPageData'] = page
            cursor['CurrentTag']  = 0
            return cursor
        else:
            return None

    def __getNextTag(self, cursor):
        page = cursor['CurrentPageData']

        if cursor['CurrentTag'] >= page.record['FirstAvailablePageTag']:
            # No more data in this page, chau
            return None

        flags, data = page.getTag(cursor['CurrentTag'])
        if page.record['PageFlags'] & FLAGS_LEAF > 0:
            # Leaf page
            if page.record['PageFlags'] & FLAGS_SPACE_TREE > 0:
                raise
            elif page.record['PageFlags'] & FLAGS_INDEX > 0:
                raise
            elif page.record['PageFlags'] & FLAGS_LONG_VALUE > 0:
                raise
            else:
                # Table Value
                leafEntry = ESENT_LEAF_ENTRY(flags, data)
                return leafEntry

        return None

    def getNextRow(self, cursor):
        cursor['CurrentTag'] += 1

        tag = self.__getNextTag(cursor)
        #hexdump(tag)

        if tag == None:
            # No more tags in this page, search for the next one on the right
            page = cursor['CurrentPageData']
            if page.record['NextPageNumber'] == 0:
                # No more pages, chau
                return None
            else:
                cursor['CurrentPageData'] = self.getPage(page.record['NextPageNumber'])
                cursor['CurrentTag'] = 0
                return self.getNextRow(cursor)
        else:
            return self.__tagToRecord(cursor, tag['EntryData'])

        # We never should get here
        raise

    def __tagToRecord(self, cursor, tag):
        # So my brain doesn't forget, the data record is composed of:
        # Header
        # Fixed Size Data (ID < 127)
        #     The easiest to parse. Their size is fixed in the record. You can get its size
        #     from the Column Record, field SpaceUsage
        # Variable Size Data (127 < ID < 255)
        #     At VariableSizeOffset you get an array of two bytes per variable entry, pointing
        #     to the length of the value. Values start at:
        #                numEntries = LastVariableDataType - 127
        #                VariableSizeOffset + numEntries * 2 (bytes)
        # Tagged Data ( > 255 )
        #     After the Variable Size Value, there's more data for the tagged values.
        #     Right at the beggining there's another array (taggedItems), pointing to the
        #     values, size.
        #
        # The interesting thing about this DB records is there's no need for all the columns to be there, hence
        # saving space. That's why I got over all the columns, and if I find data (of any type), i assign it. If 
        # not, the column's empty.
        #
        # There are a lot of caveats in the code, so take your time to explore it. 
        #
        # ToDo: Better complete this description
        #

        record = OrderedDict()
        taggedItems = OrderedDict()
        taggedItemsParsed = False

        dataDefinitionHeader = ESENT_DATA_DEFINITION_HEADER(tag)
        #dataDefinitionHeader.dump()
        variableDataBytesProcessed = (dataDefinitionHeader['LastVariableDataType'] - 127) * 2
        prevItemLen = 0
        tagLen = len(tag)
        fixedSizeOffset = len(dataDefinitionHeader)
        variableSizeOffset = dataDefinitionHeader['VariableSizeOffset'] 
 
        columns = cursor['TableData']['Columns'] 
        
        for column in columns.keys():
            columnRecord = columns[column]['Record']
            #columnRecord.dump()
            if columnRecord['Identifier'] <= dataDefinitionHeader['LastFixedSize']:
                # Fixed Size column data type, still available data
                record[column] = tag[fixedSizeOffset:][:columnRecord['SpaceUsage']]
                fixedSizeOffset += columnRecord['SpaceUsage']

            elif columnRecord['Identifier'] > 127 and columnRecord['Identifier'] <= dataDefinitionHeader['LastVariableDataType']:
                # Variable data type
                index = columnRecord['Identifier'] - 127 - 1
                itemLen = unpack('<H',tag[variableSizeOffset+index*2:][:2])[0]

                if itemLen & 0x8000:
                    # Empty item
                    itemLen = prevItemLen
                    record[column] = None
                else:
                    itemValue = tag[variableSizeOffset+variableDataBytesProcessed:][:itemLen-prevItemLen]
                    record[column] = itemValue

                #if columnRecord['Identifier'] <= dataDefinitionHeader['LastVariableDataType']:
                variableDataBytesProcessed +=itemLen-prevItemLen

                prevItemLen = itemLen

            elif columnRecord['Identifier'] > 255:
                # Have we parsed the tagged items already?
                if taggedItemsParsed is False and (variableDataBytesProcessed+variableSizeOffset) < tagLen:
                    index = variableDataBytesProcessed+variableSizeOffset
                    #hexdump(tag[index:])
                    endOfVS = self.__pageSize
                    firstOffsetTag = (unpack('<H', tag[index+2:][:2])[0] & 0x3fff) + variableDataBytesProcessed+variableSizeOffset
                    while True:
                        taggedIdentifier = unpack('<H', tag[index:][:2])[0]
                        index += 2
                        taggedOffset = (unpack('<H', tag[index:][:2])[0] & 0x3fff) 
                        # As of Windows 7 and later ( version 0x620 revision 0x11) the 
                        # tagged data type flags are always present
                        if self.__DBHeader['Version'] == 0x620 and self.__DBHeader['FileFormatRevision'] >= 17 and self.__DBHeader['PageSize'] > 8192: 
                            flagsPresent = 1
                        else:
                            flagsPresent = (unpack('<H', tag[index:][:2])[0] & 0x4000)
                        index += 2
                        if taggedOffset < endOfVS:
                            endOfVS = taggedOffset
                        taggedItems[taggedIdentifier] = (taggedOffset, tagLen, flagsPresent)
                        #print "ID: %d, Offset:%d, firstOffset:%d, index:%d, flag: 0x%x" % (taggedIdentifier, taggedOffset,firstOffsetTag,index, flagsPresent)
                        if index >= firstOffsetTag:
                            # We reached the end of the variable size array
                            break
                
                    # Calculate length of variable items
                    # Ugly.. should be redone
                    prevKey = taggedItems.keys()[0]
                    for i in range(1,len(taggedItems)):
                        offset0, length, flags = taggedItems[prevKey]
                        offset, _, _ = taggedItems.items()[i][1]
                        taggedItems[prevKey] = (offset0, offset-offset0, flags)
                        #print "ID: %d, Offset: %d, Len: %d, flags: %d" % (prevKey, offset0, offset-offset0, flags)
                        prevKey = taggedItems.keys()[i]
                    taggedItemsParsed = True
 
                # Tagged data type
                if taggedItems.has_key(columnRecord['Identifier']):
                    offsetItem = variableDataBytesProcessed + variableSizeOffset + taggedItems[columnRecord['Identifier']][0] 
                    itemSize = taggedItems[columnRecord['Identifier']][1]
                    # If item have flags, we should skip them
                    if taggedItems[columnRecord['Identifier']][2] > 0:
                        itemFlag = ord(tag[offsetItem:offsetItem+1])
                        offsetItem += 1
                        itemSize -= 1
                    else:
                        itemFlag = 0

                    #print "ID: %d, itemFlag: 0x%x" %( columnRecord['Identifier'], itemFlag)
                    if itemFlag & (TAGGED_DATA_TYPE_COMPRESSED ):
                        logging.error('Unsupported tag column: %s, flag:0x%x' % (column, itemFlag))
                        record[column] = None
                    elif itemFlag & TAGGED_DATA_TYPE_MULTI_VALUE:
                        # ToDo: Parse multi-values properly
                        logging.debug('Multivalue detected in column %s, returning raw results' % (column))
                        record[column] = (tag[offsetItem:][:itemSize].encode('hex'),)
                    else:
                        record[column] = tag[offsetItem:][:itemSize]

                else:
                    record[column] = None
            else:
                record[column] = None

            # If we understand the data type, we unpack it and cast it accordingly
            # otherwise, we just encode it in hex
            if type(record[column]) is tuple:
                # A multi value data, we won't decode it, just leave it this way
                record[column] = record[column][0]
            elif columnRecord['ColumnType'] == JET_coltypText or columnRecord['ColumnType'] == JET_coltypLongText: 
                # Let's handle strings
                if record[column] is not None:
                    if columnRecord['CodePage'] not in StringCodePages:
                        logging.error('Unknown codepage 0x%x'% columnRecord['CodePage'])
                        raise
                    stringDecoder = StringCodePages[columnRecord['CodePage']]

                    record[column] = record[column].decode(stringDecoder)
                
            else:
                unpackData = ColumnTypeSize[columnRecord['ColumnType']]
                if record[column] is not None:
                    if unpackData is None:
                        record[column] = record[column].encode('hex')
                    else:
                        unpackStr = unpackData[1]
                        unpackSize = unpackData[0]
                        record[column] = unpack(unpackStr, record[column])[0]

        return record

import sys, sqlite3, csv, sys, os, urllib, codecs, string
import shutil
import time
import platform
import re
import binascii
from PySide import QtGui, QtCore
from datetime import datetime, timedelta

#################################
#####	  GET USER NAME		#####
username = os.getenv('USERNAME')		
#################################

#################################
#####	  GET LOCAL TIME	#####
now = time.localtime()
timestamp = "%04d%02d%02d-%02d%02d%02d" %(now.tm_year, now.tm_mon, now.tm_mday, now.tm_hour, now.tm_min, now.tm_sec)		
#################################

#################################
#####	  CHECK Local OS	#####
local_os = platform.release()
#################################



def mkdir(fname):
    	
	os.chdir(fname)					# Change Directory
	if os.path.isdir("UWA_"+"%s"%timestamp) :					# If Directory is exist,
		pass													# PASS!
	else :														# Else, Make a Directory
		os.makedirs("UWA_"+"%s"%timestamp+"\\collection\\IE10++")
		os.makedirs("UWA_"+"%s"%timestamp+"\\collection\\IE10--")
		os.makedirs("UWA_"+"%s"%timestamp+"\\collection\\Chrome\\Cache")
# Make base path directory (for IE10++, IE10--, Chrome)
#############################################
#############################################
### ___unified_WebBrowser_AnalysisTool___ ###
#############################################

def IE10_copydb(fname):
    os.system('taskkill.exe /f /im iexplore.exe')
    os.system('taskkill.exe /f /im dllhost.exe')
    os.system('taskkill.exe /f /im taskhost.exe')
    # Kill to 'WebCacheV01.dat' processes (IE10++)
    
    if os.path.isdir('C:\Users\%s\AppData\Local\Microsoft\Windows\WebCache'%username):
        os.chdir('C:\Users\%s\AppData\Local\Microsoft\Windows\WebCache'%username)
        os.system('esentutl /r V01 /d')
        path = '%s\\UWA_'%fname+"%s"%timestamp+"\\collection\\IE10++\\WebCacheV01.dat"
        #os.system('esentutl /y WebCacheV01.dat /d %s'%fname+'\UWA_%s'%timestamp+"\\collection\\IE10++\\WebCacheV01.dat")
        print 'esentutl /y WebCacheV01.dat /d %s'%path
        os.system('esentutl /y WebCacheV01.dat /d %s'%path)
        
        # Copy to base directory -WebCacheV01.dat- (IE10++)
        
        #def IE10_repairEDB():
        #	os.chdir('C:\Users\%s\Desktop\UWBAT_'%username+"%s"%timestamp+"\\collection\\IE10++")
        #	if os.path.isfile('C:\Users\%s\Desktop\UWBAT_'%username+"%s"%timestamp+"\\collection\\IE10++\\WebCacheV01.dat") :
        #		os.system('esentutl /y WebCacheV01.dat /d WebCacheV01.dat')
        # Repair database state (IE10++)
        #########################################
        #########################################
        ### ___IE10++___ - collection fuction ###
        #########################################

def IE9_copyfile(fname):
    os.makedirs("\\UWA_"+"%s"%timestamp+"\\collection\\IE10--")
    
    if os.path.isfile('C:\Users\%s\AppData\Local\Microsoft\Windows\Temporary Internet Files\Content.IE5\index.dat'%username) :
        os.chdir(fname)
        os.chdir('C:\Users\%s\AppData\Local\Microsoft\Windows\Temporary Internet Files\Content.IE5'%username)
        shutil.copy2("index.dat", "%s"%fname+"\\UWA_%s"%timestamp+"\\collection\\IE10--")
        if os.path.isfile("%s"%fname+"\\UWA_%s"%timestamp+"\\collection\\IE10--\\index.dat") :
            os.chdir("%s"%fname+"\\UWA_%s"%timestamp+"\\collection\\IE10--")
            os.rename("index.dat", 'index_cache.dat')
   # Copy to base directory -index.dat(cache)- (IE10--)

    if os.path.isfile('C:\Users\%s\AppData\Roaming\Microsoft\Windows\Cookies\index.dat'%username) :
        os.chdir(fname)
        os.chdir('C:\Users\%s\AppData\Roaming\Microsoft\Windows\Cookies'%username)
        shutil.copy2("index.dat", "%s"%fname+"\\UWA_%s"%timestamp+"\\collection\\IE10--")
        if os.path.isfile("%s"%fname+"\\UWA_%s"%timestamp+"\\collection\\IE10--\\index.dat") :
            os.chdir("%s"%fname+"\\UWA_%s"%timestamp+"\\collection\\IE10--")
            os.rename("index.dat", 'index_cookies.dat')
    # Copy to base directory -index.dat(Cookies)- (IE10--)

    if os.path.isfile('C:\Users\%s\AppData\Roaming\Microsoft\Windows\IEDownloadHistory\index.dat'%username) :
        os.chdir(fname)
        os.chdir('C:\Users\%s\AppData\Roaming\Microsoft\Windows\IEDownloadHistory'%username)
        shutil.copy2("index.dat", "%s"%fname+"\\UWA_%s"%timestamp+"\\collection\\IE10--")
        if os.path.isfile("%s"%fname+"\\UWA_%s"%timestamp+"\\collection\\IE10--\\index.dat") :
            os.chdir("%s"%fname+"\\UWA_%s"%timestamp+"\\collection\\IE10--")
            os.rename("index.dat", 'index_download.dat')
    # Copy to base directory -index.dat(IE Downloadlist)- (IE10--)

    if os.path.isfile('C:\Users\%s\AppData\Local\Microsoft\Windows\History\History.IE5\index.dat'%username) :
        os.chdir(fname)
        os.chdir('C:\Users\%s\AppData\Local\Microsoft\Windows\History\History.IE5'%username)
        shutil.copy2("index.dat", "%s"%fname+"\\UWA_%s"%timestamp+"\\collection\\IE10--")
        if os.path.isfile("%s"%fname+"\\UWA_%s"%timestamp+"\\collection\\IE10--\\index.dat") :
            os.chdir("%s"%fname+"\\UWA_%s"%timestamp+"\\collection\\IE10--")
            os.rename("index.dat", 'index_history.dat')

    data = [x[0] for x in os.walk("C:\Users\%s\AppData\Local\Microsoft\Windows\History\History.IE5"%username)]
    
    for x in data:
        a = x.lower()
        if("mshist" in a):
            src = a + r"\index.dat"
            dis = r"%s"%fname+"\\UWA_%s"%timestamp+"\\collection\\IE10--\\index_history_" + a.split("mshist")[1] + ".dat"
            #print dis
            os.system("""echo f|xcopy /h /k "%s" "%s" """ % (src, dis))

   # Copy to base directory -index.dat(History)- (IE10--)
   #########################################
   #########################################
   ### ___IE10--___ - collection fuction ###
   #########################################

def Chrome_copydb(fname):
    os.chdir('C:\Users\%s\AppData\Local\Google\Chrome\User Data\Default'%username)
    shutil.copy2("Cookies", "%s"%fname+"\\UWA_%s"%timestamp+"\\collection\\Chrome")
    # Copy to Directory ___Cookies___
    
    os.chdir('C:\Users\%s\AppData\Local\Google\Chrome\User Data\Default'%username)
    shutil.copy2("Extension Cookies", "%s"%fname+"\\UWA_%s"%timestamp+"\\collection\\Chrome")
    # Copy to Directory ___Extension Cookies___
    
    os.chdir('C:\Users\%s\AppData\Local\Google\Chrome\User Data\Default'%username)
    shutil.copy2("Favicons", "%s"%fname+"\\UWA_%s"%timestamp+"\\collection\\Chrome")
    # Copy to Directory ___Favicons___
    
    os.chdir('C:\Users\%s\AppData\Local\Google\Chrome\User Data\Default'%username)
    shutil.copy2("History", "%s"%fname+"\\UWA_%s"%timestamp+"\\collection\\Chrome")
    # Copy to Directory ___History___
    
    os.chdir('C:\Users\%s\AppData\Local\Google\Chrome\User Data\Default'%username)
    shutil.copy2("Login Data", "%s"%fname+"\\UWA_%s"%timestamp+"\\collection\\Chrome")
    # Copy to Directory ___Login Data___
    
    os.chdir('C:\Users\%s\AppData\Local\Google\Chrome\User Data\Default'%username)
    shutil.copy2("Network Action Predictor", "%s"%fname+"\\UWA_%s"%timestamp+"\\collection\\Chrome")
    # Copy to Directory ___Network Action Predictor___
    
    os.chdir('C:\Users\%s\AppData\Local\Google\Chrome\User Data\Default'%username)
    shutil.copy2("Origin Bound Certs", "%s"%fname+"\\UWA_%s"%timestamp+"\\collection\\Chrome")
    # Copy to Directory ___Origin Bound Certs___
    
    os.chdir('C:\Users\%s\AppData\Local\Google\Chrome\User Data\Default'%username)
    shutil.copy2("QuotaManager", "%s"%fname+"\\UWA_%s"%timestamp+"\\collection\\Chrome")
    # Copy to Directory ___QuotaManager___
    
    os.chdir('C:\Users\%s\AppData\Local\Google\Chrome\User Data\Default'%username)
    shutil.copy2("Shortcuts", "%s"%fname+"\\UWA_%s"%timestamp+"\\collection\\Chrome")
    # Copy to Directory ___Shortcuts___
    
    os.chdir('C:\Users\%s\AppData\Local\Google\Chrome\User Data\Default'%username)
    shutil.copy2("Top Sites", "%s"%fname+"\\UWA_%s"%timestamp+"\\collection\\Chrome")
    # Copy to Directory ___Top Sites___
    
    os.chdir('C:\Users\%s\AppData\Local\Google\Chrome\User Data\Default'%username)
    shutil.copy2("Web Data", "%s"%fname+"\\UWA_%s"%timestamp+"\\collection\\Chrome")
    # Copy to Directory ___Web Data___
    
    os.system('taskkill.exe /f /im chrome.exe')
    # Kill to 'chrome.exe' processes (Chrome)
    """
    # Chrome Cache Collect
    os.chdir('C:\Users\%s\AppData\Local\Google\Chrome\User Data\Default\Cache'%username)
    cache_files = os.listdir('./')
    for files in range(len(cache_files)) :
        shutil.copy2(cache_files[files], "%s"%fname+"\\UWA_%s"%timestamp+"\\collection\\Chrome\\Cache")
    """
    # Copy to Directory ___Cache___

def Chrome_dbrename(fname):
    os.chdir("%s"%fname+"\\UWA_%s"%timestamp+"\\collection\\Chrome")
    # Choose Directory
    
    os.rename("Cookies", 'Cookies.db')
    os.rename("Extension Cookies", 'Extension Cookies.db')
    os.rename("Favicons", 'Favicons.db')
    os.rename("History", 'History.db')
    os.rename("Login Data", 'Login Data.db')
    os.rename("Network Action Predictor", 'Network Action Predictor.db')
    os.rename("Origin Bound Certs", 'Origin Bound Certs.db')
    os.rename("QuotaManager", 'QuotaManager.db')
    os.rename("Shortcuts", 'Shortcuts.db')
    os.rename("Top Sites", 'Top Sites.db')
    os.rename("Web Data", 'Web Data.db')

"""
IE Parser
"""
block_size = 128
signature = "55524c20"

count=0

block_size = 128
signature = "55524c20"

count=0

def WindowTimeConverter(gmt,time):
    gmt =0 
    return datetime(1601, 1, 1) + timedelta(microseconds=int(time, 16) / 10.) + timedelta(hours=gmt)

def IE9parser(fname):
    if os.path.isfile('%s'%fname+"\\collection\\IE10--\\index_cache.dat") | os.path.isfile('%s'%fname+"\\collection\\IE10--\\index_hisotry.dat") | os.path.isfile('%s'%fname+"\\collection\\IE10--\\index_cookies.dat"):
        if os.path.isfile(fname+"\\IE9parser.db"):
            os.remove(fname+"\\IE9parser.db")
            con = sqlite3.connect(fname+"\\IE9parser.db")
        else:
            con = sqlite3.connect(fname+"\\IE9parser.db")
        cursor = con.cursor()
        if os.path.isfile('%s'%fname+"\\collection\\IE10--\\index_history.dat"):
            cursor.execute("CREATE TABLE History(URL text, AccessedTime text,CreateTime text)")
            index=0
            gdata = {}
            filepath = '%s'%fname+"\\collection\\IE10--\\index_history.dat"

            with open(filepath, "rb") as f:
                for m in re.finditer( b'\x55\x52\x4c\x20', f.read()):
                    #print "%X" % m.start()
                    f.seek(m.start()+4)

                    block_count = f.read(4).encode("hex")
                    record_size = block_size * int("".join([block_count[i:i+2] for i in range(0, len(block_count), 2)][::-1]).lstrip('0'), 16)

                    f.seek(m.start() + 104) #Move to URL STRING
                    data = f.read(record_size - 104).split(b'\x00')
            
                    gdata[index] = data[0]
                    #print gdata[index]

                    f.seek(m.start()+4)

                    block_count = f.read(4).encode("hex")
                    record_size = block_size * int("".join([block_count[i:i+2] for i in range(0, len(block_count), 2)][::-1]).lstrip('0'), 16)
                    try:
                        f.seek(m.start() + 16) 
                        data = f.read(8).encode("hex")
                        #print data
                        time = "".join([data[i:i+2] for i in range(0, len(data), 2)][::-1]).lstrip('0')
                        #t = data[::-1]
                        convert_time = WindowTimeConverter(0,time)
                        #print convert_time

                        timedata = convert_time
                    #t = data[::-1]
                    except ValueError:
                        pass

                    f.seek(m.start()+4)

                    block_count = f.read(4).encode("hex")
                    record_size = block_size * int("".join([block_count[i:i+2] for i in range(0, len(block_count), 2)][::-1]).lstrip('0'), 16)
                    try:
                        f.seek(m.start() + 8) 
                        data = f.read(8).encode("hex")
                        #print data
                        Create_time = "".join([data[i:i+2] for i in range(0, len(data), 2)][::-1]).lstrip('0')
                        #t = data[::-1]
                        Create_convert_time = WindowTimeConverter(0,Create_time)

                        Create_time_data = Create_convert_time
                    #t = data[::-1]
                    except ValueError:
                        pass

                    if os.path.isfile('%s'%fname+"\\collection\\IE10--\\index_history.dat"):
                        cursor.execute("INSERT INTO History VALUES(?,?,?)", ([gdata[index],timedata,Create_time_data]))
                    index = index+1
                    #print index
                    #index=index+1

        if os.path.isfile('%s'%fname+"\\collection\\IE10--\\index_cache.dat"):
            cursor.execute("CREATE TABLE Cache(URL text, AccessedTime text,CreateTime text)")
            index=0
            gdata = {}
            filepath = '%s'%fname+"\\collection\\IE10--\\index_cache.dat"
            with open(filepath, "rb") as f:
                for m in re.finditer( b'\x55\x52\x4c\x20', f.read()):
                    #print "%X" % m.start()
                    f.seek(m.start()+4)

                    block_count = f.read(4).encode("hex")
                    record_size = block_size * int("".join([block_count[i:i+2] for i in range(0, len(block_count), 2)][::-1]).lstrip('0'), 16)

                    f.seek(m.start() + 104) #Move to URL STRING
                    data = f.read(record_size - 104).split(b'\x00')
            
                    gdata[index] = data[0]
                    #print gdata[index]

                    f.seek(m.start()+4)

                    block_count = f.read(4).encode("hex")
                    record_size = block_size * int("".join([block_count[i:i+2] for i in range(0, len(block_count), 2)][::-1]).lstrip('0'), 16)
                    try:
                        f.seek(m.start() + 16) 
                        data = f.read(8).encode("hex")
                        #print data
                        time = "".join([data[i:i+2] for i in range(0, len(data), 2)][::-1]).lstrip('0')
                        #t = data[::-1]
                        convert_time = WindowTimeConverter(0,time)
                        #print convert_time

                        timedata = convert_time
                    #t = data[::-1]
                    except ValueError:
                        pass

                    f.seek(m.start()+4)

                    block_count = f.read(4).encode("hex")
                    record_size = block_size * int("".join([block_count[i:i+2] for i in range(0, len(block_count), 2)][::-1]).lstrip('0'), 16)
                    try:
                        f.seek(m.start() + 8) 
                        data = f.read(8).encode("hex")
                        #print data
                        Create_time = "".join([data[i:i+2] for i in range(0, len(data), 2)][::-1]).lstrip('0')
                        #t = data[::-1]
                        Create_convert_time = WindowTimeConverter(0,Create_time)

                        Create_time_data = Create_convert_time
                    #t = data[::-1]
                    except ValueError:
                        pass

                    if os.path.isfile('%s'%fname+"\\collection\\IE10--\\index_cache.dat"):
                        cursor.execute("INSERT INTO Cache VALUES(?,?,?)", ([gdata[index],timedata,Create_time_data]))
                    index = index+1
                    #print index
                    #index=index+1

        if os.path.isfile('%s'%fname+"\\collection\\IE10--\\index_Cookies.dat"):
            cursor.execute("CREATE TABLE Cookies(URL text, AccessedTime text,CreateTime text)")
            index=0
            gdata = {}
            filepath = '%s'%fname+"\\collection\\IE10--\\index_Cookies.dat"

            with open(filepath, "rb") as f:
                for m in re.finditer( b'\x55\x52\x4c\x20', f.read()):
                    #print "%X" % m.start()
                    f.seek(m.start()+4)

                    block_count = f.read(4).encode("hex")
                    record_size = block_size * int("".join([block_count[i:i+2] for i in range(0, len(block_count), 2)][::-1]).lstrip('0'), 16)

                    f.seek(m.start() + 104) #Move to URL STRING
                    data = f.read(record_size - 104).split(b'\x00')
            
                    gdata[index] = data[0]
                    #print gdata[index]

                    f.seek(m.start()+4)

                    block_count = f.read(4).encode("hex")
                    record_size = block_size * int("".join([block_count[i:i+2] for i in range(0, len(block_count), 2)][::-1]).lstrip('0'), 16)
                    try:
                        f.seek(m.start() + 16) 
                        data = f.read(8).encode("hex")
                        #print data
                        time = "".join([data[i:i+2] for i in range(0, len(data), 2)][::-1]).lstrip('0')
                        #t = data[::-1]
                        convert_time = WindowTimeConverter(0,time)
                        #print convert_time

                        timedata = convert_time
                    #t = data[::-1]
                    except ValueError:
                        pass

                    f.seek(m.start()+4)

                    block_count = f.read(4).encode("hex")
                    record_size = block_size * int("".join([block_count[i:i+2] for i in range(0, len(block_count), 2)][::-1]).lstrip('0'), 16)
                    try:
                        f.seek(m.start() + 8) 
                        data = f.read(8).encode("hex")
                        #print data
                        Create_time = "".join([data[i:i+2] for i in range(0, len(data), 2)][::-1]).lstrip('0')
                        #t = data[::-1]
                        Create_convert_time = WindowTimeConverter(0,Create_time)

                        Create_time_data = Create_convert_time
                    #t = data[::-1]
                    except ValueError:
                        pass

                    if os.path.isfile('%s'%fname+"\\collection\\IE10--\\index_cookies.dat"):
                        cursor.execute("INSERT INTO Cookies VALUES(?,?,?)", ([gdata[index],timedata,Create_time_data]))
                    index = index+1
                    #print index
                    #index=index+1

        print 'ie finish'
        con.commit()
        con.close()

def IEDownloadparser(fname):
    if os.path.isfile('%s'%fname+"\\collection\\IE10--\\index_download.dat"):
        filepath = '%s'%fname+"\\collection\\IE10--\\index_download.dat"
        con = sqlite3.connect(fname+"\\IE9parser.db")
        cursor = con.cursor()
        cursor.execute("CREATE TABLE Downlist(URL text,AccessedTime text,FileSize text)")
        index=0

        with open(filepath, "rb") as f:
            for m in re.finditer( b'\x55\x52\x4c\x20', f.read()):
                #print "%X" % m.start()
                f.seek(m.start()+4)

                block_count = f.read(4).encode("hex")
                record_size = block_size * int("".join([block_count[i:i+2] for i in range(0, len(block_count), 2)][::-1]).lstrip('0'), 16)

                f.seek(m.start() + 516) #Move to Download STRING
                data = f.read(record_size - 516).split(b'\x00\x00')

                final_data = data[0].replace("\x00","")

                f.seek(m.start() + 516 + len(data[0]))
                path_data = f.read(record_size - (516 + len(data[0]))).split(b'\x00\xEF')

                final_path_data = path_data[0].replace("\x00","")

                #print final_path_data

                f.seek(m.start()+4)

                block_count = f.read(4).encode("hex")
                record_size = block_size * int("".join([block_count[i:i+2] for i in range(0, len(block_count), 2)][::-1]).lstrip('0'), 16)

                f.seek(m.start() + 228)
                data = f.read(4).encode("hex")
                file_size = int("".join([data[i:i+2] for i in range(0, len(data), 2)][::-1]),16)
            
                #print file_size

                f.seek(m.start()+4)

                block_count = f.read(4).encode("hex")
                record_size = block_size * int("".join([block_count[i:i+2] for i in range(0, len(block_count), 2)][::-1]).lstrip('0'), 16)
                try:
                    f.seek(m.start() + 16) 
                    data = f.read(8).encode("hex")
                    #print data
                    Create_time = "".join([data[i:i+2] for i in range(0, len(data), 2)][::-1]).lstrip('0')
                    #t = data[::-1]
                    Create_convert_time = WindowTimeConverter(0,Create_time)

                    Create_time_data = Create_convert_time
                #t = data[::-1]
                except ValueError:
                    pass
                if os.path.isfile('%s'%fname+"\\collection\\IE10--\\index_download.dat"):
                    cursor.execute("INSERT INTO Downlist VALUES(?,?,?)", (final_data,Create_time_data,file_size))

                index = index+1
                #print index
                #index=index+1

        print 'ie finish'
        con.commit()
        con.close()

#################
#chrome
#################
class Chrome_Parser():
    def __init__(self, fname):
        self.dname = fname
        if os.path.isfile(self.dname+"\\Chrome.db"):
            os.remove(self.dname+"\\Chrome.db")
        self.Cookies()
        self.Favicons()
        self.History()
        self.Login_Data()
        self.Network_Action_Predictor()
        self.Origin_Bound_Certs()
        self.Top_Sites()
        self.Shortcuts()
        self.Web_Data()
        self.Extension_Cookies()
        print "Chrome Finish"

    def Cookies(self):
        """
        Cookies_origin_md5 = hashlib.md5(open("C:\\Users\%s\AppData\\Local\\Google\\Chrome\\User Data\\Default"%username+"\Cookies", 'rb').read()).hexdigest()
        Cookies_copy_md5 = hashlib.md5(open("C:\\Users\%s\Desktop\\Chrome WebCache "%username+"%s"%timestamp+"\Cookies.db", 'rb').read()).hexdigest()
        
        if Cookies_origin_md5 == Cookies_copy_md5:
            print "------------------------------------------------------------------------"
            print "\t\t\tCookies.db Hash Matched!"
            print "Cookies.db Orginal File Hash : " + "%s"%Cookies_origin_md5
            print "Cookies.db  Copied File Hash : " + "%s"%Cookies_copy_md5
            print "------------------------------------------------------------------------"
        else:
            print "Wrong with file hash! Not matched..."
            print "Module going to be TERMINATE.."
            def TERMINATE(n):
                while n > 0:
                    print (n)
                    n = n - 1
                sys.exit()
                SystemExit
            TERMINATE(5)
            #hash
        """
        con = sqlite3.connect(self.dname+"\\collection\\Chrome\\Cookies.db")
        dbcon = sqlite3.connect(self.dname+"\\Chrome.db")
        cursor = con.cursor()
        dbcursor = dbcon.cursor()
        
        dbcursor.execute("CREATE TABLE Cookies_DB(creation_utc text, host_key text, name text, value text, path text, expires_utc text, secure text, httponly text, last_access_utc text, has_expires text, persistent text, priority text, encrypted_value text, firstpartyonly text)")
        for row in cursor.execute("SELECT * from cookies") :
            dbcursor.execute("INSERT INTO Cookies_DB VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (row[0], row[1], row[2], row[3], row[4], row[5], row[6], row[7], row[8], row[9], row[10], row[11], row[12], row[13]))
            
        dbcon.commit()
        con.close()
    
    def Favicons(self):
        """
        Favicons_origin_md5 = hashlib.md5(open("C:\\Users\%s\AppData\\Local\\Google\\Chrome\\User Data\\Default"%username+"\\Favicons", 'rb').read()).hexdigest()
        Favicons_copy_md5 = hashlib.md5(open("C:\\Users\%s\Desktop\\Chrome WebCache "%username+"%s"%timestamp+"\\Favicons.db", 'rb').read()).hexdigest()
        
        if Favicons_origin_md5 == Favicons_copy_md5:
            print "------------------------------------------------------------------------"
            print "\t\t\tFavicons.db Hash Matched!"
            print "Favicons.db Orginal File Hash : " + "%s"%Favicons_origin_md5
            print "Favicons.db  Copied File Hash : " + "%s"%Favicons_copy_md5
            print "------------------------------------------------------------------------"
        else:
            print "Wrong with file hash! Not matched..."
            print "Module going to be TERMINATE.."
            def TERMINATE(n):
                while n > 0:
                    print (n)
                    n = n - 1
                
                sys.exit()
                SystemExit
            TERMINATE(5)
        """    
        con = sqlite3.connect(self.dname+"\\collection\\Chrome\\Favicons.db")
        dbcon = sqlite3.connect(self.dname+"\\Chrome.db")
        cursor = con.cursor()
        dbcursor = dbcon.cursor()
        
        dbcursor.execute("CREATE TABLE Favicons_DB(id text, url text, icon_type text)")
        
        for row in cursor.execute("SELECT * from favicons") :
            dbcursor.execute("INSERT INTO Favicons_DB VALUES (?,?,?)", (row[0],row[1],row[2]))
            
        dbcon.commit()
        con.close()
    
    def History(self):
        """
        History_origin_md5 = hashlib.md5(open("C:\\Users\%s\AppData\\Local\\Google\\Chrome\\User Data\\Default"%username+"\\History", 'rb').read()).hexdigest()
        History_copy_md5 = hashlib.md5(open("C:\\Users\%s\Desktop\\Chrome WebCache "%username+"%s"%timestamp+"\\History.db", 'rb').read()).hexdigest()
        
        if History_origin_md5 == History_copy_md5:
            print "------------------------------------------------------------------------"
            print "\t\t\tHistory.db Hash Matched!"
            print "History.db Orginal File Hash : " + "%s"%History_origin_md5
            print "History.db  Copied File Hash : " + "%s"%History_copy_md5
            print "------------------------------------------------------------------------"
        else:
            print "Wrong with file hash! Not matched..."
            print "Module going to be TERMINATE.."
            def TERMINATE(n):
                while n > 0:
                    print (n)
                    n = n - 1
                    
                sys.exit()
                SystemExit
            TERMINATE(5)
        """    
        con = sqlite3.connect(self.dname+"\\collection\\Chrome\\History.db")
        dbcon = sqlite3.connect(self.dname+"\\Chrome.db")
        cursor = con.cursor()
        dbcursor = dbcon.cursor()
        
        dbcursor.execute("CREATE TABLE History_downloads_DB(id text, current_path text, target_path text, start_time text, received_bytes text, total_bytes text, state text, danger_type text, interrupt_reason text, end_time text, opened text, referrer text, by_ext_id text, by_ext_name text, etag text, last_modified text, mime_type text, original_mime_type text)")
        for row in cursor.execute("SELECT * from downloads"):
            dbcursor.execute("INSERT INTO History_downloads_DB VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (row[0],row[1],row[2],row[3],row[4],row[5],row[6],row[7],row[8],row[9],row[10],row[11],row[12],row[13],row[14],row[15],row[16],row[17]))
            
        dbcursor.execute("CREATE TABLE History_keyword_DB(keyword_id text, url_id text, lower_term text, term text)")
        for row in cursor.execute("SELECT * from keyword_search_terms"):
            dbcursor.execute("INSERT INTO History_keyword_DB VALUES (?,?,?,?)", (row[0],row[1],row[2],row[3]))
            
        dbcursor.execute("CREATE TABLE History_url_DB(id text, url text, title text, visit_count text, typed_count text, last_visit_time text, hidden text, favicon_id text)")
        for row in cursor.execute("SELECT * from urls") :
            dbcursor.execute("INSERT INTO History_url_DB VALUES (?,?,?,?,?,?,?,?)", (row[0], row[1], row[2], row[3], row[4], row[5], row[6], row[7]))
        
        dbcon.commit()
        con.close()
    
    def Login_Data(self):
        """
        Login_Data_origin_md5 = hashlib.md5(open("C:\\Users\%s\AppData\\Local\\Google\\Chrome\\User Data\\Default"%username+"\\Login Data", 'rb').read()).hexdigest()
        Login_Data_copy_md5 = hashlib.md5(open("C:\\Users\%s\Desktop\\Chrome WebCache "%username+"%s"%timestamp+"\\Login Data.db", 'rb').read()).hexdigest()
        
        if Login_Data_origin_md5 == Login_Data_copy_md5:
            print "------------------------------------------------------------------------"
            print "\t\t\tLogin Data.db Hash Matched!"
            print "Login Data.db Orginal File Hash : " + "%s"%Login_Data_origin_md5
            print "Login Data.db  Copied File Hash : " + "%s"%Login_Data_copy_md5
            print "------------------------------------------------------------------------"
        else:
            print "Wrong with file hash! Not matched..."
            print "Module going to be TERMINATE.."
            def TERMINATE(n):
                while n > 0:
                    print (n)
                    n = n - 1
                    
                sys.exit()
                SystemExit
            TERMINATE(5)
        """    
        con = sqlite3.connect(self.dname+"\\collection\\Chrome\\Login Data.db")
        dbcon = sqlite3.connect(self.dname+"\\Chrome.db")
        cursor = con.cursor()
        dbcursor = dbcon.cursor()
        
        dbcursor.execute("CREATE TABLE Login_Data(origin_url text, action_url text, username_element text, username_value text, password_element text, password_value text, submit_element text, signon_realm text, ssl_valid text, preferred text, date_created text, blacklisted_by_user text, scheme text, password_type text, possible_usernames text, times_used text, form_data text, date_synced text, display_name text, icon_url text, federation_url text, skip_zero_click text, generation_upload_status text)")
        for row in cursor.execute("SELECT * from logins"):
            dbcursor.execute("INSERT INTO Login_Data VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (row[0],row[1],row[2],row[3],row[4],row[5],row[6],row[7],row[8],row[9],row[10],row[11],row[12],row[13],row[14],row[15],row[16],row[17],row[18],row[19],row[20],row[21],row[22]))
            
        dbcon.commit()
        con.close()
    
    def Network_Action_Predictor(self):
        """
        Network_Action_Predictor_origin_md5 = hashlib.md5(open("C:\\Users\%s\AppData\\Local\\Google\\Chrome\\User Data\\Default"%username+"\\Network Action Predictor", 'rb').read()).hexdigest()
        Network_Action_Predictor_copy_md5 = hashlib.md5(open("C:\\Users\%s\Desktop\\Chrome WebCache "%username+"%s"%timestamp+"\\Network Action Predictor.db", 'rb').read()).hexdigest()
        
        if Network_Action_Predictor_origin_md5 == Network_Action_Predictor_copy_md5:
            print "------------------------------------------------------------------------"
            print "\t\t\tNetwork Action Predictor.db Hash Matched!"
            print "Network Action Predictor.db Orginal File Hash : " + "%s"%Network_Action_Predictor_origin_md5
            print "Network Action Predictor.db Copied File Hash  : " + "%s"%Network_Action_Predictor_copy_md5
            print "------------------------------------------------------------------------"
        else:
            print "Wrong with file hash! Not matched..."
            print "Module going to be TERMINATE.."
            def TERMINATE(n):
                while n > 0:
                    print (n)
                    n = n - 1
                    
                sys.exit()
                SystemExit
            TERMINATE(5)
        """    
        con = sqlite3.connect(self.dname+"\\collection\\Chrome\\Network Action Predictor.db")
        dbcon = sqlite3.connect(self.dname+"\\Chrome.db")
        cursor = con.cursor()
        dbcursor = dbcon.cursor()
        
        dbcursor.execute("CREATE TABLE Network_Action_Predictor(id text, user_text text, url text, number_of_hits text, number_of_misses text)")
        for row in cursor.execute("SELECT * from network_action_predictor"):
            dbcursor.execute("INSERT INTO Network_Action_Predictor VALUES (?,?,?,?,?)", (row[0],row[1],row[2],row[3],row[4]))
            
        dbcon.commit()
        con.close()
    
    def Origin_Bound_Certs(self):
        """
        Origin_Bound_Certs_origin_md5 = hashlib.md5(open("C:\\Users\%s\AppData\\Local\\Google\\Chrome\\User Data\\Default"%username+"\\Origin Bound Certs", 'rb').read()).hexdigest()
        Origin_Bound_Certs_copy_md5 = hashlib.md5(open("C:\\Users\%s\Desktop\\Chrome WebCache "%username+"%s"%timestamp+"\\Origin Bound Certs.db", 'rb').read()).hexdigest()
        
        if Origin_Bound_Certs_origin_md5 == Origin_Bound_Certs_copy_md5:
            print "------------------------------------------------------------------------"
            print "\t\t\tOrigin Bound Certs.db Hash Matched!"
            print "Origin Bound Certs.db Orginal File Hash : " + "%s"%Origin_Bound_Certs_origin_md5
            print "Origin Bound Certs.db Copied File Hash  : " + "%s"%Origin_Bound_Certs_copy_md5
            print "------------------------------------------------------------------------"
        else:
            print "Wrong with file hash! Not matched..."
            print "Module going to be TERMINATE.."
            def TERMINATE(n):
                while n > 0:
                    print (n)
                    n = n - 1
                    
                sys.exit()
                SystemExit
            TERMINATE(5)
        """    
        con = sqlite3.connect(self.dname+"\\collection\\Chrome\\Origin Bound Certs.db")
        dbcon = sqlite3.connect(self.dname+"\\Chrome.db")
        cursor = con.cursor()
        dbcursor = dbcon.cursor()
        
        dbcursor.execute("CREATE TABLE Origin_Bound_Certs_channel_id(host text, private_key text, public_key text, creation_time text)")
        for row in cursor.execute("SELECT * from channel_id"):
            dbcursor.execute("INSERT INTO Origin_Bound_Certs_channel_id VALUES (?,?,?,?)", (row[0],row[1],row[2],row[3]))
            
        dbcon.commit()
        con.close()

    def Shortcuts(self):
        """
        Shortcuts_origin_md5 = hashlib.md5(open("C:\\Users\%s\AppData\\Local\\Google\\Chrome\\User Data\\Default"%username+"\\Shortcuts", 'rb').read()).hexdigest()
        Shortcuts_copy_md5 = hashlib.md5(open("C:\\Users\%s\Desktop\\Chrome WebCache "%username+"%s"%timestamp+"\\Shortcuts.db", 'rb').read()).hexdigest()
        
        if Shortcuts_origin_md5 == Shortcuts_copy_md5:
            print "------------------------------------------------------------------------"
            print "\t\t\tShortcuts.db Hash Matched!"
            print "Shortcuts.db Orginal File Hash : " + "%s"%Shortcuts_origin_md5
            print "Shortcuts.db Copied File Hash  : " + "%s"%Shortcuts_copy_md5
            print "------------------------------------------------------------------------"
        else:
            print "Wrong with file hash! Not matched..."
            print "Module going to be TERMINATE.."
            def TERMINATE(n):
                while n > 0:
                    print (n)
                    n = n - 1
                    
                sys.exit()
                SystemExit
            TERMINATE(5)
        """    
        con = sqlite3.connect(self.dname+"\\collection\\Chrome\\Shortcuts.db")
        dbcon = sqlite3.connect(self.dname+"\\Chrome.db")
        cursor = con.cursor()
        dbcursor = dbcon.cursor()
        
        dbcursor.execute("CREATE TABLE Shortcuts_omni_box_shortcuts(id text, text text, fill_into_edit text, url text, contents text, contents_class text, description text, description_class text, transition text, type text, keyword text, last_access_time text, number_of_hits text)")
        for row in cursor.execute("SELECT * from omni_box_shortcuts"):
            dbcursor.execute("INSERT INTO Shortcuts_omni_box_shortcuts VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", (row[0],row[1],row[2],row[3],row[4],row[5],row[6],row[7],row[8],row[9],row[10],row[11],row[12]))
            
        dbcon.commit()
        con.close()

    def Top_Sites(self):
        """
        Top_Sites_origin_md5 = hashlib.md5(open("C:\\Users\%s\AppData\\Local\\Google\\Chrome\\User Data\\Default"%username+"\\Top Sites", 'rb').read()).hexdigest()
        Top_Sites_copy_md5 = hashlib.md5(open("C:\\Users\%s\Desktop\\Chrome WebCache "%username+"%s"%timestamp+"\\Top_Sites.db", 'rb').read()).hexdigest()
        
        if Top_Sites_origin_md5 == Top_Sites_copy_md5:
            print "------------------------------------------------------------------------"
            print "\t\t\tTop Sites.db Hash Matched!"
            print "Top Sites.db Orginal File Hash : " + "%s"%Top_Sites_origin_md5
            print "Top Sites.db Copied File Hash  : " + "%s"%Top_Sites_copy_md5
            print "------------------------------------------------------------------------"
        else:
            print "Wrong with file hash! Not matched..."
            print "Module going to be TERMINATE.."
            def TERMINATE(n):
                while n > 0:
                    print (n)
                    n = n - 1
                    
                sys.exit()
                SystemExit
            TERMINATE(5)
        """    
        con = sqlite3.connect(self.dname+"\\collection\\Chrome\\Top Sites.db")
        dbcon = sqlite3.connect(self.dname+"\\Chrome.db")
        cursor = con.cursor()
        dbcursor = dbcon.cursor()
        
        dbcursor.execute("CREATE TABLE Top_Sites_thumbnails(url text, url_rank text, title text, thumbnail text, redirects text, boring_score text, good_clipping text, at_top text, last_updated text, load_completed text, last_forced text)")
        for row in cursor.execute("SELECT * from thumbnails"):
            dbcursor.execute("INSERT INTO Top_Sites_thumbnails VALUES (?,?,?,?,?,?,?,?,?,?,?)", (row[0],row[1],row[2],row[3],row[4],row[5],row[6],row[7],row[8],row[9],row[10]))
            
        dbcon.commit()
        con.close()
    
    def Web_Data(self):
        """
        Web_Data_origin_md5 = hashlib.md5(open("C:\\Users\%s\AppData\\Local\\Google\\Chrome\\User Data\\Default"%username+"\\Web Data", 'rb').read()).hexdigest()
        Web_Data_copy_md5 = hashlib.md5(open("C:\\Users\%s\Desktop\\Chrome WebCache "%username+"%s"%timestamp+"\\Web Data.db", 'rb').read()).hexdigest()
        
        if Web_Data_origin_md5 == Web_Data_copy_md5:
            print "------------------------------------------------------------------------"
            print "\t\t\tWeb Data.db Hash Matched!"
            print "Web Data.db Orginal File Hash : " + "%s"%Web_Data_origin_md5
            print "Web Data.db  Copied File Hash : " + "%s"%Web_Data_copy_md5
            print "------------------------------------------------------------------------"
        else:
            print "Wrong with file hash! Not matched..."
            print "Module going to be TERMINATE.."
            def TERMINATE(n):
                while n > 0:
                    print (n)
                    n = n - 1
                    
                sys.exit()
                SystemExit
            TERMINATE(5)
        """    
        con = sqlite3.connect(self.dname+"\\collection\\Chrome\\Web Data.db")
        dbcon = sqlite3.connect(self.dname+"\\Chrome.db")
        cursor = con.cursor()
        dbcursor = dbcon.cursor()
        
        dbcursor.execute("CREATE TABLE Web_Data_autofill_DB(name text, value text, value_lower text, date_created text, date_last_used text, count text)")
        for row in cursor.execute("SELECT * from autofill") :
            dbcursor.execute("INSERT INTO Web_Data_autofill_DB VALUES (?,?,?,?,?,?)", (row[0], row[1], row[2], row[3], row[4], row[5]))
        
        dbcon.commit()
        con.close()

    def Extension_Cookies(self):
        """
        Extension_Cookies_origin_md5 = hashlib.md5(open("C:\\Users\%s\AppData\\Local\\Google\\Chrome\\User Data\\Default"%username+"\\Extension Cookies", 'rb').read()).hexdigest()
        Extension_Cookies_copy_md5 = hashlib.md5(open("C:\\Users\%s\Desktop\\Chrome WebCache "%username+"%s"%timestamp+"\\Extension Cookies.db", 'rb').read()).hexdigest()
        
        if Extension_Cookies_origin_md5 == Extension_Cookies_copy_md5:
            print "------------------------------------------------------------------------"
            print "\t\t\tExtension_Cookies.db Hash Matched!"
            print "Extension Cookies.db Orginal File Hash : " + "%s"%Extension_Cookies_origin_md5
            print "Extension Cookies.db Copied File Hash  : " + "%s"%Extension_Cookies_copy_md5
            print "------------------------------------------------------------------------"
        else:
            print "Wrong with file hash! Not matched..."
            print "Module going to be TERMINATE.."
            def TERMINATE(n):
                while n > 0:
                    print (n)
                    n = n - 1
                    
                sys.exit()
                SystemExit
            TERMINATE(5)
        """    
        con = sqlite3.connect(self.dname+"\\collection\\Chrome\\Extension Cookies.db")
        dbcon = sqlite3.connect(self.dname+"\\Chrome.db")
        cursor = con.cursor()
        dbcursor = dbcon.cursor()
        
        dbcursor.execute("CREATE TABLE Extension_Cookies_cookies(creation_utc text, host_key text, name text, value text, path text, expires_utc text, secure text, httponly text, last_access_utc text, has_expires text, persistent text, priority text, encrypted_value text, firstpartyonly text)")
        for row in cursor.execute("SELECT * from cookies"):
            dbcursor.execute("INSERT INTO Extension_Cookies_cookies VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (row[0],row[1],row[2],row[3],row[4],row[5], row[6], row[7],row[8],row[9],row[10],row[11],row[12],row[13]))
            
        dbcon.commit()
        con.close()

#################
def TimeConverter(time, gmt):
    if time==0:
        return 0
    time = str(time)
    time = time + "00"
    time = int(time)
    nanoseconds = time
    seconds, nanoseconds = divmod(nanoseconds, 1000000000)
    days, seconds = divmod(seconds, 86400)
    return datetime(1601, 1, 1) + timedelta(days, seconds, nanoseconds) + timedelta(hours=gmt)

def index_TimeConverter(time, gmt):
    if time==0:
        return 0
    value = datetime.fromtimestamp(int(time)) + timedelta(hours=gmt)
    return(value.strftime('%Y-%m-%d %H:%M:%S'))

def Chrome_TimeConverter(time, gmt):
    if time==0:
        return 0
    if len(time) == 18:
        return "-"
    microseconds = int(time)
    seconds, microseconds = divmod(microseconds, 1000000)
    days, seconds = divmod(seconds, 86400)
    return datetime(1601, 1, 1) + timedelta(days, seconds, microseconds) + timedelta(hours=gmt)

def UWA_Parser(fname, gmt):
    print gmt
    if os.path.isfile(fname+"\\Integrated_DB.db"):
        os.remove(fname+"\\Integrated_DB.db")

    i_db = sqlite3.connect(fname+"\\Integrated_DB.db")
    i_cursor = i_db.cursor()
    i_cursor.execute('CREATE TABLE Cookies(Browser text, URL text, FileName text, Value text, CreationTime text, LastAccessTime text, ExpiryTime text, Path text)')
    i_cursor.execute('CREATE TABLE Cache(Browser text, URL text, FileName text, FileSize text, CreationTime text, LastAccessTime text, ExpiryTime text, Path text)')
    i_cursor.execute('CREATE TABLE History(Browser text, URL text, VisitCount text, LastVisitTime text)')
    i_cursor.execute('CREATE TABLE DownList(Browser text, URL text, FileName text, FileSize text, DownloadTime text, Path text)')

    wc_db = sqlite3.connect(fname+"\\WC_DB.db")
    wc_cursor = wc_db.cursor()

    container_list = []

    #WC_Containers에 접근해 WC_Container_X의 번호와 기능을 매치시킴
    for container in wc_cursor.execute('SELECT `_rowid_`,* FROM `WC_Containers`  ORDER BY `_rowid_`'):
        container_list.append((container[1], container[9].replace('\x00', '').lower()))


    for container in container_list:
        container_num = container[0]
        container_name = container[1]

        if(container_name == "cookies"):
            for row in wc_cursor.execute('SELECT `_rowid_`,* FROM `WC_Container_%s`  ORDER BY `_rowid_`'% container_num):
                i_cursor.execute("INSERT INTO Cookies VALUES (?, ?, ?, ?, ?, ?, ?, ?)", ("WebCache", row[18], row[19],  None, TimeConverter(row[11], gmt), TimeConverter(row[14], gmt), TimeConverter(row[12], gmt), None))

        if(container_name == "content"):
            for row in wc_cursor.execute('SELECT `_rowid_`,* FROM `WC_Container_%s`  ORDER BY `_rowid_`'% container_num):
                i_cursor.execute("INSERT INTO Cache VALUES (?, ?, ?, ?, ?, ?, ?, ?)", ("WebCache", row[18], row[19], row[6], TimeConverter(row[11], gmt), TimeConverter(row[14], gmt), TimeConverter(row[13], gmt), None))

        if(container_name == "history"):
            for row in wc_cursor.execute('SELECT `_rowid_`,* FROM `WC_Container_%s`  ORDER BY `_rowid_`'% container_num):
                i_cursor.execute("INSERT INTO History VALUES (?, ?, ?, ?)", ("WebCache", row[18], row[9], TimeConverter(row[14], gmt)))

        if(container_name == "iedownload"):
            for row in wc_cursor.execute('SELECT `_rowid_`,* FROM `WC_Container_%s`  ORDER BY `_rowid_`'% container_num):
                i_cursor.execute("INSERT INTO DownList VALUES (?, ?, ?, ?, ?, ?)", ("WebCache", row[18], row[19], row[6], TimeConverter(row[14], gmt), None))

    #index.dat
    index_db = sqlite3.connect(fname+"\\IE9parser.db")
    index_cursor = index_db.cursor()

    index_cursor.execute("SELECT name FROM sqlite_master WHERE type IN ('table', 'view') AND name NOT LIKE 'sqlite_%' UNION ALL SELECT name FROM sqlite_temp_master WHERE type IN ('table', 'view') ORDER BY 1")
    name = index_cursor.fetchall()
    num = 0
    tablename = {}

    for i in name:
        tablename[num] = i
        num = num+1
        for tablenamelist in i:
            if tablenamelist == 'Cookies':
                for row in index_cursor.execute('SELECT `_rowid_`,* FROM `Cookies`  ORDER BY `_rowid_`'):
                    i_cursor.execute("INSERT INTO Cookies VALUES (?, ?, ?, ?, ?, ?, ?, ?)", ("index.dat", "".join(row[1].split('@')[1:]), None, None, row[3], row[2], None, None))
            elif tablenamelist == 'Cache':
                for row in index_cursor.execute('SELECT `_rowid_`,* FROM `Cache`  ORDER BY `_rowid_`'):
                    i_cursor.execute("INSERT INTO Cache VALUES (?, ?, ?, ?, ?, ?, ?, ?)", ("index.dat", row[1], None, None, row[3], row[2], None, None))
            elif tablenamelist == 'History':
                for row in index_cursor.execute('SELECT `_rowid_`,* FROM `History`  ORDER BY `_rowid_`'):
                    i_cursor.execute("INSERT INTO History VALUES (?, ?, ?, ?)", ("index.dat", "".join(row[1].split('@')[1:]), None, row[2]))
            elif tablenamelist == 'Downlist':
                for row in index_cursor.execute('SELECT `_rowid_`,* FROM `Downlist`  ORDER BY `_rowid_`'):
                    i_cursor.execute("INSERT INTO Downlist VALUES (?, ?, ?, ?, ?, ?)", ("index.dat", row[1], None, row[3], row[2], None))


    chrome_db = sqlite3.connect(fname+"\\Chrome.db")
    chrome_cursor = chrome_db.cursor()

    for row in chrome_cursor.execute('SELECT `_rowid_`,* FROM `History_url_DB`  ORDER BY `_rowid_`'):
        i_cursor.execute("INSERT INTO History VALUES (?, ?, ?, ?)", ("Chrome", row[2], row[4], Chrome_TimeConverter(str(row[6]), gmt)))

    for row in chrome_cursor.execute('SELECT `_rowid_`,* FROM `Cookies_DB`  ORDER BY `_rowid_`'):
        i_cursor.execute("INSERT INTO Cookies VALUES (?, ?, ?, ?, ?, ?, ?, ?)", ("Chrome", row[2]+row[5], row[3], row[4], Chrome_TimeConverter(str(row[1]), gmt), Chrome_TimeConverter(str(row[9]), gmt), Chrome_TimeConverter(str(row[6]), gmt), row[5]))

    i_db.commit()
    i_db.close()

class WC_Data_Insert():
    def __init__(self, fname):
        self.dname = fname
        self.fname = '%s'%fname+"\\collection\\IE10++\\WebCacheV01.dat"

        ese = ESENT_DB(self.fname)
        if os.path.isfile(self.dname+"\\WC_DB.db"):
            os.remove(self.dname+"\\WC_DB.db")
            conn = sqlite3.connect(self.dname+"\\WC_DB.db")
        else:
            conn = sqlite3.connect(self.dname+"\\WC_DB.db")
        cursor = conn.cursor()
        num = 0
        data = {}
        tablename = {}
        tablename = ese.printCatalog()

        for i in tablename:
            Data_table = ese.openTable(tablename[i])
            Container_ = tablename[i].find("Container_")
            if Container_ >= 0:
                cursor.execute("CREATE TABLE WC_"+tablename[i]+"(EntryId text, ContainerId text, CacheId text, UrlHash text, SecureDirectory text, FileSize text, Type text, Flags text, AccessCount text, SyncTime text, CreationTime text, ExpiryTime text, ModifiedTime text, AccessedTime text, PostCheckTime text, SyncCount text, ExemptionDelta text, Url text, Filename text, FileExtension text, RequestHeaders text, ResponseHeaders text, RedirectUrl text, Groupp text, ExtraData text)")
                while True:
                    record = ese.getNextRow(Data_table)
                    if record is None:
                        break
                    for j in record:
                        data[num] = record[j]
                        num=num+1
                        if num==25:
                            string.strip(data[17], "\00")
                            cursor.execute("INSERT INTO WC_"+tablename[i]+" VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7], data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15], data[16], data[17], data[18], data[19], data[20], data[21], data[22], data[23], data[24]))
                            num=0
                            break;
            DependencyEntry_ = tablename[i].find("DependencyEntry_")
            if DependencyEntry_ >= 0:
                cursor.execute("CREATE TABLE WC_"+tablename[i]+"(EntryId text, UrlSchemaType text, Port text, ModifiedTime text, Url text, Data text, HostName text)")
                while True:
                    record = ese.getNextRow(Data_table)
                    if record is None:
                        break
                    for j in record:
                        data[num] = record[j]
                        num=num+1
                        if num==7:
                            string.strip(data[4], "\00")
                            cursor.execute("INSERT INTO WC_"+tablename[i]+" VALUES (?, ?, ?, ?, ?, ?, ?)", (data[0], data[1], data[2], data[3], data[4], data[5], data[6]))
                            num=0
                            break;
            AppCache_ = tablename[i].find("AppCache_")
            if AppCache_ >= 0:
                cursor.execute("CREATE TABLE WC_"+tablename[i]+"(AppCacheId text, UrlHash text, State text, AccessTime text, Size text, Url text, Filename text, ParsedData text)")
                while True:
                    record = ese.getNextRow(Data_table)
                    if record is None:
                        break
                    for j in record:
                        data[num] = record[j]
                        num=num+1
                        if num==8:
                            string.strip(data[5], "\00")
                            cursor.execute("INSERT INTO WC_"+tablename[i]+" VALUES (?, ?, ?, ?, ?, ?, ?, ?)", (data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7]))
                            num=0
                            break;
            HstsEntry_ = tablename[i].find("HstsEntry_")
            if HstsEntry_ >= 0:
                cursor.execute("CREATE TABLE WC_"+tablename[i]+"(EntryId text, MinimizedRDomainHash text, MinimizedRDomainLength text, IncludeSubdomains text, Expires text, LastTimeUsed text, RDomain text)")
                while True:
                    record = ese.getNextRow(Data_table)
                    if record is None:
                        break
                    for j in record:
                        data[num] = record[j]
                        num=num+1
                        if num==7:
                            cursor.execute("INSERT INTO WC_"+tablename[i]+" VALUES (?, ?, ?, ?, ?, ?, ?)", (data[0], data[1], data[2], data[3], data[4], data[5], data[6]))
                            num=0
                            break;
            AppCacheEntry_ = tablename[i].find("AppCacheEntry_")
            if AppCacheEntry_ >= 0:
                cursor.execute("CREATE TABLE WC_"+tablename[i]+"(EntryId text, AppCacheId text, UrlHash text, Flags text, Master text, ExpiryTime text, ModifiedTime text, PostCheckTime text, Type text, FileSize text, Url text, RequestHeaders text, ResponseHeaders text, Filename text, ExtraData text)")
                while True:
                    record = ese.getNextRow(Data_table)
                    if record is None:
                        break
                    for j in record:
                        data[num] = record[j]
                        num=num+1
                        if num==10:
                            string.strip(data[10], "\00")
                            cursor.execute("INSERT INTO WC_"+tablename[i]+" VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7], data[8], data[9], data[10], data[11], data[12], data[13], data[14]))
                            num=0
                            break;
            elif tablename[i] == "MSysObjects":
                cursor.execute("CREATE TABLE WC_MSysObjects(ObjidTable text, Type text, Id text, ColtypOrPgnoFDP text, SpaceUsage text, Flags text, PagesOrLocale text, RootFlag text, RecordOffset text, LCMapFlags text, KeyMost text, Name text, Stats text, TemplateTable text, DefaultValue text, KeyFldIDs text, VarSegMac text, ConditionalColumns text, TupleLimits text, Version text, CallbackData text, CallbackDependencies text, SeparateLV text, SpaceHints text, SpaceDeferredLVHints text)")
                while True:
                    record = ese.getNextRow(Data_table)
                    if record is None:
                        break
                    for j in record:
                        data[num] = record[j]
                        num=num+1
                        if num==25:
                            cursor.execute("INSERT INTO WC_MSysObjects VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7], data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15], data[16], data[17], data[18], data[19], data[20], data[21], data[22], data[23], data[24]))
                            num=0
                            break;
            elif tablename[i] == "MSysObjectsShadow":
                cursor.execute("CREATE TABLE WC_MSysObjectsShadow(ObjidTable text, Type text, Id text, ColtypOrPgnoFDP text, SpaceUsage text, Flags text, PagesOrLocale text, RootFlag text, RecordOffset text, LCMapFlags text, KeyMost text, Name text, Stats text, TemplateTable text, DefaultValue text, KeyFldIDs text, VarSegMac text, ConditionalColumns text, TupleLimits text, Version text, CallbackData text, CallbackDependencies text, SeparateLV text, SpaceHints text, SpaceDeferredLVHints text)")
                while True:
                    record = ese.getNextRow(Data_table)
                    if record is None:
                        break
                    for j in record:
                        data[num] = record[j]
                        num=num+1
                        if num==25:
                            cursor.execute("INSERT INTO WC_MSysObjectsShadow VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7], data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15], data[16], data[17], data[18], data[19], data[20], data[21], data[22], data[23], data[24]))
                            num=0
                            break;
            elif tablename[i] == "MSysUnicodeFixupVer2":
                cursor.execute("CREATE TABLE WC_MSysUnicodeFixupVer2(autoinc text, objidTable text, objidIndex text, keyPrimary text, keySecondary text, lcid text, sortVersion text, definedVersion text, rgitag text, ichOffset text)")
                while True:
                    record = ese.getNextRow(Data_table)
                    if record is None:
                        break
                    for j in record:
                        data[num] = record[j]
                        num=num+1
                        if num==10:
                            cursor.execute("INSERT INTO WC_MSysUnicodeFixupVer2 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7], data[8], data[9]))
                            num=0
                            break;
            elif tablename[i] == "LeakFiles":
                cursor.execute("CREATE TABLE WC_LeakFiles(LeakId text, CreationTime text, Filename text)")
                while True:
                    record = ese.getNextRow(Data_table)
                    if record is None:
                        break
                    for j in record:
                        data[num] = record[j]
                        num=num+1
                        if num==3:
                            cursor.execute("INSERT INTO WC_LeakFiles VALUES (?, ?, ?)", (data[0], data[1], data[2]))
                            num=0
                            break;
            elif tablename[i] == "Partitions":
                cursor.execute("CREATE TABLE WC_Partitions(TableId text, PartitionType text, SetId text, LastScavengeTime text, PartitionId text, Directory text)")
                while True:
                    record = ese.getNextRow(Data_table)
                    if record is None:
                        break
                    for j in record:
                        data[num] = record[j]
                        num=num+1
                        if num==6:
                            cursor.execute("INSERT INTO WC_Partitions VALUES (?, ?, ?, ?, ?, ?)", (data[0], data[1], data[2], data[3], data[4], data[5]))
                            num=0
                            break;
            elif tablename[i] == "Containers":
                cursor.execute("CREATE TABLE WC_Containers(ContainerId text, SetId text, Flags text, Size text, Limitt text, LastScavengeTime text, EntryMaxAge text, LastAccessTime text, Name text, PartitionId text, Directory text, SecureDirectories text, SecureUsage text, Groupp text)")
                while True:
                    record = ese.getNextRow(Data_table)
                    if record is None:
                        break
                    for j in record:
                        data[num] = record[j]
                        num=num+1
                        if num==14:
                            cursor.execute("INSERT INTO WC_Containers VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7], data[8], data[9], data[10], data[11], data[12], data[13]))
                            num=0
                            break;
        conn.commit()
        conn.close()
        ese.close()

    def WindowTimeConverter(self, WC_time):
        dt = str(WC_time)
        us = int(dt,16) / 10.
        return (datetime(1601,1,1) + timedelta(microseconds=us))

class WC_Containers_Parser():
    def __init__(self, fname):
        self.fname = fname

        conn = sqlite3.connect("WC_db.db")
        cursor = conn.cursor()
        cursor.execute("CREATE TABLE WC_Containers(ContainerId integer, SetId integer, Flags integer, Size integer, Limitt integer, LastScavengeTime integer, EntryMaxAge integer, LastAccessTime integer, Name text, PartitionId text, Directory text, SecureDirectories text, SecureUsage blob, Groupp blob)")
        
        ese = ESENT_DB(self.fname)
        containers_table = ese.openTable("Containers")

        data = {}
        num = 0
        if containers_table is None:
            return
        while True:
            record = ese.getNextRow(containers_table)
            if record is None:
                break
            for i in record:
                data[num] = record[i]
                num=num+1
                if i=="Group":
                    cursor.execute("INSERT INTO WC_Containers VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7], data[8], data[9], data[10], data[11], data[12], data[13]))
                    
        conn.commit()
        conn.close()
        ese.close()

class WC_Data_Parser():
    def __init__(self, fname):
        self.fname = fname

        ese = ESENT_DB(self.fname)
        conn = sqlite3.connect("WC_DB.db")
        cursor = conn.cursor()
        num = 0
        data = {}
        tablename = {}
        tablename = ese.printCatalog()

        conn.commit()
        conn.close()
        ese.close()

class SearchKey_Parser():
    def __init__(self, fname):
        self.fname = fname
        print fname
        conn = sqlite3.connect(self.fname+"\\Integrated_DB.db")
        cursor = conn.cursor()

        cursor.execute("SELECT name FROM sqlite_master WHERE type IN ('table', 'view') AND name NOT LIKE 'sqlite_%' UNION ALL SELECT name FROM sqlite_temp_master WHERE type IN ('table', 'view') ORDER BY 1")
        name = cursor.fetchall()
        num=0
        index = 0
        cunt = 0
        tablename = {}
        table_date = {}
        query_date = {}
        access_time = {}

        head_naver="search.naver.com/search.naver?" # key query =
        head_daum="search.daum.net/search?" # key = q
        head_google="www.google.co.kr/search?"  # key = q or oq
        head_nate="search.daum.net/nate?"   # key = q
        head_yahoo="search.yahoo.com/search;"   # key = p
        head_bing="www.bing.com/search?"    # key = q
        head_facebook="www.facebook.com/search/"    # group 내의 search는 search가 뒤에있음. key = q

        for i in name:
            tablename[num] = i
            num = num+1
            for tablenamelist in i:
                cursor.execute("select * from "+tablenamelist+"")
                if tablenamelist == 'Cache':
                    Urldata = cursor.fetchall()
                    #print Urldata
                    for temp in Urldata:
                        #if temp[1].find(head_nate) >= 0:
                        #    separate=temp[1].split('&')
                        #    for i in range(0,len(separate)):
                        #        if separate[i].find('q=') == 0:
                                    #keyword_nate = separate[i][6:]
                                    #query_date[index] = urllib.unquote(str(unicode(keyword_nate))).decode('utf8').replace('+',' ')
                                    #index = index+1
                                    #print urllib.unquote(str(unicode(keyword_nate))).decode('utf8').replace('+',' ')
                                    #print "key",urllib.unquote(str(unicode(keyword_naver))).decode('utf8')
                                    #print "s",urllib.unquote(keyword_naver).encode('utf-8').decode('utf-8').decode('utf-8').replace('+',' ')
                        #            break
                        if temp[1].find(head_yahoo) >= 0:
                            separate=temp[1].split('&')
                            for i in range(0,len(separate)):
                                if separate[i].find('p=') == 0:
                                    keyword_yahoo = separate[i][6:]
                                    query_date[index] = urllib.unquote(str(unicode(keyword_yahoo))).decode('utf8').replace('+',' ')
                                    access_time[index] = temp[5]
                                    index = index+1
                                    #print "key",urllib.unquote(str(unicode(keyword_naver))).decode('utf8')
                                    #print "s",urllib.unquote(keyword_naver).encode('utf-8').decode('utf-8').decode('utf-8').replace('+',' ')
                                    break
                        elif temp[1].find(head_bing) >= 0:
                            separate=temp[1].split('&')
                            for i in range(0,len(separate)):
                                if separate[i].find('q=') == 0:
                                    keyword_bing = separate[i][6:]
                                    query_date[index] = urllib.unquote(str(unicode(keyword_bing))).decode('utf8').replace('+',' ')
                                    access_time[index] = temp[5]
                                    index = index+1
                                    #print "key",urllib.unquote(str(unicode(keyword_naver))).decode('utf8')
                                    #print "s",urllib.unquote(keyword_naver).encode('utf-8').decode('utf-8').decode('utf-8').replace('+',' ')
                                    break
                        #elif temp[1].find(head_facebook) >= 0:
                        #    separate=temp[1].split('&')
                        #    for i in range(0,len(separate)):
                        #        if separate[i].find('q=') == 0:
                                    #keyword_facebook = separate[i][6:]
                                    #query_date[index] = urllib.unquote(str(unicode(keyword_facebook))).decode('utf8').replace('+',' ')
                                    #access_time[index] = temp[5]
                                    #index = index+1
                                    #print "key",urllib.unquote(str(unicode(keyword_naver))).decode('utf8')
                                    #print "s",urllib.unquote(keyword_naver).encode('utf-8').decode('utf-8').decode('utf-8').replace('+',' ')
                        #            break
                        elif temp[1].find(head_naver) >= 0:
                            separate=temp[1].split('&')
                            for i in range(0,len(separate)):
                                if separate[i].find('query=') == 0:
                                    keyword_naver = separate[i][6:]
                                    query_date[index] = urllib.unquote(str(unicode(keyword_naver))).decode('utf8').replace('+',' ')
                                    access_time[index] = temp[5]
                                    index = index+1
                                    #print "key",urllib.unquote(str(unicode(keyword_naver))).decode('utf8')
                                    #print "s",urllib.unquote(keyword_naver).encode('utf-8').decode('utf-8').decode('utf-8').replace('+',' ')
                                    break
                        elif temp[1].find(head_daum) >= 0:
                            separate=temp[1].split('&')
                            for i in range(0,len(separate)):
                                if separate[i].find('q=') == 0:
                                    keyword_daum = separate[i][2:]
                                    query_date[index] = urllib.unquote(str(unicode(keyword_daum))).decode('utf8').replace('+',' ')
                                    access_time[index] = temp[5]
                                    index = index+1
                                    break
                        elif temp[1].find(head_google) >= 0:
                            separate=temp[1].replace('?','&').split('&')
                            for i in range(len(separate)-1,0,-1):
                                if separate[i].find('q=')==0 & ~separate[i].find('oq='):
                                    keyword_google = separate[i][2:]
                                    query_date[index] = urllib.unquote(str(unicode(keyword_google))).decode('utf8').replace('+',' ')
                                    access_time[index] = temp[5]
                                    index = index+1
                                    break
                elif tablenamelist == 'Cookies':
                    Urldata = cursor.fetchall()
                    #print Urldata
                    for temp in Urldata:
                        #if temp[1].find(head_nate) >= 0:
                        #    separate=temp[1].split('&')
                        #    for i in range(0,len(separate)):
                        #        if separate[i].find('q=') == 0:
                                    #keyword_nate = separate[i][6:]
                                    #query_date[index] = urllib.unquote(str(unicode(keyword_nate))).decode('utf8').replace('+',' ')
                                    #index = index+1
                                    #print urllib.unquote(str(unicode(keyword_nate))).decode('utf8').replace('+',' ')
                                    #print "key",urllib.unquote(str(unicode(keyword_naver))).decode('utf8')
                                    #print "s",urllib.unquote(keyword_naver).encode('utf-8').decode('utf-8').decode('utf-8').replace('+',' ')
                        #            break
                        if temp[1].find(head_yahoo) >= 0:
                            separate=temp[1].split('&')
                            for i in range(0,len(separate)):
                                if separate[i].find('p=') == 0:
                                    keyword_yahoo = separate[i][6:]
                                    query_date[index] = urllib.unquote(str(unicode(keyword_yahoo))).decode('utf8').replace('+',' ')
                                    access_time[index] = temp[5]
                                    index = index+1
                                    #print "key",urllib.unquote(str(unicode(keyword_naver))).decode('utf8')
                                    #print "s",urllib.unquote(keyword_naver).encode('utf-8').decode('utf-8').decode('utf-8').replace('+',' ')
                                    break
                        elif temp[1].find(head_bing) >= 0:
                            separate=temp[1].split('&')
                            for i in range(0,len(separate)):
                                if separate[i].find('q=') == 0:
                                    keyword_bing = separate[i][6:]
                                    query_date[index] = urllib.unquote(str(unicode(keyword_bing))).decode('utf8').replace('+',' ')
                                    access_time[index] = temp[5]
                                    index = index+1
                                    #print "key",urllib.unquote(str(unicode(keyword_naver))).decode('utf8')
                                    #print "s",urllib.unquote(keyword_naver).encode('utf-8').decode('utf-8').decode('utf-8').replace('+',' ')
                                    break
                        #elif temp[1].find(head_facebook) >= 0:
                        #    separate=temp[1].split('&')
                        #    for i in range(0,len(separate)):
                        #        if separate[i].find('q=') == 0:
                                    #keyword_facebook = separate[i][6:]
                                    #query_date[index] = urllib.unquote(str(unicode(keyword_facebook))).decode('utf8').replace('+',' ')
                                    #access_time[index] = temp[5]
                                    #index = index+1
                                    #print "key",urllib.unquote(str(unicode(keyword_naver))).decode('utf8')
                                    #print "s",urllib.unquote(keyword_naver).encode('utf-8').decode('utf-8').decode('utf-8').replace('+',' ')
                        #            break
                        elif temp[1].find(head_naver) >= 0:
                            separate=temp[1].split('&')
                            for i in range(0,len(separate)):
                                if separate[i].find('query=') == 0:
                                    keyword_naver = separate[i][6:]
                                    query_date[index] = urllib.unquote(str(unicode(keyword_naver))).decode('utf8').replace('+',' ')
                                    access_time[index] = temp[5]
                                    index = index+1
                                    #print "key",urllib.unquote(str(unicode(keyword_naver))).decode('utf8')
                                    #print "s",urllib.unquote(keyword_naver).encode('utf-8').decode('utf-8').decode('utf-8').replace('+',' ')
                                    break
                        elif temp[1].find(head_daum) >= 0:
                            separate=temp[1].split('&')
                            for i in range(0,len(separate)):
                                if separate[i].find('q=') == 0:
                                    keyword_daum = separate[i][2:]
                                    query_date[index] = urllib.unquote(str(unicode(keyword_daum))).decode('utf8').replace('+',' ')
                                    access_time[index] = temp[5]
                                    index = index+1
                                    break
                        elif temp[1].find(head_google) >= 0:
                            separate=temp[1].replace('?','&').split('&')
                            for i in range(len(separate)-1,0,-1):
                                if separate[i].find('q=')==0 & ~separate[i].find('oq='):
                                    keyword_google = separate[i][2:]
                                    query_date[index] = urllib.unquote(str(unicode(keyword_google))).decode('utf8').replace('+',' ')
                                    access_time[index] = temp[5]
                                    index = index+1
                                    break
                elif tablenamelist == 'DownList':
                    Urldata = cursor.fetchall()
                    #print Urldata
                    for temp in Urldata:
                        #if temp[1].find(head_nate) >= 0:
                        #    separate=temp[1].split('&')
                        #    for i in range(0,len(separate)):
                        #        if separate[i].find('q=') == 0:
                                    #keyword_nate = separate[i][6:]
                                    #query_date[index] = urllib.unquote(str(unicode(keyword_nate))).decode('utf8').replace('+',' ')
                                    #index = index+1
                                    #print urllib.unquote(str(unicode(keyword_nate))).decode('utf8').replace('+',' ')
                                    #print "key",urllib.unquote(str(unicode(keyword_naver))).decode('utf8')
                                    #print "s",urllib.unquote(keyword_naver).encode('utf-8').decode('utf-8').decode('utf-8').replace('+',' ')
                        #            break
                        if temp[1].find(head_yahoo) >= 0:
                            separate=temp[1].split('&')
                            for i in range(0,len(separate)):
                                if separate[i].find('p=') == 0:
                                    keyword_yahoo = separate[i][6:]
                                    query_date[index] = urllib.unquote(str(unicode(keyword_yahoo))).decode('utf8').replace('+',' ')
                                    access_time[index] = temp[4]
                                    index = index+1
                                    #print "key",urllib.unquote(str(unicode(keyword_naver))).decode('utf8')
                                    #print "s",urllib.unquote(keyword_naver).encode('utf-8').decode('utf-8').decode('utf-8').replace('+',' ')
                                    break
                        elif temp[1].find(head_bing) >= 0:
                            separate=temp[1].split('&')
                            for i in range(0,len(separate)):
                                if separate[i].find('q=') == 0:
                                    keyword_bing = separate[i][6:]
                                    query_date[index] = urllib.unquote(str(unicode(keyword_bing))).decode('utf8').replace('+',' ')
                                    access_time[index] = temp[4]
                                    index = index+1
                                    #print "key",urllib.unquote(str(unicode(keyword_naver))).decode('utf8')
                                    #print "s",urllib.unquote(keyword_naver).encode('utf-8').decode('utf-8').decode('utf-8').replace('+',' ')
                                    break
                        #elif temp[1].find(head_facebook) >= 0:
                        #    separate=temp[1].split('&')
                        #    for i in range(0,len(separate)):
                        #        if separate[i].find('q=') == 0:
                                    #keyword_facebook = separate[i][6:]
                                    #query_date[index] = urllib.unquote(str(unicode(keyword_facebook))).decode('utf8').replace('+',' ')
                                    #access_time[index] = temp[5]
                                    #index = index+1
                                    #print "key",urllib.unquote(str(unicode(keyword_naver))).decode('utf8')
                                    #print "s",urllib.unquote(keyword_naver).encode('utf-8').decode('utf-8').decode('utf-8').replace('+',' ')
                        #            break
                        elif temp[1].find(head_naver) >= 0:
                            separate=temp[1].split('&')
                            for i in range(0,len(separate)):
                                if separate[i].find('query=') == 0:
                                    keyword_naver = separate[i][6:]
                                    query_date[index] = urllib.unquote(str(unicode(keyword_naver))).decode('utf8').replace('+',' ')
                                    access_time[index] = temp[4]
                                    index = index+1
                                    #print "key",urllib.unquote(str(unicode(keyword_naver))).decode('utf8')
                                    #print "s",urllib.unquote(keyword_naver).encode('utf-8').decode('utf-8').decode('utf-8').replace('+',' ')
                                    break
                        elif temp[1].find(head_daum) >= 0:
                            separate=temp[1].split('&')
                            for i in range(0,len(separate)):
                                if separate[i].find('q=') == 0:
                                    keyword_daum = separate[i][2:]
                                    query_date[index] = urllib.unquote(str(unicode(keyword_daum))).decode('utf8').replace('+',' ')
                                    access_time[index] = temp[4]
                                    index = index+1
                                    break
                        elif temp[1].find(head_google) >= 0:
                            separate=temp[1].replace('?','&').split('&')
                            for i in range(len(separate)-1,0,-1):
                                if separate[i].find('q=')==0 & ~separate[i].find('oq='):
                                    keyword_google = separate[i][2:]
                                    query_date[index] = urllib.unquote(str(unicode(keyword_google))).decode('utf8').replace('+',' ')
                                    access_time[index] = temp[4]
                                    index = index+1
                                    break
                elif tablenamelist == 'History':
                    Urldata = cursor.fetchall()
                    #print Urldata
                    for temp in Urldata:
                        #if temp[1].find(head_nate) >= 0:
                        #    separate=temp[1].split('&')
                        #    for i in range(0,len(separate)):
                        #        if separate[i].find('q=') == 0:
                                    #keyword_nate = separate[i][6:]
                                    #query_date[index] = urllib.unquote(str(unicode(keyword_nate))).decode('utf8').replace('+',' ')
                                    #index = index+1
                                    #print urllib.unquote(str(unicode(keyword_nate))).decode('utf8').replace('+',' ')
                                    #print "key",urllib.unquote(str(unicode(keyword_naver))).decode('utf8')
                                    #print "s",urllib.unquote(keyword_naver).encode('utf-8').decode('utf-8').decode('utf-8').replace('+',' ')
                        #            break
                        if temp[1].find(head_yahoo) >= 0:
                            separate=temp[1].split('&')
                            for i in range(0,len(separate)):
                                if separate[i].find('p=') == 0:
                                    keyword_yahoo = separate[i][6:]
                                    query_date[index] = urllib.unquote(str(unicode(keyword_yahoo))).decode('utf8').replace('+',' ')
                                    access_time[index] = temp[3]
                                    index = index+1
                                    #print "key",urllib.unquote(str(unicode(keyword_naver))).decode('utf8')
                                    #print "s",urllib.unquote(keyword_naver).encode('utf-8').decode('utf-8').decode('utf-8').replace('+',' ')
                                    break
                        elif temp[1].find(head_bing) >= 0:
                            separate=temp[1].split('&')
                            for i in range(0,len(separate)):
                                if separate[i].find('q=') == 0:
                                    keyword_bing = separate[i][6:]
                                    query_date[index] = urllib.unquote(str(unicode(keyword_bing))).decode('utf8').replace('+',' ')
                                    access_time[index] = temp[3]
                                    index = index+1
                                    #print "key",urllib.unquote(str(unicode(keyword_naver))).decode('utf8')
                                    #print "s",urllib.unquote(keyword_naver).encode('utf-8').decode('utf-8').decode('utf-8').replace('+',' ')
                                    break
                        #elif temp[1].find(head_facebook) >= 0:
                        #    separate=temp[1].split('&')
                        #    for i in range(0,len(separate)):
                        #        if separate[i].find('q=') == 0:
                                    #keyword_facebook = separate[i][6:]
                                    #query_date[index] = urllib.unquote(str(unicode(keyword_facebook))).decode('utf8').replace('+',' ')
                                    #access_time[index] = temp[5]
                                    #index = index+1
                                    #print "key",urllib.unquote(str(unicode(keyword_naver))).decode('utf8')
                                    #print "s",urllib.unquote(keyword_naver).encode('utf-8').decode('utf-8').decode('utf-8').replace('+',' ')
                        #            break
                        elif temp[1].find(head_naver) >= 0:
                            separate=temp[1].split('&')
                            for i in range(0,len(separate)):
                                if separate[i].find('query=') == 0:
                                    keyword_naver = separate[i][6:]
                                    query_date[index] = urllib.unquote(str(unicode(keyword_naver))).decode('utf8').replace('+',' ')
                                    access_time[index] = temp[3]
                                    index = index+1
                                    #print "key",urllib.unquote(str(unicode(keyword_naver))).decode('utf8')
                                    #print "s",urllib.unquote(keyword_naver).encode('utf-8').decode('utf-8').decode('utf-8').replace('+',' ')
                                    break
                        elif temp[1].find(head_daum) >= 0:
                            separate=temp[1].split('&')
                            for i in range(0,len(separate)):
                                if separate[i].find('q=') == 0:
                                    keyword_daum = separate[i][2:]
                                    query_date[index] = urllib.unquote(str(unicode(keyword_daum))).decode('utf8').replace('+',' ')
                                    access_time[index] = temp[3]
                                    index = index+1
                                    break
                        elif temp[1].find(head_google) >= 0:
                            separate=temp[1].replace('?','&').split('&')
                            for i in range(len(separate)-1,0,-1):
                                if separate[i].find('q=')==0 & ~separate[i].find('oq='):
                                    keyword_google = separate[i][2:]
                                    query_date[index] = urllib.unquote(str(unicode(keyword_google))).decode('utf8').replace('+',' ')
                                    access_time[index] = temp[3]
                                    index = index+1
                                    break

        if os.path.isfile(self.fname+"\\Search_word.db"):
            os.remove(self.fname+"\\Search_word.db")
            conn = sqlite3.connect(self.fname+"\\Search_word.db")
        else:
            conn = sqlite3.connect(self.fname+"\\Search_word.db")
        cursor = conn.cursor()
        cursor.execute("CREATE TABLE Search_word(Word text, Count text, LastAccessTime text)")

        for i in range(0,index):
            if i==0:
                cursor.execute("INSERT INTO Search_word VALUES (?, ?, ?)", (query_date[i].replace(b'\x00', ''), 1, access_time[i]))
                continue
            
            for j in range(0,i):
                inde = {}
                number = 0
                if query_date[i].replace(b'\x00', '') == query_date[j].replace(b'\x00', ''):
                    cursor.execute("SELECT * from Search_word where Word = '"+query_date[i].replace(b'\x00', '')+"'")
                    word_count = cursor.fetchone()
                    for k in word_count:
                        inde[number] = k
                        number=number+1
                    plus_count = int(inde[1])+1
                    cursor.execute("UPDATE Search_word set Count = '"+str(plus_count)+"', LastAccessTime = '"+access_time[i]+"' where Word = '"+query_date[i].replace(b'\x00', '')+"'")
                    break
                if j==i-1:
                    cursor.execute("INSERT INTO Search_word VALUES (?, ?, ?)", (query_date[i].replace(b'\x00', ''), 1, access_time[i]))
                    break

        conn.commit()
        conn.close()

class WC_SearchKey_Parser():
    def __init__(self, fname):
        self.fname = fname
        conn = sqlite3.connect(self.fname+"\\WC_DB.db")
        cursor = conn.cursor()
        #appcache , appcacheentry , containers, dependency entry,

        cursor.execute("SELECT name FROM sqlite_master WHERE type IN ('table', 'view') AND name NOT LIKE 'sqlite_%' UNION ALL SELECT name FROM sqlite_temp_master WHERE type IN ('table', 'view') ORDER BY 1")
        name = cursor.fetchall()
        num=0
        index = 0
        tablename = {}
        query_date = {}

        head_naver="search.naver.com/search.naver?" # key query =
        head_daum="search.daum.net/search?" # key = q
        head_google="www.google.co.kr/search?"  # key = q or oq
        head_nate="search.daum.net/nate?"   # key = q
        head_yahoo="search.yahoo.com/search;"   # key = p
        head_bing="www.bing.com/search?"    # key = q
        head_facebook="www.facebook.com/search/"    # group 내의 search는 search가 뒤에있음. key = q

        print ("\nStart")
        for i in name:
            tablename[num] = i
            num = num+1
            for tablenamelist in i:
                print tablenamelist
                Container_ = tablenamelist.find("Container_")
                if Container_ >= 0:
                    cursor.execute("select Url from "+tablenamelist+"")
                    Urldata = cursor.fetchall()
                    for temp in Urldata:
                        for data in temp:
                            if data.find(head_nate) >= 0:
                                separate=data.split('&')
                                for i in range(0,len(separate)):
                                    if separate[i].find('q=') == 0:
                                        keyword_nate = separate[i][6:]
                                        print keyword_nate
                                        query_date[index] = urllib.unquote(str(unicode(keyword_nate))).decode('utf8').replace('+',' ')
                                        index = index+1
                                        print urllib.unquote(str(unicode(keyword_nate))).decode('utf8').replace('+',' ')
                                        #print "key",urllib.unquote(str(unicode(keyword_naver))).decode('utf8')
                                        #print "s",urllib.unquote(keyword_naver).encode('utf-8').decode('utf-8').decode('utf-8').replace('+',' ')
                                        break
                            if data.find(head_yahoo) >= 0:
                                separate=data.split('&')
                                for i in range(0,len(separate)):
                                    if separate[i].find('p=') == 0:
                                        keyword_yahoo = separate[i][6:]
                                        print keyword_yahoo
                                        query_date[index] = urllib.unquote(str(unicode(keyword_yahoo))).decode('utf8').replace('+',' ')
                                        index = index+1
                                        print urllib.unquote(str(unicode(keyword_yahoo))).decode('utf8').replace('+',' ')
                                        #print "key",urllib.unquote(str(unicode(keyword_naver))).decode('utf8')
                                        #print "s",urllib.unquote(keyword_naver).encode('utf-8').decode('utf-8').decode('utf-8').replace('+',' ')
                                        break
                            if data.find(head_bing) >= 0:
                                separate=data.split('&')
                                for i in range(0,len(separate)):
                                    if separate[i].find('q=') == 0:
                                        keyword_bing = separate[i][6:]
                                        print keyword_bing
                                        query_date[index] = urllib.unquote(str(unicode(keyword_bing))).decode('utf8').replace('+',' ')
                                        index = index+1
                                        print urllib.unquote(str(unicode(keyword_bing))).decode('utf8').replace('+',' ')
                                        #print "key",urllib.unquote(str(unicode(keyword_naver))).decode('utf8')
                                        #print "s",urllib.unquote(keyword_naver).encode('utf-8').decode('utf-8').decode('utf-8').replace('+',' ')
                                        break
                            if data.find(head_facebook) >= 0:
                                separate=data.split('&')
                                for i in range(0,len(separate)):
                                    if separate[i].find('q=') == 0:
                                        keyword_facebook = separate[i][6:]
                                        print keyword_facebook
                                        query_date[index] = urllib.unquote(str(unicode(keyword_facebook))).decode('utf8').replace('+',' ')
                                        index = index+1
                                        print urllib.unquote(str(unicode(keyword_facebook))).decode('utf8').replace('+',' ')
                                        #print "key",urllib.unquote(str(unicode(keyword_naver))).decode('utf8')
                                        #print "s",urllib.unquote(keyword_naver).encode('utf-8').decode('utf-8').decode('utf-8').replace('+',' ')
                                        break
                            if data.find(head_naver) >= 0:
                                separate=data.split('&')
                                for i in range(0,len(separate)):
                                    if separate[i].find('query=') == 0:
                                        keyword_naver = separate[i][6:]
                                        print keyword_naver
                                        query_date[index] = urllib.unquote(str(unicode(keyword_naver))).decode('utf8').replace('+',' ')
                                        index = index+1
                                        print urllib.unquote(str(unicode(keyword_naver))).decode('utf8').replace('+',' ')
                                        #print "key",urllib.unquote(str(unicode(keyword_naver))).decode('utf8')
                                        #print "s",urllib.unquote(keyword_naver).encode('utf-8').decode('utf-8').decode('utf-8').replace('+',' ')
                                        break
                            elif data.find(head_daum) >= 0:
                                separate=data.split('&')
                                for i in range(0,len(separate)):
                                    if separate[i].find('q=') == 0:
                                        keyword_daum = separate[i][2:]
                                        print keyword_daum
                                        query_date[index] = urllib.unquote(str(unicode(keyword_daum))).decode('utf8').replace('+',' ')
                                        index = index+1
                                        print urllib.unquote(str(unicode(keyword_daum))).decode('utf8').replace('+',' ')
                                        break
                            elif data.find(head_google) >= 0:
                                separate=data.replace('?','&').split('&')
                                for i in range(len(separate)-1,0,-1):
                                    if separate[i].find('q=')==0 & ~separate[i].find('oq='):
                                        keyword_google = separate[i][2:]
                                        print keyword_google
                                        query_date[index] = urllib.unquote(str(unicode(keyword_google))).decode('utf8').replace('+',' ')
                                        index = index+1
                                        print urllib.unquote(str(unicode(keyword_google))).decode('utf8').replace('+',' ')
                                        break

                DependencyEntry_ = tablenamelist.find("DependencyEntry_")
                if DependencyEntry_ >= 0:
                    cursor.execute("select Url from "+tablenamelist+"")
                    Urldata = cursor.fetchall()
                    for temp in Urldata:
                        for data in temp:
                            if data.find(head_nate) >= 0:
                                separate=data.split('&')
                                for i in range(0,len(separate)):
                                    if separate[i].find('q=') == 0:
                                        keyword_nate = separate[i][6:]
                                        query_date[index] = urllib.unquote(str(unicode(keyword_nate))).decode('utf8').replace('+',' ')
                                        index = index+1
                                        print urllib.unquote(str(unicode(keyword_nate))).decode('utf8').replace('+',' ')
                                        #print "key",urllib.unquote(str(unicode(keyword_naver))).decode('utf8')
                                        #print "s",urllib.unquote(keyword_naver).encode('utf-8').decode('utf-8').decode('utf-8').replace('+',' ')
                                        break
                            if data.find(head_yahoo) >= 0:
                                separate=data.split('&')
                                for i in range(0,len(separate)):
                                    if separate[i].find('p=') == 0:
                                        keyword_yahoo = separate[i][6:]
                                        query_date[index] = urllib.unquote(str(unicode(keyword_yahoo))).decode('utf8').replace('+',' ')
                                        index = index+1
                                        print urllib.unquote(str(unicode(keyword_yahoo))).decode('utf8').replace('+',' ')
                                        #print "key",urllib.unquote(str(unicode(keyword_naver))).decode('utf8')
                                        #print "s",urllib.unquote(keyword_naver).encode('utf-8').decode('utf-8').decode('utf-8').replace('+',' ')
                                        break
                            if data.find(head_bing) >= 0:
                                separate=data.split('&')
                                for i in range(0,len(separate)):
                                    if separate[i].find('q=') == 0:
                                        keyword_bing = separate[i][6:]
                                        query_date[index] = urllib.unquote(str(unicode(keyword_bing))).decode('utf8').replace('+',' ')
                                        index = index+1
                                        print urllib.unquote(str(unicode(keyword_bing))).decode('utf8').replace('+',' ')
                                        #print "key",urllib.unquote(str(unicode(keyword_naver))).decode('utf8')
                                        #print "s",urllib.unquote(keyword_naver).encode('utf-8').decode('utf-8').decode('utf-8').replace('+',' ')
                                        break
                            if data.find(head_facebook) >= 0:
                                separate=data.split('&')
                                for i in range(0,len(separate)):
                                    if separate[i].find('q=') == 0:
                                        keyword_facebook = separate[i][6:]
                                        query_date[index] = urllib.unquote(str(unicode(keyword_facebook))).decode('utf8').replace('+',' ')
                                        index = index+1
                                        print urllib.unquote(str(unicode(keyword_facebook))).decode('utf8').replace('+',' ')
                                        #print "key",urllib.unquote(str(unicode(keyword_naver))).decode('utf8')
                                        #print "s",urllib.unquote(keyword_naver).encode('utf-8').decode('utf-8').decode('utf-8').replace('+',' ')
                                        break
                            if data.find(head_naver) >= 0:
                                separate=data.split('&')
                                for i in range(0,len(separate)):
                                    if separate[i].find('query=') == 0:
                                        keyword_naver = separate[i][6:]
                                        query_date[index] = urllib.unquote(str(unicode(keyword_naver))).decode('utf8').replace('+',' ')
                                        index = index+1
                                        print urllib.unquote(str(unicode(keyword_naver))).decode('utf8').replace('+',' ')
                                        #print "key",urllib.unquote(str(unicode(keyword_naver))).decode('utf8')
                                        #print "s",urllib.unquote(keyword_naver).encode('utf-8').decode('utf-8').decode('utf-8').replace('+',' ')
                                        break
                            elif data.find(head_daum) >= 0:
                                separate=data.split('&')
                                for i in range(0,len(separate)):
                                    if separate[i].find('q=') == 0:
                                        keyword_daum = separate[i][2:]
                                        query_date[index] = urllib.unquote(str(unicode(keyword_daum))).decode('utf8').replace('+',' ')
                                        index = index+1
                                        print urllib.unquote(str(unicode(keyword_daum))).decode('utf8').replace('+',' ')
                                        break
                            elif data.find(head_google) >= 0:
                                separate=data.replace('?','&').split('&')
                                for i in range(len(separate)-1,0,-1):
                                    if separate[i].find('q=')==0 & ~separate[i].find('oq='):
                                        keyword_google = separate[i][2:]
                                        query_date[index] = urllib.unquote(str(unicode(keyword_google))).decode('utf8').replace('+',' ')
                                        index = index+1
                                        print urllib.unquote(str(unicode(keyword_google))).decode('utf8').replace('+',' ')
                                        break

                AppCache_ = tablenamelist.find("AppCache_")
                if AppCache_ >= 0:
                    cursor.execute("select Url from "+tablenamelist+"")
                    Urldata = cursor.fetchall()
                    for temp in Urldata:
                        for data in temp:
                            if data.find(head_nate) >= 0:
                                separate=data.split('&')
                                for i in range(0,len(separate)):
                                    if separate[i].find('q=') == 0:
                                        keyword_nate = separate[i][6:]
                                        query_date[index] = urllib.unquote(str(unicode(keyword_nate))).decode('utf8').replace('+',' ')
                                        index = index+1
                                        print urllib.unquote(str(unicode(keyword_nate))).decode('utf8').replace('+',' ')
                                        #print "key",urllib.unquote(str(unicode(keyword_naver))).decode('utf8')
                                        #print "s",urllib.unquote(keyword_naver).encode('utf-8').decode('utf-8').decode('utf-8').replace('+',' ')
                                        break
                            if data.find(head_yahoo) >= 0:
                                separate=data.split('&')
                                for i in range(0,len(separate)):
                                    if separate[i].find('p=') == 0:
                                        keyword_yahoo = separate[i][6:]
                                        query_date[index] = urllib.unquote(str(unicode(keyword_yahoo))).decode('utf8').replace('+',' ')
                                        index = index+1
                                        print urllib.unquote(str(unicode(keyword_yahoo))).decode('utf8').replace('+',' ')
                                        #print "key",urllib.unquote(str(unicode(keyword_naver))).decode('utf8')
                                        #print "s",urllib.unquote(keyword_naver).encode('utf-8').decode('utf-8').decode('utf-8').replace('+',' ')
                                        break
                            if data.find(head_bing) >= 0:
                                separate=data.split('&')
                                for i in range(0,len(separate)):
                                    if separate[i].find('q=') == 0:
                                        keyword_bing = separate[i][6:]
                                        query_date[index] = urllib.unquote(str(unicode(keyword_bing))).decode('utf8').replace('+',' ')
                                        index = index+1
                                        print urllib.unquote(str(unicode(keyword_bing))).decode('utf8').replace('+',' ')
                                        #print "key",urllib.unquote(str(unicode(keyword_naver))).decode('utf8')
                                        #print "s",urllib.unquote(keyword_naver).encode('utf-8').decode('utf-8').decode('utf-8').replace('+',' ')
                                        break
                            if data.find(head_facebook) >= 0:
                                separate=data.split('&')
                                for i in range(0,len(separate)):
                                    if separate[i].find('q=') == 0:
                                        keyword_facebook = separate[i][6:]
                                        query_date[index] = urllib.unquote(str(unicode(keyword_facebook))).decode('utf8').replace('+',' ')
                                        index = index+1
                                        print urllib.unquote(str(unicode(keyword_facebook))).decode('utf8').replace('+',' ')
                                        #print "key",urllib.unquote(str(unicode(keyword_naver))).decode('utf8')
                                        #print "s",urllib.unquote(keyword_naver).encode('utf-8').decode('utf-8').decode('utf-8').replace('+',' ')
                                        break
                            if data.find(head_naver) >= 0:
                                separate=data.split('&')
                                for i in range(0,len(separate)):
                                    if separate[i].find('query=') == 0:
                                        keyword_naver = separate[i][6:]
                                        query_date[index] = urllib.unquote(str(unicode(keyword_naver))).decode('utf8').replace('+',' ')
                                        index = index+1
                                        print urllib.unquote(str(unicode(keyword_naver))).decode('utf8').replace('+',' ')
                                        #print "key",urllib.unquote(str(unicode(keyword_naver))).decode('utf8')
                                        #print "s",urllib.unquote(keyword_naver).encode('utf-8').decode('utf-8').decode('utf-8').replace('+',' ')
                                        break
                            elif data.find(head_daum) >= 0:
                                separate=data.split('&')
                                for i in range(0,len(separate)):
                                    if separate[i].find('q=') == 0:
                                        keyword_daum = separate[i][2:]
                                        query_date[index] = urllib.unquote(str(unicode(keyword_daum))).decode('utf8').replace('+',' ')
                                        index = index+1
                                        print urllib.unquote(str(unicode(keyword_daum))).decode('utf8').replace('+',' ')
                                        break
                            elif data.find(head_google) >= 0:
                                separate=data.replace('?','&').split('&')
                                for i in range(len(separate)-1,0,-1):
                                    if separate[i].find('q=')==0 & ~separate[i].find('oq='):
                                        keyword_google = separate[i][2:]
                                        query_date[index] = urllib.unquote(str(unicode(keyword_google))).decode('utf8').replace('+',' ')
                                        index = index+1
                                        print urllib.unquote(str(unicode(keyword_google))).decode('utf8').replace('+',' ')
                                        break

                AppCacheEntry_ = tablenamelist.find("AppCacheEntry_")
                if AppCacheEntry_ >= 0:
                    cursor.execute("select Url from "+tablenamelist+"")
                    Urldata = cursor.fetchall()
                    for temp in Urldata:
                        for data in temp:
                            if data.find(head_nate) >= 0:
                                separate=data.split('&')
                                for i in range(0,len(separate)):
                                    if separate[i].find('q=') == 0:
                                        keyword_nate = separate[i][6:]
                                        query_date[index] = urllib.unquote(str(unicode(keyword_nate))).decode('utf8').replace('+',' ')
                                        index = index+1
                                        print urllib.unquote(str(unicode(keyword_nate))).decode('utf8').replace('+',' ')
                                        #print "key",urllib.unquote(str(unicode(keyword_naver))).decode('utf8')
                                        #print "s",urllib.unquote(keyword_naver).encode('utf-8').decode('utf-8').decode('utf-8').replace('+',' ')
                                        break
                            if data.find(head_yahoo) >= 0:
                                separate=data.split('&')
                                for i in range(0,len(separate)):
                                    if separate[i].find('p=') == 0:
                                        keyword_yahoo = separate[i][6:]
                                        query_date[index] = urllib.unquote(str(unicode(keyword_yahoo))).decode('utf8').replace('+',' ')
                                        index = index+1
                                        print urllib.unquote(str(unicode(keyword_yahoo))).decode('utf8').replace('+',' ')
                                        #print "key",urllib.unquote(str(unicode(keyword_naver))).decode('utf8')
                                        #print "s",urllib.unquote(keyword_naver).encode('utf-8').decode('utf-8').decode('utf-8').replace('+',' ')
                                        break
                            if data.find(head_bing) >= 0:
                                separate=data.split('&')
                                for i in range(0,len(separate)):
                                    if separate[i].find('query=') == 0:
                                        keyword_bing = separate[i][6:]
                                        query_date[index] = urllib.unquote(str(unicode(keyword_bing))).decode('utf8').replace('+',' ')
                                        index = index+1
                                        print urllib.unquote(str(unicode(keyword_bing))).decode('utf8').replace('+',' ')
                                        #print "key",urllib.unquote(str(unicode(keyword_naver))).decode('utf8')
                                        #print "s",urllib.unquote(keyword_naver).encode('utf-8').decode('utf-8').decode('utf-8').replace('+',' ')
                                        break
                            if data.find(head_facebook) >= 0:
                                separate=data.split('&')
                                for i in range(0,len(separate)):
                                    if separate[i].find('q=') == 0:
                                        keyword_facebook = separate[i][6:]
                                        query_date[index] = urllib.unquote(str(unicode(keyword_facebook))).decode('utf8').replace('+',' ')
                                        index = index+1
                                        print urllib.unquote(str(unicode(keyword_facebook))).decode('utf8').replace('+',' ')
                                        #print "key",urllib.unquote(str(unicode(keyword_naver))).decode('utf8')
                                        #print "s",urllib.unquote(keyword_naver).encode('utf-8').decode('utf-8').decode('utf-8').replace('+',' ')
                                        break
                            if data.find(head_naver) >= 0:
                                separate=data.split('&')
                                for i in range(0,len(separate)):
                                    if separate[i].find('q=') == 0:
                                        keyword_naver = separate[i][6:]
                                        query_date[index] = urllib.unquote(str(unicode(keyword_naver))).decode('utf8').replace('+',' ')
                                        index = index+1
                                        print urllib.unquote(str(unicode(keyword_naver))).decode('utf8').replace('+',' ')
                                        #print "key",urllib.unquote(str(unicode(keyword_naver))).decode('utf8')
                                        #print "s",urllib.unquote(keyword_naver).encode('utf-8').decode('utf-8').decode('utf-8').replace('+',' ')
                                        break
                            elif data.find(head_daum) >= 0:
                                separate=data.split('&')
                                for i in range(0,len(separate)):
                                    if separate[i].find('q=') == 0:
                                        keyword_daum = separate[i][2:]
                                        query_date[index] = urllib.unquote(str(unicode(keyword_daum))).decode('utf8').replace('+',' ')
                                        index = index+1
                                        print urllib.unquote(str(unicode(keyword_daum))).decode('utf8').replace('+',' ')
                                        break
                            elif data.find(head_google) >= 0:
                                separate=data.replace('?','&').split('&')
                                for i in range(len(separate)-1,0,-1):
                                    if separate[i].find('q=')==0 & ~separate[i].find('oq='):
                                        keyword_google = separate[i][2:]
                                        query_date[index] = urllib.unquote(str(unicode(keyword_google))).decode('utf8').replace('+',' ')
                                        index = index+1
                                        print urllib.unquote(str(unicode(keyword_google))).decode('utf8').replace('+',' ')
                                        break
                
        conn.commit()
        conn.close()

        if os.path.isfile(self.fname+"\\Search_word.db"):
            os.remove(self.fname+"\\Search_word.db")
            conn = sqlite3.connect(self.fname+"\\Search_word.db")
        else:
            conn = sqlite3.connect(self.fname+"\\Search_word.db")
        cursor = conn.cursor()
        cursor.execute("CREATE TABLE Search_word(Word text, Count text)")
        
        

        for i in range(0,index):
            print query_date[i].replace(b'\x00', '')
            print i
            if i==0:
                cursor.execute("INSERT INTO Search_word VALUES (?, ?)", (query_date[i].replace(b'\x00', ''), 1))
                continue
            
            for j in range(0,i):
                print j
                inde = {}
                number = 0
                if query_date[i].replace(b'\x00', '') == query_date[j].replace(b'\x00', ''):
                    cursor.execute("SELECT * from Search_word where Word = '"+query_date[i].replace(b'\x00', '')+"'")
                    word_count = cursor.fetchone()
                    for k in word_count:
                        inde[number] = k
                        number=number+1
                    plus_count = int(inde[1])+1
                    print plus_count
                    cursor.execute("UPDATE Search_word set Count = "+str(plus_count)+" where Word = '"+query_date[i].replace(b'\x00', '')+"'")
                    break
                if j==i-1:
                    cursor.execute("INSERT INTO Search_word VALUES (?, ?)", (query_date[i].replace(b'\x00', ''), 1))
                    break

        conn.commit()
        conn.close()

class Chrome_SearchKey_Parser():
    def __init__(self, fname):
        self.fname = fname
        conn = sqlite3.connect(self.fname+"\\Chrome.db")
        cursor = conn.cursor()

        cursor.execute("SELECT name FROM sqlite_master WHERE type IN ('table', 'view') AND name NOT LIKE 'sqlite_%' UNION ALL SELECT name FROM sqlite_temp_master WHERE type IN ('table', 'view') ORDER BY 1")
        name = cursor.fetchall()
        num=0
        index = 0
        tablename = {}

        head_naver="search.naver.com/search.naver?" # key query =
        head_daum="search.daum.net/search?" # key = q
        head_google="www.google.co.kr/search?"  # key = q or oq
        head_nate="search.daum.net/nate?"   # key = q
        head_yahoo="search.yahoo.com/search;"   # key = p
        head_bing="www.bing.com/search?"    # key = q
        head_facebook="www.facebook.com/search/"    # group 내의 search는 search가 뒤에있음. key = q

        cursor.execute("select URL from History_url_DB")
        Urldata = cursor.fetchall()
        #print Urldata
        for temp in Urldata:
            for data in temp:
                if data.find(head_nate) >= 0:
                    separate=data.split('&')
                    for i in range(0,len(separate)):
                        if separate[i].find('q=') == 0:
                            keyword_nate = separate[i][6:]
                            query_date[index] = urllib.unquote(str(unicode(keyword_nate))).decode('utf8').replace('+',' ')
                            index = index+1
                            print urllib.unquote(str(unicode(keyword_nate))).decode('utf8').replace('+',' ')
                            #print "key",urllib.unquote(str(unicode(keyword_naver))).decode('utf8')
                            #print "s",urllib.unquote(keyword_naver).encode('utf-8').decode('utf-8').decode('utf-8').replace('+',' ')
                            break
                elif data.find(head_yahoo) >= 0:
                    separate=data.split('&')
                    for i in range(0,len(separate)):
                        if separate[i].find('p=') == 0:
                            keyword_yahoo = separate[i][6:]
                            query_date[index] = urllib.unquote(str(unicode(keyword_yahoo))).decode('utf8').replace('+',' ')
                            index = index+1
                            print urllib.unquote(str(unicode(keyword_yahoo))).decode('utf8').replace('+',' ')
                            break
                elif data.find(head_bing) >= 0:
                    separate=data.split('&')
                    for i in range(0,len(separate)):
                        if separate[i].find('q=') == 0:
                            keyword_bing = separate[i][6:]
                            query_date[index] = urllib.unquote(str(unicode(keyword_bing))).decode('utf8').replace('+',' ')
                            index = index+1
                            print urllib.unquote(str(unicode(keyword_bing))).decode('utf8').replace('+',' ')
                            break
                elif data.find(head_facebook) >= 0:
                    separate=data.split('&')
                    for i in range(0,len(separate)):
                        if separate[i].find('q=') == 0:
                            keyword_facebook = separate[i][6:]
                            query_date[index] = urllib.unquote(str(unicode(keyword_facebook))).decode('utf8').replace('+',' ')
                            index = index+1
                            print urllib.unquote(str(unicode(keyword_facebook))).decode('utf8').replace('+',' ')
                            break
                elif data.find(head_naver) >= 0:
                    separate=data.split('&')
                    for i in range(0,len(separate)):
                        if separate[i].find('query=') == 0:
                            keyword_naver = separate[i][6:]
                            query_date[index] = urllib.unquote(str(unicode(keyword_naver))).decode('utf8').replace('+',' ')
                            index = index+1
                            print urllib.unquote(str(unicode(keyword_naver))).decode('utf8').replace('+',' ')
                            break
                elif data.find(head_daum) >= 0:
                    separate=data.split('&')
                    for i in range(0,len(separate)):
                        if separate[i].find('q=') == 0:
                            keyword_daum = separate[i][2:]
                            query_date[index] = urllib.unquote(str(unicode(keyword_daum))).decode('utf8').replace('+',' ')
                            index = index+1
                            print urllib.unquote(str(unicode(keyword_daum))).decode('utf8').replace('+',' ')
                            break
                elif data.find(head_google) >= 0:
                    separate=data.replace('?','&').split('&')
                    for i in range(len(separate)-1,0,-1):
                        if separate[i].find('q=')==0 & ~separate[i].find('oq='):
                            keyword_google = separate[i][2:]
                            query_date[index] = urllib.unquote(str(unicode(keyword_google))).decode('utf8').replace('+',' ')
                            index = index+1
                            print urllib.unquote(str(unicode(keyword_google))).decode('utf8').replace('+',' ')
                            break

class Window(QtGui.QMainWindow):
    def __init__(self, parent=None):                                                             # init
        super(Window, self).__init__(parent)
        
        self.fdirectory = None
        self.first_tabwidget_num = 0
        self.second_tabwidget_num = 0
        self.initUI()

    def initUI(self):
        self.AnalysisProgressBar = QtGui.QProgressBar()
        self.CollectProgressBar = QtGui.QProgressBar()
        #first Tab UI Setting
        self.Vlayout = QtGui.QVBoxLayout()
        self.Hlayout = QtGui.QHBoxLayout()
        
        self.TabWidget = QtGui.QTabWidget()
        self.TableWidget = QtGui.QTableWidget()
        self.WC_listWidget = QtGui.QListWidget()
        self.Indexdat_listWidget = QtGui.QListWidget()
        self.Chrome_listWidget = QtGui.QListWidget()
        self.listTabWidget = QtGui.QTabWidget()
        self.listTabWidget.setMaximumWidth(300)
        
        #self.Tabbar.currentChanged.connect(self.setting_SearchTab)
        
        self.TabWidget.currentChanged.connect(self.first_tabwidget_num_setting)
        self.listTabWidget.currentChanged.connect(self.second_tabwidget_num_setting)
        #self.listTabWidget.CurrentChanged.connect(self.second_tabwidget_num_setting)

        self.Indexdat_listWidget.itemClicked.connect(self.resetting_Indexdat_tablewidget)
        self.WC_listWidget.itemClicked.connect(self.resetting_WC_tablewidget)
        self.Chrome_listWidget.itemClicked.connect(self.resetting_Chrome_tablewidget)
        #self.setting_setting_tablewidget()
        #self.connect(self.listWidget, QtCore.SIGNAL("itemDoubleClicked(QtGui.QListWidgetItem)"), self.setting_tablewidget())

        self.listTabWidget.addTab(self.Indexdat_listWidget, "IE ~9")
        self.listTabWidget.addTab(self.WC_listWidget, "IE 10~")
        self.listTabWidget.addTab(self.Chrome_listWidget, "Chrome")

        self.splitter1 = QtGui.QSplitter(QtCore.Qt.Horizontal)
        self.splitter1.addWidget(self.listTabWidget)
        self.splitter1.addWidget(self.TableWidget)
        
        #self.Hlayout.addWidget(self.listWidget)
        self.Hlayout.addWidget(self.splitter1)

        #self.Vlayout.addWidget(self.Tabbar)
        #self.Vlayout.addLayout(self.Hlayout)
               
        self.main_widget = QtGui.QWidget(self)
        self.main_widget.setLayout(self.Hlayout)
        
        #self.TabWidget.setLayout(self.Vlayout)
       
        #second Tab UI Setting
        self.second_Vlayout = QtGui.QVBoxLayout()
        self.second_Hlayout = QtGui.QHBoxLayout()
        
        self.second_TableWidget = QtGui.QTableWidget()
        self.second_listWidget = QtGui.QListWidget()
        self.second_listWidget.setMaximumWidth(300)
        self.second_Frame = QtGui.QFrame()
        self.second_Frame.setFrameShape(QtGui.QFrame.StyledPanel)
        self.second_listWidget.itemClicked.connect(self.resetting_second_tablewidget)
        self.splitter2 = QtGui.QSplitter(QtCore.Qt.Horizontal)
        self.splitter2.addWidget(self.second_listWidget)
        self.splitter2.addWidget(self.second_TableWidget)

        self.second_Hlayout.addWidget(self.splitter2)

        self.second_widget = QtGui.QWidget(self)
        self.second_widget.setLayout(self.second_Hlayout)

        #Search_word Tab UI Setting
        self.Search_word_Vlayout = QtGui.QVBoxLayout()
        self.Search_word_Hlayout = QtGui.QHBoxLayout()

        self.Search_word_Frame = QtGui.QFrame()
        self.Search_word_TableWidget = QtGui.QTableWidget()
        self.Search_word_TableWidget.setMaximumWidth(600)
        self.Search_word_Frame.setFrameShape(QtGui.QFrame.StyledPanel)

        self.Search_word_Hlayout.addWidget(self.Search_word_TableWidget)

        self.Search_word_widget = QtGui.QWidget(self)
        self.Search_word_widget.setLayout(self.Search_word_Hlayout)
        
        #Timeline Tab UI Setting
        self.Timeline_Vlayout = QtGui.QVBoxLayout()
        self.Timeline_Hlayout = QtGui.QHBoxLayout()

        self.Timeline_Frame = QtGui.QFrame()
        self.Timeline_Frame.setFrameShape(QtGui.QFrame.StyledPanel)

        self.Timeline_Hlayout.addWidget(self.Timeline_Frame)

        self.Timeline_widget = QtGui.QWidget(self)
        self.Timeline_widget.setLayout(self.Timeline_Hlayout)

        self.TabWidget.addTab(self.main_widget, "Raw")
        self.TabWidget.addTab(self.second_widget, "Analysis")
        self.TabWidget.addTab(self.Search_word_widget, "Search Word")


        #UI start
        self.setCentralWidget(self.TabWidget)
                
        #File Tab
        CollectAction = QtGui.QAction('&Collect', self)
        CollectAction.setShortcut('Ctrl+C')
        CollectAction.setStatusTip('Web Data Collect')
        CollectAction.triggered.connect(self.Collecteropen)

        AnalysisAction = QtGui.QAction(QtGui.QIcon('Analysis.png'), '&Analysis', self)
        AnalysisAction.setShortcut('Ctrl+A')
        AnalysisAction.setStatusTip('Data Analysis')
        AnalysisAction.triggered.connect(self.Analysisopen)

        #exitAction = QtGui.QAction(QtGui.QIcon('exit.png'), '&Exit', self)              # MenuBar Setting
        exitAction = QtGui.QAction('&Exit', self)
        exitAction.setShortcut('Ctrl+Q')
        exitAction.setStatusTip('Exit')
        exitAction.triggered.connect(self.close)

        #Toll Tab
        FilterAction = QtGui.QAction('&Filter', self)
        FilterAction.setShortcut('Ctrl+F')
        FilterAction.setStatusTip('Data Filtering')
        FilterAction.triggered.connect(self.Filter)
        
        CsvAction = QtGui.QAction('C&sv File', self)
        CsvAction.setShortcut('Ctrl+S')
        CsvAction.setStatusTip('Csv file extration')
        CsvAction.triggered.connect(self.Csvwrite)

        #View Tab
        ColumnAction = QtGui.QAction('&Column', self)
        ColumnAction.setShortcut('Ctrl+S')
        ColumnAction.setStatusTip('Table Column Setting')
        #CollectAction.triggered.connect(self.Collecteropen)

        #Help Tab
        WriterAction = QtGui.QAction('&Writer', self)
        WriterAction.setShortcut('Ctrl+W')
        WriterAction.setStatusTip('Writer Information')
        WriterAction.triggered.connect(self.Writeropen)

        VersionAction = QtGui.QAction('&Version', self)
        VersionAction.setShortcut('Ctrl+V')
        VersionAction.setStatusTip('Version Information')
        VersionAction.triggered.connect(self.Versionopen)

        menubar = self.menuBar()
        fileMenu = menubar.addMenu('&File')
        fileMenu.addAction(CollectAction)
        fileMenu.addAction(AnalysisAction)
        fileMenu.addAction(exitAction)
        fileMenu = menubar.addMenu('&Tool')
        fileMenu.addAction(CsvAction)
        fileMenu.addAction(FilterAction)
        fileMenu = menubar.addMenu('&View')
        fileMenu.addAction(ColumnAction)
        fileMenu = menubar.addMenu('&Help')
        fileMenu.addAction(WriterAction)
        fileMenu.addAction(VersionAction)

        self.statusBar()                                                                # StatusBar Setting
        
        toolbar = self.addToolBar('&Toolbar')
        toolbar.addAction(FilterAction)

        appIcon = QtGui.QIcon('appIcon.png')                                            # Icon Setting
        self.setWindowIcon(appIcon)
        
        QtGui.QApplication.setStyle(QtGui.QStyleFactory.create('Cleanlooks'))

        self.setGeometry(100, 100, 1300, 800)                                           # Window Setting
        self.setWindowTitle('UWA (Unfied Web Analyer)')
        self.show()

    def first_tabwidget_num_setting(self):
        number = self.TabWidget.currentIndex()
        self.first_tabwidget_num = str(number)

    def second_tabwidget_num_setting(self):
        number = self.listTabWidget.currentIndex()
        self.second_tabwidget_num = str(number)

    def method_call(self, fname):
        self.fdirectory = fname
        self.setting_Indexdat_listWidget(fname)
        self.setting_WC_listWidget(fname)
        self.setting_Chrome_listWidget(fname)
        self.setting_Indexdat_tablewidget(fname)
        self.setting_second_listWidget(fname)
        self.setting_second_TableWidget(fname)
        self.setting_Search_word_TableWidget(fname)

    def Analysisopen(self):
        Adlalog = MyPopup(self)
        Adlalog.show()
        Adlalog.exec_()

    def Collecteropen(self):
        Cdlalog = CollerterPopup(self)
        Cdlalog.show()
        Cdlalog.exec_()

    def Writeropen(self):
        Wdlalog = WriterPopup(self)
        Wdlalog.show()
        Wdlalog.exec_()

    def Versionopen(self):
        Vdlalog = VersionPopup(self)
        Vdlalog.show()
        Vdlalog.exec_()

    def Csvwrite(self):
        os.chdir(self.fdirectory)
        con = sqlite3.connect(self.fdirectory+"\\Integrated_DB.db")
        privcon = sqlite3.connect(self.fdirectory+"\\Integrated_DB.db")
        cursor = con.cursor()

        f = open(self.fdirectory+"\\Integrated_DB.txt", 'w+')
        f.write("Browser, URL, FileName, FileSize, CreationTime, LastAccessTime, ExpiryTime, Path\n")
        for row in cursor.execute("SELECT * FROM Cache ORDER BY _rowid_ ASC") :
            f.write(str(row))
            f.write("\n")
        con.close()
        f.close()

        #Replace Unicode Prefix 1
        f1 = open("Integrated_DB.txt", 'r')
        f2 = open("Integrated_DB2.txt", 'w+')
        for line in f1:
            f2.write(line.replace(" u'", ""))
        f1.close()
        f2.close()
        os.remove("Integrated_DB.txt")
        os.rename("Integrated_DB2.txt", "Integrated_DB.txt")

        #Replace Unicode Prefix 2
        f3 = open("Integrated_DB.txt", 'r')
        f4 = open("Integrated_DB2.txt", 'w+')
        for line in f3:
            f4.write(line.replace("(u'WebCache'", "WebCache"))
        f3.close()
        f4.close()
        os.remove("Integrated_DB.txt")
        os.rename("Integrated_DB2.txt", "Integrated_DB.txt")

        #Replace Unicode Prefix 3
        f5 = open("Integrated_DB.txt", 'r')
        f6 = open("Integrated_DB2.txt", 'w+')
        for line in f5:
            f6.write(line.replace("ieflipahead:d:", ""))
        f5.close()
        f6.close()
        os.remove("Integrated_DB.txt")
        os.rename("Integrated_DB2.txt", "Integrated_DB.txt")

        #Replace Unicode Prefix 4
        f7 = open("Integrated_DB.txt", 'r')
        f8 = open("Integrated_DB2.txt", 'w+')
        for line in f7:
            f8.write(line.replace("(u'index.dat'", "index.dat"))
        f7.close()
        f8.close()
        os.remove("Integrated_DB.txt")
        os.rename("Integrated_DB2.txt", "Integrated_DB.txt")

        #Replace Unicode Prefix 5
        f9 = open("Integrated_DB.txt", 'r')
        f10 = open("Integrated_DB2.txt", 'w+')
        for line in f9:
            f10.write(line.replace("0'", "0"))
        f9.close()
        f10.close()
        os.remove("Integrated_DB.txt")
        os.rename("Integrated_DB2.txt", "Integrated_DB.txt")

        #Replace Unicode Prefix 6
        f11 = open("Integrated_DB.txt", 'r')
        f12 = open("Integrated_DB2.txt", 'w+')
        for line in f11:
            f12.write(line.replace(" None)", "None"))
        f11.close()
        f12.close()
        os.remove("Integrated_DB.txt")
        os.rename("Integrated_DB2.txt", "Integrated_DB.csv")

    def Filter(self):
        text, ok = QtGui.QInputDialog.getText(self, 'Input Dialog', 
            'Enter Search Word:')

        if ok:
            if int(self.first_tabwidget_num) == 0 & int(self.second_tabwidget_num) == 0:
                item = self.Indexdat_listWidget.currentItem()
                self.TableWidget.clear()
                #item = self.listWidget.currentItem()
                #print (unicode(item.text()))

                conn = sqlite3.connect(self.fdirectory+"\\IE9parser.db")
                cursor = conn.cursor()
                cursor.execute("PRAGMA TABLE_INFO ("+unicode(item.text())+")")
                column = cursor.fetchall()

                columnname = {}
                num = 0
                for i in column:
                    lists = i
                    for j in range(1,2):
                        columnname[num] = lists[j]
                        num = num+1

            
                self.TableWidget.setColumnCount(len(columnname))
                n=0
                m=0
                #for k in range(len(columnname)):
                for key in columnname:
                    #self.TableWidget = QtGui.QTableWidget(100, 100)
                    newitem = QtGui.QTableWidgetItem(columnname[key])
                    self.TableWidget.setHorizontalHeaderItem(m, newitem)
                    m = m+1
                n=n+1

                data = {}
                m=0
                n=0
                r=0
                for key in columnname:
                    cursor.execute("select * from "+unicode(item.text())+" WHERE "+columnname[key]+" LIKE '%"+str(text)+"%' order by "+columnname[0]+" asc")
                    #cursor.execute("select * from "+unicode(item.text()))
                    #datarow = cursor.fetchone()
                    
                    while True:
                        index = 0
                        datarow = cursor.fetchone()

                        if datarow == None:
                            break
                        r=r+1
                        self.TableWidget.setRowCount(r)
                        for j in range(len(columnname)):
                            data[index] = datarow[j]
                            index = index+1
                            #print (datarow[j])
                            #print (data[index])
                            #for k in range(len(columnname)):

                        for datakey in data:
                            #print (data[datakey])
                            newitem = QtGui.QTableWidgetItem(data[datakey])
                            #print (newitem)
                            self.TableWidget.setItem(m, n, newitem)
                            n = n+1
                        data = {}
                    self.TableWidget.setSortingEnabled(True)
                    #n=n+1

                conn.commit()
                conn.close()
            elif int(self.first_tabwidget_num) == 0 & int(self.second_tabwidget_num) == 1:
                item = self.WC_listWidget.currentItem()
                self.TableWidget.clear()
                #item = self.listWidget.currentItem()
                #print (unicode(item.text()))

                conn = sqlite3.connect(self.fdirectory+"\\WC_DB.db")
                cursor = conn.cursor()
        
                cursor.execute("PRAGMA TABLE_INFO ("+unicode(item.text())+")")
                column = cursor.fetchall()

                columnname = {}
                num = 0
                for i in column:
                    lists = i
                    for j in range(1,2):
                        columnname[num] = lists[j]
                        num = num+1

            
                self.TableWidget.setColumnCount(len(columnname))
                n=0
                m=0
                #for k in range(len(columnname)):
                for key in columnname:
                    #self.TableWidget = QtGui.QTableWidget(100, 100)
                    newitem = QtGui.QTableWidgetItem(columnname[key])
                    self.TableWidget.setHorizontalHeaderItem(m, newitem)
                    m = m+1
                n=n+1
                
                data = {}
                m=0
                n=0
                r=0
                for key in columnname:
                    cursor.execute("select * from "+unicode(item.text())+" WHERE "+columnname[key]+" LIKE '%"+str(text)+"%' order by "+columnname[0]+" asc")
                    #cursor.execute("select * from "+unicode(item.text()))
                    #datarow = cursor.fetchone()
            
                    while True:
                        index = 0
                        datarow = cursor.fetchone()

                        if datarow == None:
                            break
                        r=r+1
                        self.TableWidget.setRowCount(r)
                        for j in range(len(columnname)):
                            data[index] = datarow[j]
                            index = index+1
                            #print (datarow[j])
                            #print (data[index])
                            #for k in range(len(columnname)):

                        for datakey in data:
                            #print (data[datakey])
                            newitem = QtGui.QTableWidgetItem(data[datakey])
                            #print (newitem)
                            self.TableWidget.setItem(m, n, newitem)
                            n = n+1
                        data = {}
                    self.TableWidget.setSortingEnabled(True)
                    #n=n+1

                conn.commit()
                conn.close()
            elif int(self.first_tabwidget_num) == 0 & int(self.second_tabwidget_num) == 2:
                item = self.Chrome_listWidget.currentItem()
                self.TableWidget.clear()
                #item = self.listWidget.currentItem()
                #print (unicode(item.text()))

                conn = sqlite3.connect(self.fdirectory+"\\Chrome.db")
                cursor = conn.cursor()
                cursor.execute("PRAGMA TABLE_INFO ("+unicode(item.text())+")")
                column = cursor.fetchall()

                columnname = {}
                num = 0
                for i in column:
                    lists = i
                    for j in range(1,2):
                        columnname[num] = lists[j]
                        num = num+1

            
                self.TableWidget.setColumnCount(len(columnname))
                n=0
                m=0
                #for k in range(len(columnname)):
                for key in columnname:
                    #self.TableWidget = QtGui.QTableWidget(100, 100)
                    newitem = QtGui.QTableWidgetItem(columnname[key])
                    self.TableWidget.setHorizontalHeaderItem(m, newitem)
                    m = m+1
                n=n+1
                
                data = {}
                m=0
                n=0
                r=0
                for key in columnname:
                    cursor.execute("select * from "+unicode(item.text())+" WHERE "+columnname[key]+" LIKE '%"+str(text)+"%' order by "+columnname[0]+" asc")
                    #cursor.execute("select * from "+unicode(item.text()))
                    #datarow = cursor.fetchone()
            
                    while True:
                        index = 0
                        datarow = cursor.fetchone()

                        if datarow == None:
                            break
                        r=r+1
                        self.TableWidget.setRowCount(r)
                        for j in range(len(columnname)):
                            data[index] = datarow[j]
                            index = index+1
                            #print (datarow[j])
                            #print (data[index])
                            #for k in range(len(columnname)):

                        for datakey in data:
                            #print (data[datakey])
                            newitem = QtGui.QTableWidgetItem(data[datakey])
                            #print (newitem)
                            self.TableWidget.setItem(m, n, newitem)
                            n = n+1
                        data = {}
                    self.TableWidget.setSortingEnabled(True)
                    #n=n+1

                conn.commit()
                conn.close()
            elif int(self.first_tabwidget_num) == 1:
                item = self.second_listWidget.currentItem()
                self.second_TableWidget.clear()
                #item = self.listWidget.currentItem()
                #print (unicode(item.text()))

                conn = sqlite3.connect(self.fdirectory+"\\Integrated_DB.db")
                cursor = conn.cursor()
                cursor.execute("PRAGMA TABLE_INFO ("+unicode(item.text())+")")
                column = cursor.fetchall()

                columnname = {}
                num = 0
                for i in column:
                    lists = i
                    for j in range(1,2):
                        columnname[num] = lists[j]
                        num = num+1

            
                self.second_TableWidget.setColumnCount(len(columnname))
                n=0
                m=0
                #for k in range(len(columnname)):
                for key in columnname:
                    #self.TableWidget = QtGui.QTableWidget(100, 100)
                    newitem = QtGui.QTableWidgetItem(columnname[key])
                    self.second_TableWidget.setHorizontalHeaderItem(m, newitem)
                    m = m+1
                n=n+1
                
                data = {}
                m=0
                n=0
                r=0
                for key in columnname:
                    cursor.execute("select * from "+unicode(item.text())+" WHERE "+columnname[key]+" LIKE '%"+str(text)+"%' order by "+columnname[0]+" asc")
                    #cursor.execute("select * from "+unicode(item.text()))
                    #datarow = cursor.fetchone()
            
                    while True:
                        index = 0
                        datarow = cursor.fetchone()

                        if datarow == None:
                            break
                        r=r+1
                        self.second_TableWidget.setRowCount(r)
                        for j in range(len(columnname)):
                            data[index] = datarow[j]
                            index = index+1
                            #print (datarow[j])
                            #print (data[index])
                            #for k in range(len(columnname)):

                        for datakey in data:
                            #print (data[datakey])
                            newitem = QtGui.QTableWidgetItem(data[datakey])
                            #print (newitem)
                            self.second_TableWidget.setItem(m, n, newitem)
                            n = n+1
                        data = {}
                    self.second_TableWidget.setSortingEnabled(True)
                    #n=n+1

                conn.commit()
                conn.close()
            elif int(self.first_tabwidget_num) == 2:
                self.Search_word_TableWidget.clear()
                #item = self.listWidget.currentItem()
                #print (unicode(item.text()))

                conn = sqlite3.connect(self.fdirectory+"\\Search_word.db")
                cursor = conn.cursor()
        
                cursor.execute("PRAGMA TABLE_INFO (Search_word)")
                column = cursor.fetchall()

                columnname = {}
                num = 0
                for i in column:
                    lists = i
                    for j in range(1,2):
                        columnname[num] = lists[j]
                        num = num+1

            
                self.Search_word_TableWidget.setColumnCount(len(columnname))
                n=0
                m=0
                #for k in range(len(columnname)):
                for key in columnname:
                    #self.TableWidget = QtGui.QTableWidget(100, 100)
                    newitem = QtGui.QTableWidgetItem(columnname[key])
                    self.second_TableWidget.setHorizontalHeaderItem(m, newitem)
                    m = m+1
                n=n+1
                
                data = {}
                m=0
                n=0
                r=0
                for key in columnname:
                    cursor.execute("select * from Search_word WHERE "+columnname[key]+" LIKE '%"+str(text)+"%' order by "+columnname[0]+" asc")
                    #cursor.execute("select * from "+unicode(item.text()))
                    #datarow = cursor.fetchone()

                    while True:
                        index = 0
                        datarow = cursor.fetchone()
                        #print datarow

                        if datarow == None:
                            #print ("data is None")
                            break
                        r=r+1
                        self.Search_word_TableWidget.setRowCount(r)
                        for j in range(len(columnname)):
                            data[index] = datarow[j]
                            index = index+1
                            #print (datarow[j])
                            #print (data[index])
                            #for k in range(len(columnname)):

                        for datakey in data:
                            #print (data[datakey])
                            newitem = QtGui.QTableWidgetItem(data[datakey])
                            #print (newitem)
                            self.Search_word_TableWidget.setItem(m, n, newitem)
                            n = n+1
                        data = {}
                    self.Search_word_TableWidget.setSortingEnabled(True)
                    #n=n+1

                #self.TableWidget.item(1,1).setFont(font)
                conn.commit()
                conn.close()

    def Column_setting(self):
        print "ss"

    def setting_Indexdat_listWidget(self, fname):
        #self.listWidget.clear()
        self.list_widget_num = 1
        self.fdirectory = fname
        if os.path.isfile(fname+"\\IE9parser.db"):
            self.listname = self.IndexdatsearchTable(fname)
            r=0
            for listindex in self.listname:
                print listindex
                for item in self.listname[listindex]:
                    print item
                    newlist = QtGui.QListWidgetItem(item)
                    self.Indexdat_listWidget.addItem(newlist)
    """
    def setting_Indexdat_listWidget(self):
        #self.listWidget.clear()
        print ("ss")
        if os.path.isfile("IE9parser.db"):
            print ("os")
            self.listname = self.IndexdatsearchTable()
            r=0
            for listindex in self.listname:
                print listindex
                for item in self.listname[listindex]:
                    print item
                    newlist = QtGui.QListWidgetItem(item)
                    self.Indexdat_listWidget.addItem(newlist)
    """

    def setting_WC_listWidget(self, fname):
        #self.listWidget.clear()
        self.list_widget_num = 2
        self.fdirectory = fname
        if os.path.isfile(fname+"\\WC_DB.db"):
            self.listname = self.searchTable(fname)
            r=0
            for listindex in self.listname:
                print listindex
                for item in self.listname[listindex]:
                    print item
                    newlist = QtGui.QListWidgetItem(item)
                    self.WC_listWidget.addItem(newlist)

    def setting_Chrome_listWidget(self, fname):
        #self.listWidget.clear()
        self.list_widget_num = 3
        self.fdirectory = fname
        if os.path.isfile(fname+"\\Chrome.db"):
            self.listname = self.Chrome_searchTable(fname)
            r=0
            for listindex in self.listname:
                print listindex
                for item in self.listname[listindex]:
                    print item
                    newlist = QtGui.QListWidgetItem(item)
                    self.Chrome_listWidget.addItem(newlist)

    def setting_second_listWidget(self, fname):
        #self.listWidget.clear()
        self.list_widget_num = 4
        self.fdirectory = fname
        if os.path.isfile(fname+"\\Integrated_DB.db"):
            self.listname = self.Integrated_searchTable(fname)
            r=0
            for listindex in self.listname:
                print listindex
                for item in self.listname[listindex]:
                    print item
                    newlist = QtGui.QListWidgetItem(item)
                    self.second_listWidget.addItem(newlist)

    def setting_Indexdat_tablewidget(self, fname):
        self.fdirectory = fname
        self.Table_widget_num = 1
        if os.path.isfile(fname+"\\IE9parser.db"):
            #item = self.listWidget.currentItem()
            #print (unicode(item.text()))
            #m=0
            #self.Tablename = self.searchTable()
            #n=0
            #print("self.setting_setting_tablewidget()")
            #self.searchData()
            #for key in self.Tablename:
            #    print (key)
            #    for item in self.Tablename[key]:
            #        print (item)
            #        self.TableWidget = QtGui.QTableWidget(len(self.Tablename), 1)
            #        newitem = QtGui.QTableWidgetItem(item)
            #        print (newitem)
            #        self.TableWidget.setItem(m, n, newitem)
            #        m = m+1
            #Chrome_SearchKey_Parser(fname)
            #WC_SearchKey_Parser(fname)
            self.TableWidget.clear()
            #item = self.listWidget.currentItem()
            #print (unicode(item.text()))

            conn = sqlite3.connect(fname+"\\IE9parser.db")
            cursor = conn.cursor()
        
            cursor.execute("PRAGMA TABLE_INFO (Downlist)")
            column = cursor.fetchall()

            columnname = {}
            num = 0
            for i in column:
                lists = i
                for j in range(1,2):
                    columnname[num] = lists[j]
                    num = num+1

            
            self.TableWidget.setColumnCount(len(columnname))
            n=0
            m=0
            #for k in range(len(columnname)):
            for key in columnname:
                #self.TableWidget = QtGui.QTableWidget(100, 100)
                newitem = QtGui.QTableWidgetItem(columnname[key])
                self.TableWidget.setHorizontalHeaderItem(m, newitem)
                m = m+1
            n=n+1

            cursor.execute("select * from Downlist order by "+columnname[0]+" asc")
            #cursor.execute("select * from "+unicode(item.text()))
            #datarow = cursor.fetchone()
            data = {}
            
            m=0
            #datarow = cursor.fetchone()
            #for datarow in cursor.fetchone():
            #print datarow
            n=0
            r=0
            while True:
                index = 0
                datarow = cursor.fetchone()
                #print datarow

                if datarow == None:
                    #print ("data is None")
                    break
                r=r+1
                self.TableWidget.setRowCount(r)
                for j in range(len(columnname)):
                    data[index] = datarow[j]
                    index = index+1
                    #print (datarow[j])
                    #print (data[index])
                    #for k in range(len(columnname)):

                for datakey in data:
                    #print (data[datakey])
                    newitem = QtGui.QTableWidgetItem(data[datakey])
                    #print (newitem)
                    self.TableWidget.setItem(m, n, newitem)
                    n = n+1
                data = {}
            self.TableWidget.setSortingEnabled(True)
            #n=n+1
            font = QtGui.QFont()
            font.setBold(True)

            #self.TableWidget.item(1,1).setFont(font)
            conn.commit()
            conn.close()

    def setting_WC_tablewidget(self, fname):
        self.fdirectory = fname
        self.Table_widget_num = 2
        if os.path.isfile(fname+"\\WC_DB.db"):
            #item = self.listWidget.currentItem()
            #print (unicode(item.text()))
            #m=0
            #self.Tablename = self.searchTable()
            #n=0
            #print("self.setting_setting_tablewidget()")
            #self.searchData()
            #for key in self.Tablename:
            #    print (key)
            #    for item in self.Tablename[key]:
            #        print (item)
            #        self.TableWidget = QtGui.QTableWidget(len(self.Tablename), 1)
            #        newitem = QtGui.QTableWidgetItem(item)
            #        print (newitem)
            #        self.TableWidget.setItem(m, n, newitem)
            #        m = m+1
            #SearchKey_Parser()
            self.TableWidget.clear()
            #item = self.listWidget.currentItem()
            #print (unicode(item.text()))

            conn = sqlite3.connect(fname+"\\WC_DB.db")
            cursor = conn.cursor()
        
            cursor.execute("PRAGMA TABLE_INFO (WC_Containers)")
            column = cursor.fetchall()

            columnname = {}
            num = 0
            for i in column:
                lists = i
                for j in range(1,2):
                    columnname[num] = lists[j]
                    num = num+1

            
            self.TableWidget.setColumnCount(len(columnname))
            n=0
            m=0
            #for k in range(len(columnname)):
            for key in columnname:
                #self.TableWidget = QtGui.QTableWidget(100, 100)
                newitem = QtGui.QTableWidgetItem(columnname[key])
                self.TableWidget.setHorizontalHeaderItem(m, newitem)
                m = m+1
            n=n+1

            cursor.execute("select * from WC_Containers order by "+columnname[0]+" asc")
            #cursor.execute("select * from "+unicode(item.text()))
            #datarow = cursor.fetchone()
            data = {}
            
            m=0
            #datarow = cursor.fetchone()
            #for datarow in cursor.fetchone():
            #print datarow
            n=0
            r=0
            while True:
                index = 0
                datarow = cursor.fetchone()
                #print datarow

                if datarow == None:
                    #print ("data is None")
                    break
                r=r+1
                self.TableWidget.setRowCount(r)
                for j in range(len(columnname)):
                    data[index] = datarow[j]
                    index = index+1
                    #print (datarow[j])
                    #print (data[index])
                    #for k in range(len(columnname)):

                for datakey in data:
                    #print (data[datakey])
                    newitem = QtGui.QTableWidgetItem(data[datakey])
                    #print (newitem)
                    self.TableWidget.setItem(m, n, newitem)
                    n = n+1
                data = {}
            self.TableWidget.setSortingEnabled(True)
            #n=n+1
            font = QtGui.QFont()
            font.setBold(True)

            #self.TableWidget.item(1,1).setFont(font)
            conn.commit()
            conn.close()
    
    def setting_Chrome_tablewidget(self, fname):
        self.fdirectory = fname
        self.Table_widget_num = 3
        if os.path.isfile(fname+"\\Chrome.db"):
            #item = self.listWidget.currentItem()
            #print (unicode(item.text()))
            #m=0
            #self.Tablename = self.searchTable()
            #n=0
            #print("self.setting_setting_tablewidget()")
            #self.searchData()
            #for key in self.Tablename:
            #    print (key)
            #    for item in self.Tablename[key]:
            #        print (item)
            #        self.TableWidget = QtGui.QTableWidget(len(self.Tablename), 1)
            #        newitem = QtGui.QTableWidgetItem(item)
            #        print (newitem)
            #        self.TableWidget.setItem(m, n, newitem)
            #        m = m+1
            #WC_SearchKey_Parser()
            #SearchKey_Parser()
            self.TableWidget.clear()
            #item = self.listWidget.currentItem()
            #print (unicode(item.text()))

            conn = sqlite3.connect(fname+"\\Chrome.db")
            cursor = conn.cursor()
        
            cursor.execute("PRAGMA TABLE_INFO (Cookies_DB)")
            column = cursor.fetchall()

            columnname = {}
            num = 0
            for i in column:
                lists = i
                for j in range(1,2):
                    columnname[num] = lists[j]
                    num = num+1

            
            self.TableWidget.setColumnCount(len(columnname))
            n=0
            m=0
            #for k in range(len(columnname)):
            for key in columnname:
                #self.TableWidget = QtGui.QTableWidget(100, 100)
                newitem = QtGui.QTableWidgetItem(columnname[key])
                self.TableWidget.setHorizontalHeaderItem(m, newitem)
                m = m+1
            n=n+1

            cursor.execute("select * from Cookies_DB order by "+columnname[0]+" asc")
            #cursor.execute("select * from "+unicode(item.text()))
            #datarow = cursor.fetchone()
            data = {}
            
            m=0
            #datarow = cursor.fetchone()
            #for datarow in cursor.fetchone():
            #print datarow
            n=0
            r=0
            while True:
                index = 0
                datarow = cursor.fetchone()
                #print datarow

                if datarow == None:
                    #print ("data is None")
                    break
                r=r+1
                self.TableWidget.setRowCount(r)
                for j in range(len(columnname)):
                    data[index] = datarow[j]
                    index = index+1
                    #print (datarow[j])
                    #print (data[index])
                    #for k in range(len(columnname)):

                for datakey in data:
                    #print (data[datakey])
                    newitem = QtGui.QTableWidgetItem(data[datakey])
                    #print (newitem)
                    self.TableWidget.setItem(m, n, newitem)
                    n = n+1
                data = {}
            self.TableWidget.setSortingEnabled(True)
            #n=n+1
            font = QtGui.QFont()
            font.setBold(True)

            #self.TableWidget.item(1,1).setFont(font)
            conn.commit()
            conn.close()

    def setting_second_TableWidget(self, fname):
        self.fdirectory = fname
        self.Table_widget_num = 4
        print fname+"Integrated_DB.db"
        if os.path.isfile(fname+"\\Integrated_DB.db"):
            #item = self.listWidget.currentItem()
            #print (unicode(item.text()))
            #m=0
            #self.Tablename = self.searchTable()
            #n=0
            #print("self.setting_setting_tablewidget()")
            #self.searchData()
            #for key in self.Tablename:
            #    print (key)
            #    for item in self.Tablename[key]:
            #        print (item)
            #        self.TableWidget = QtGui.QTableWidget(len(self.Tablename), 1)
            #        newitem = QtGui.QTableWidgetItem(item)
            #        print (newitem)
            #        self.TableWidget.setItem(m, n, newitem)
            #        m = m+1
            self.second_TableWidget.clear()
            #item = self.listWidget.currentItem()
            #print (unicode(item.text()))

            conn = sqlite3.connect(fname+"\\Integrated_DB.db")
            cursor = conn.cursor()
        
            cursor.execute("PRAGMA TABLE_INFO (Cache)")
            column = cursor.fetchall()

            columnname = {}
            num = 0
            for i in column:
                lists = i
                for j in range(1,2):
                    columnname[num] = lists[j]
                    num = num+1

            
            self.second_TableWidget.setColumnCount(len(columnname))
            n=0
            m=0
            #for k in range(len(columnname)):
            for key in columnname:
                #self.TableWidget = QtGui.QTableWidget(100, 100)
                newitem = QtGui.QTableWidgetItem(columnname[key])
                self.second_TableWidget.setHorizontalHeaderItem(m, newitem)
                m = m+1
            n=n+1

            cursor.execute("select * from Cache order by "+columnname[0]+" asc")
            #cursor.execute("select * from "+unicode(item.text()))
            #datarow = cursor.fetchone()
            data = {}
            
            m=0
            #datarow = cursor.fetchone()
            #for datarow in cursor.fetchone():
            #print datarow
            n=0
            r=0
            while True:
                index = 0
                datarow = cursor.fetchone()
                #print datarow

                if datarow == None:
                    #print ("data is None")
                    break
                r=r+1
                self.second_TableWidget.setRowCount(r)
                for j in range(len(columnname)):
                    data[index] = datarow[j]
                    index = index+1
                    #print (datarow[j])
                    #print (data[index])
                    #for k in range(len(columnname)):

                for datakey in data:
                    #print (data[datakey])
                    newitem = QtGui.QTableWidgetItem(data[datakey])
                    #print (newitem)
                    self.second_TableWidget.setItem(m, n, newitem)
                    n = n+1
                data = {}
            self.second_TableWidget.setSortingEnabled(True)
            #n=n+1
            font = QtGui.QFont()
            font.setBold(True)

            #self.TableWidget.item(1,1).setFont(font)
            conn.commit()
            conn.close()

    def setting_Search_word_TableWidget(self, fname):
        self.fdirectory = fname
        if os.path.isfile(fname+"\\Search_word.db"):
            #item = self.listWidget.currentItem()
            #print (unicode(item.text()))
            #m=0
            #self.Tablename = self.searchTable()
            #n=0
            #print("self.setting_setting_tablewidget()")
            #self.searchData()
            #for key in self.Tablename:
            #    print (key)
            #    for item in self.Tablename[key]:
            #        print (item)
            #        self.TableWidget = QtGui.QTableWidget(len(self.Tablename), 1)
            #        newitem = QtGui.QTableWidgetItem(item)
            #        print (newitem)
            #        self.TableWidget.setItem(m, n, newitem)
            #        m = m+1
            self.Search_word_TableWidget.clear()
            #item = self.listWidget.currentItem()
            #print (unicode(item.text()))

            conn = sqlite3.connect(fname+"\\Search_word.db")
            cursor = conn.cursor()
        
            cursor.execute("PRAGMA TABLE_INFO (Search_word)")
            column = cursor.fetchall()

            columnname = {}
            num = 0
            for i in column:
                lists = i
                for j in range(1,2):
                    columnname[num] = lists[j]
                    num = num+1

            
            self.Search_word_TableWidget.setColumnCount(len(columnname))
            n=0
            m=0
            #for k in range(len(columnname)):
            for key in columnname:
                #self.TableWidget = QtGui.QTableWidget(100, 100)
                newitem = QtGui.QTableWidgetItem(columnname[key])
                self.Search_word_TableWidget.setHorizontalHeaderItem(m, newitem)
                m = m+1
            n=n+1

            cursor.execute("select * from Search_word order by "+columnname[0]+" asc")
            #cursor.execute("select * from "+unicode(item.text()))
            #datarow = cursor.fetchone()
            data = {}
            
            m=0
            #datarow = cursor.fetchone()
            #for datarow in cursor.fetchone():
            #print datarow
            n=0
            r=0
            while True:
                index = 0
                datarow = cursor.fetchone()
                #print datarow

                if datarow == None:
                    #print ("data is None")
                    break
                r=r+1
                self.Search_word_TableWidget.setRowCount(r)
                for j in range(len(columnname)):
                    data[index] = datarow[j]
                    index = index+1
                    #print (datarow[j])
                    #print (data[index])
                    #for k in range(len(columnname)):

                for datakey in data:
                    #print (data[datakey])
                    newitem = QtGui.QTableWidgetItem(data[datakey])
                    #print (newitem)
                    self.Search_word_TableWidget.setItem(m, n, newitem)
                    n = n+1
                data = {}
            self.Search_word_TableWidget.setSortingEnabled(True)
            #n=n+1
            font = QtGui.QFont()
            font.setBold(True)

            #self.TableWidget.item(1,1).setFont(font)
            conn.commit()
            conn.close()

    def resetting_Indexdat_tablewidget(self):
        self.Table_widget_num = 1
        if os.path.isfile(self.fdirectory+"\\IE9parser.db"):
            item = self.Indexdat_listWidget.currentItem()
            #print (unicode(item.text()))
            #m=0
            #self.Tablename = self.searchTable()
            #n=0
            #print("self.setting_setting_tablewidget()")
            #self.searchData()
            #for key in self.Tablename:
            #    print (key)
            #    for item in self.Tablename[key]:
            #        print (item)
            #        self.TableWidget = QtGui.QTableWidget(len(self.Tablename), 1)
            #        newitem = QtGui.QTableWidgetItem(item)
            #        print (newitem)
            #        self.TableWidget.setItem(m, n, newitem)
            #        m = m+1
            self.TableWidget.clear()
            #item = self.listWidget.currentItem()
            #print (unicode(item.text()))

            conn = sqlite3.connect(self.fdirectory+"\\IE9parser.db")
            cursor = conn.cursor()
            cursor.execute("PRAGMA TABLE_INFO ("+unicode(item.text())+")")
            column = cursor.fetchall()

            columnname = {}
            num = 0
            for i in column:
                lists = i
                for j in range(1,2):
                    columnname[num] = lists[j]
                    num = num+1

            
            self.TableWidget.setColumnCount(len(columnname))
            n=0
            m=0
            #for k in range(len(columnname)):
            for key in columnname:
                #self.TableWidget = QtGui.QTableWidget(100, 100)
                newitem = QtGui.QTableWidgetItem(columnname[key])
                self.TableWidget.setHorizontalHeaderItem(m, newitem)
                m = m+1
            n=n+1

            cursor.execute("select * from "+unicode(item.text())+" order by "+columnname[0]+" asc")
            #cursor.execute("select * from "+unicode(item.text()))
            #datarow = cursor.fetchone()
            data = {}
            
            m=0
            #datarow = cursor.fetchone()
            #for datarow in cursor.fetchone():
            #print datarow
            n=0
            r=0
            while True:
                index = 0
                datarow = cursor.fetchone()

                if datarow == None:
                    break
                r=r+1
                self.TableWidget.setRowCount(r)
                for j in range(len(columnname)):
                    data[index] = datarow[j]
                    index = index+1
                    #print (datarow[j])
                    #print (data[index])
                    #for k in range(len(columnname)):

                for datakey in data:
                    #print (data[datakey])
                    newitem = QtGui.QTableWidgetItem(data[datakey])
                    #print (newitem)
                    self.TableWidget.setItem(m, n, newitem)
                    n = n+1
                data = {}
            self.TableWidget.setSortingEnabled(True)
            #n=n+1

            conn.commit()
            conn.close()
                    
    def resetting_WC_tablewidget(self):
        self.Table_widget_num = 2
        if os.path.isfile(self.fdirectory+"\\WC_DB.db"):
            item = self.WC_listWidget.currentItem()
            #print (unicode(item.text()))
            #m=0
            #self.Tablename = self.searchTable()
            #n=0
            #print("self.setting_setting_tablewidget()")
            #self.searchData()
            #for key in self.Tablename:
            #    print (key)
            #    for item in self.Tablename[key]:
            #        print (item)
            #        self.TableWidget = QtGui.QTableWidget(len(self.Tablename), 1)
            #        newitem = QtGui.QTableWidgetItem(item)
            #        print (newitem)
            #        self.TableWidget.setItem(m, n, newitem)
            #        m = m+1
            self.TableWidget.clear()
            #item = self.listWidget.currentItem()
            #print (unicode(item.text()))

            conn = sqlite3.connect(self.fdirectory+"\\WC_DB.db")
            cursor = conn.cursor()
        
            cursor.execute("PRAGMA TABLE_INFO ("+unicode(item.text())+")")
            column = cursor.fetchall()

            columnname = {}
            num = 0
            for i in column:
                lists = i
                for j in range(1,2):
                    columnname[num] = lists[j]
                    num = num+1

            
            self.TableWidget.setColumnCount(len(columnname))
            n=0
            m=0
            #for k in range(len(columnname)):
            for key in columnname:
                #self.TableWidget = QtGui.QTableWidget(100, 100)
                newitem = QtGui.QTableWidgetItem(columnname[key])
                self.TableWidget.setHorizontalHeaderItem(m, newitem)
                m = m+1
            n=n+1

            cursor.execute("select * from "+unicode(item.text())+" order by "+columnname[0]+" asc")
            #cursor.execute("select * from "+unicode(item.text()))
            #datarow = cursor.fetchone()
            data = {}
            
            m=0
            #datarow = cursor.fetchone()
            #for datarow in cursor.fetchone():
            #print datarow
            n=0
            r=0
            while True:
                index = 0
                datarow = cursor.fetchone()

                if datarow == None:
                    break
                r=r+1
                self.TableWidget.setRowCount(r)
                for j in range(len(columnname)):
                    data[index] = datarow[j]
                    index = index+1
                    #print (datarow[j])
                    #print (data[index])
                    #for k in range(len(columnname)):

                for datakey in data:
                    #print (data[datakey])
                    newitem = QtGui.QTableWidgetItem(data[datakey])
                    #print (newitem)
                    self.TableWidget.setItem(m, n, newitem)
                    n = n+1
                data = {}
            self.TableWidget.setSortingEnabled(True)
            #n=n+1

            conn.commit()
            conn.close()
    
    def resetting_Chrome_tablewidget(self):
        self.Table_widget_num = 3
        if os.path.isfile(self.fdirectory+"\\Chrome.db"):
            item = self.Chrome_listWidget.currentItem()
            #print (unicode(item.text()))
            #m=0
            #self.Tablename = self.searchTable()
            #n=0
            #print("self.setting_setting_tablewidget()")
            #self.searchData()
            #for key in self.Tablename:
            #    print (key)
            #    for item in self.Tablename[key]:
            #        print (item)
            #        self.TableWidget = QtGui.QTableWidget(len(self.Tablename), 1)
            #        newitem = QtGui.QTableWidgetItem(item)
            #        print (newitem)
            #        self.TableWidget.setItem(m, n, newitem)
            #        m = m+1
            self.TableWidget.clear()
            #item = self.listWidget.currentItem()
            #print (unicode(item.text()))

            conn = sqlite3.connect(self.fdirectory+"\\Chrome.db")
            cursor = conn.cursor()
            cursor.execute("PRAGMA TABLE_INFO ("+unicode(item.text())+")")
            column = cursor.fetchall()

            columnname = {}
            num = 0
            for i in column:
                lists = i
                for j in range(1,2):
                    columnname[num] = lists[j]
                    num = num+1

            
            self.TableWidget.setColumnCount(len(columnname))
            n=0
            m=0
            #for k in range(len(columnname)):
            for key in columnname:
                #self.TableWidget = QtGui.QTableWidget(100, 100)
                newitem = QtGui.QTableWidgetItem(columnname[key])
                self.TableWidget.setHorizontalHeaderItem(m, newitem)
                m = m+1
            n=n+1

            cursor.execute("select * from "+unicode(item.text())+" order by "+columnname[0]+" asc")
            #cursor.execute("select * from "+unicode(item.text()))
            #datarow = cursor.fetchone()
            data = {}
            
            m=0
            #datarow = cursor.fetchone()
            #for datarow in cursor.fetchone():
            #print datarow
            n=0
            r=0
            while True:
                index = 0
                datarow = cursor.fetchone()

                if datarow == None:
                    break
                r=r+1
                self.TableWidget.setRowCount(r)
                for j in range(len(columnname)):
                    data[index] = datarow[j]
                    index = index+1
                    #print (datarow[j])
                    #print (data[index])
                    #for k in range(len(columnname)):

                for datakey in data:
                    #print (data[datakey])
                    newitem = QtGui.QTableWidgetItem(data[datakey])
                    #print (newitem)
                    self.TableWidget.setItem(m, n, newitem)
                    n = n+1
                data = {}
            self.TableWidget.setSortingEnabled(True)
            #n=n+1

            conn.commit()
            conn.close()

    def resetting_second_tablewidget(self):
        self.Table_widget_num = 4
        if os.path.isfile(self.fdirectory+"\\Integrated_DB.db"):
            item = self.second_listWidget.currentItem()
            #print (unicode(item.text()))
            #m=0
            #self.Tablename = self.searchTable()
            #n=0
            #print("self.setting_setting_tablewidget()")
            #self.searchData()
            #for key in self.Tablename:
            #    print (key)
            #    for item in self.Tablename[key]:
            #        print (item)
            #        self.TableWidget = QtGui.QTableWidget(len(self.Tablename), 1)
            #        newitem = QtGui.QTableWidgetItem(item)
            #        print (newitem)
            #        self.TableWidget.setItem(m, n, newitem)
            #        m = m+1
            self.second_TableWidget.clear()
            #item = self.listWidget.currentItem()
            #print (unicode(item.text()))

            conn = sqlite3.connect(self.fdirectory+"\\Integrated_DB.db")
            cursor = conn.cursor()
            cursor.execute("PRAGMA TABLE_INFO ("+unicode(item.text())+")")
            column = cursor.fetchall()

            columnname = {}
            num = 0
            for i in column:
                lists = i
                for j in range(1,2):
                    columnname[num] = lists[j]
                    num = num+1

            
            self.second_TableWidget.setColumnCount(len(columnname))
            n=0
            m=0
            #for k in range(len(columnname)):
            for key in columnname:
                #self.TableWidget = QtGui.QTableWidget(100, 100)
                newitem = QtGui.QTableWidgetItem(columnname[key])
                self.second_TableWidget.setHorizontalHeaderItem(m, newitem)
                m = m+1
            n=n+1

            cursor.execute("select * from "+unicode(item.text())+" order by "+columnname[0]+" asc")
            #cursor.execute("select * from "+unicode(item.text()))
            #datarow = cursor.fetchone()
            data = {}
            
            m=0
            #datarow = cursor.fetchone()
            #for datarow in cursor.fetchone():
            #print datarow
            n=0
            r=0
            while True:
                index = 0
                datarow = cursor.fetchone()

                if datarow == None:
                    break
                r=r+1
                self.second_TableWidget.setRowCount(r)
                for j in range(len(columnname)):
                    data[index] = datarow[j]
                    index = index+1
                    #print (datarow[j])
                    #print (data[index])
                    #for k in range(len(columnname)):

                for datakey in data:
                    #print (data[datakey])
                    newitem = QtGui.QTableWidgetItem(data[datakey])
                    #print (newitem)
                    self.second_TableWidget.setItem(m, n, newitem)
                    n = n+1
                data = {}
            self.second_TableWidget.setSortingEnabled(True)
            #n=n+1

            conn.commit()
            conn.close()

    """
    def setting_Indexdat_listWidget(self, fname):
        #self.listWidget.clear()
        self.fdirectory = fname
        print ("ss")
        if os.path.isfile(fname+"\\IE9parser.db"):
            print ("os")
            self.listname = self.searchTable()
            r=0
            for listindex in self.listname:
                print listindex
                for item in self.listname[listindex]:
                    print item
                    newlist = QtGui.QListWidgetItem(item)
                    self.Indexdat_listWidget.addItem(newlist)

    def setting_WC_listWidget(self, fname):
        #self.listWidget.clear()
        self.fdirectory = fname
        print ("ss")
        if os.path.isfile('%s'%fname+"\\collection\\IE10++\\WebCacheV01.dat"):
            print ("os")
            self.listname = self.searchTable()
            r=0
            for listindex in self.listname:
                print listindex
                for item in self.listname[listindex]:
                    print item
                    newlist = QtGui.QListWidgetItem(item)
                    self.WC_listWidget.addItem(newlist)
    
    def setting_Indexdat_tablewidget(self, fname):
        self.fdirectory = fname
        if os.path.isfile(fname+"\\IE9parser.db"):
            #item = self.listWidget.currentItem()
            #print (unicode(item.text()))
            #m=0
            #self.Tablename = self.searchTable()
            #n=0
            #print("self.setting_setting_tablewidget()")
            #self.searchData()
            #for key in self.Tablename:
            #    print (key)
            #    for item in self.Tablename[key]:
            #        print (item)
            #        self.TableWidget = QtGui.QTableWidget(len(self.Tablename), 1)
            #        newitem = QtGui.QTableWidgetItem(item)
            #        print (newitem)
            #        self.TableWidget.setItem(m, n, newitem)
            #        m = m+1
            print ("ss")
            SearchKey_Parser()
            self.TableWidget.clear()
            #item = self.listWidget.currentItem()
            #print (unicode(item.text()))

            conn = sqlite3.connect(fname+"\\IE9parser.db")
            cursor = conn.cursor()
        
            cursor.execute("PRAGMA TABLE_INFO (Hisotry)")
            column = cursor.fetchall()

            columnname = {}
            num = 0
            for i in column:
                lists = i
                for j in range(1,2):
                    columnname[num] = lists[j]
                    num = num+1

            
            self.TableWidget.setColumnCount(len(columnname))
            n=0
            m=0
            #for k in range(len(columnname)):
            for key in columnname:
                #self.TableWidget = QtGui.QTableWidget(100, 100)
                newitem = QtGui.QTableWidgetItem(columnname[key])
                self.TableWidget.setHorizontalHeaderItem(m, newitem)
                m = m+1
            n=n+1

            cursor.execute("select * from Hisotry order by "+columnname[0]+" asc")
            #cursor.execute("select * from "+unicode(item.text()))
            #datarow = cursor.fetchone()
            data = {}
            
            m=0
            #datarow = cursor.fetchone()
            #for datarow in cursor.fetchone():
            #print datarow
            n=0
            r=0
            while True:
                index = 0
                datarow = cursor.fetchone()
                #print datarow

                if datarow == None:
                    #print ("data is None")
                    break
                r=r+1
                self.TableWidget.setRowCount(r)
                for j in range(len(columnname)):
                    data[index] = datarow[j]
                    index = index+1
                    #print (datarow[j])
                    #print (data[index])
                    #for k in range(len(columnname)):

                for datakey in data:
                    #print (data[datakey])
                    newitem = QtGui.QTableWidgetItem(data[datakey])
                    #print (newitem)
                    self.TableWidget.setItem(m, n, newitem)
                    n = n+1
                data = {}
            self.TableWidget.setSortingEnabled(True)
            #n=n+1
            font = QtGui.QFont()
            font.setBold(True)

            #self.TableWidget.item(1,1).setFont(font)
            conn.commit()
            conn.close()

    def setting_WC_tablewidget(self, fname):
        self.fdirectory = fname
        if os.path.isfile(fname+"\\WC_DB.db"):
            #item = self.listWidget.currentItem()
            #print (unicode(item.text()))
            #m=0
            #self.Tablename = self.searchTable()
            #n=0
            #print("self.setting_setting_tablewidget()")
            #self.searchData()
            #for key in self.Tablename:
            #    print (key)
            #    for item in self.Tablename[key]:
            #        print (item)
            #        self.TableWidget = QtGui.QTableWidget(len(self.Tablename), 1)
            #        newitem = QtGui.QTableWidgetItem(item)
            #        print (newitem)
            #        self.TableWidget.setItem(m, n, newitem)
            #        m = m+1
            print ("ss")
            SearchKey_Parser()
            self.TableWidget.clear()
            #item = self.listWidget.currentItem()
            #print (unicode(item.text()))

            conn = sqlite3.connect(fname+"\\WC_DB.db")
            cursor = conn.cursor()
        
            cursor.execute("PRAGMA TABLE_INFO (WC_Containers)")
            column = cursor.fetchall()

            columnname = {}
            num = 0
            for i in column:
                lists = i
                for j in range(1,2):
                    columnname[num] = lists[j]
                    num = num+1

            
            self.TableWidget.setColumnCount(len(columnname))
            n=0
            m=0
            #for k in range(len(columnname)):
            for key in columnname:
                #self.TableWidget = QtGui.QTableWidget(100, 100)
                newitem = QtGui.QTableWidgetItem(columnname[key])
                self.TableWidget.setHorizontalHeaderItem(m, newitem)
                m = m+1
            n=n+1

            cursor.execute("select * from WC_Containers order by "+columnname[0]+" asc")
            #cursor.execute("select * from "+unicode(item.text()))
            #datarow = cursor.fetchone()
            data = {}
            
            m=0
            #datarow = cursor.fetchone()
            #for datarow in cursor.fetchone():
            #print datarow
            n=0
            r=0
            while True:
                index = 0
                datarow = cursor.fetchone()
                #print datarow

                if datarow == None:
                    #print ("data is None")
                    break
                r=r+1
                self.TableWidget.setRowCount(r)
                for j in range(len(columnname)):
                    data[index] = datarow[j]
                    index = index+1
                    #print (datarow[j])
                    #print (data[index])
                    #for k in range(len(columnname)):

                for datakey in data:
                    #print (data[datakey])
                    newitem = QtGui.QTableWidgetItem(data[datakey])
                    #print (newitem)
                    self.TableWidget.setItem(m, n, newitem)
                    n = n+1
                data = {}
            self.TableWidget.setSortingEnabled(True)
            #n=n+1
            font = QtGui.QFont()
            font.setBold(True)

            #self.TableWidget.item(1,1).setFont(font)
            conn.commit()
            conn.close()

    def resetting_WC_tablewidget(self):
        if os.path.isfile(self.fdirectory+"\\WC_DB.db"):
            item = self.WC_listWidget.currentItem()
            #print (unicode(item.text()))
            #m=0
            #self.Tablename = self.searchTable()
            #n=0
            #print("self.setting_setting_tablewidget()")
            #self.searchData()
            #for key in self.Tablename:
            #    print (key)
            #    for item in self.Tablename[key]:
            #        print (item)
            #        self.TableWidget = QtGui.QTableWidget(len(self.Tablename), 1)
            #        newitem = QtGui.QTableWidgetItem(item)
            #        print (newitem)
            #        self.TableWidget.setItem(m, n, newitem)
            #        m = m+1
            self.TableWidget.clear()
            #item = self.listWidget.currentItem()
            #print (unicode(item.text()))

            conn = sqlite3.connect(self.fdirectory+"\\WC_DB.db")
            cursor = conn.cursor()
        
            cursor.execute("PRAGMA TABLE_INFO ("+unicode(item.text())+")")
            column = cursor.fetchall()

            columnname = {}
            num = 0
            for i in column:
                lists = i
                for j in range(1,2):
                    columnname[num] = lists[j]
                    num = num+1

            
            self.TableWidget.setColumnCount(len(columnname))
            n=0
            m=0
            #for k in range(len(columnname)):
            for key in columnname:
                #self.TableWidget = QtGui.QTableWidget(100, 100)
                newitem = QtGui.QTableWidgetItem(columnname[key])
                self.TableWidget.setHorizontalHeaderItem(m, newitem)
                m = m+1
            n=n+1

            cursor.execute("select * from "+unicode(item.text())+" order by "+columnname[0]+" asc")
            #cursor.execute("select * from "+unicode(item.text()))
            #datarow = cursor.fetchone()
            data = {}
            
            m=0
            #datarow = cursor.fetchone()
            #for datarow in cursor.fetchone():
            #print datarow
            n=0
            r=0
            while True:
                index = 0
                datarow = cursor.fetchone()
                print datarow

                if datarow == None:
                    print ("data is None")
                    break
                r=r+1
                self.TableWidget.setRowCount(r)
                for j in range(len(columnname)):
                    data[index] = datarow[j]
                    index = index+1
                    #print (datarow[j])
                    #print (data[index])
                    #for k in range(len(columnname)):

                for datakey in data:
                    #print (data[datakey])
                    newitem = QtGui.QTableWidgetItem(data[datakey])
                    #print (newitem)
                    self.TableWidget.setItem(m, n, newitem)
                    n = n+1
                data = {}
            self.TableWidget.setSortingEnabled(True)
            #n=n+1

            conn.commit()
            conn.close()
             
    def resetting_Indexdat_tablewidget(self):
        if os.path.isfile(self.fdirectory+"\\IE9parser.db"):
            item = self.WC_listWidget.currentItem()
            #print (unicode(item.text()))
            #m=0
            #self.Tablename = self.searchTable()
            #n=0
            #print("self.setting_setting_tablewidget()")
            #self.searchData()
            #for key in self.Tablename:
            #    print (key)
            #    for item in self.Tablename[key]:
            #        print (item)
            #        self.TableWidget = QtGui.QTableWidget(len(self.Tablename), 1)
            #        newitem = QtGui.QTableWidgetItem(item)
            #        print (newitem)
            #        self.TableWidget.setItem(m, n, newitem)
            #        m = m+1
            self.TableWidget.clear()
            #item = self.listWidget.currentItem()
            #print (unicode(item.text()))

            conn = sqlite3.connect(self.fdirectory+"\\IE9parser.db")
            cursor = conn.cursor()
        
            cursor.execute("PRAGMA TABLE_INFO ("+unicode(item.text())+")")
            column = cursor.fetchall()

            columnname = {}
            num = 0
            for i in column:
                lists = i
                for j in range(1,2):
                    columnname[num] = lists[j]
                    num = num+1

            
            self.TableWidget.setColumnCount(len(columnname))
            n=0
            m=0
            #for k in range(len(columnname)):
            for key in columnname:
                #self.TableWidget = QtGui.QTableWidget(100, 100)
                newitem = QtGui.QTableWidgetItem(columnname[key])
                self.TableWidget.setHorizontalHeaderItem(m, newitem)
                m = m+1
            n=n+1

            cursor.execute("select * from "+unicode(item.text())+" order by "+columnname[0]+" asc")
            #cursor.execute("select * from "+unicode(item.text()))
            #datarow = cursor.fetchone()
            data = {}
            
            m=0
            #datarow = cursor.fetchone()
            #for datarow in cursor.fetchone():
            #print datarow
            n=0
            r=0
            while True:
                index = 0
                datarow = cursor.fetchone()
                print datarow

                if datarow == None:
                    print ("data is None")
                    break
                r=r+1
                self.TableWidget.setRowCount(r)
                for j in range(len(columnname)):
                    data[index] = datarow[j]
                    index = index+1
                    #print (datarow[j])
                    #print (data[index])
                    #for k in range(len(columnname)):

                for datakey in data:
                    #print (data[datakey])
                    newitem = QtGui.QTableWidgetItem(data[datakey])
                    #print (newitem)
                    self.TableWidget.setItem(m, n, newitem)
                    n = n+1
                data = {}
            self.TableWidget.setSortingEnabled(True)
            #n=n+1

            conn.commit()
            conn.close()
    """
    def Chrome_searchTable(self, fname):
        self.fdirectory = fname
        conn = sqlite3.connect(fname+"\\Chrome.db")
        cursor = conn.cursor()

        list = {}
        num = 0

        cursor.execute("SELECT name FROM sqlite_master WHERE type IN ('table', 'view') AND name NOT LIKE 'sqlite_%' UNION ALL SELECT name FROM sqlite_temp_master WHERE type IN ('table', 'view') ORDER BY 1")
        name = cursor.fetchall()
        for i in name:
            list[num] = i
            num = num+1

        conn.commit()
        conn.close()

        return list

    def Integrated_searchTable(self, fname):
        self.fdirectory = fname
        conn = sqlite3.connect(fname+"\\Integrated_DB.db")
        cursor = conn.cursor()

        list = {}
        num = 0

        cursor.execute("SELECT name FROM sqlite_master WHERE type IN ('table', 'view') AND name NOT LIKE 'sqlite_%' UNION ALL SELECT name FROM sqlite_temp_master WHERE type IN ('table', 'view') ORDER BY 1")
        name = cursor.fetchall()
        for i in name:
            list[num] = i
            num = num+1

        conn.commit()
        conn.close()

        return list

    def IndexdatsearchTable(self, fname):
        self.fdirectory = fname
        conn = sqlite3.connect(fname+"\\IE9parser.db")
        cursor = conn.cursor()

        list = {}
        num = 0

        cursor.execute("SELECT name FROM sqlite_master WHERE type IN ('table', 'view') AND name NOT LIKE 'sqlite_%' UNION ALL SELECT name FROM sqlite_temp_master WHERE type IN ('table', 'view') ORDER BY 1")
        name = cursor.fetchall()
        for i in name:
            list[num] = i
            num = num+1

        conn.commit()
        conn.close()

        return list

    def searchTable(self, fname):
        self.fdirectory = fname
        conn = sqlite3.connect(fname+"\\WC_DB.db")
        cursor = conn.cursor()

        list = {}
        num = 0

        cursor.execute("SELECT name FROM sqlite_master WHERE type IN ('table', 'view') AND name NOT LIKE 'sqlite_%' UNION ALL SELECT name FROM sqlite_temp_master WHERE type IN ('table', 'view') ORDER BY 1")
        name = cursor.fetchall()
        for i in name:
            list[num] = i
            num = num+1

        conn.commit()
        conn.close()

        return list

    def searchColumn(tname):
        conn = sqlite3.connect("WC_DB.db")
        cursor = conn.cursor()

        #for key in self.Tablename:
        #    print (key)
        #    for tname in self.Tablename[key]:
        cursor.execute("PRAGMA TABLE_INFO ("+tname+")")
        column = cursor.fetchall()
                
        conn.commit()
        conn.close()

    def searchData(self):
        item = self.listWidget.currentItem()

        conn = sqlite3.connect("WC_DB.db")
        cursor = conn.cursor()
        
        cursor.execute("PRAGMA TABLE_INFO ("+unicode(item.text())+")")
        column = cursor.fetchall()

        #cursor.execute("select * from "+unicode(item.text()))
        #data = cursor.fetchone()
        columnname = {}
        num = 0
        for i in column:
            lists = i
            for j in range(1,2):
                columnname[num] = lists[j]
                print columnname[num]
                num = num+1

        n=0
        self.TableWidget = QtGui.QTableWidget(100, 100)
        #for k in range(len(columnname)):
        for key in columnname:
            m=0
            #self.TableWidget = QtGui.QTableWidget(100, 100)
            newitem = QtGui.QTableWidgetItem(columnname[key])
            self.TableWidget.setItem(m, n, newitem)
            m = m+1
        n=n+1

        conn.commit()
        conn.close()
        
class VersionPopup(QtGui.QDialog):
    def __init__(self, parent=Window):
        super(VersionPopup, self).__init__(parent)

        self.label1 = QtGui.QLabel('                                      ', self)
        self.label1.move(130, 220)

        self.setWindowTitle('Version')
        self.resize(500, 300)

class WriterPopup(QtGui.QDialog):
    def __init__(self, parent=Window):
        super(WriterPopup, self).__init__(parent)

        self.label1 = QtGui.QLabel('                                      ', self)
        self.label1.move(130, 220)

        self.setWindowTitle('Writer')
        self.resize(500, 300)

class CollerterPopup(QtGui.QDialog):
    def __init__(self, parent=Window):
        super(CollerterPopup, self).__init__(parent)

        self.fname = None

        self.Filedirectory = QtGui.QLineEdit(self)
        self.Filedirectory.move(40, 80)
        self.Filedirectory.setFixedWidth(300)

        Browse = QtGui.QPushButton("Select Directory", self)
        Browse.move(380, 80)
        Browse.clicked.connect(self.selectDirecotry)

        self.IE_Checkbox = QtGui.QCheckBox('IE 10-- Collect', self)
        self.IE_Checkbox.move(60, 150)

        self.WC_Checkbox = QtGui.QCheckBox('IE 10++ Collect', self)
        self.WC_Checkbox.move(200, 150)

        self.Chrome_Checkbox = QtGui.QCheckBox('Chrome Collect', self)
        self.Chrome_Checkbox.move(330, 150)

        Collect = QtGui.QPushButton("Collect", self)
        Collect.move(300, 250)
        Collect.clicked.connect(self.CollectFile)

        Cancel = QtGui.QPushButton("Cancel", self)
        Cancel.move(400, 250)
        Cancel.clicked.connect(self.close)

        self.setWindowTitle('Collect')
        self.resize(500, 300)
    
    def selectDirecotry(self):
        self.fname = QtGui.QFileDialog.getExistingDirectory()

        if self.fname:
            self.Filedirectory.setText(str(self.fname))

    def CollectFile(self):
        if self.fname == None:
            self.notFileExist()
            return
        if self.IE_Checkbox.checkState() == QtCore.Qt.Unchecked & self.WC_Checkbox.checkState() == QtCore.Qt.Unchecked & self.Chrome_Checkbox.checkState() == QtCore.Qt.Unchecked:
            self.notCollect()
            return

        print self.fname
        mkdir(self.fname)
        if self.IE_Checkbox.checkState() == QtCore.Qt.Checked:
            IE9_copyfile(self.fname)
        if self.WC_Checkbox.checkState() == QtCore.Qt.Checked:
            IE10_copydb(self.fname)
        if self.Chrome_Checkbox.checkState() == QtCore.Qt.Checked:
            Chrome_copydb(self.fname)
            Chrome_dbrename(self.fname)

        self.CollectFinish()
        self.close()

    def CollectFinish(self):
        CollectFinish = QtGui.QMessageBox()
        CollectFinish.setText("Collect Finish!!")
        CollectFinish.exec_()

    def notFileExist(self):
        notfileExist = QtGui.QMessageBox()
        notfileExist.setText("file directory not exist")
        notfileExist.exec_()

    def notCollect(self):
        notcollect = QtGui.QMessageBox()
        notcollect.setText("Not Select Collect Version!!")
        notcollect.exec_()

class MyPopup(QtGui.QDialog):
    def __init__(self, parent=Window):
        super(MyPopup, self).__init__(parent)
        self.myWindow = parent
        self.fname = None
        self.timezone = 0

        self.Filedirectory = QtGui.QLineEdit(self)
        self.Filedirectory.move(40, 80)
        self.Filedirectory.setFixedWidth(300)

        Browse = QtGui.QPushButton("Select Directory", self)
        Browse.move(380, 80)
        Browse.clicked.connect(self.selectFile)

        Finish = QtGui.QPushButton("Analysis", self)
        Finish.move(290, 250)
        Finish.clicked.connect(self.Analysismethod)

        Cancel = QtGui.QPushButton("Cancel", self)
        Cancel.move(390, 250)
        Cancel.clicked.connect(self.close)
        
        self.combo = QtGui.QComboBox(self)
        self.combo.addItem("UTC + 00:00 : Ghana, Morocco, Togo")
        self.combo.addItem("UTC + 01:00 : Italy, Germany, Denmark")
        self.combo.addItem("UTC + 02:00 : Bulgaria, Egypt, Israel")
        self.combo.addItem("UTC + 03:00 : Iraq, Qatar, Saudi Arabia")
        self.combo.addItem("UTC + 03:30 : Iran")
        self.combo.addItem("UTC + 04:00 : Armenia")
        self.combo.addItem("UTC + 04:30 : Afghanista")
        self.combo.addItem("UTC + 05:00 : Maldives, Uzbekistan")
        self.combo.addItem("UTC + 05:30 : India, Sri Lanka")
        self.combo.addItem("UTC + 05:45 : Nepal")
        self.combo.addItem("UTC + 06:00 : Bhutan, Bangladesh")
        self.combo.addItem("UTC + 06:30 : Myanmar")
        self.combo.addItem("UTC + 07:00 : Cambodia, Laos, Vietnam")
        self.combo.addItem("UTC + 08:00 : China, Malaysia, Philippines")
        self.combo.addItem("UTC + 08:30 : North Korea")
        self.combo.addItem("UTC + 08:45 : Australia - Western Australia - Eucla")
        self.combo.addItem("UTC + 09:00 : South Korea, Japan")
        self.combo.addItem("UTC + 09:30 : Australia - Northern Territory")
        self.combo.addItem("UTC + 10:00 : Russia - Vladivostok Time, United States - Guam")
        self.combo.addItem("UTC + 10:30 : Australia - New South Wales - Lord Howe Island")
        self.combo.addItem("UTC + 11:00 : Russia - Srednekolymsk Time, Solomon Islands")
        self.combo.addItem("UTC + 12:00 : Fiji, Kiribati, Russia – Kamchatka Time")
        self.combo.addItem("UTC + 12:45 : New Zealand – Chatham Islands")
        self.combo.addItem("UTC + 13:00 : Kiribati, New Zealand,Samoa")
        self.combo.addItem("UTC + 14:00 : Kiribati")
        self.combo.addItem("UTC - 01:00 : Portugal - Azores islands, Cape Verde")
        self.combo.addItem("UTC - 02:00 : United Kingdom - South Georgia, Brazil - Fernando de Noronha")
        self.combo.addItem("UTC - 03:00 : Argentina, Chile")
        self.combo.addItem("UTC - 04:00 : Bolivia, Dominica, Paraguay")
        self.combo.addItem("UTC - 04:30 : Venezuela")
        self.combo.addItem("UTC - 05:00 : United States (Eastern Time Zone) - New York, Jamaica")
        self.combo.addItem("UTC - 06:00 : United States (Central Time Zone) – Illinois, Belize")
        self.combo.addItem("UTC - 07:00 : Canada (Mountain Time Zone) – Alberta, United States (Mountain Time Zone) - Arizona")
        self.combo.addItem("UTC - 09:00 : United States (Alaska Time Zone) - Alaska")
        self.combo.addItem("UTC - 09:30 : France French Polynesia - Marquesas Islands")
        self.combo.addItem("UTC - 10:00 : New Zealand - Cook Islands, United States (Hawaii-Aleutian Time Zone) - Hawaii")
        self.combo.addItem("UTC - 11:00 : United States – Hawaii, New Zealand - Niue")
        self.combo.addItem("UTC - 12:00 : United States Minor Outlying Islands - Baker Island")
        self.combo.setFixedWidth(410)

        self.combo.move(49, 150)
        """
        left = QtGui.QFrame(self)
        left.setFrameShape(QtGui.QFrame.StyledPanel)
        left.setGeometry(100, 200, 480, 300)
        
        self.label1 = QtGui.QLabel('                                      ', self)
        self.label1.move(130, 220)

        self.label2 = QtGui.QLabel('                                      ', self)
        self.label2.move(130, 260)
        
        self.label3 = QtGui.QLabel('                                      ', self)
        self.label3.move(330, 260)

        self.label4 = QtGui.QLabel('                                      ', self)
        self.label4.move(130, 300)

        self.label5 = QtGui.QLabel('                                      ', self)
        self.label5.move(290, 300)

        self.label6 = QtGui.QLabel('                                      ', self)
        self.label6.move(130, 340)

        self.label7 = QtGui.QLabel('                                      ', self)
        self.label7.move(330, 340)
        """

        self.setWindowTitle('Analysis')
        self.resize(500, 300)

    def setting_UTC(self):
        cindex = self.combo.currentIndex()
        ctext = self.combo.currentText()
        if (cindex) == 0:
            self.timezone = 0
        if (cindex) == 1:
            self.timezone = 1
        if (cindex) == 2:
            self.timezone = 2
        if (cindex) == 3:
            self.timezone = 3
        if (cindex) == 4:
            self.timezone = 3.5
        if (cindex) == 5:
            self.timezone = 4
        if (cindex) == 6:
            self.timezone = 4.5
        if (cindex) == 7:
            self.timezone = 5
        if (cindex) == 8:
            self.timezone = 5.5
        if (cindex) == 9:
            self.timezone = 5.75
        if (cindex) == 10:
            self.timezone = 6
        if (cindex) == 11:
            self.timezone = 6.5
        if (cindex) == 12:
            self.timezone = 7
        if (cindex) == 13:
            self.timezone = 8
        if (cindex) == 14:
            self.timezone = 8.5
        if (cindex) == 15:
            self.timezone = 8.75
        if (cindex) == 16:
            self.timezone = 9
        if (cindex) == 17:
            self.timezone = 9.5
        if (cindex) == 18:
            self.timezone = 10
        if (cindex) == 19:
            self.timezone = 10.5
        if (cindex) == 20:
            self.timezone = 11
        if (cindex) == 21:
            self.timezone = 12
        if (cindex) == 22:
            self.timezone = 12.75
        if (cindex) == 23:
            self.timezone = 13
        if (cindex) == 24:
            self.timezone = 14
        if (cindex) == 25:
            self.timezone = -1
        if (cindex) == 26:
            self.timezone = -2
        if (cindex) == 27:
            self.timezone = -3
        if (cindex) == 28:
            self.timezone = -4
        if (cindex) == 29:
            self.timezone = -4.5
        if (cindex) == 30:
            self.timezone = -5
        if (cindex) == 31:
            self.timezone = -6
        if (cindex) == 32:
            self.timezone = -7
        if (cindex) == 33:
            self.timezone = -9
        if (cindex) == 34:
            self.timezone = -9.5
        if (cindex) == 35:
            self.timezone = -10
        if (cindex) == 36:
            self.timezone = -11
        if (cindex) == 37:
            self.timezone = -12

    def selectFile(self):
        self.fname = QtGui.QFileDialog.getExistingDirectory()

        if self.fname:
            self.Filedirectory.setText(str(self.fname))
        """
            ese = ESENT_DB(self.fname)
            Catalog = ese.DBCatalog()
            self.label1.setText("CheckSum : 0x%x" % Catalog[0])
            self.label2.setText("File Type : 0x%x" % Catalog[1])
            self.label3.setText("DBState : 0x%x" % Catalog[2])
            self.label4.setText("Format ulVersion : 0x%x," % Catalog[3])
            self.label5.setText("0x%x" % Catalog[4])
            self.label6.setText("PageSize : %d" % Catalog[5])
            self.label7.setText("Number of pages : %d" % Catalog[6])
        """
    def Analysismethod(self):
        if self.fname == None:
            self.notExist()
            return
        
        self.close()
        WC_Data_Insert(self.fname)
        IE9parser(self.fname)
        IEDownloadparser(self.fname)
        Chrome_Parser(self.fname)
        self.setting_UTC()
        UWA_Parser(self.fname, self.timezone)
        SearchKey_Parser(self.fname)
        self.myWindow.method_call(self.fname)
        #Window.setting_WC_listWidget(Window, self.fname)
        #Window.setting_tablewidget(Window, self.fname)

    def notExist(self):
        notexist = QtGui.QMessageBox()
        notexist.setText("file directory not exist")
        notexist.exec_()

def main():                                     # main code
    app = QtGui.QApplication(sys.argv)
    myWindow = Window()
    sys.exit(app.exec_())                       # start main event loop

if __name__ == "__main__":
    main()