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

import sys, sqlite3, csv, sys, os, urllib, codecs
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

	if os.path.isdir('C:\Users\%s\AppData\Local\Microsoft\Windows\WebCache'%username) :
		os.chdir('C:\Users\%s\AppData\Local\Microsoft\Windows\WebCache'%username)
		os.system('esentutl /r V01 /d')
		os.system('esentutl /y WebCacheV01.dat /d %s'%fname+'\\UWA_%s'%timestamp+"\\collection\\IE10++\\WebCacheV01.dat")
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
    
    os.chdir('C:\Users\%s\AppData\Local\Google\Chrome\User Data\Default\Cache'%username)
    cache_files = os.listdir('./')
    #for files in range(len(cache_files)) :
    #    shutil.copy2(cache_files[files], "%s"%fname+"\\UWA_%s"%timestamp+"\\collection\\Chrome\\Cache")
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

def WindowTimeConverter(gmt,time):
    gmt =0 
    return datetime(1601, 1, 1) + timedelta(microseconds=int(time, 16) / 10.) + timedelta(hours=gmt)

def IE9parser(fname):
    if os.path.isfile('%s'%fname+"\\collection\\IE10--\\index_cache.dat"):
        filepath = '%s'%fname+"\\collection\\IE10--\\index_cache.dat"
        con = sqlite3.connect(fname+"\\IE9parser.db")
        cursor = con.cursor()
        if filepath == "index_hisotry.dat":
            cursor.execute("CREATE TABLE Hisotry(URL text, AccessedTime text,CreateTime text)")
        if filepath == "index_cache.dat":
            cursor.execute("CREATE TABLE Cache(URL text, AccessedTime text,CreateTime text)")
        if filepath == "index_cookies.dat":
            cursor.execute("CREATE TABLE Cookies(URL text, AccessedTime text,CreateTime text)")
        index=0
        gdata = {}

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

                if filepath == "index_hisotry.dat":
                    cursor.execute("INSERT INTO History VALUES(?,?,?)", ([gdata[index],timedata,Create_time_data]))
                if filepath == "index_cache.dat":
                    cursor.execute("INSERT INTO Cache VALUES(?,?,?)", ([gdata[index],timedata,Create_time_data]))
                if filepath == "index_cookies.dat":
                    cursor.execute("INSERT INTO Cookies VALUES(?,?,?)", ([gdata[index],timedata,Create_time_data]))
                index = index+1
                #print index
                #index=index+1
            con.commit()
            con.close()

def IEDownloadparser(fname):
    if os.path.isfile('%s'%fname+"\\collection\\IE10--\\index_download.dat"):
        filepath = '%s'%fname+"\\collection\\IE10--\\index_download.dat"
        con = sqlite3.connect(fname+"\\IE9DownLoadParsers.db")
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
            
                cursor.execute("INSERT INTO Downlist VALUES(?,?,?)", (final_data,Create_time_data,file_size))

                index = index+1
                #print index
                #index=index+1
            con.commit()
            con.close()

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
        print ("finish")
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
        conn = sqlite3.connect("WC_DB.db")
        cursor = conn.cursor()
        #appcache , appcacheentry , containers, dependency entry,

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
                            if data.find(head_naver) >= 0:
                                separate=data.split('&')
                                for i in range(0,len(separate)):
                                    if separate[i].find('query=') == 0:
                                        keyword_naver = separate[i][6:]
                                        print urllib.unquote(str(unicode(keyword_naver))).decode('utf8').replace('+',' ')
                                        #print "key",urllib.unquote(str(unicode(keyword_naver))).decode('utf8')
                                        #print "s",urllib.unquote(keyword_naver).encode('utf-8').decode('utf-8').decode('utf-8').replace('+',' ')
                                        break
                            elif data.find(head_daum) >= 0:
                                separate=data.split('&')
                                for i in range(0,len(separate)):
                                    if separate[i].find('q=') == 0:
                                        keyword_daum = separate[i][2:]
                                        print urllib.unquote(str(unicode(keyword_daum))).decode('utf8').replace('+',' ')
                                        break
                            elif data.find(head_google) >= 0:
                                separate=data.replace('?','&').split('&')
                                for i in range(len(separate)-1,0,-1):
                                    if separate[i].find('q=')==0 & ~separate[i].find('oq='):
                                        keyword_google = separate[i][2:]
                                        print urllib.unquote(str(unicode(keyword_google))).decode('utf8').replace('+',' ')
                                        break
                    continue;
                DependencyEntry_ = tablenamelist.find("DependencyEntry_")
                if DependencyEntry_ >= 0:
                    cursor.execute("select Url from "+tablenamelist+"")
                    Urldata = cursor.fetchall()
                    for temp in Urldata:
                        for data in temp:
                            if data.find(head_naver) >= 0:
                                separate=data.split('&')
                                for i in range(0,len(separate)):
                                    if separate[i].find('query=') == 0:
                                        keyword_naver = separate[i][6:]
                                        print urllib.unquote(str(unicode(keyword_naver))).decode('utf8').replace('+',' ')
                                        #print "key",urllib.unquote(str(unicode(keyword_naver))).decode('utf8')
                                        #print "s",urllib.unquote(keyword_naver).encode('utf-8').decode('utf-8').decode('utf-8').replace('+',' ')
                                        break
                            elif data.find(head_daum) >= 0:
                                separate=data.split('&')
                                for i in range(0,len(separate)):
                                    if separate[i].find('q=') == 0:
                                        keyword_daum = separate[i][2:]
                                        print urllib.unquote(str(unicode(keyword_daum))).decode('utf8').replace('+',' ')
                                        break
                            elif data.find(head_google) >= 0:
                                separate=data.replace('?','&').split('&')
                                for i in range(len(separate)-1,0,-1):
                                    if separate[i].find('q=')==0 & ~separate[i].find('oq='):
                                        keyword_google = separate[i][2:]
                                        print urllib.unquote(str(unicode(keyword_google))).decode('utf8').replace('+',' ')
                                        break
                    continue;
                AppCache_ = tablenamelist.find("AppCache_")
                if AppCache_ >= 0:
                    cursor.execute("select Url from "+tablenamelist+"")
                    Urldata = cursor.fetchall()
                    for temp in Urldata:
                        for data in temp:
                            if data.find(head_naver) >= 0:
                                separate=data.split('&')
                                for i in range(0,len(separate)):
                                    if separate[i].find('query=') == 0:
                                        keyword_naver = separate[i][6:]
                                        print urllib.unquote(str(unicode(keyword_naver))).decode('utf8').replace('+',' ')
                                        #print "key",urllib.unquote(str(unicode(keyword_naver))).decode('utf8')
                                        #print "s",urllib.unquote(keyword_naver).encode('utf-8').decode('utf-8').decode('utf-8').replace('+',' ')
                                        break
                            elif data.find(head_daum) >= 0:
                                separate=data.split('&')
                                for i in range(0,len(separate)):
                                    if separate[i].find('q=') == 0:
                                        keyword_daum = separate[i][2:]
                                        print urllib.unquote(str(unicode(keyword_daum))).decode('utf8').replace('+',' ')
                                        break
                            elif data.find(head_google) >= 0:
                                separate=data.replace('?','&').split('&')
                                for i in range(len(separate)-1,0,-1):
                                    if separate[i].find('q=')==0 & ~separate[i].find('oq='):
                                        keyword_google = separate[i][2:]
                                        print urllib.unquote(str(unicode(keyword_google))).decode('utf8').replace('+',' ')
                                        break
                    continue;
                AppCacheEntry_ = tablenamelist.find("AppCacheEntry_")
                if AppCacheEntry_ >= 0:
                    cursor.execute("select Url from "+tablenamelist+"")
                    Urldata = cursor.fetchall()
                    for temp in Urldata:
                        for data in temp:
                            if data.find(head_naver) >= 0:
                                separate=data.split('&')
                                for i in range(0,len(separate)):
                                    if separate[i].find('query=') == 0:
                                        keyword_naver = separate[i][6:]
                                        print urllib.unquote(str(unicode(keyword_naver))).decode('utf8').replace('+',' ')
                                        #print "key",urllib.unquote(str(unicode(keyword_naver))).decode('utf8')
                                        #print "s",urllib.unquote(keyword_naver).encode('utf-8').decode('utf-8').decode('utf-8').replace('+',' ')
                                        break
                            elif data.find(head_daum) >= 0:
                                separate=data.split('&')
                                for i in range(0,len(separate)):
                                    if separate[i].find('q=') == 0:
                                        keyword_daum = separate[i][2:]
                                        print urllib.unquote(str(unicode(keyword_daum))).decode('utf8').replace('+',' ')
                                        break
                            elif data.find(head_google) >= 0:
                                separate=data.replace('?','&').split('&')
                                for i in range(len(separate)-1,0,-1):
                                    if separate[i].find('q=')==0 & ~separate[i].find('oq='):
                                        keyword_google = separate[i][2:]
                                        print urllib.unquote(str(unicode(keyword_google))).decode('utf8').replace('+',' ')
                                        break
                    continue;
                
        conn.commit()
        conn.close()

class Window(QtGui.QMainWindow):
    def __init__(self, parent=None):                                                             # init
        super(Window, self).__init__(parent)
        
        self.fdirectory = None
        self.initUI()

    def initUI(self):
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

        self.setting_Indexdat_listWidget()
        self.setting_WC_listWidget()
        self.setting_Indexdat_tablewidget()
        self.setting_WC_tablewidget()
        self.Indexdat_listWidget.itemClicked.connect(self.resetting_Indexdat_tablewidget)
        self.WC_listWidget.itemClicked.connect(self.resetting_WC_tablewidget)
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

        self.splitter2 = QtGui.QSplitter(QtCore.Qt.Horizontal)
        self.splitter2.addWidget(self.second_listWidget)
        self.splitter2.addWidget(self.second_TableWidget)

        self.second_Hlayout.addWidget(self.splitter2)

        self.second_widget = QtGui.QWidget(self)
        self.second_widget.setLayout(self.second_Hlayout)

        #third Tab UI Setting
        self.third_Vlayout = QtGui.QVBoxLayout()
        self.third_Hlayout = QtGui.QHBoxLayout()

        self.third_Frame = QtGui.QFrame()
        self.third_Frame.setFrameShape(QtGui.QFrame.StyledPanel)

        self.third_Hlayout.addWidget(self.third_Frame)

        self.third_widget = QtGui.QWidget(self)
        self.third_widget.setLayout(self.third_Hlayout)

        self.TabWidget.addTab(self.main_widget, "Raw")
        self.TabWidget.addTab(self.second_widget, "Analysis")
        self.TabWidget.addTab(self.third_widget, "Search Word")

        #UI start
        self.setCentralWidget(self.TabWidget)
                
        #exitAction = QtGui.QAction(QtGui.QIcon('exit.png'), '&Exit', self)              # MenuBar Setting
        exitAction = QtGui.QAction('&Exit', self)
        exitAction.setShortcut('Ctrl+Q')
        exitAction.setStatusTip('Exit')
        exitAction.triggered.connect(self.close)

        AnalysisAction = QtGui.QAction(QtGui.QIcon('Analysis.png'), '&Analysis', self)
        AnalysisAction.setShortcut('Ctrl+A')
        AnalysisAction.setStatusTip('Data Analysis')
        AnalysisAction.triggered.connect(self.Analysisopen)
        
        CollectAction = QtGui.QAction('&Collect', self)
        CollectAction.setShortcut('Ctrl+C')
        CollectAction.setStatusTip('Web Data Collect')
        CollectAction.triggered.connect(self.Collecteropen)

        FilterAction = QtGui.QAction('&Filter', self)
        FilterAction.setShortcut('Ctrl+F')
        FilterAction.setStatusTip('Data Filtering')
        FilterAction.triggered.connect(self.Filter)

        ColumnAction = QtGui.QAction('&Column', self)
        ColumnAction.setShortcut('Ctrl+S')
        ColumnAction.setStatusTip('Table Column Setting')
        #CollectAction.triggered.connect(self.Collecteropen)

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
        fileMenu.addAction(exitAction)
        fileMenu = menubar.addMenu('&Tool')
        fileMenu.addAction(CollectAction)
        fileMenu.addAction(AnalysisAction)
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

    def Filter(self):
        text, ok = QtGui.QInputDialog.getText(self, 'Input Dialog', 
            'Enter Search Word:')

        if ok:
            item = self.listWidget.currentItem()
            print (unicode(item.text()))

    def Column_setting(self):
        print "ss"

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

    def setting_WC_listWidget(self):
        #self.listWidget.clear()
        print ("ss")
        if os.path.isfile("WC_DB.db"):
            print ("os")
            self.listname = self.searchTable()
            r=0
            for listindex in self.listname:
                print listindex
                for item in self.listname[listindex]:
                    print item
                    newlist = QtGui.QListWidgetItem(item)
                    self.WC_listWidget.addItem(newlist)

    def setting_Indexdat_tablewidget(self):
        if os.path.isfile("IE9parser.db"):
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
            #SearchKey_Parser()
            self.TableWidget.clear()
            #item = self.listWidget.currentItem()
            #print (unicode(item.text()))

            conn = sqlite3.connect("IE9parser.db")
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

    def setting_WC_tablewidget(self):
        if os.path.isfile("WC_DB.db"):
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
            #SearchKey_Parser()
            self.TableWidget.clear()
            #item = self.listWidget.currentItem()
            #print (unicode(item.text()))

            conn = sqlite3.connect("WC_DB.db")
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

    def resetting_Indexdat_tablewidget(self):
        if os.path.isfile("IE9parser.db"):
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

            conn = sqlite3.connect("IE9parser.db")
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
                    
    def resetting_WC_tablewidget(self):
        if os.path.isfile("WC_DB.db"):
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

            conn = sqlite3.connect("WC_DB.db")
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

    def IndexdatsearchTable(self):
        conn = sqlite3.connect("IE9parser.db")
        cursor = conn.cursor()

        list = {}
        num = 0

        cursor.execute("SELECT name FROM sqlite_master WHERE type IN ('table', 'view') AND name NOT LIKE 'sqlite_%' UNION ALL SELECT name FROM sqlite_temp_master WHERE type IN ('table', 'view') ORDER BY 1")
        name = cursor.fetchall()
        print name
        for i in name:
            list[num] = i
            num = num+1

        conn.commit()
        conn.close()

        return list

    def searchTable(self):
        conn = sqlite3.connect("WC_DB.db")
        cursor = conn.cursor()

        list = {}
        num = 0

        cursor.execute("SELECT name FROM sqlite_master WHERE type IN ('table', 'view') AND name NOT LIKE 'sqlite_%' UNION ALL SELECT name FROM sqlite_temp_master WHERE type IN ('table', 'view') ORDER BY 1")
        name = cursor.fetchall()
        print name
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
        print (tname)
        cursor.execute("PRAGMA TABLE_INFO ("+tname+")")
        column = cursor.fetchall()
                
        conn.commit()
        conn.close()

    def searchData(self):
        item = self.listWidget.currentItem()
        print (unicode(item.text()))

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
            print (columnname[key])
            m=0
            #self.TableWidget = QtGui.QTableWidget(100, 100)
            newitem = QtGui.QTableWidgetItem(columnname[key])
            print (newitem)
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
            print "ie success"
        if self.WC_Checkbox.checkState() == QtCore.Qt.Checked:
            #IE10_copydb(self.fname)
            print "wc success"
        if self.Chrome_Checkbox.checkState() == QtCore.Qt.Checked:
            Chrome_copydb(self.fname)
            Chrome_dbrename(self.fname)
            print "ch success"

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
        
        self.fname = None

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
        
        combo = QtGui.QComboBox(self)
        combo.addItem("1")
        combo.addItem("2")
        combo.addItem("3")
        combo.addItem("4")
        combo.addItem("5")
        combo.setFixedWidth(410)

        combo.move(49, 150)
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
        IEDownloadparser(self.fname)
        IE9parser(self.fname)
        #Window.setting_Indexdat_listWidget(Window, self.fname)
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