'''
Created on May 29, 2016

@author: bsipos
'''

from scapy import fields, volatile, packet
from . import sdnv

class UInt8Field(fields.Field):
    ''' Unsigned 8-bit value. '''
    def __init__(self, name, default):
        fields.Field.__init__(self, name, default, "!B")

class UInt16Field(fields.Field):
    ''' Unsigned 16-bit value. '''
    def __init__(self, name, default):
        fields.Field.__init__(self, name, default, '!H')

class UInt64Field(fields.Field):
    ''' Unsigned 64-bit value. '''
    def __init__(self, name, default):
        fields.Field.__init__(self, name, default, '!Q')

class UInt16FieldLenField(fields.FieldLenField):
    ''' Unsigned 16-bit value. '''
    def __init__(self, *args, **kwargs):
        kwargs['fmt'] = '!H'
        fields.FieldLenField.__init__(self, *args, **kwargs)

class UInt64FieldLenField(fields.FieldLenField):
    ''' Unsigned 64-bit value. '''
    def __init__(self, *args, **kwargs):
        kwargs['fmt'] = '!Q'
        fields.FieldLenField.__init__(self, *args, **kwargs)

class UInt32PayloadLenField(fields.LenField):
    ''' Unsigned 32-bit value. '''
    def __init__(self, *args, **kwargs):
        kwargs['fmt'] = '!I'
        fields.LenField.__init__(self, *args, **kwargs)

class SdnvField(fields.Field):
    ''' Represent a single independent SDNV-encoded integer.
    
    If the value/default is None the output is the zero-value SDNV.
    
    :param maxval: The maximum value allowed in this field.
        Warnings will be output if the actual value is above this limit
    '''
    def __init__(self, name, default, maxval=None):
        fields.Field.__init__(self, name, default, fmt='!s')
        if maxval is None:
            maxval = 2L**32-1
        self._maxval = maxval
    
    def i2m(self, pkt, x):
        ''' Convert internal-to-machine encoding. '''
        if x is None:
            x = 0
        return sdnv.int2sdnv(x)
    
    def m2i(self, pkt, x):
        ''' Convert machine-to-internal encoding. '''
        if x is None:
            return None, 0
        return sdnv.sdnv2int(x)[1]
    
    def addfield(self, pkt, s, val):
        ''' Append this field to a packet contents. '''
        return s+self.i2m(pkt, val)
    
    def getfield(self, pkt, s):
        ''' Extract this field from a packet contents. '''
        return sdnv.sdnv2int(s)
    
    def randval(self):
        return volatile.RandNum(0, self._maxval)

class SdnvPayloadLenField(SdnvField):
    ''' An SDNV value which represents the octet length of the payload data.
    '''
    def i2m(self, pkt, x):
        if x is None:
            x = len(pkt.payload)
        return SdnvField.i2m(self, pkt, x)

class SdnvFieldLenField(SdnvField):
    ''' An SDNV value which represents a count/length of another field.
    '''
    def __init__(self, name, default=None, count_of=None, length_of=None, adjust=None):
        SdnvField.__init__(self, name, default)
        if length_of:
            def func(pkt):
                fld,fval = pkt.getfield_and_val(length_of)
                val = fld.i2len(pkt, fval)
                return val
            self.extract = func
        elif count_of:
            def func(pkt):
                fld,fval = pkt.getfield_and_val(count_of)
                val = fld.i2count(pkt, fval)
                return val
            self.extract = func
        else:
            raise ValueError('One of length_of or count_of is required')
        
        if adjust is None:
            adjust = lambda pkt,x: x
        self.adjust = adjust
    
    def i2h(self, pkt, x):
        ''' override to extract value from packet '''
        if x is None:
            x = self.extract(pkt)
            x = self.adjust(pkt,x)
        return x
    
    def i2m(self, pkt, x):
        ''' override to extract value from packet '''
        if x is None:
            x = self.extract(pkt)
            x = self.adjust(pkt,x)
        return SdnvField.i2m(self, pkt, x)

#class BlobField(fields.StrFixedLenField):
class BlobField(fields.StrLenField):
    ''' Overload i2h and i2repr to hide the actual data contents. '''
    
    def i2h(self, pkt, x):
        if not x:
            lenstr = 'empty'
        else:
            lenstr = '{0} octets'.format(len(x))
        return '({0})'.format(lenstr)
    
    def i2repr(self, pkt, x):
        return self.i2h(pkt, x)

class NoPayloadPacket(packet.Packet):
    ''' A packet which never contains payload data.
    '''
    def extract_padding(self, s):
        ''' No payload, all extra data is padding '''
        return (None, s)

def remove_padding(pkt):
    ''' Traverse a packet and remove any trailing padding payload.
    
    :param pkt: The root packet to traverse.
    '''
    testload = pkt.payload
    while True:
        if testload is None or isinstance(testload, packet.NoPayload):
            break
        if isinstance(testload, packet.Padding):
            testload.underlayer.remove_payload()
            break
        
        testload = testload.payload
