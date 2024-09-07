#!/usr/bin/env python
from ipaddress import IPv4Address, IPv6Address
from ipaddress import IPv4Network, IPv6Network
from collections import OrderedDict
from copy import copy
import struct
import binascii
import base64
import os
import sys
import logging
import yaml
import argparse
import hashlib
import select
import socket
import time
import hmac
try:
    import secrets
    random_generator = secrets.SystemRandom()
except ImportError:
    import random
    random_generator = random.SystemRandom()

if sys.version_info >= (3, 0):
    hmac_new = lambda *x, **y: hmac.new(*x, digestmod='MD5', **y)
else:
    hmac_new = hmac.new

try:
    import hashlib
    md5_constructor = hashlib.md5
except ImportError:
    # BBB for python 2.4
    import md5
    md5_constructor = md5.new

def main():
    vendor = 812300
    parser = argparse.ArgumentParser(
        prog='Auth RADIUS',
        description='Home Assistant RADIUS authentication via CLI',
        epilog='https://github.com/Losenmann/auth-radius'
    )
    parser.add_argument('-m', '--meta', action='store_true', help='enable meta to output credentials to stdout')
    parser.add_argument('-U', '--username', type=str, help='username')
    parser.add_argument('-P', '--password', type=str, help='user password')
    parser.add_argument('-s', '--server', type=str, help='RADIUS server')
    parser.add_argument('-S', '--secret', type=str, help='RADIUS secret')
    args = parser.parse_args()

    if not os.path.isfile("/config/.storage/dictionary.radius"):
        if not args.meta:
            print("Create dictionary file")
        f = open("/config/.storage/dictionary.radius", "w")
        f.write(base64.b64decode(DictFileBase64()).decode("utf-8"))
        f.close()

    with open("/config/secrets.yaml") as fh:
        secret = yaml.load(fh, Loader=yaml.FullLoader)
    try:
        v_username = args.username if args.username else os.environ['username']
    except:
        print("\033[33m{}\033[0m".format("Username not specified"))
        sys.exit(1)
    try:
        v_password = args.password if args.password else os.environ['password']
    except:
        print("\033[33m{}\033[0m".format("User password not specified"))
        sys.exit(1)
    try:
        v_server = args.server if args.server else secret['radius_server']
    except:
        print("\033[33m{}\033[0m".format("Server not specified"))
        sys.exit(1)
    try:
        v_secret = args.secret if args.secret else secret['radius_secret']
    except:
        print("\033[33m{}\033[0m".format("Server secret not specified"))
        sys.exit(1)

    srv = Client(
        server=bytes(v_server, encoding="utf-8"),
        secret=bytes(v_secret, encoding="utf-8"),
        dict=Dictionary("/config/.storage/dictionary.radius")
    )

    req = srv.CreateAuthPacket(code=AccessRequest)
    req["User-Name"] = v_username
    req["User-Password"] = req.PwCrypt(v_password)

    try:
        if not args.meta:
            print("Sending authentication request")
        reply = srv.SendPacket(req)
    except Timeout:
        if not args.meta:
            print("RADIUS server does not reply")
        sys.exit(1)
    except socket.error as error:
        if not args.meta:
            print("Network error: " + error[1])
        sys.exit(1)

    if reply.code == AccessAccept:
        if reply[(vendor, 1)][0].decode("utf-8") in ['system-admin', 'system-users']:
            v_local_only = "false"
            if int(reply[(vendor, 2)][0].hex(), 16) > 0:
                v_local_only = "true"
            if args.meta:
                print("name=" + req["User-Name"][0])
                print("group=" + reply[(vendor, 1)][0].decode("utf-8"))
                print("local_only=" + v_local_only)
                print("is_activ=" + "true")
            else:
                print("\033[32m{}\033[0m".format("Access accepted"))
            exit(0)
        else:
            if not args.meta:
                print("\033[31m{}\033[0m".format("Insufficient access rights"))
    else:
        if not args.meta:
            print("\033[31m{}\033[0m".format("Access denied"))
        exit(1)

"""bidict.py"""
class BiDict(object):
    def __init__(self):
        self.forward = {}
        self.backward = {}

    def Add(self, one, two):
        self.forward[one] = two
        self.backward[two] = one

    def __len__(self):
        return len(self.forward)

    def __getitem__(self, key):
        return self.GetForward(key)

    def __delitem__(self, key):
        if key in self.forward:
            del self.backward[self.forward[key]]
            del self.forward[key]
        else:
            del self.forward[self.backward[key]]
            del self.backward[key]

    def GetForward(self, key):
        return self.forward[key]

    def HasForward(self, key):
        return key in self.forward

    def GetBackward(self, key):
        return self.backward[key]

    def HasBackward(self, key):
        return key in self.backward

"""host.py"""
class Host(object):
    """Generic RADIUS capable host.

    :ivar     dict: RADIUS dictionary
    :type     dict: pyrad.dictionary.Dictionary
    :ivar authport: port to listen on for authentication packets
    :type authport: integer
    :ivar acctport: port to listen on for accounting packets
    :type acctport: integer
    """
    def __init__(self, authport=1812, acctport=1813, coaport=3799, dict=None):
        """Constructor

        :param authport: port to listen on for authentication packets
        :type  authport: integer
        :param acctport: port to listen on for accounting packets
        :type  acctport: integer
        :param coaport: port to listen on for CoA packets
        :type  coaport: integer
        :param     dict: RADIUS dictionary
        :type      dict: pyrad.dictionary.Dictionary
        """
        self.dict = dict
        self.authport = authport
        self.acctport = acctport
        self.coaport = coaport

    def CreatePacket(self, **args):
        """Create a new RADIUS packet.
        This utility function creates a new RADIUS authentication
        packet which can be used to communicate with the RADIUS server
        this client talks to. This is initializing the new packet with
        the dictionary and secret used for the client.

        :return: a new empty packet instance
        :rtype:  pyrad.packet.Packet
        """
        return Packet(dict=self.dict, **args)

    def CreateAuthPacket(self, **args):
        """Create a new authentication RADIUS packet.
        This utility function creates a new RADIUS authentication
        packet which can be used to communicate with the RADIUS server
        this client talks to. This is initializing the new packet with
        the dictionary and secret used for the client.

        :return: a new empty packet instance
        :rtype:  pyrad.packet.AuthPacket
        """
        return AuthPacket(dict=self.dict, **args)

    def CreateAcctPacket(self, **args):
        """Create a new accounting RADIUS packet.
        This utility function creates a new accounting RADIUS packet
        which can be used to communicate with the RADIUS server this
        client talks to. This is initializing the new packet with the
        dictionary and secret used for the client.

        :return: a new empty packet instance
        :rtype:  pyrad.packet.AcctPacket
        """
        return AcctPacket(dict=self.dict, **args)

    def CreateCoAPacket(self, **args):
        """Create a new CoA RADIUS packet.
        This utility function creates a new CoA RADIUS packet
        which can be used to communicate with the RADIUS server this
        client talks to. This is initializing the new packet with the
        dictionary and secret used for the client.

        :return: a new empty packet instance
        :rtype:  pyrad.packet.CoAPacket
        """
        return CoAPacket(dict=self.dict, **args)

    def SendPacket(self, fd, pkt):
        """Send a packet.

        :param fd: socket to send packet with
        :type  fd: socket class instance
        :param pkt: packet to send
        :type  pkt: Packet class instance
        """
        fd.sendto(pkt.Packet(), pkt.source)

    def SendReplyPacket(self, fd, pkt):
        """Send a packet.

        :param fd: socket to send packet with
        :type  fd: socket class instance
        :param pkt: packet to send
        :type  pkt: Packet class instance
        """
        fd.sendto(pkt.ReplyPacket(), pkt.source)

"""tool.py"""
def EncodeString(origstr):
    if len(origstr) > 253:
        raise ValueError('Can only encode strings of <= 253 characters')
    if isinstance(origstr, str):
        return origstr.encode('utf-8')
    else:
        return origstr

def EncodeOctets(octetstring):
    # Check for max length of the hex encoded with 0x prefix, as a sanity check
    if len(octetstring) > 508:
        raise ValueError('Can only encode strings of <= 253 characters')

    if isinstance(octetstring, bytes) and octetstring.startswith(b'0x'):
        hexstring = octetstring.split(b'0x')[1]
        encoded_octets = binascii.unhexlify(hexstring)
    elif isinstance(octetstring, str) and octetstring.startswith('0x'):
        hexstring = octetstring.split('0x')[1]
        encoded_octets = binascii.unhexlify(hexstring)
    elif isinstance(octetstring, str) and octetstring.isdecimal():
        encoded_octets = struct.pack('>L',int(octetstring)).lstrip((b'\x00'))
    else:
        encoded_octets = octetstring

    # Check for the encoded value being longer than 253 chars
    if len(encoded_octets) > 253:
        raise ValueError('Can only encode strings of <= 253 characters')

    return encoded_octets

def EncodeAddress(addr):
    if not isinstance(addr, str):
        raise TypeError('Address has to be a string')
    return IPv4Address(addr).packed

def EncodeIPv6Prefix(addr):
    if not isinstance(addr, str):
        raise TypeError('IPv6 Prefix has to be a string')
    ip = IPv6Network(addr)
    return struct.pack('2B', *[0, ip.prefixlen]) + ip.ip.packed

def EncodeIPv6Address(addr):
    if not isinstance(addr, str):
        raise TypeError('IPv6 Address has to be a string')
    return IPv6Address(addr).packed

def EncodeAscendBinary(orig_str):
    """
    Format: List of type=value pairs separated by spaces.

    Example: 'family=ipv4 action=discard direction=in dst=10.10.255.254/32'

    Note: redirect(0x20) action is added for http-redirect (walled garden) use case

    Type:
        family      ipv4(default) or ipv6
        action      discard(default) or accept or redirect
        direction   in(default) or out
        src         source prefix (default ignore)
        dst         destination prefix (default ignore)
        proto       protocol number / next-header number (default ignore)
        sport       source port (default ignore)
        dport       destination port (default ignore)
        sportq      source port qualifier (default 0)
        dportq      destination port qualifier (default 0)

    Source/Destination Port Qualifier:
        0   no compare
        1   less than
        2   equal to
        3   greater than
        4   not equal to
    """

    terms = {
        'family':       b'\x01',
        'action':       b'\x00',
        'direction':    b'\x01',
        'src':          b'\x00\x00\x00\x00',
        'dst':          b'\x00\x00\x00\x00',
        'srcl':         b'\x00',
        'dstl':         b'\x00',
        'proto':        b'\x00',
        'sport':        b'\x00\x00',
        'dport':        b'\x00\x00',
        'sportq':       b'\x00',
        'dportq':       b'\x00'
    }

    family = 'ipv4'
    for t in orig_str.split(' '):
        key, value = t.split('=')
        if key == 'family' and value == 'ipv6':
            family = 'ipv6'
            terms[key] = b'\x03'
            if terms['src'] == b'\x00\x00\x00\x00':
                terms['src'] = 16 * b'\x00'
            if terms['dst'] == b'\x00\x00\x00\x00':
                terms['dst'] = 16 * b'\x00'
        elif key == 'action' and value == 'accept':
            terms[key] = b'\x01'
        elif key == 'action' and value == 'redirect':
            terms[key] = b'\x20'
        elif key == 'direction' and value == 'out':
            terms[key] = b'\x00'
        elif key == 'src' or key == 'dst':
            if family == 'ipv4':
                ip = IPv4Network(value)
            else:
                ip = IPv6Network(value)
            terms[key] = ip.network_address.packed
            terms[key+'l'] = struct.pack('B', ip.prefixlen)
        elif key == 'sport' or key == 'dport':
            terms[key] = struct.pack('!H', int(value))
        elif key == 'sportq' or key == 'dportq' or key == 'proto':
            terms[key] = struct.pack('B', int(value))

    trailer = 8 * b'\x00'

    result = b''.join((terms['family'], terms['action'], terms['direction'], b'\x00',
        terms['src'], terms['dst'], terms['srcl'], terms['dstl'], terms['proto'], b'\x00',
        terms['sport'], terms['dport'], terms['sportq'], terms['dportq'], b'\x00\x00', trailer))
    return result

def EncodeInteger(num, format='!I'):
    try:
        num = int(num)
    except:
        raise TypeError('Can not encode non-integer as integer')
    return struct.pack(format, num)

def EncodeInteger64(num, format='!Q'):
    try:
        num = int(num)
    except:
        raise TypeError('Can not encode non-integer as integer64')
    return struct.pack(format, num)

def EncodeDate(num):
    if not isinstance(num, int):
        raise TypeError('Can not encode non-integer as date')
    return struct.pack('!I', num)

def DecodeString(orig_str):
    return orig_str.decode('utf-8')

def DecodeOctets(orig_bytes):
    return orig_bytes

def DecodeAddress(addr):
    return '.'.join(map(str, struct.unpack('BBBB', addr)))

def DecodeIPv6Prefix(addr):
    addr = addr + b'\x00' * (18-len(addr))
    _, length, prefix = ':'.join(map('{0:x}'.format, struct.unpack('!BB'+'H'*8, addr))).split(":", 2)
    return str(IPv6Network("%s/%s" % (prefix, int(length, 16))))

def DecodeIPv6Address(addr):
    addr = addr + b'\x00' * (16-len(addr))
    prefix = ':'.join(map('{0:x}'.format, struct.unpack('!'+'H'*8, addr)))
    return str(IPv6Address(prefix))

def DecodeAscendBinary(orig_bytes):
    return orig_bytes

def DecodeInteger(num, format='!I'):
    return (struct.unpack(format, num))[0]

def DecodeInteger64(num, format='!Q'):
    return (struct.unpack(format, num))[0]

def DecodeDate(num):
    return (struct.unpack('!I', num))[0]

def EncodeAttr(datatype, value):
    if datatype == 'string':
        return EncodeString(value)
    elif datatype == 'octets':
        return EncodeOctets(value)
    elif datatype == 'integer':
        return EncodeInteger(value)
    elif datatype == 'ipaddr':
        return EncodeAddress(value)
    elif datatype == 'ipv6prefix':
        return EncodeIPv6Prefix(value)
    elif datatype == 'ipv6addr':
        return EncodeIPv6Address(value)
    elif datatype == 'abinary':
        return EncodeAscendBinary(value)
    elif datatype == 'signed':
        return EncodeInteger(value, '!i')
    elif datatype == 'short':
        return EncodeInteger(value, '!H')
    elif datatype == 'byte':
        return EncodeInteger(value, '!B')
    elif datatype == 'date':
        return EncodeDate(value)
    elif datatype == 'integer64':
        return EncodeInteger64(value)
    else:
        raise ValueError('Unknown attribute type %s' % datatype)

def DecodeAttr(datatype, value):
    if datatype == 'string':
        return DecodeString(value)
    elif datatype == 'octets':
        return DecodeOctets(value)
    elif datatype == 'integer':
        return DecodeInteger(value)
    elif datatype == 'ipaddr':
        return DecodeAddress(value)
    elif datatype == 'ipv6prefix':
        return DecodeIPv6Prefix(value)
    elif datatype == 'ipv6addr':
        return DecodeIPv6Address(value)
    elif datatype == 'abinary':
        return DecodeAscendBinary(value)
    elif datatype == 'signed':
        return DecodeInteger(value, '!i')
    elif datatype == 'short':
        return DecodeInteger(value, '!H')
    elif datatype == 'byte':
        return DecodeInteger(value, '!B')
    elif datatype == 'date':
        return DecodeDate(value)
    elif datatype == 'integer64':
        return DecodeInteger64(value)
    else:
        raise ValueError('Unknown attribute type %s' % datatype)

"""dictfile.py"""
class _Node(object):
    __slots__ = ('name', 'lines', 'current', 'length', 'dir')

    def __init__(self, fd, name, parentdir):
        self.lines = fd.readlines()
        self.length = len(self.lines)
        self.current = 0
        self.name = os.path.basename(name)
        path = os.path.dirname(name)
        if os.path.isabs(path):
            self.dir = path
        else:
            self.dir = os.path.join(parentdir, path)

    def Next(self):
        if self.current >= self.length:
            return None
        self.current += 1
        return self.lines[self.current - 1]


class DictFile(object):
    """Dictionary file class

    An iterable file type that handles $INCLUDE
    directives internally.
    """
    __slots__ = ('stack')

    def __init__(self, fil):
        """
        @param fil: a dictionary file to parse
        @type fil: string or file
        """
        self.stack = []
        self.__ReadNode(fil)

    def __ReadNode(self, fil):
        parentdir = self.__CurDir()
        if isinstance(fil, str):
            if os.path.isabs(fil):
                fname = fil
            else:
                fname = os.path.join(parentdir, fil)
            fd = open(fname, "rt")
            node = _Node(fd, fil, parentdir)
            fd.close()
        else:
            node = _Node(fil, '', parentdir)
        self.stack.append(node)

    def __CurDir(self):
        if self.stack:
            return self.stack[-1].dir
        else:
            return os.path.realpath(os.curdir)

    def __GetInclude(self, line):
        line = line.split("#", 1)[0].strip()
        tokens = line.split()
        if tokens and tokens[0].upper() == '$INCLUDE':
            return " ".join(tokens[1:])
        else:
            return None

    def Line(self):
        """Returns line number of current file
        """
        if self.stack:
            return self.stack[-1].current
        else:
            return -1

    def File(self):
        """Returns name of current file
        """
        if self.stack:
            return self.stack[-1].name
        else:
            return ''

    def __iter__(self):
        return self

    def __next__(self):
        while self.stack:
            line = self.stack[-1].Next()
            if line == None:
                self.stack.pop()
            else:
                inc = self.__GetInclude(line)
                if inc:
                    self.__ReadNode(inc)
                else:
                    return line
        raise StopIteration
    next = __next__  # BBB for python <3

"""distionary.py"""
__docformat__ = 'epytext en'


DATATYPES = frozenset(['string', 'ipaddr', 'integer', 'date', 'octets',
                       'abinary', 'ipv6addr', 'ipv6prefix', 'short', 'byte',
                       'signed', 'ifid', 'ether', 'tlv', 'integer64'])


class ParseError(Exception):
    """Dictionary parser exceptions.

    :ivar msg:        Error message
    :type msg:        string
    :ivar linenumber: Line number on which the error occurred
    :type linenumber: integer
    """

    def __init__(self, msg=None, **data):
        self.msg = msg
        self.file = data.get('file', '')
        self.line = data.get('line', -1)

    def __str__(self):
        str = ''
        if self.file:
            str += self.file
        if self.line > -1:
            str += '(%d)' % self.line
        if self.file or self.line > -1:
            str += ': '
        str += 'Parse error'
        if self.msg:
            str += ': %s' % self.msg

        return str


class Attribute(object):
    def __init__(self, name, code, datatype, is_sub_attribute=False, vendor='', values=None,
                 encrypt=0, has_tag=False):
        if datatype not in DATATYPES:
            raise ValueError('Invalid data type')
        self.name = name
        self.code = code
        self.type = datatype
        self.vendor = vendor
        self.encrypt = encrypt
        self.has_tag = has_tag
        self.values = BiDict()
        self.sub_attributes = {}
        self.parent = None
        self.is_sub_attribute = is_sub_attribute
        if values:
            for (key, value) in values.items():
                self.values.Add(key, value)


class Dictionary(object):
    """RADIUS dictionary class.
    This class stores all information about vendors, attributes and their
    values as defined in RADIUS dictionary files.

    :ivar vendors:    bidict mapping vendor name to vendor code
    :type vendors:    bidict
    :ivar attrindex:  bidict mapping
    :type attrindex:  bidict
    :ivar attributes: bidict mapping attribute name to attribute class
    :type attributes: bidict
    """

    def __init__(self, dict=None, *dicts):
        """
        :param dict:  path of dictionary file or file-like object to read
        :type dict:   string or file
        :param dicts: list of dictionaries
        :type dicts:  sequence of strings or files
        """
        self.vendors = BiDict()
        self.vendors.Add('', 0)
        self.attrindex = BiDict()
        self.attributes = {}
        self.defer_parse = []

        if dict:
            self.ReadDictionary(dict)

        for i in dicts:
            self.ReadDictionary(i)

    def __len__(self):
        return len(self.attributes)

    def __getitem__(self, key):
        return self.attributes[key]

    def __contains__(self, key):
        return key in self.attributes

    has_key = __contains__

    def __ParseAttribute(self, state, tokens):
        if not len(tokens) in [4, 5]:
            raise ParseError(
                'Incorrect number of tokens for attribute definition',
                name=state['file'],
                line=state['line'])

        vendor = state['vendor']
        has_tag = False
        encrypt = 0
        if len(tokens) >= 5:
            def keyval(o):
                kv = o.split('=')
                if len(kv) == 2:
                    return (kv[0], kv[1])
                else:
                    return (kv[0], None)
            options = [keyval(o) for o in tokens[4].split(',')]
            for (key, val) in options:
                if key == 'has_tag':
                    has_tag = True
                elif key == 'encrypt':
                    if val not in ['1', '2', '3']:
                        raise ParseError(
                                'Illegal attribute encryption: %s' % val,
                                file=state['file'],
                                line=state['line'])
                    encrypt = int(val)

            if (not has_tag) and encrypt == 0:
                vendor = tokens[4]
                if not self.vendors.HasForward(vendor):
                    if vendor == "concat":
                        # ignore attributes with concat (freeradius compat.)
                        return None
                    else:
                        raise ParseError('Unknown vendor ' + vendor,
                                         file=state['file'],
                                         line=state['line'])

        (attribute, code, datatype) = tokens[1:4]

        codes = code.split('.')

        # Codes can be sent as hex, or octal or decimal string representations.
        tmp = []
        for c in codes:
          if c.startswith('0x'):
            tmp.append(int(c, 16))
          elif c.startswith('0o'):
            tmp.append(int(c, 8))
          else:
            tmp.append(int(c, 10))
        codes = tmp

        is_sub_attribute = (len(codes) > 1)
        if len(codes) == 2:
            code = int(codes[1])
            parent_code = int(codes[0])
        elif len(codes) == 1:
            code = int(codes[0])
            parent_code = None
        else:
            raise ParseError('nested tlvs are not supported')

        datatype = datatype.split("[")[0]

        if datatype not in DATATYPES:
            raise ParseError('Illegal type: ' + datatype,
                             file=state['file'],
                             line=state['line'])
        if vendor:
            if is_sub_attribute:
                key = (self.vendors.GetForward(vendor), parent_code, code)
            else:
                key = (self.vendors.GetForward(vendor), code)
        else:
            if is_sub_attribute:
                key = (parent_code, code)
            else:
                key = code

        self.attrindex.Add(attribute, key)
        self.attributes[attribute] = Attribute(attribute, code, datatype, is_sub_attribute, vendor, encrypt=encrypt, has_tag=has_tag)
        if datatype == 'tlv':
            # save attribute in tlvs
            state['tlvs'][code] = self.attributes[attribute]
        if is_sub_attribute:
            # save sub attribute in parent tlv and update their parent field
            state['tlvs'][parent_code].sub_attributes[code] = attribute
            self.attributes[attribute].parent = state['tlvs'][parent_code]

    def __ParseValue(self, state, tokens, defer):
        if len(tokens) != 4:
            raise ParseError('Incorrect number of tokens for value definition',
                             file=state['file'],
                             line=state['line'])

        (attr, key, value) = tokens[1:]

        try:
            adef = self.attributes[attr]
        except KeyError:
            if defer:
                self.defer_parse.append((copy(state), copy(tokens)))
                return
            raise ParseError('Value defined for unknown attribute ' + attr,
                             file=state['file'],
                             line=state['line'])

        if adef.type in ['integer', 'signed', 'short', 'byte', 'integer64']:
            value = int(value, 0)
        value = EncodeAttr(adef.type, value)
        self.attributes[attr].values.Add(key, value)

    def __ParseVendor(self, state, tokens):
        if len(tokens) not in [3, 4]:
            raise ParseError(
                    'Incorrect number of tokens for vendor definition',
                    file=state['file'],
                    line=state['line'])

        # Parse format specification, but do
        # nothing about it for now
        if len(tokens) == 4:
            fmt = tokens[3].split('=')
            if fmt[0] != 'format':
                raise ParseError(
                        "Unknown option '%s' for vendor definition" % (fmt[0]),
                        file=state['file'],
                        line=state['line'])
            try:
                (t, l) = tuple(int(a) for a in fmt[1].split(','))
                if t not in [1, 2, 4] or l not in [0, 1, 2]:
                    raise ParseError(
                        'Unknown vendor format specification %s' % (fmt[1]),
                        file=state['file'],
                        line=state['line'])
            except ValueError:
                raise ParseError(
                        'Syntax error in vendor specification',
                        file=state['file'],
                        line=state['line'])

        (vendorname, vendor) = tokens[1:3]
        self.vendors.Add(vendorname, int(vendor, 0))

    def __ParseBeginVendor(self, state, tokens):
        if len(tokens) != 2:
            raise ParseError(
                    'Incorrect number of tokens for begin-vendor statement',
                    file=state['file'],
                    line=state['line'])

        vendor = tokens[1]

        if not self.vendors.HasForward(vendor):
            raise ParseError(
                    'Unknown vendor %s in begin-vendor statement' % vendor,
                    file=state['file'],
                    line=state['line'])

        state['vendor'] = vendor

    def __ParseEndVendor(self, state, tokens):
        if len(tokens) != 2:
            raise ParseError(
                'Incorrect number of tokens for end-vendor statement',
                file=state['file'],
                line=state['line'])

        vendor = tokens[1]

        if state['vendor'] != vendor:
            raise ParseError(
                    'Ending non-open vendor' + vendor,
                    file=state['file'],
                    line=state['line'])
        state['vendor'] = ''

    def ReadDictionary(self, file):
        """Parse a dictionary file.
        Reads a RADIUS dictionary file and merges its contents into the
        class instance.

        :param file: Name of dictionary file to parse or a file-like object
        :type file:  string or file-like object
        """

        fil = DictFile(file)

        state = {}
        state['vendor'] = ''
        state['tlvs'] = {}
        self.defer_parse = []
        for line in fil:
            state['file'] = fil.File()
            state['line'] = fil.Line()
            line = line.split('#', 1)[0].strip()

            tokens = line.split()
            if not tokens:
                continue

            key = tokens[0].upper()
            if key == 'ATTRIBUTE':
                self.__ParseAttribute(state, tokens)
            elif key == 'VALUE':
                self.__ParseValue(state, tokens, True)
            elif key == 'VENDOR':
                self.__ParseVendor(state, tokens)
            elif key == 'BEGIN-VENDOR':
                self.__ParseBeginVendor(state, tokens)
            elif key == 'END-VENDOR':
                self.__ParseEndVendor(state, tokens)

        for state, tokens in self.defer_parse:
            key = tokens[0].upper()
            if key == 'VALUE':
                self.__ParseValue(state, tokens, False)
        self.defer_parse = []

"""packet.py"""
# Packet codes
AccessRequest = 1
AccessAccept = 2
AccessReject = 3
AccountingRequest = 4
AccountingResponse = 5
AccessChallenge = 11
StatusServer = 12
StatusClient = 13
DisconnectRequest = 40
DisconnectACK = 41
DisconnectNAK = 42
CoARequest = 43
CoAACK = 44
CoANAK = 45

# Current ID
CurrentID = random_generator.randrange(1, 255)


class PacketError(Exception):
    pass


class Packet(OrderedDict):
    """Packet acts like a standard python map to provide simple access
    to the RADIUS attributes. Since RADIUS allows for repeated
    attributes the value will always be a sequence. pyrad makes sure
    to preserve the ordering when encoding and decoding packets.

    There are two ways to use the map interface: if attribute
    names are used pyrad take care of en-/decoding data. If
    the attribute type number (or a vendor ID/attribute type
    tuple for vendor attributes) is used you work with the
    raw data.

    Normally you will not use this class directly, but one of the
    :obj:`AuthPacket` or :obj:`AcctPacket` classes.
    """

    def __init__(self, code=0, id=None, secret=b'', authenticator=None,
                 **attributes):
        """Constructor

        :param dict:   RADIUS dictionary
        :type dict:    pyrad.dictionary.Dictionary class
        :param secret: secret needed to communicate with a RADIUS server
        :type secret:  string
        :param id:     packet identification number
        :type id:      integer (8 bits)
        :param code:   packet type code
        :type code:    integer (8bits)
        :param packet: raw packet to decode
        :type packet:  string
        """
        OrderedDict.__init__(self)
        self.code = code
        if id is not None:
            self.id = id
        else:
            self.id = CreateID()
        if not isinstance(secret, bytes):
            raise TypeError('secret must be a binary string')
        self.secret = secret
        if authenticator is not None and \
                not isinstance(authenticator, bytes):
            raise TypeError('authenticator must be a binary string')
        self.authenticator = authenticator
        self.message_authenticator = None
        self.raw_packet = None

        if 'dict' in attributes:
            self.dict = attributes['dict']

        if 'packet' in attributes:
            self.raw_packet = attributes['packet']
            self.DecodePacket(self.raw_packet)

        if 'message_authenticator' in attributes:
            self.message_authenticator = attributes['message_authenticator']

        for (key, value) in attributes.items():
            if key in [
                'dict', 'fd', 'packet',
                'message_authenticator',
            ]:
                continue
            key = key.replace('_', '-')
            self.AddAttribute(key, value)

    def add_message_authenticator(self):

        self.message_authenticator = True
        # Maintain a zero octets content for md5 and hmac calculation.
        self['Message-Authenticator'] = 16 * b'\00'

        if self.id is None:
            self.id = self.CreateID()

        if self.authenticator is None and self.code == AccessRequest:
            self.authenticator = self.CreateAuthenticator()
            self._refresh_message_authenticator()

    def get_message_authenticator(self):
        self._refresh_message_authenticator()
        return self.message_authenticator

    def _refresh_message_authenticator(self):
        hmac_constructor = hmac_new(self.secret)

        # Maintain a zero octets content for md5 and hmac calculation.
        self['Message-Authenticator'] = 16 * b'\00'
        attr = self._PktEncodeAttributes()

        header = struct.pack('!BBH', self.code, self.id,
                             (20 + len(attr)))

        hmac_constructor.update(header[0:4])
        if self.code in (AccountingRequest, DisconnectRequest,
                         CoARequest, AccountingResponse):
            hmac_constructor.update(16 * b'\00')
        else:
            # NOTE: self.authenticator on reply packet is initialized
            #       with request authenticator by design.
            #       For AccessAccept, AccessReject and AccessChallenge
            #       it is needed use original Authenticator.
            #       For AccessAccept, AccessReject and AccessChallenge
            #       it is needed use original Authenticator.
            if self.authenticator is None:
                raise Exception('No authenticator found')
            hmac_constructor.update(self.authenticator)

        hmac_constructor.update(attr)
        self['Message-Authenticator'] = hmac_constructor.digest()

    def verify_message_authenticator(self, secret=None,
                                     original_authenticator=None,
                                     original_code=None):
        """Verify packet Message-Authenticator.

        :return: False if verification failed else True
        :rtype: boolean
        """
        if self.message_authenticator is None:
            raise Exception('No Message-Authenticator AVP present')

        prev_ma = self['Message-Authenticator']
        # Set zero bytes for Message-Authenticator for md5 calculation
        if secret is None and self.secret is None:
            raise Exception('Missing secret for HMAC/MD5 verification')

        if secret:
            key = secret
        else:
            key = self.secret

        # If there's a raw packet, use that to calculate the expected
        # Message-Authenticator. While the Packet class keeps multiple
        # instances of an attribute grouped together in the attribute list,
        # other applications may not. Using _PktEncodeAttributes to get
        # the attributes could therefore end up changing the attribute order
        # because of the grouping Packet does, which would cause
        # Message-Authenticator verification to fail. Using the raw packet
        # instead, if present, ensures the verification is done using the
        # attributes exactly as sent.
        if self.raw_packet:
            attr = self.raw_packet[20:]
            attr = attr.replace(prev_ma[0], 16 * b'\00')
        else:
            self['Message-Authenticator'] = 16 * b'\00'
            attr = self._PktEncodeAttributes()

        header = struct.pack('!BBH', self.code, self.id,
                             (20 + len(attr)))

        hmac_constructor = hmac_new(key)
        hmac_constructor.update(header)
        if self.code in (AccountingRequest, DisconnectRequest,
                         CoARequest, AccountingResponse):
            if original_code is None or original_code != StatusServer:
                # TODO: Handle Status-Server response correctly.
                hmac_constructor.update(16 * b'\00')
        elif self.code in (AccessAccept, AccessChallenge,
                           AccessReject):
            if original_authenticator is None:
                if self.authenticator:
                    # NOTE: self.authenticator on reply packet is initialized
                    #       with request authenticator by design.
                    original_authenticator = self.authenticator
                else:
                    raise Exception('Missing original authenticator')

            hmac_constructor.update(original_authenticator)
        else:
            # On Access-Request and Status-Server use dynamic authenticator
            hmac_constructor.update(self.authenticator)

        hmac_constructor.update(attr)
        self['Message-Authenticator'] = prev_ma[0]
        return prev_ma[0] == hmac_constructor.digest()

    def CreateReply(self, **attributes):
        """Create a new packet as a reply to this one. This method
        makes sure the authenticator and secret are copied over
        to the new instance.
        """
        return Packet(id=self.id, secret=self.secret,
                      authenticator=self.authenticator, dict=self.dict,
                      **attributes)

    def _DecodeValue(self, attr, value):

        if attr.encrypt == 2:
            #salt decrypt attribute
            value = self.SaltDecrypt(value)

        if attr.values.HasBackward(value):
            return attr.values.GetBackward(value)
        else:
            return DecodeAttr(attr.type, value)

    def _EncodeValue(self, attr, value):
        result = ''
        if attr.values.HasForward(value):
            result = attr.values.GetForward(value)
        else:
            result = EncodeAttr(attr.type, value)

        if attr.encrypt == 2:
            # salt encrypt attribute
            result = self.SaltCrypt(result)

        return result

    def _EncodeKeyValues(self, key, values):
        if not isinstance(key, str):
            return (key, values)

        if not isinstance(values, (list, tuple)):
            values = [values]

        key, _, tag = key.partition(":")
        attr = self.dict.attributes[key]
        key = self._EncodeKey(key)
        if tag:
            tag = struct.pack('B', int(tag))
            if attr.type == "integer":
                return (key, [tag + self._EncodeValue(attr, v)[1:] for v in values])
            else:
                return (key, [tag + self._EncodeValue(attr, v) for v in values])
        else:
            return (key, [self._EncodeValue(attr, v) for v in values])

    def _EncodeKey(self, key):
        if not isinstance(key, str):
            return key

        attr = self.dict.attributes[key]
        if attr.vendor and not attr.is_sub_attribute:  #sub attribute keys don't need vendor
            return (self.dict.vendors.GetForward(attr.vendor), attr.code)
        else:
            return attr.code

    def _DecodeKey(self, key):
        """Turn a key into a string if possible"""

        if self.dict.attrindex.HasBackward(key):
            return self.dict.attrindex.GetBackward(key)
        return key

    def AddAttribute(self, key, value):
        """Add an attribute to the packet.

        :param key:   attribute name or identification
        :type key:    string, attribute code or (vendor code, attribute code)
                      tuple
        :param value: value
        :type value:  depends on type of attribute
        """
        attr = self.dict.attributes[key.partition(':')[0]]

        (key, value) = self._EncodeKeyValues(key, value)

        if attr.is_sub_attribute:
            tlv = self.setdefault(self._EncodeKey(attr.parent.name), {})
            encoded = tlv.setdefault(key, [])
        else:
            encoded = self.setdefault(key, [])

        encoded.extend(value)

    def get(self, key, failobj=None):
        try:
            res = self.__getitem__(key)
        except KeyError:
            res = failobj
        return res

    def __getitem__(self, key):
        if not isinstance(key, str):
            return OrderedDict.__getitem__(self, key)

        values = OrderedDict.__getitem__(self, self._EncodeKey(key))
        attr = self.dict.attributes[key]
        if attr.type == 'tlv':  # return map from sub attribute code to its values
            res = {}
            for (sub_attr_key, sub_attr_val) in values.items():
                sub_attr_name = attr.sub_attributes[sub_attr_key]
                sub_attr = self.dict.attributes[sub_attr_name]
                for v in sub_attr_val:
                    res.setdefault(sub_attr_name, []).append(self._DecodeValue(sub_attr, v))
            return res
        else:
            res = []
            for v in values:
                res.append(self._DecodeValue(attr, v))
            return res

    def __contains__(self, key):
        try:
            return OrderedDict.__contains__(self, self._EncodeKey(key))
        except KeyError:
            return False

    has_key = __contains__

    def __delitem__(self, key):
        OrderedDict.__delitem__(self, self._EncodeKey(key))

    def __setitem__(self, key, item):
        if isinstance(key, str):
            (key, item) = self._EncodeKeyValues(key, item)
            OrderedDict.__setitem__(self, key, item)
        else:
            OrderedDict.__setitem__(self, key, item)

    def keys(self):
        return [self._DecodeKey(key) for key in OrderedDict.keys(self)]

    @staticmethod
    def CreateAuthenticator():
        """Create a packet authenticator. All RADIUS packets contain a sixteen
        byte authenticator which is used to authenticate replies from the
        RADIUS server and in the password hiding algorithm. This function
        returns a suitable random string that can be used as an authenticator.

        :return: valid packet authenticator
        :rtype: binary string
        """
        return bytes(
            random_generator.randrange(0, 256)
            for _ in range(16)
        )

    def CreateID(self):
        """Create a packet ID.  All RADIUS requests have a ID which is used to
        identify a request. This is used to detect retries and replay attacks.
        This function returns a suitable random number that can be used as ID.

        :return: ID number
        :rtype:  integer

        """
        return random_generator.randrange(0, 256)

    def ReplyPacket(self):
        """Create a ready-to-transmit authentication reply packet.
        Returns a RADIUS packet which can be directly transmitted
        to a RADIUS server. This differs with Packet() in how
        the authenticator is calculated.

        :return: raw packet
        :rtype:  string
        """
        assert(self.authenticator)

        assert(self.secret is not None)

        if self.message_authenticator:
            self._refresh_message_authenticator()

        attr = self._PktEncodeAttributes()
        header = struct.pack('!BBH', self.code, self.id, (20 + len(attr)))

        authenticator = md5_constructor(header[0:4] + self.authenticator
                                        + attr + self.secret).digest()

        return header + authenticator + attr

    def VerifyReply(self, reply, rawreply=None):
        if reply.id != self.id:
            return False

        if rawreply is None:
            rawreply = reply.ReplyPacket()

        attr = reply._PktEncodeAttributes()
        # The Authenticator field in an Accounting-Response packet is called
        # the Response Authenticator, and contains a one-way MD5 hash
        # calculated over a stream of octets consisting of the Accounting
        # Response Code, Identifier, Length, the Request Authenticator field
        # from the Accounting-Request packet being replied to, and the
        # response attributes if any, followed by the shared secret.  The
        # resulting 16 octet MD5 hash value is stored in the Authenticator
        # field of the Accounting-Response packet.
        hash = md5_constructor(rawreply[0:4] + self.authenticator +
                               rawreply[20:] + self.secret).digest()

        if hash != rawreply[4:20]:
            return False
        return True

    def _PktEncodeAttribute(self, key, value):
        if isinstance(key, tuple):
            value = struct.pack('!L', key[0]) + \
                self._PktEncodeAttribute(key[1], value)
            key = 26

        return struct.pack('!BB', key, (len(value) + 2)) + value

    def _PktEncodeTlv(self, tlv_key, tlv_value):
        tlv_attr = self.dict.attributes[self._DecodeKey(tlv_key)]
        curr_avp = b''
        avps = []
        max_sub_attribute_len = max(map(lambda item: len(item[1]), tlv_value.items()))
        for i in range(max_sub_attribute_len):
            sub_attr_encoding = b''
            for (code, datalst) in tlv_value.items():
                if i < len(datalst):
                    sub_attr_encoding += self._PktEncodeAttribute(code, datalst[i])
            # split above 255. assuming len of one instance of all sub tlvs is lower than 255
            if (len(sub_attr_encoding) + len(curr_avp)) < 245:
                curr_avp += sub_attr_encoding
            else:
                avps.append(curr_avp)
                curr_avp = sub_attr_encoding
        avps.append(curr_avp)
        tlv_avps = []
        for avp in avps:
            value = struct.pack('!BB', tlv_attr.code, (len(avp) + 2)) + avp
            tlv_avps.append(value)
        if tlv_attr.vendor:
            vendor_avps = b''
            for avp in tlv_avps:
                vendor_avps += struct.pack(
                    '!BBL', 26, (len(avp) + 6),
                    self.dict.vendors.GetForward(tlv_attr.vendor)
                ) + avp
            return vendor_avps
        else:
            return b''.join(tlv_avps)

    def _PktEncodeAttributes(self):
        result = b''
        for (code, datalst) in self.items():
            attribute = self.dict.attributes.get(self._DecodeKey(code))
            if attribute and attribute.type == 'tlv':
                result += self._PktEncodeTlv(code, datalst)
            else:
                for data in datalst:
                    result += self._PktEncodeAttribute(code, data)
        return result

    def _PktDecodeVendorAttribute(self, data):
        # Check if this packet is long enough to be in the
        # RFC2865 recommended form
        if len(data) < 6:
            return [(26, data)]

        (vendor, atype, length) = struct.unpack('!LBB', data[:6])[0:3]
        attribute = self.dict.attributes.get(self._DecodeKey((vendor, atype)))
        try:
            if attribute and attribute.type == 'tlv':
                self._PktDecodeTlvAttribute((vendor, atype), data[6:length + 4])
                tlvs = []  # tlv is added to the packet inside _PktDecodeTlvAttribute
            else:
                tlvs = [((vendor, atype), data[6:length + 4])]
        except:
            return [(26, data)]

        sumlength = 4 + length
        while len(data) > sumlength:
            try:
                atype, length = struct.unpack('!BB', data[sumlength:sumlength+2])[0:2]
            except:
                return [(26, data)]
            tlvs.append(((vendor, atype), data[sumlength+2:sumlength+length]))
            sumlength += length
        return tlvs

    def _PktDecodeTlvAttribute(self, code, data):
        sub_attributes = self.setdefault(code, {})
        loc = 0

        while loc < len(data):
            atype, length = struct.unpack('!BB', data[loc:loc+2])[0:2]
            sub_attributes.setdefault(atype, []).append(data[loc+2:loc+length])
            loc += length

    def DecodePacket(self, packet):
        """Initialize the object from raw packet data.  Decode a packet as
        received from the network and decode it.

        :param packet: raw packet
        :type packet:  string"""

        try:
            (self.code, self.id, length, self.authenticator) = \
                    struct.unpack('!BBH16s', packet[0:20])

        except struct.error:
            raise PacketError('Packet header is corrupt')
        if len(packet) != length:
            raise PacketError('Packet has invalid length')
        if length > 8192:
            raise PacketError('Packet length is too long (%d)' % length)

        self.clear()

        packet = packet[20:]
        while packet:
            try:
                (key, attrlen) = struct.unpack('!BB', packet[0:2])
            except struct.error:
                raise PacketError('Attribute header is corrupt')

            if attrlen < 2:
                raise PacketError(
                        'Attribute length is too small (%d)' % attrlen)

            value = packet[2:attrlen]
            attribute = self.dict.attributes.get(self._DecodeKey(key))
            if key == 26:
                for (key, value) in self._PktDecodeVendorAttribute(value):
                    self.setdefault(key, []).append(value)
            elif key == 80:
                # POST: Message Authenticator AVP is present.
                self.message_authenticator = True
                self.setdefault(key, []).append(value)
            elif attribute and attribute.type == 'tlv':
                self._PktDecodeTlvAttribute(key,value)
            else:
                self.setdefault(key, []).append(value)

            packet = packet[attrlen:]


    def _salt_en_decrypt(self, data, salt):
        result = b''
        last = self.authenticator + salt
        while data:
            hash = md5_constructor(self.secret + last).digest()
            for i in range(16):
                result += bytes((hash[i] ^ data[i],))

            last = result[-16:]
            data = data[16:]
        return result


    def SaltCrypt(self, value):
        """SaltEncrypt

        :param value:    plaintext value
        :type:           unicode string
        :return:         obfuscated version of the value
        :rtype:          binary string
        """

        if isinstance(value, str):
            value = value.encode('utf-8')

        if self.authenticator is None:
            # self.authenticator = self.CreateAuthenticator()
            self.authenticator = 16 * b'\x00'

        #create salt
        random_value = 32768 + random_generator.randrange(0, 32767)
        salt_raw = struct.pack('!H', random_value)

        #length prefixing
        length = struct.pack("B", len(value))
        value = length + value

        #zero padding
        if len(value) % 16 != 0:
            value += b'\x00' * (16 - (len(value) % 16))

        return salt_raw + self._salt_en_decrypt(value, salt_raw)

    def SaltDecrypt(self, value):
        """ SaltDecrypt

        :param value:   encrypted value including salt
        :type:          binary string
        :return:        decrypted plaintext string
        :rtype:         unicode string
        """
        #extract salt
        salt = value[:2]

        #decrypt
        value = self._salt_en_decrypt(value[2:], salt)

        #remove padding
        length = value[0]
        value = value[1:length+1]

        return value


class AuthPacket(Packet):
    def __init__(self, code=AccessRequest, id=None, secret=b'',
                 authenticator=None, auth_type='pap', **attributes):
        """Constructor

        :param code:   packet type code
        :type code:    integer (8bits)
        :param id:     packet identification number
        :type id:      integer (8 bits)
        :param secret: secret needed to communicate with a RADIUS server
        :type secret:  string

        :param dict:   RADIUS dictionary
        :type dict:    pyrad.dictionary.Dictionary class

        :param packet: raw packet to decode
        :type packet:  string
        """

        Packet.__init__(self, code, id, secret, authenticator, **attributes)
        self.auth_type = auth_type

    def CreateReply(self, **attributes):
        """Create a new packet as a reply to this one. This method
        makes sure the authenticator and secret are copied over
        to the new instance.
        """
        return AuthPacket(AccessAccept, self.id,
                          self.secret, self.authenticator, dict=self.dict,
                          auth_type=self.auth_type, **attributes)

    def RequestPacket(self):
        """Create a ready-to-transmit authentication request packet.
        Return a RADIUS packet which can be directly transmitted
        to a RADIUS server.

        :return: raw packet
        :rtype:  string
        """
        if self.authenticator is None:
            self.authenticator = self.CreateAuthenticator()

        if self.id is None:
            self.id = self.CreateID()

        if self.message_authenticator:
            self._refresh_message_authenticator()

        attr = self._PktEncodeAttributes()
        if self.auth_type == 'eap-md5':
            header = struct.pack(
                '!BBH16s', self.code, self.id, (20 + 18 + len(attr)), self.authenticator
            )
            digest = hmac_new(
                self.secret,
                header
                + attr
                + struct.pack('!BB16s', 80, struct.calcsize('!BB16s'), b''),
            ).digest()
            return (
                header
                + attr
                + struct.pack('!BB16s', 80, struct.calcsize('!BB16s'), digest)
            )

        header = struct.pack('!BBH16s', self.code, self.id,
                             (20 + len(attr)), self.authenticator)

        return header + attr

    def PwDecrypt(self, password):
        """De-Obfuscate a RADIUS password. RADIUS hides passwords in packets by
        using an algorithm based on the MD5 hash of the packet authenticator
        and RADIUS secret. This function reverses the obfuscation process.

        Although RFC2865 does not explicitly state UTF-8 for the password field,
        the rest of RFC2865 defines UTF-8 as the encoding expected for the decrypted password.


        :param password: obfuscated form of password
        :type password:  binary string
        :return:         plaintext password
        :rtype:          unicode string
        """
        buf = password
        pw = b''

        last = self.authenticator
        while buf:
            hash = md5_constructor(self.secret + last).digest()
            for i in range(16):
                pw += bytes((hash[i] ^ buf[i],))
            (last, buf) = (buf[:16], buf[16:])

        # This is safe even with UTF-8 encoding since no valid encoding of UTF-8
        # (other than encoding U+0000 NULL) will produce a bytestream containing 0x00 byte.
        while pw.endswith(b'\x00'):
            pw = pw[:-1]

        # If the shared secret with the client is not the same, then de-obfuscating the password
        # field may yield illegal UTF-8 bytes. Therefore, in order not to provoke an Exception here
        # (which would be not consistently generated since this will depend on the random data 
        # chosen by the client) we simply ignore un-parsable UTF-8 sequences.
        return pw.decode('utf-8', errors="ignore")

    def PwCrypt(self, password):
        """Obfuscate password.
        RADIUS hides passwords in packets by using an algorithm
        based on the MD5 hash of the packet authenticator and RADIUS
        secret. If no authenticator has been set before calling PwCrypt
        one is created automatically. Changing the authenticator after
        setting a password that has been encrypted using this function
        will not work.

        :param password: plaintext password
        :type password:  unicode string
        :return:         obfuscated version of the password
        :rtype:          binary string
        """
        if self.authenticator is None:
            self.authenticator = self.CreateAuthenticator()

        if isinstance(password, str):
            password = password.encode('utf-8')

        buf = password
        if len(password) % 16 != 0:
            buf += b'\x00' * (16 - (len(password) % 16))

        result = b''

        last = self.authenticator
        while buf:
            hash = md5_constructor(self.secret + last).digest()
            for i in range(16):
                result += bytes((hash[i] ^ buf[i],))
            last = result[-16:]
            buf = buf[16:]

        return result

    def VerifyChapPasswd(self, userpwd):
        """ Verify RADIUS ChapPasswd

        :param userpwd: plaintext password
        :type userpwd:  str
        :return:        is verify ok
        :rtype:         bool
        """

        if not self.authenticator:
            self.authenticator = self.CreateAuthenticator()

        if isinstance(userpwd, str):
            userpwd = userpwd.strip().encode('utf-8')

        chap_password = DecodeOctets(self.get(3)[0])
        if len(chap_password) != 17:
            return False

        chapid = chap_password[:1]
        password = chap_password[1:]

        challenge = self.authenticator
        if 'CHAP-Challenge' in self:
            challenge = self['CHAP-Challenge'][0]
        return password == md5_constructor(chapid + userpwd + challenge).digest()

    def VerifyAuthRequest(self):
        """Verify request authenticator.

        :return: True if verification passed else False
        :rtype: boolean
        """
        assert (self.raw_packet)
        hash = md5_constructor(self.raw_packet[0:4] + 16 * b'\x00' +
                               self.raw_packet[20:] + self.secret).digest()
        return hash == self.authenticator


class AcctPacket(Packet):
    """RADIUS accounting packets. This class is a specialization
    of the generic :obj:`Packet` class for accounting packets.
    """

    def __init__(self, code=AccountingRequest, id=None, secret=b'',
                 authenticator=None, **attributes):
        """Constructor

        :param dict:   RADIUS dictionary
        :type dict:    pyrad.dictionary.Dictionary class
        :param secret: secret needed to communicate with a RADIUS server
        :type secret:  string
        :param id:     packet identification number
        :type id:      integer (8 bits)
        :param code:   packet type code
        :type code:    integer (8bits)
        :param packet: raw packet to decode
        :type packet:  string
        """
        Packet.__init__(self, code, id, secret, authenticator, **attributes)

    def CreateReply(self, **attributes):
        """Create a new packet as a reply to this one. This method
        makes sure the authenticator and secret are copied over
        to the new instance.
        """
        return AcctPacket(AccountingResponse, self.id,
                          self.secret, self.authenticator, dict=self.dict,
                          **attributes)

    def VerifyAcctRequest(self):
        """Verify request authenticator.

        :return: True if verification passed else False
        :rtype: boolean
        """
        assert(self.raw_packet)

        hash = md5_constructor(self.raw_packet[0:4] + 16 * b'\x00' +
                               self.raw_packet[20:] + self.secret).digest()

        return hash == self.authenticator

    def RequestPacket(self):
        """Create a ready-to-transmit authentication request packet.
        Return a RADIUS packet which can be directly transmitted
        to a RADIUS server.

        :return: raw packet
        :rtype:  string
        """

        if self.id is None:
            self.id = self.CreateID()

        if self.message_authenticator:
            self._refresh_message_authenticator()

        attr = self._PktEncodeAttributes()
        header = struct.pack('!BBH', self.code, self.id, (20 + len(attr)))
        self.authenticator = md5_constructor(header[0:4] + 16 * b'\x00' +
                                             attr + self.secret).digest()

        ans = header + self.authenticator + attr

        return ans


class CoAPacket(Packet):
    """RADIUS CoA packets. This class is a specialization
    of the generic :obj:`Packet` class for CoA packets.
    """

    def __init__(self, code=CoARequest, id=None, secret=b'',
            authenticator=None, **attributes):
        """Constructor

        :param dict:   RADIUS dictionary
        :type dict:    pyrad.dictionary.Dictionary class
        :param secret: secret needed to communicate with a RADIUS server
        :type secret:  string
        :param id:     packet identification number
        :type id:      integer (8 bits)
        :param code:   packet type code
        :type code:    integer (8bits)
        :param packet: raw packet to decode
        :type packet:  string
        """
        Packet.__init__(self, code, id, secret, authenticator, **attributes)

    def CreateReply(self, **attributes):
        """Create a new packet as a reply to this one. This method
        makes sure the authenticator and secret are copied over
        to the new instance.
        """
        return CoAPacket(CoAACK, self.id,
                         self.secret, self.authenticator, dict=self.dict,
                         **attributes)

    def VerifyCoARequest(self):
        """Verify request authenticator.

        :return: True if verification passed else False
        :rtype: boolean
        """
        assert(self.raw_packet)
        hash = md5_constructor(self.raw_packet[0:4] + 16 * b'\x00' +
                               self.raw_packet[20:] + self.secret).digest()
        return hash == self.authenticator

    def RequestPacket(self):
        """Create a ready-to-transmit CoA request packet.
        Return a RADIUS packet which can be directly transmitted
        to a RADIUS server.

        :return: raw packet
        :rtype:  string
        """

        attr = self._PktEncodeAttributes()

        if self.id is None:
            self.id = self.CreateID()

        header = struct.pack('!BBH', self.code, self.id, (20 + len(attr)))
        self.authenticator = md5_constructor(header[0:4] + 16 * b'\x00' +
                                             attr + self.secret).digest()

        if self.message_authenticator:
            self._refresh_message_authenticator()
            attr = self._PktEncodeAttributes()
            self.authenticator = md5_constructor(header[0:4] + 16 * b'\x00' +
                                                 attr + self.secret).digest()

        return header + self.authenticator + attr


def CreateID():
    """Generate a packet ID.

    :return: packet ID
    :rtype:  8 bit integer
    """
    global CurrentID

    CurrentID = (CurrentID + 1) % 256
    return CurrentID

"""client.py"""
EAP_CODE_REQUEST = 1
EAP_CODE_RESPONSE = 2
EAP_TYPE_IDENTITY = 1

class Timeout(Exception):
    """Simple exception class which is raised when a timeout occurs
    while waiting for a RADIUS server to respond."""


class Client(Host):
    """Basic RADIUS client.
    This class implements a basic RADIUS client. It can send requests
    to a RADIUS server, taking care of timeouts and retries, and
    validate its replies.

    :ivar retries: number of times to retry sending a RADIUS request
    :type retries: integer
    :ivar timeout: number of seconds to wait for an answer
    :type timeout: float
    """
    def __init__(self, server, authport=1812, acctport=1813,
            coaport=3799, secret=b'', dict=None, retries=3, timeout=5):

        """Constructor.

        :param   server: hostname or IP address of RADIUS server
        :type    server: string
        :param authport: port to use for authentication packets
        :type  authport: integer
        :param acctport: port to use for accounting packets
        :type  acctport: integer
        :param coaport: port to use for CoA packets
        :type  coaport: integer
        :param   secret: RADIUS secret
        :type    secret: string
        :param     dict: RADIUS dictionary
        :type      dict: pyrad.dictionary.Dictionary
        """
        Host.__init__(self, authport, acctport, coaport, dict)

        self.server = server
        self.secret = secret
        self._socket = None
        self.retries = retries
        self.timeout = timeout
        self._poll = select.poll()

    def bind(self, addr):
        """Bind socket to an address.
        Binding the socket used for communicating to an address can be
        usefull when working on a machine with multiple addresses.

        :param addr: network address (hostname or IP) and port to bind to
        :type  addr: host,port tuple
        """
        self._CloseSocket()
        self._SocketOpen()
        self._socket.bind(addr)

    def _SocketOpen(self):
        try:
            family = socket.getaddrinfo(self.server, 80)[0][0]
        except:
            family = socket.AF_INET
        if not self._socket:
            self._socket = socket.socket(family,
                                       socket.SOCK_DGRAM)
            self._socket.setsockopt(socket.SOL_SOCKET,
                                    socket.SO_REUSEADDR, 1)
            self._poll.register(self._socket, select.POLLIN)

    def _CloseSocket(self):
        if self._socket:
            self._poll.unregister(self._socket)
            self._socket.close()
            self._socket = None

    def CreateAuthPacket(self, **args):
        """Create a new RADIUS packet.
        This utility function creates a new RADIUS packet which can
        be used to communicate with the RADIUS server this client
        talks to. This is initializing the new packet with the
        dictionary and secret used for the client.

        :return: a new empty packet instance
        :rtype:  pyrad.packet.AuthPacket
        """
        return Host.CreateAuthPacket(self, secret=self.secret, **args)

    def CreateAcctPacket(self, **args):
        """Create a new RADIUS packet.
        This utility function creates a new RADIUS packet which can
        be used to communicate with the RADIUS server this client
        talks to. This is initializing the new packet with the
        dictionary and secret used for the client.

        :return: a new empty packet instance
        :rtype:  pyrad.packet.Packet
        """
        return Host.CreateAcctPacket(self, secret=self.secret, **args)

    def CreateCoAPacket(self, **args):
        """Create a new RADIUS packet.
        This utility function creates a new RADIUS packet which can
        be used to communicate with the RADIUS server this client
        talks to. This is initializing the new packet with the
        dictionary and secret used for the client.

        :return: a new empty packet instance
        :rtype:  pyrad.packet.Packet
        """
        return Host.CreateCoAPacket(self, secret=self.secret, **args)

    def _SendPacket(self, pkt, port):
        """Send a packet to a RADIUS server.

        :param pkt:  the packet to send
        :type pkt:   pyrad.packet.Packet
        :param port: UDP port to send packet to
        :type port:  integer
        :return:     the reply packet received
        :rtype:      pyrad.packet.Packet
        :raise Timeout: RADIUS server does not reply
        """
        self._SocketOpen()

        for attempt in range(self.retries):
            if attempt and pkt.code == AccountingRequest:
                if "Acct-Delay-Time" in pkt:
                    pkt["Acct-Delay-Time"] = \
                            pkt["Acct-Delay-Time"][0] + self.timeout
                else:
                    pkt["Acct-Delay-Time"] = self.timeout

            now = time.time()
            waitto = now + self.timeout

            self._socket.sendto(pkt.RequestPacket(), (self.server, port))

            while now < waitto:
                ready = self._poll.poll((waitto - now) * 1000)

                if ready:
                    rawreply = self._socket.recv(4096)
                else:
                    now = time.time()
                    continue

                try:
                    reply = pkt.CreateReply(packet=rawreply)
                    if pkt.VerifyReply(reply, rawreply):
                        return reply
                except PacketError:
                    pass

                now = time.time()

        raise Timeout

    def SendPacket(self, pkt):
        """Send a packet to a RADIUS server.

        :param pkt: the packet to send
        :type pkt:  pyrad.packet.Packet
        :return:    the reply packet received
        :rtype:     pyrad.packet.Packet
        :raise Timeout: RADIUS server does not reply
        """
        if isinstance(pkt, AuthPacket):
            if pkt.auth_type == 'eap-md5':
                # Creating EAP-Identity
                password = pkt[2][0] if 2 in pkt else pkt[1][0]
                pkt[79] = [struct.pack('!BBHB%ds' % len(password),
                                       EAP_CODE_RESPONSE,
                                       CurrentID,
                                       len(password) + 5,
                                       EAP_TYPE_IDENTITY,
                                       password)]
            reply = self._SendPacket(pkt, self.authport)
            if (
                reply
                and reply.code == AccessChallenge
                and pkt.auth_type == 'eap-md5'
            ):
                # Got an Access-Challenge
                eap_code, eap_id, eap_size, eap_type, eap_md5 = struct.unpack(
                    '!BBHB%ds' % (len(reply[79][0]) - 5), reply[79][0]
                )
                # Sending back an EAP-Type-MD5-Challenge
                # Thank god for http://www.secdev.org/python/eapy.py
                client_pw = pkt[2][0] if 2 in pkt else pkt[1][0]
                md5_challenge = hashlib.md5(
                    struct.pack('!B', eap_id) + client_pw + eap_md5[1:]
                ).digest()
                pkt[79] = [
                    struct.pack('!BBHBB', 2, eap_id, len(md5_challenge) + 6,
                                4, len(md5_challenge)) + md5_challenge
                ]
                # Copy over Challenge-State
                pkt[24] = reply[24]
                reply = self._SendPacket(pkt, self.authport)
            return reply
        elif isinstance(pkt, CoAPacket):
            return self._SendPacket(pkt, self.coaport)
        else:
            return self._SendPacket(pkt, self.acctport)

def DictFileBase64():
    return "IwojIFZlcnNpb24gJElkOiBkaWN0aW9uYXJ5LHYgMS4xLjEuMSAyMDAyLzEwLzExIDEyOjI1OjM5IHdpY2hlcnQgRXhwICQKIwojCVRoaXMgZmlsZSBjb250YWlucyBkaWN0aW9uYXJ5IHRyYW5zbGF0aW9ucyBmb3IgcGFyc2luZwojCXJlcXVlc3RzIGFuZCBnZW5lcmF0aW5nIHJlc3BvbnNlcy4gIEFsbCB0cmFuc2FjdGlvbnMgYXJlCiMJY29tcG9zZWQgb2YgQXR0cmlidXRlL1ZhbHVlIFBhaXJzLiAgVGhlIHZhbHVlIG9mIGVhY2ggYXR0cmlidXRlCiMJaXMgc3BlY2lmaWVkIGFzIG9uZSBvZiA0IGRhdGEgdHlwZXMuICBWYWxpZCBkYXRhIHR5cGVzIGFyZToKIwojCXN0cmluZyAgLSAwLTI1MyBvY3RldHMKIwlpcGFkZHIgIC0gNCBvY3RldHMgaW4gbmV0d29yayBieXRlIG9yZGVyCiMJaW50ZWdlciAtIDMyIGJpdCB2YWx1ZSBpbiBiaWcgZW5kaWFuIG9yZGVyIChoaWdoIGJ5dGUgZmlyc3QpCiMJZGF0ZSAgICAtIDMyIGJpdCB2YWx1ZSBpbiBiaWcgZW5kaWFuIG9yZGVyIC0gc2Vjb25kcyBzaW5jZQojCQkJCQkwMDowMDowMCBHTVQsICBKYW4uICAxLCAgMTk3MAojCiMJRnJlZVJBRElVUyBpbmNsdWRlcyBleHRlbmRlZCBkYXRhIHR5cGVzIHdoaWNoIGFyZSBub3QgZGVmaW5lZAojCWluIFJGQyAyODY1IG9yIFJGQyAyODY2LiAgVGhlc2UgZGF0YSB0eXBlcyBhcmU6CiMKIwlhYmluYXJ5IC0gQXNjZW5kJ3MgYmluYXJ5IGZpbHRlciBmb3JtYXQuCiMJb2N0ZXRzICAtIHJhdyBvY3RldHMsIHByaW50ZWQgYW5kIGlucHV0IGFzIGhleCBzdHJpbmdzLgojCQkgIGUuZy46IDB4MTIzNDU2Nzg5YWJjZGVmCiMKIwojCUVudW1lcmF0ZWQgdmFsdWVzIGFyZSBzdG9yZWQgaW4gdGhlIHVzZXIgZmlsZSB3aXRoIGRpY3Rpb25hcnkKIwlWQUxVRSB0cmFuc2xhdGlvbnMgZm9yIGVhc3kgYWRtaW5pc3RyYXRpb24uCiMKIwlFeGFtcGxlOgojCiMJQVRUUklCVVRFCSAgVkFMVUUKIwktLS0tLS0tLS0tLS0tLS0gICAtLS0tLQojCUZyYW1lZC1Qcm90b2NvbCA9IFBQUAojCTcJCT0gMQkoaW50ZWdlciBlbmNvZGluZykKIwoKIwojCUluY2x1ZGUgY29tcGF0aWJpbGl0eSBkaWN0aW9uYXJ5IGZvciBvbGRlciB1c2VycyBmaWxlLiBNb3ZlIHRoaXMKIwlkaXJlY3RpdmUgdG8gdGhlIGVuZCBvZiB0aGUgZmlsZSBpZiB5b3Ugd2FudCB0byBzZWUgdGhlIG9sZCBuYW1lcwojCWluIHRoZSBsb2dmaWxlcyB0b28uCiMKIyRJTkNMVURFIGRpY3Rpb25hcnkuY29tcGF0CSMgY29tcGFiaWxpdHkgaXNzdWVzCiMkSU5DTFVERSBkaWN0aW9uYXJ5LmFjYwojJElOQ0xVREUgZGljdGlvbmFyeS5hc2NlbmQKIyRJTkNMVURFIGRpY3Rpb25hcnkuYmF5CiMkSU5DTFVERSBkaWN0aW9uYXJ5LmNpc2NvCiMkSU5DTFVERSBkaWN0aW9uYXJ5LmxpdmluZ3N0b24KIyRJTkNMVURFIGRpY3Rpb25hcnkubWljcm9zb2Z0CiMkSU5DTFVERSBkaWN0aW9uYXJ5LnF1aW50dW0KIyRJTkNMVURFIGRpY3Rpb25hcnkucmVkYmFjawojJElOQ0xVREUgZGljdGlvbmFyeS5zaGFzdGEKIyRJTkNMVURFIGRpY3Rpb25hcnkuc2hpdmEKIyRJTkNMVURFIGRpY3Rpb25hcnkudHVubmVsCiMkSU5DTFVERSBkaWN0aW9uYXJ5LnVzcgojJElOQ0xVREUgZGljdGlvbmFyeS52ZXJzYW5ldAojJElOQ0xVREUgZGljdGlvbmFyeS5lcngKIyRJTkNMVURFIGRpY3Rpb25hcnkuZnJlZXJhZGl1cwojJElOQ0xVREUgZGljdGlvbmFyeS5hbGNhdGVsCgojCiMJRm9sbG93aW5nIGFyZSB0aGUgcHJvcGVyIG5ldyBuYW1lcy4gVXNlIHRoZXNlLgojCkFUVFJJQlVURQlVc2VyLU5hbWUJCTEJc3RyaW5nCkFUVFJJQlVURQlVc2VyLVBhc3N3b3JkCQkyCXN0cmluZwpBVFRSSUJVVEUJQ0hBUC1QYXNzd29yZAkJMwlvY3RldHMKQVRUUklCVVRFCU5BUy1JUC1BZGRyZXNzCQk0CWlwYWRkcgpBVFRSSUJVVEUJTkFTLVBvcnQJCTUJaW50ZWdlcgpBVFRSSUJVVEUJU2VydmljZS1UeXBlCQk2CWludGVnZXIKQVRUUklCVVRFCUZyYW1lZC1Qcm90b2NvbAkJNwlpbnRlZ2VyCkFUVFJJQlVURQlGcmFtZWQtSVAtQWRkcmVzcwk4CWlwYWRkcgpBVFRSSUJVVEUJRnJhbWVkLUlQLU5ldG1hc2sJOQlpcGFkZHIKQVRUUklCVVRFCUZyYW1lZC1Sb3V0aW5nCQkxMAlpbnRlZ2VyCkFUVFJJQlVURQlGaWx0ZXItSWQJCTExCXN0cmluZwpBVFRSSUJVVEUJRnJhbWVkLU1UVQkJMTIJaW50ZWdlcgpBVFRSSUJVVEUJRnJhbWVkLUNvbXByZXNzaW9uCTEzCWludGVnZXIKQVRUUklCVVRFCUxvZ2luLUlQLUhvc3QJCTE0CWlwYWRkcgpBVFRSSUJVVEUJTG9naW4tU2VydmljZQkJMTUJaW50ZWdlcgpBVFRSSUJVVEUJTG9naW4tVENQLVBvcnQJCTE2CWludGVnZXIKQVRUUklCVVRFCVJlcGx5LU1lc3NhZ2UJCTE4CXN0cmluZwpBVFRSSUJVVEUJQ2FsbGJhY2stTnVtYmVyCQkxOQlzdHJpbmcKQVRUUklCVVRFCUNhbGxiYWNrLUlkCQkyMAlzdHJpbmcKQVRUUklCVVRFCUZyYW1lZC1Sb3V0ZQkJMjIJc3RyaW5nCkFUVFJJQlVURQlGcmFtZWQtSVBYLU5ldHdvcmsJMjMJaXBhZGRyCkFUVFJJQlVURQlTdGF0ZQkJCTI0CW9jdGV0cwpBVFRSSUJVVEUJQ2xhc3MJCQkyNQlvY3RldHMKQVRUUklCVVRFCVZlbmRvci1TcGVjaWZpYwkJMjYJb2N0ZXRzCkFUVFJJQlVURQlTZXNzaW9uLVRpbWVvdXQJCTI3CWludGVnZXIKQVRUUklCVVRFCUlkbGUtVGltZW91dAkJMjgJaW50ZWdlcgpBVFRSSUJVVEUJVGVybWluYXRpb24tQWN0aW9uCTI5CWludGVnZXIKQVRUUklCVVRFCUNhbGxlZC1TdGF0aW9uLUlkCTMwCXN0cmluZwpBVFRSSUJVVEUJQ2FsbGluZy1TdGF0aW9uLUlkCTMxCXN0cmluZwpBVFRSSUJVVEUJTkFTLUlkZW50aWZpZXIJCTMyCXN0cmluZwpBVFRSSUJVVEUJUHJveHktU3RhdGUJCTMzCW9jdGV0cwpBVFRSSUJVVEUJTG9naW4tTEFULVNlcnZpY2UJMzQJc3RyaW5nCkFUVFJJQlVURQlMb2dpbi1MQVQtTm9kZQkJMzUJc3RyaW5nCkFUVFJJQlVURQlMb2dpbi1MQVQtR3JvdXAJCTM2CW9jdGV0cwpBVFRSSUJVVEUJRnJhbWVkLUFwcGxlVGFsay1MaW5rCTM3CWludGVnZXIKQVRUUklCVVRFCUZyYW1lZC1BcHBsZVRhbGstTmV0d29yayAzOAlpbnRlZ2VyCkFUVFJJQlVURQlGcmFtZWQtQXBwbGVUYWxrLVpvbmUJMzkJc3RyaW5nCgpBVFRSSUJVVEUJQWNjdC1TdGF0dXMtVHlwZQk0MAlpbnRlZ2VyCkFUVFJJQlVURQlBY2N0LURlbGF5LVRpbWUJCTQxCWludGVnZXIKQVRUUklCVVRFCUFjY3QtSW5wdXQtT2N0ZXRzCTQyCWludGVnZXIKQVRUUklCVVRFCUFjY3QtT3V0cHV0LU9jdGV0cwk0MwlpbnRlZ2VyCkFUVFJJQlVURQlBY2N0LVNlc3Npb24tSWQJCTQ0CXN0cmluZwpBVFRSSUJVVEUJQWNjdC1BdXRoZW50aWMJCTQ1CWludGVnZXIKQVRUUklCVVRFCUFjY3QtU2Vzc2lvbi1UaW1lCTQ2CWludGVnZXIKQVRUUklCVVRFICAgICAgIEFjY3QtSW5wdXQtUGFja2V0cwk0NwlpbnRlZ2VyCkFUVFJJQlVURSAgICAgICBBY2N0LU91dHB1dC1QYWNrZXRzCTQ4CWludGVnZXIKQVRUUklCVVRFCUFjY3QtVGVybWluYXRlLUNhdXNlCTQ5CWludGVnZXIKQVRUUklCVVRFCUFjY3QtTXVsdGktU2Vzc2lvbi1JZAk1MAlzdHJpbmcKQVRUUklCVVRFCUFjY3QtTGluay1Db3VudAkJNTEJaW50ZWdlcgpBVFRSSUJVVEUJQWNjdC1JbnB1dC1HaWdhd29yZHMgICAgNTIgICAgICBpbnRlZ2VyCkFUVFJJQlVURQlBY2N0LU91dHB1dC1HaWdhd29yZHMgICA1MyAgICAgIGludGVnZXIKQVRUUklCVVRFCUV2ZW50LVRpbWVzdGFtcCAgICAgICAgIDU1ICAgICAgZGF0ZQoKQVRUUklCVVRFCUNIQVAtQ2hhbGxlbmdlCQk2MAlzdHJpbmcKQVRUUklCVVRFCU5BUy1Qb3J0LVR5cGUJCTYxCWludGVnZXIKQVRUUklCVVRFCVBvcnQtTGltaXQJCTYyCWludGVnZXIKQVRUUklCVVRFCUxvZ2luLUxBVC1Qb3J0CQk2MwlpbnRlZ2VyCgpBVFRSSUJVVEUJQWNjdC1UdW5uZWwtQ29ubmVjdGlvbgk2OAlzdHJpbmcKCkFUVFJJQlVURQlBUkFQLVBhc3N3b3JkICAgICAgICAgICA3MCAgICAgIHN0cmluZwpBVFRSSUJVVEUJQVJBUC1GZWF0dXJlcyAgICAgICAgICAgNzEgICAgICBzdHJpbmcKQVRUUklCVVRFCUFSQVAtWm9uZS1BY2Nlc3MgICAgICAgIDcyICAgICAgaW50ZWdlcgpBVFRSSUJVVEUJQVJBUC1TZWN1cml0eSAgICAgICAgICAgNzMgICAgICBpbnRlZ2VyCkFUVFJJQlVURQlBUkFQLVNlY3VyaXR5LURhdGEgICAgICA3NCAgICAgIHN0cmluZwpBVFRSSUJVVEUJUGFzc3dvcmQtUmV0cnkgICAgICAgICAgNzUgICAgICBpbnRlZ2VyCkFUVFJJQlVURQlQcm9tcHQgICAgICAgICAgICAgICAgICA3NiAgICAgIGludGVnZXIKQVRUUklCVVRFCUNvbm5lY3QtSW5mbwkJNzcJc3RyaW5nCkFUVFJJQlVURQlDb25maWd1cmF0aW9uLVRva2VuCTc4CXN0cmluZwpBVFRSSUJVVEUJRUFQLU1lc3NhZ2UJCTc5CXN0cmluZwpBVFRSSUJVVEUJTWVzc2FnZS1BdXRoZW50aWNhdG9yCTgwCW9jdGV0cwpBVFRSSUJVVEUJQVJBUC1DaGFsbGVuZ2UtUmVzcG9uc2UJODQJc3RyaW5nCSMgMTAgb2N0ZXRzCkFUVFJJQlVURQlBY2N0LUludGVyaW0tSW50ZXJ2YWwgICA4NSAgICAgIGludGVnZXIKQVRUUklCVVRFCU5BUy1Qb3J0LUlkCQk4NwlzdHJpbmcKQVRUUklCVVRFCUZyYW1lZC1Qb29sCQk4OAlzdHJpbmcKQVRUUklCVVRFCU5BUy1JUHY2LUFkZHJlc3MJOTUJb2N0ZXRzCSMgcmVhbGx5IElQdjYKQVRUUklCVVRFCUZyYW1lZC1JbnRlcmZhY2UtSWQJOTYJb2N0ZXRzCSMgOCBvY3RldHMKQVRUUklCVVRFCUZyYW1lZC1JUHY2LVByZWZpeAk5NwlpcHY2cHJlZml4CSMgc3R1cGlkIGZvcm1hdApBVFRSSUJVVEUJTG9naW4tSVB2Ni1Ib3N0CQk5OAlvY3RldHMJIyByZWFsbHkgSVB2NgpBVFRSSUJVVEUJRnJhbWVkLUlQdjYtUm91dGUJOTkJc3RyaW5nCkFUVFJJQlVURQlGcmFtZWQtSVB2Ni1Qb29sCTEwMAlzdHJpbmcKQVRUUklCVVRFICAgRGVsZWdhdGVkLUlQdjYtUHJlZml4ICAgMTIzICAgICBpcHY2cHJlZml4CgoKQVRUUklCVVRFCURpZ2VzdC1SZXNwb25zZQkJMjA2CXN0cmluZwpBVFRSSUJVVEUJRGlnZXN0LUF0dHJpYnV0ZXMJMjA3CW9jdGV0cwkjIHN0dXBpZCBmb3JtYXQKCiMKIwlFeHBlcmltZW50YWwgTm9uIFByb3RvY29sIEF0dHJpYnV0ZXMgdXNlZCBieSBDaXN0cm9uLVJhZGl1c2QKIwoKIyAJVGhlc2UgYXR0cmlidXRlcyBDQU4gZ28gaW4gdGhlIHJlcGx5IGl0ZW0gbGlzdC4KQVRUUklCVVRFCUZhbGwtVGhyb3VnaAkJNTAwCWludGVnZXIKQVRUUklCVVRFCUV4ZWMtUHJvZ3JhbQkJNTAyCXN0cmluZwpBVFRSSUJVVEUJRXhlYy1Qcm9ncmFtLVdhaXQJNTAzCXN0cmluZwoKIwlUaGVzZSBhdHRyaWJ1dGVzIENBTk5PVCBnbyBpbiB0aGUgcmVwbHkgaXRlbSBsaXN0LgpBVFRSSUJVVEUJVXNlci1DYXRlZ29yeQkJMTAyOQlzdHJpbmcKQVRUUklCVVRFCUdyb3VwLU5hbWUJCTEwMzAJc3RyaW5nCkFUVFJJQlVURQlIdW50Z3JvdXAtTmFtZQkJMTAzMQlzdHJpbmcKQVRUUklCVVRFCVNpbXVsdGFuZW91cy1Vc2UJMTAzNAlpbnRlZ2VyCkFUVFJJQlVURQlTdHJpcC1Vc2VyLU5hbWUJCTEwMzUJaW50ZWdlcgpBVFRSSUJVVEUJSGludAkJCTEwNDAJc3RyaW5nCkFUVFJJQlVURQlQYW0tQXV0aAkJMTA0MQlzdHJpbmcKQVRUUklCVVRFCUxvZ2luLVRpbWUJCTEwNDIJc3RyaW5nCkFUVFJJQlVURQlTdHJpcHBlZC1Vc2VyLU5hbWUJMTA0MwlzdHJpbmcKQVRUUklCVVRFCUN1cnJlbnQtVGltZQkJMTA0NAlzdHJpbmcKQVRUUklCVVRFCVJlYWxtCQkJMTA0NQlzdHJpbmcKQVRUUklCVVRFCU5vLVN1Y2gtQXR0cmlidXRlCTEwNDYJc3RyaW5nCkFUVFJJQlVURQlQYWNrZXQtVHlwZQkJMTA0NwlpbnRlZ2VyCkFUVFJJQlVURQlQcm94eS1Uby1SZWFsbQkJMTA0OAlzdHJpbmcKQVRUUklCVVRFCVJlcGxpY2F0ZS1Uby1SZWFsbQkxMDQ5CXN0cmluZwpBVFRSSUJVVEUJQWNjdC1TZXNzaW9uLVN0YXJ0LVRpbWUJMTA1MAlkYXRlCkFUVFJJQlVURQlBY2N0LVVuaXF1ZS1TZXNzaW9uLUlkICAxMDUxCXN0cmluZwpBVFRSSUJVVEUJQ2xpZW50LUlQLUFkZHJlc3MJMTA1MglpcGFkZHIKQVRUUklCVVRFCUxkYXAtVXNlckRuCQkxMDUzCXN0cmluZwpBVFRSSUJVVEUJTlMtTVRBLU1ENS1QYXNzd29yZAkxMDU0CXN0cmluZwpBVFRSSUJVVEUJU1FMLVVzZXItTmFtZQkgCTEwNTUJc3RyaW5nCkFUVFJJQlVURQlMTS1QYXNzd29yZAkJMTA1NwlvY3RldHMKQVRUUklCVVRFCU5ULVBhc3N3b3JkCQkxMDU4CW9jdGV0cwpBVFRSSUJVVEUJU01CLUFjY291bnQtQ1RSTAkxMDU5CWludGVnZXIKQVRUUklCVVRFCVNNQi1BY2NvdW50LUNUUkwtVEVYVAkxMDYxCXN0cmluZwpBVFRSSUJVVEUJVXNlci1Qcm9maWxlCQkxMDYyCXN0cmluZwpBVFRSSUJVVEUJRGlnZXN0LVJlYWxtCQkxMDYzCXN0cmluZwpBVFRSSUJVVEUJRGlnZXN0LU5vbmNlCQkxMDY0CXN0cmluZwpBVFRSSUJVVEUJRGlnZXN0LU1ldGhvZAkJMTA2NQlzdHJpbmcKQVRUUklCVVRFCURpZ2VzdC1VUkkJCTEwNjYJc3RyaW5nCkFUVFJJQlVURQlEaWdlc3QtUU9QCQkxMDY3CXN0cmluZwpBVFRSSUJVVEUJRGlnZXN0LUFsZ29yaXRobQkxMDY4CXN0cmluZwpBVFRSSUJVVEUJRGlnZXN0LUJvZHktRGlnZXN0CTEwNjkJc3RyaW5nCkFUVFJJQlVURQlEaWdlc3QtQ05vbmNlCQkxMDcwCXN0cmluZwpBVFRSSUJVVEUJRGlnZXN0LU5vbmNlLUNvdW50CTEwNzEJc3RyaW5nCkFUVFJJQlVURQlEaWdlc3QtVXNlci1OYW1lCTEwNzIJc3RyaW5nCkFUVFJJQlVURQlQb29sLU5hbWUJCTEwNzMJc3RyaW5nCkFUVFJJQlVURQlMZGFwLUdyb3VwCQkxMDc0CXN0cmluZwpBVFRSSUJVVEUJTW9kdWxlLVN1Y2Nlc3MtTWVzc2FnZQkxMDc1CXN0cmluZwpBVFRSSUJVVEUJTW9kdWxlLUZhaWx1cmUtTWVzc2FnZQkxMDc2CXN0cmluZwojCQlYOTktRmFzdAkJMTA3NwlpbnRlZ2VyCgojCiMJTm9uLVByb3RvY29sIEF0dHJpYnV0ZXMKIwlUaGVzZSBhdHRyaWJ1dGVzIGFyZSB1c2VkIGludGVybmFsbHkgYnkgdGhlIHNlcnZlcgojCkFUVFJJQlVURQlBdXRoLVR5cGUJCTEwMDAJaW50ZWdlcgpBVFRSSUJVVEUJTWVudQkJCTEwMDEJc3RyaW5nCkFUVFJJQlVURQlUZXJtaW5hdGlvbi1NZW51CTEwMDIJc3RyaW5nCkFUVFJJQlVURQlQcmVmaXgJCQkxMDAzCXN0cmluZwpBVFRSSUJVVEUJU3VmZml4CQkJMTAwNAlzdHJpbmcKQVRUUklCVVRFCUdyb3VwCQkJMTAwNQlzdHJpbmcKQVRUUklCVVRFCUNyeXB0LVBhc3N3b3JkCQkxMDA2CXN0cmluZwpBVFRSSUJVVEUJQ29ubmVjdC1SYXRlCQkxMDA3CWludGVnZXIKQVRUUklCVVRFCUFkZC1QcmVmaXgJCTEwMDgJc3RyaW5nCkFUVFJJQlVURQlBZGQtU3VmZml4CQkxMDA5CXN0cmluZwpBVFRSSUJVVEUJRXhwaXJhdGlvbgkJMTAxMAlkYXRlCkFUVFJJQlVURQlBdXR6LVR5cGUJCTEwMTEJaW50ZWdlcgoKIwojCUludGVnZXIgVHJhbnNsYXRpb25zCiMKCiMJVXNlciBUeXBlcwoKVkFMVUUJCVNlcnZpY2UtVHlwZQkJTG9naW4tVXNlcgkJMQpWQUxVRQkJU2VydmljZS1UeXBlCQlGcmFtZWQtVXNlcgkJMgpWQUxVRQkJU2VydmljZS1UeXBlCQlDYWxsYmFjay1Mb2dpbi1Vc2VyCTMKVkFMVUUJCVNlcnZpY2UtVHlwZQkJQ2FsbGJhY2stRnJhbWVkLVVzZXIJNApWQUxVRQkJU2VydmljZS1UeXBlCQlPdXRib3VuZC1Vc2VyCQk1ClZBTFVFCQlTZXJ2aWNlLVR5cGUJCUFkbWluaXN0cmF0aXZlLVVzZXIJNgpWQUxVRQkJU2VydmljZS1UeXBlCQlOQVMtUHJvbXB0LVVzZXIJCTcKVkFMVUUJCVNlcnZpY2UtVHlwZQkJQXV0aGVudGljYXRlLU9ubHkJOApWQUxVRQkJU2VydmljZS1UeXBlCQlDYWxsYmFjay1OQVMtUHJvbXB0CTkKVkFMVUUJCVNlcnZpY2UtVHlwZQkJQ2FsbC1DaGVjawkJMTAKVkFMVUUJCVNlcnZpY2UtVHlwZQkJQ2FsbGJhY2stQWRtaW5pc3RyYXRpdmUJMTEKCiMJRnJhbWVkIFByb3RvY29scwoKVkFMVUUJCUZyYW1lZC1Qcm90b2NvbAkJUFBQCQkJMQpWQUxVRQkJRnJhbWVkLVByb3RvY29sCQlTTElQCQkJMgpWQUxVRQkJRnJhbWVkLVByb3RvY29sCQlBUkFQCQkJMwpWQUxVRQkJRnJhbWVkLVByb3RvY29sCQlHYW5kYWxmLVNMTUwJCTQKVkFMVUUJCUZyYW1lZC1Qcm90b2NvbAkJWHlsb2dpY3MtSVBYLVNMSVAJNQpWQUxVRQkJRnJhbWVkLVByb3RvY29sCQlYLjc1LVN5bmNocm9ub3VzCTYKCiMJRnJhbWVkIFJvdXRpbmcgVmFsdWVzCgpWQUxVRQkJRnJhbWVkLVJvdXRpbmcJCU5vbmUJCQkwClZBTFVFCQlGcmFtZWQtUm91dGluZwkJQnJvYWRjYXN0CQkxClZBTFVFCQlGcmFtZWQtUm91dGluZwkJTGlzdGVuCQkJMgpWQUxVRQkJRnJhbWVkLVJvdXRpbmcJCUJyb2FkY2FzdC1MaXN0ZW4JMwoKIwlGcmFtZWQgQ29tcHJlc3Npb24gVHlwZXMKClZBTFVFCQlGcmFtZWQtQ29tcHJlc3Npb24JTm9uZQkJCTAKVkFMVUUJCUZyYW1lZC1Db21wcmVzc2lvbglWYW4tSmFjb2Jzb24tVENQLUlQCTEKVkFMVUUJCUZyYW1lZC1Db21wcmVzc2lvbglJUFgtSGVhZGVyLUNvbXByZXNzaW9uCTIKVkFMVUUJCUZyYW1lZC1Db21wcmVzc2lvbglTdGFjLUxaUwkJMwoKIwlMb2dpbiBTZXJ2aWNlcwoKVkFMVUUJCUxvZ2luLVNlcnZpY2UJCVRlbG5ldAkJCTAKVkFMVUUJCUxvZ2luLVNlcnZpY2UJCVJsb2dpbgkJCTEKVkFMVUUJCUxvZ2luLVNlcnZpY2UJCVRDUC1DbGVhcgkJMgpWQUxVRQkJTG9naW4tU2VydmljZQkJUG9ydE1hc3RlcgkJMwpWQUxVRQkJTG9naW4tU2VydmljZQkJTEFUCQkJNApWQUxVRQkJTG9naW4tU2VydmljZQkJWDI1LVBBRAkJCTUKVkFMVUUJCUxvZ2luLVNlcnZpY2UJCVgyNS1UM1BPUwkJNgpWQUxVRQkJTG9naW4tU2VydmljZQkJVENQLUNsZWFyLVF1aWV0CQk4CgojCUxvZ2luLVRDUC1Qb3J0CQkoc2VlIC9ldGMvc2VydmljZXMgZm9yIG1vcmUgZXhhbXBsZXMpCgpWQUxVRQkJTG9naW4tVENQLVBvcnQJCVRlbG5ldAkJCTIzClZBTFVFCQlMb2dpbi1UQ1AtUG9ydAkJUmxvZ2luCQkJNTEzClZBTFVFCQlMb2dpbi1UQ1AtUG9ydAkJUnNoCQkJNTE0CgojCVN0YXR1cyBUeXBlcwoKVkFMVUUJCUFjY3QtU3RhdHVzLVR5cGUJU3RhcnQJCQkxClZBTFVFCQlBY2N0LVN0YXR1cy1UeXBlCVN0b3AJCQkyClZBTFVFCQlBY2N0LVN0YXR1cy1UeXBlCUludGVyaW0tVXBkYXRlCQkzClZBTFVFCQlBY2N0LVN0YXR1cy1UeXBlCUFsaXZlCQkJMwpWQUxVRQkJQWNjdC1TdGF0dXMtVHlwZQlBY2NvdW50aW5nLU9uCQk3ClZBTFVFCQlBY2N0LVN0YXR1cy1UeXBlCUFjY291bnRpbmctT2ZmCQk4CiMJUkZDIDI4NjcgQWRkaXRpb25hbCBTdGF0dXMtVHlwZSBWYWx1ZXMKVkFMVUUJCUFjY3QtU3RhdHVzLVR5cGUJVHVubmVsLVN0YXJ0CQk5ClZBTFVFCQlBY2N0LVN0YXR1cy1UeXBlCVR1bm5lbC1TdG9wCQkxMApWQUxVRQkJQWNjdC1TdGF0dXMtVHlwZQlUdW5uZWwtUmVqZWN0CQkxMQpWQUxVRQkJQWNjdC1TdGF0dXMtVHlwZQlUdW5uZWwtTGluay1TdGFydAkxMgpWQUxVRQkJQWNjdC1TdGF0dXMtVHlwZQlUdW5uZWwtTGluay1TdG9wCTEzClZBTFVFCQlBY2N0LVN0YXR1cy1UeXBlCVR1bm5lbC1MaW5rLVJlamVjdAkxNAoKIwlBdXRoZW50aWNhdGlvbiBUeXBlcwoKVkFMVUUJCUFjY3QtQXV0aGVudGljCQlSQURJVVMJCQkxClZBTFVFCQlBY2N0LUF1dGhlbnRpYwkJTG9jYWwJCQkyCgojCVRlcm1pbmF0aW9uIE9wdGlvbnMKClZBTFVFCQlUZXJtaW5hdGlvbi1BY3Rpb24JRGVmYXVsdAkJCTAKVkFMVUUJCVRlcm1pbmF0aW9uLUFjdGlvbglSQURJVVMtUmVxdWVzdAkJMQoKIwlOQVMgUG9ydCBUeXBlcwoKVkFMVUUJCU5BUy1Qb3J0LVR5cGUJCUFzeW5jCQkJMApWQUxVRQkJTkFTLVBvcnQtVHlwZQkJU3luYwkJCTEKVkFMVUUJCU5BUy1Qb3J0LVR5cGUJCUlTRE4JCQkyClZBTFVFCQlOQVMtUG9ydC1UeXBlCQlJU0ROLVYxMjAJCTMKVkFMVUUJCU5BUy1Qb3J0LVR5cGUJCUlTRE4tVjExMAkJNApWQUxVRQkJTkFTLVBvcnQtVHlwZQkJVmlydHVhbAkJCTUKVkFMVUUJCU5BUy1Qb3J0LVR5cGUJCVBJQUZTCQkJNgpWQUxVRQkJTkFTLVBvcnQtVHlwZQkJSERMQy1DbGVhci1DaGFubmVsCTcKVkFMVUUJCU5BUy1Qb3J0LVR5cGUJCVguMjUJCQk4ClZBTFVFCQlOQVMtUG9ydC1UeXBlCQlYLjc1CQkJOQpWQUxVRQkJTkFTLVBvcnQtVHlwZQkJRy4zLUZheAkJCTEwClZBTFVFCQlOQVMtUG9ydC1UeXBlCQlTRFNMCQkJMTEKVkFMVUUJCU5BUy1Qb3J0LVR5cGUJCUFEU0wtQ0FQCQkxMgpWQUxVRQkJTkFTLVBvcnQtVHlwZQkJQURTTC1ETVQJCTEzClZBTFVFCQlOQVMtUG9ydC1UeXBlCQlJRFNMCQkJMTQKVkFMVUUJCU5BUy1Qb3J0LVR5cGUJCUV0aGVybmV0CQkxNQpWQUxVRQkJTkFTLVBvcnQtVHlwZQkJeERTTAkJCTE2ClZBTFVFCQlOQVMtUG9ydC1UeXBlCQlDYWJsZQkJCTE3ClZBTFVFCQlOQVMtUG9ydC1UeXBlCQlXaXJlbGVzcy1PdGhlcgkJMTgKVkFMVUUJCU5BUy1Qb3J0LVR5cGUJCVdpcmVsZXNzLTgwMi4xMQkJMTkKCiMJQWNjdCBUZXJtaW5hdGUgQ2F1c2VzLCBhdmFpbGFibGUgaW4gMy4zLjIgYW5kIGxhdGVyCgpWQUxVRSAgICAgICAgICAgQWNjdC1UZXJtaW5hdGUtQ2F1c2UgICAgVXNlci1SZXF1ZXN0ICAgICAgICAgICAgMQpWQUxVRSAgICAgICAgICAgQWNjdC1UZXJtaW5hdGUtQ2F1c2UgICAgTG9zdC1DYXJyaWVyICAgICAgICAgICAgMgpWQUxVRSAgICAgICAgICAgQWNjdC1UZXJtaW5hdGUtQ2F1c2UgICAgTG9zdC1TZXJ2aWNlICAgICAgICAgICAgMwpWQUxVRSAgICAgICAgICAgQWNjdC1UZXJtaW5hdGUtQ2F1c2UgICAgSWRsZS1UaW1lb3V0ICAgICAgICAgICAgNApWQUxVRSAgICAgICAgICAgQWNjdC1UZXJtaW5hdGUtQ2F1c2UgICAgU2Vzc2lvbi1UaW1lb3V0ICAgICAgICAgNQpWQUxVRSAgICAgICAgICAgQWNjdC1UZXJtaW5hdGUtQ2F1c2UgICAgQWRtaW4tUmVzZXQgICAgICAgICAgICAgNgpWQUxVRSAgICAgICAgICAgQWNjdC1UZXJtaW5hdGUtQ2F1c2UgICAgQWRtaW4tUmVib290ICAgICAgICAgICAgNwpWQUxVRSAgICAgICAgICAgQWNjdC1UZXJtaW5hdGUtQ2F1c2UgICAgUG9ydC1FcnJvciAgICAgICAgICAgICAgOApWQUxVRSAgICAgICAgICAgQWNjdC1UZXJtaW5hdGUtQ2F1c2UgICAgTkFTLUVycm9yICAgICAgICAgICAgICAgOQpWQUxVRSAgICAgICAgICAgQWNjdC1UZXJtaW5hdGUtQ2F1c2UgICAgTkFTLVJlcXVlc3QgICAgICAgICAgICAgMTAKVkFMVUUgICAgICAgICAgIEFjY3QtVGVybWluYXRlLUNhdXNlICAgIE5BUy1SZWJvb3QgICAgICAgICAgICAgIDExClZBTFVFICAgICAgICAgICBBY2N0LVRlcm1pbmF0ZS1DYXVzZSAgICBQb3J0LVVubmVlZGVkICAgICAgICAgICAxMgpWQUxVRSAgICAgICAgICAgQWNjdC1UZXJtaW5hdGUtQ2F1c2UgICAgUG9ydC1QcmVlbXB0ZWQgICAgICAgICAgMTMKVkFMVUUgICAgICAgICAgIEFjY3QtVGVybWluYXRlLUNhdXNlICAgIFBvcnQtU3VzcGVuZGVkICAgICAgICAgIDE0ClZBTFVFICAgICAgICAgICBBY2N0LVRlcm1pbmF0ZS1DYXVzZSAgICBTZXJ2aWNlLVVuYXZhaWxhYmxlICAgICAxNQpWQUxVRSAgICAgICAgICAgQWNjdC1UZXJtaW5hdGUtQ2F1c2UgICAgQ2FsbGJhY2sgICAgICAgICAgICAgICAgMTYKVkFMVUUgICAgICAgICAgIEFjY3QtVGVybWluYXRlLUNhdXNlICAgIFVzZXItRXJyb3IgICAgICAgICAgICAgIDE3ClZBTFVFICAgICAgICAgICBBY2N0LVRlcm1pbmF0ZS1DYXVzZSAgICBIb3N0LVJlcXVlc3QgICAgICAgICAgICAxOAoKI1ZBTFVFCQlUdW5uZWwtVHlwZQkJTDJUUAkJCTMKI1ZBTFVFCQlUdW5uZWwtTWVkaXVtLVR5cGUJSVAJCQkxCgpWQUxVRQkJUHJvbXB0CQkJTm8tRWNobwkJCTAKVkFMVUUJCVByb21wdAkJCUVjaG8JCQkxCgojCiMJTm9uLVByb3RvY29sIEludGVnZXIgVHJhbnNsYXRpb25zCiMKClZBTFVFCQlBdXRoLVR5cGUJCUxvY2FsCQkJMApWQUxVRQkJQXV0aC1UeXBlCQlTeXN0ZW0JCQkxClZBTFVFCQlBdXRoLVR5cGUJCVNlY3VySUQJCQkyClZBTFVFCQlBdXRoLVR5cGUJCUNyeXB0LUxvY2FsCQkzClZBTFVFCQlBdXRoLVR5cGUJCVJlamVjdAkJCTQKVkFMVUUJCUF1dGgtVHlwZQkJQWN0aXZDYXJkCQk1ClZBTFVFCQlBdXRoLVR5cGUJCUVBUAkJCTYKVkFMVUUJCUF1dGgtVHlwZQkJQVJBUAkJCTcKCiMKIwlDaXN0cm9uIGV4dGVuc2lvbnMKIwpWQUxVRQkJQXV0aC1UeXBlCQlMZGFwCQkJMjUyClZBTFVFCQlBdXRoLVR5cGUJCVBhbQkJCTI1MwpWQUxVRQkJQXV0aC1UeXBlCQlBY2NlcHQJCQkyNTQKClZBTFVFCQlBdXRoLVR5cGUJCVBBUAkJCTEwMjQKVkFMVUUJCUF1dGgtVHlwZQkJQ0hBUAkJCTEwMjUKVkFMVUUJCUF1dGgtVHlwZQkJTERBUAkJCTEwMjYKVkFMVUUJCUF1dGgtVHlwZQkJUEFNCQkJMTAyNwpWQUxVRQkJQXV0aC1UeXBlCQlNUy1DSEFQCQkJMTAyOApWQUxVRQkJQXV0aC1UeXBlCQlLZXJiZXJvcwkJMTAyOQpWQUxVRQkJQXV0aC1UeXBlCQlDUkFNCQkJMTAzMApWQUxVRQkJQXV0aC1UeXBlCQlOUy1NVEEtTUQ1CQkxMDMxClZBTFVFCQlBdXRoLVR5cGUJCUNSQU0JCQkxMDMyClZBTFVFCQlBdXRoLVR5cGUJCVNNQgkJCTEwMzMKCiMKIwlBdXRob3JpemF0aW9uIHR5cGUsIHRvby4KIwpWQUxVRQkJQXV0ei1UeXBlCQlMb2NhbAkJCTAKCiMKIwlFeHBlcmltZW50YWwgTm9uLVByb3RvY29sIEludGVnZXIgVHJhbnNsYXRpb25zIGZvciBDaXN0cm9uLVJhZGl1c2QKIwpWQUxVRQkJRmFsbC1UaHJvdWdoCQlObwkJCTAKVkFMVUUJCUZhbGwtVGhyb3VnaAkJWWVzCQkJMQoKVkFMVUUJCVBhY2tldC1UeXBlCUFjY2Vzcy1SZXF1ZXN0CQkJMQpWQUxVRQkJUGFja2V0LVR5cGUJQWNjZXNzLUFjY2VwdAkJCTIKVkFMVUUJCVBhY2tldC1UeXBlCUFjY2Vzcy1SZWplY3QJCQkzClZBTFVFCQlQYWNrZXQtVHlwZQlBY2NvdW50aW5nLVJlcXVlc3QJCTQKVkFMVUUJCVBhY2tldC1UeXBlCUFjY291bnRpbmctUmVzcG9uc2UJCTUKVkFMVUUJCVBhY2tldC1UeXBlCUFjY291bnRpbmctU3RhdHVzCQk2ClZBTFVFCQlQYWNrZXQtVHlwZQlQYXNzd29yZC1SZXF1ZXN0CQk3ClZBTFVFCQlQYWNrZXQtVHlwZQlQYXNzd29yZC1BY2NlcHQJCQk4ClZBTFVFCQlQYWNrZXQtVHlwZQlQYXNzd29yZC1SZWplY3QJCQk5ClZBTFVFCQlQYWNrZXQtVHlwZQlBY2NvdW50aW5nLU1lc3NhZ2UJCTEwClZBTFVFCQlQYWNrZXQtVHlwZQlBY2Nlc3MtQ2hhbGxlbmdlCQkxMQpWQUxVRQkJUGFja2V0LVR5cGUJU3RhdHVzLVNlcnZlcgkJCTEyClZBTFVFCQlQYWNrZXQtVHlwZQlTdGF0dXMtQ2xpZW50CQkJMTMK"

if __name__ == "__main__":
    main()
