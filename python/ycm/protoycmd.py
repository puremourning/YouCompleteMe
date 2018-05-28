# encoding: utf-8
#
# Copyright (C) 2018 ycmd contributors
#
# This file is part of ycmd.
#
# ycmd is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# ycmd is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with ycmd.  If not, see <http://www.gnu.org/licenses/>.

from __future__ import unicode_literals
from __future__ import print_function
from __future__ import division
from __future__ import absolute_import
# Not installing aliases from python-future; it's unreliable and slow.
from builtins import *  # noqa

from collections import defaultdict
from future.utils import PY2, iteritems, with_metaclass
from frozendict import frozendict
import abc
import collections
import copy
import hmac
import hashlib
import json
import logging
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
import threading

_logger = logging.getLogger( __name__ )

MESSAGE_POLL_TIMEOUT = 5

# Creation flag to disable creating a console window on Windows. See
# https://msdn.microsoft.com/en-us/library/windows/desktop/ms684863.aspx
CREATE_NO_WINDOW = 0x08000000

EXECUTABLE_FILE_MASK = os.F_OK | os.X_OK

_USER_OPTIONS = {}

# At least c++ and javascript support unicode identifiers, and identifiers may
# start with unicode character, e.g. ålpha. So we need to accept any identifier
# starting with an 'alpha' character or underscore. i.e. not starting with a
# 'digit'. The following regex will match:
#   - A character which is alpha or _. That is a character which is NOT:
#     - a digit (\d)
#     - non-alphanumeric
#     - not an underscore
#       (The latter two come from \W which is the negation of \w)
#   - Followed by any alphanumeric or _ characters
DEFAULT_IDENTIFIER_REGEX = re.compile( r"[^\W\d]\w*", re.UNICODE )

TRIGGER_REGEX_PREFIX = 're!'

DEFAULT_FILETYPE_TRIGGERS = {
  'c' : [ '->', '.' ],
  'objc,objcpp' : [
    '->',
    '.',
    r're!\[[_a-zA-Z]+\w*\s',    # bracketed calls
    r're!^\s*[^\W\d]\w*\s',     # bracketless calls
    r're!\[.*\]\s',             # method composition
  ],
  'ocaml' : [ '.', '#' ],
  'cpp,cuda,objcpp' : [ '->', '.', '::' ],
  'perl' : [ '->' ],
  'php' : [ '->', '::' ],
  'cs,java,javascript,typescript,d,python,perl6,scala,vb,elixir,go,groovy' : [
    '.'
  ],
  'ruby,rust' : [ '.', '::' ],
  'lua' : [ '.', ':' ],
  'erlang' : [ ':' ],
}

FILETYPE_TO_IDENTIFIER_REGEX = {
    # Spec:
    # http://www.ecma-international.org/ecma-262/6.0/#sec-names-and-keywords
    # Default identifier plus the dollar sign.
    'javascript': re.compile( r"(?:[^\W\d]|\$)[\w$]*", re.UNICODE ),

    # Spec: https://www.w3.org/TR/css-syntax-3/#ident-token-diagram
    'css': re.compile( r"-?[^\W\d][\w-]*", re.UNICODE ),

    # Spec: http://www.w3.org/TR/html5/syntax.html#tag-name-state
    # But not quite since not everything we want to pull out is a tag name. We
    # also want attribute names (and probably unquoted attribute values).
    # And we also want to ignore common template chars like `}` and `{`.
    'html': re.compile( r"[a-zA-Z][^\s/>='\"}{\.]*", re.UNICODE ),

    # Spec: http://cran.r-project.org/doc/manuals/r-release/R-lang.pdf
    # Section 10.3.2.
    # Can be any sequence of '.', '_' and alphanum BUT can't start with:
    #   - '.' followed by digit
    #   - digit
    #   - '_'
    'r': re.compile( r"(?!(?:\.\d|\d|_))[\.\w]+", re.UNICODE ),

    # Spec: http://clojure.org/reader
    # Section: Symbols
    'clojure': re.compile(
         r"[-\*\+!_\?:\.a-zA-Z][-\*\+!_\?:\.\w]*/?[-\*\+!_\?:\.\w]*",
         re.UNICODE ),

    # Spec: http://www.haskell.org/onlinereport/lexemes.html
    # Section 2.4
    'haskell': re.compile( r"[_a-zA-Z][\w']+", re.UNICODE ),

    # Spec: ?
    # Colons are often used in labels (e.g. \label{fig:foobar}) so we accept
    # them in the middle of an identifier but not at its extremities. We also
    # accept dashes for compound words.
    'tex': re.compile( r"[^\W\d](?:[\w:-]*\w)?", re.UNICODE ),

    # Spec: http://doc.perl6.org/language/syntax
    'perl6': re.compile( r"[_a-zA-Z](?:\w|[-'](?=[_a-zA-Z]))*", re.UNICODE ),

    # https://www.scheme.com/tspl4/grammar.html#grammar:symbols
    'scheme': re.compile( r"\+|\-|\.\.\.|"
                          r"(?:->|(:?\\x[0-9A-Fa-f]+;|[!$%&*/:<=>?~^]|[^\W\d]))"
                          r"(?:\\x[0-9A-Fa-f]+;|[-+.@!$%&*/:<=>?~^\w])*",
                          re.UNICODE ),
}

FILETYPE_TO_IDENTIFIER_REGEX[ 'typescript' ] = (
  FILETYPE_TO_IDENTIFIER_REGEX[ 'javascript' ] )
FILETYPE_TO_IDENTIFIER_REGEX[ 'scss' ] = FILETYPE_TO_IDENTIFIER_REGEX[ 'css' ]
FILETYPE_TO_IDENTIFIER_REGEX[ 'sass' ] = FILETYPE_TO_IDENTIFIER_REGEX[ 'css' ]
FILETYPE_TO_IDENTIFIER_REGEX[ 'less' ] = FILETYPE_TO_IDENTIFIER_REGEX[ 'css' ]
FILETYPE_TO_IDENTIFIER_REGEX[ 'elisp' ] = (
  FILETYPE_TO_IDENTIFIER_REGEX[ 'clojure' ] )
FILETYPE_TO_IDENTIFIER_REGEX[ 'lisp' ] = (
  FILETYPE_TO_IDENTIFIER_REGEX[ 'clojure' ] )


def CreateHmac( content, hmac_secret ):
  # Note that py2's str type passes this check (and that's ok)
  if not isinstance( content, bytes ):
    raise TypeError( 'content was not of bytes type; you have a bug!' )
  if not isinstance( hmac_secret, bytes ):
    raise TypeError( 'hmac_secret was not of bytes type; you have a bug!' )

  return bytes( hmac.new( hmac_secret,
                          msg = content,
                          digestmod = hashlib.sha256 ).digest() )


def CreateRequestHmac( method, path, body, hmac_secret ):
  # Note that py2's str type passes this check (and that's ok)
  if not isinstance( body, bytes ):
    raise TypeError( 'body was not of bytes type; you have a bug!' )
  if not isinstance( hmac_secret, bytes ):
    raise TypeError( 'hmac_secret was not of bytes type; you have a bug!' )
  if not isinstance( method, bytes ):
    raise TypeError( 'method was not of bytes type; you have a bug!' )
  if not isinstance( path, bytes ):
    raise TypeError( 'path was not of bytes type; you have a bug!' )

  method_hmac = CreateHmac( method, hmac_secret )
  path_hmac = CreateHmac( path, hmac_secret )
  body_hmac = CreateHmac( body, hmac_secret )

  joined_hmac_input = bytes().join( ( method_hmac, path_hmac, body_hmac ) )
  return CreateHmac( joined_hmac_input, hmac_secret )


# This is the compare_digest function from python 3.4
#   http://hg.python.org/cpython/file/460407f35aa9/Lib/hmac.py#l16
def SecureBytesEqual( a, b ):
  """Returns the equivalent of 'a == b', but avoids content based short
  circuiting to reduce the vulnerability to timing attacks."""
  # Consistent timing matters more here than data type flexibility
  # We do NOT want to support py2's str type because iterating over them
  # (below) produces different results.
  if type( a ) != bytes or type( b ) != bytes:
    raise TypeError( "inputs must be bytes instances" )

  # We assume the length of the expected digest is public knowledge,
  # thus this early return isn't leaking anything an attacker wouldn't
  # already know
  if len( a ) != len( b ):
    return False

  # We assume that integers in the bytes range are all cached,
  # thus timing shouldn't vary much due to integer object creation
  result = 0
  for x, y in zip( a, b ):
    result |= x ^ y
  return result == 0


# ycmd.user_options_store
def DefaultOptions():
  settings_path = os.path.join(
      os.path.dirname( os.path.abspath( __file__ ) ),
                       '..',
                       '..',
                       'third_party',
                       'ycmd',
                       'ycmd',
                       'default_settings.json' )
  options = json.loads( ReadFile( settings_path ) )
  options.pop( 'hmac_secret', None )
  return options


def Value( key ):
  return _USER_OPTIONS[ key ]


def GetAll():
  return _USER_OPTIONS


def SetAll( new_options  ):
  global _USER_OPTIONS
  _USER_OPTIONS = frozendict( new_options )


# ycmd.identifier_utils
class HashableDict( collections.Mapping ):
  """An immutable dictionary that can be used in dictionary's keys. The
  dictionary must be JSON-encodable; in particular, all keys must be strings."""

  def __init__( self, *args, **kwargs ):
    self._dict = dict( *args, **kwargs )


  def __getitem__( self, key ):
    return copy.deepcopy( self._dict[ key ] )


  def __iter__( self ):
    return iter( self._dict )


  def __len__( self ):
    return len( self._dict )


  def __repr__( self ):
    return '<HashableDict %s>' % repr( self._dict )


  def __hash__( self ):
    try:
      return self._hash
    except AttributeError:
      self._hash = json.dumps( self._dict, sort_keys = True ).__hash__()
      return self._hash


  def __eq__( self, other ):
    return isinstance( other, HashableDict ) and self._dict == other._dict


  def __ne__( self, other ):
    return not self == other


def SplitLines( contents ):
  """Return a list of each of the lines in the unicode string |contents|."""

  # We often want to get a list representation of a buffer such that we can
  # index all of the 'lines' within it. Python provides str.splitlines for this
  # purpose. However, this method not only splits on newline characters (\n,
  # \r\n, and \r) but also on line boundaries like \v and \f. Since old
  # Macintosh newlines (\r) are obsolete and Windows newlines (\r\n) end with a
  # \n character, we can ignore carriage return characters (\r) and only split
  # on \n.
  return contents.split( '\n' )


def IdentifierRegexForFiletype( filetype ):
  return FILETYPE_TO_IDENTIFIER_REGEX.get( filetype, DEFAULT_IDENTIFIER_REGEX )


def IsIdentifier( text, filetype = None ):
  if not text:
    return False
  regex = IdentifierRegexForFiletype( filetype )
  match = regex.match( text )
  return match and match.end() == len( text )


def StartOfLongestIdentifierEndingAtIndex( text, index, filetype = None ):
  if not text or index < 1 or index > len( text ):
    return index

  for i in range( index ):
    if IsIdentifier( text[ i : index ], filetype ):
      return i
  return index


# ycmd.utils
def CreateLogfile( prefix = '' ):
  with tempfile.NamedTemporaryFile( prefix = prefix,
                                    suffix = '.log',
                                    delete = False ) as logfile:
    return logfile.name


# Get the Windows short path name.
# Based on http://stackoverflow.com/a/23598461/200291
def GetShortPathName( path ):
  if not OnWindows():
    return path

  from ctypes import windll, wintypes, create_unicode_buffer

  # Set the GetShortPathNameW prototype
  _GetShortPathNameW = windll.kernel32.GetShortPathNameW
  _GetShortPathNameW.argtypes = [ wintypes.LPCWSTR,
                                  wintypes.LPWSTR,
                                  wintypes.DWORD]
  _GetShortPathNameW.restype = wintypes.DWORD

  output_buf_size = 0

  while True:
    output_buf = create_unicode_buffer( output_buf_size )
    needed = _GetShortPathNameW( path, output_buf, output_buf_size )
    if output_buf_size >= needed:
      return output_buf.value
    else:
      output_buf_size = needed


def ConvertArgsToShortPath( args ):
  def ConvertIfPath( arg ):
    if os.path.exists( arg ):
      return GetShortPathName( arg )
    return arg

  if isinstance( args, str ) or isinstance( args, bytes ):
    return ConvertIfPath( args )
  return [ ConvertIfPath( arg ) for arg in args ]


def SafePopen( args, **kwargs ):
  if OnWindows():
    # We need this to start the server otherwise bad things happen.
    # See issue #637.
    if kwargs.get( 'stdin_windows' ) is subprocess.PIPE:
      kwargs[ 'stdin' ] = subprocess.PIPE
    # Do not create a console window
    kwargs[ 'creationflags' ] = CREATE_NO_WINDOW
    # Python 2 fails to spawn a process from a command containing unicode
    # characters on Windows.  See https://bugs.python.org/issue19264 and
    # http://bugs.python.org/issue1759845.
    # Since paths are likely to contains such characters, we convert them to
    # short ones to obtain paths with only ascii characters.
    if PY2:
      args = ConvertArgsToShortPath( args )

  kwargs.pop( 'stdin_windows', None )
  return subprocess.Popen( args, **kwargs )


def RemoveIfExists( filename ):
  try:
    os.remove( filename )
  except OSError:
    pass


def GetUnusedLocalhostPort():
  sock = socket.socket()
  # This tells the OS to give us any free port in the range [1024 - 65535]
  sock.bind( ( '', 0 ) )
  port = sock.getsockname()[ 1 ]
  sock.close()
  return port


def CodepointOffsetToByteOffset( unicode_line_value, codepoint_offset ):
  """The API calls for byte offsets into the UTF-8 encoded version of the
  buffer. However, ycmd internally uses unicode strings. This means that
  when we need to walk 'characters' within the buffer, such as when checking
  for semantic triggers and similar, we must use codepoint offets, rather than
  byte offsets.

  This method converts the |codepoint_offset| which is a unicode codepoint
  offset into an byte offset into the utf-8 encoded bytes version of
  |unicode_line_value|."""

  # Should be a no-op, but in case someone passes a bytes instance.
  unicode_line_value = ToUnicode( unicode_line_value )
  return len( ToBytes( unicode_line_value[ : codepoint_offset - 1 ] ) ) + 1


def ByteOffsetToCodepointOffset( line_value, byte_offset ):
  """The API calls for byte offsets into the UTF-8 encoded version of the
  buffer. However, ycmd internally uses unicode strings. This means that
  when we need to walk 'characters' within the buffer, such as when checking
  for semantic triggers and similar, we must use codepoint offets, rather than
  byte offsets.

  This method converts the |byte_offset|, which is a utf-8 byte offset, into
  a codepoint offset in the unicode string |line_value|."""

  byte_line_value = ToBytes( line_value )
  return len( ToUnicode( byte_line_value[ : byte_offset - 1 ] ) ) + 1


def JoinLinesAsUnicode( lines ):
  try:
    first = next( iter( lines ) )
  except StopIteration:
    return str()

  if isinstance( first, str ):
    return ToUnicode( '\n'.join( lines ) )
  if isinstance( first, bytes ):
    return ToUnicode( b'\n'.join( lines ) )
  raise ValueError( 'lines must contain either strings or bytes.' )


def ToBytes( value ):
  if not value:
    return bytes()

  # This is tricky. On py2, the bytes type from builtins (from python-future) is
  # a subclass of str. So all of the following are true:
  #   isinstance(str(), bytes)
  #   isinstance(bytes(), str)
  # But they don't behave the same in one important aspect: iterating over a
  # bytes instance yields ints, while iterating over a (raw, py2) str yields
  # chars. We want consistent behavior so we force the use of bytes().
  if type( value ) == bytes:
    return value

  # This is meant to catch Python 2's native str type.
  if isinstance( value, bytes ):
    return bytes( value, encoding = 'utf8' )

  if isinstance( value, str ):
    # On py2, with `from builtins import *` imported, the following is true:
    #
    #   bytes(str(u'abc'), 'utf8') == b"b'abc'"
    #
    # Obviously this is a bug in python-future. So we work around it. Also filed
    # upstream at: https://github.com/PythonCharmers/python-future/issues/193
    # We can't just return value.encode( 'utf8' ) on both py2 & py3 because on
    # py2 that *sometimes* returns the built-in str type instead of the newbytes
    # type from python-future.
    if PY2:
      return bytes( value.encode( 'utf8' ), encoding = 'utf8' )
    else:
      return bytes( value, encoding = 'utf8' )

  # This is meant to catch `int` and similar non-string/bytes types.
  return ToBytes( str( value ) )


def ToUnicode( value ):
  if not value:
    return str()
  if isinstance( value, str ):
    return value
  if isinstance( value, bytes ):
    # All incoming text should be utf8
    return str( value, 'utf8' )
  return str( value )


if PY2:
  from urlparse import urljoin, urlparse
  from urllib import pathname2url, url2pathname
else:
  from urllib.parse import urljoin, urlparse  # noqa
  from urllib.request import pathname2url, url2pathname  # noqa


def GetCurrentDirectory():
  """Returns the current directory as an unicode object. If the current
  directory does not exist anymore, returns the temporary folder instead."""
  try:
    if PY2:
      return os.getcwdu()
    return os.getcwd()
  # os.getcwdu throws an OSError exception when the current directory has been
  # deleted while os.getcwd throws a FileNotFoundError, which is a subclass of
  # OSError.
  except OSError:
    return tempfile.gettempdir()


def StartThread( func, *args ):
  thread = threading.Thread( target = func, args = args )
  thread.daemon = True
  thread.start()
  return thread


def PathToFirstExistingExecutable( executable_name_list ):
  for executable_name in executable_name_list:
    path = FindExecutable( executable_name )
    if path:
      return path
  return None


def FindExecutable( executable ):
  # If we're given a path with a directory part, look it up directly rather
  # than referring to PATH directories. This includes checking relative to the
  # current directory, e.g. ./script
  if os.path.dirname( executable ):
    return GetExecutable( executable )

  paths = os.environ[ 'PATH' ].split( os.pathsep )

  if OnWindows():
    # The current directory takes precedence on Windows.
    curdir = os.path.abspath( os.curdir )
    if curdir not in paths:
      paths.insert( 0, curdir )

  for path in paths:
    exe = GetExecutable( os.path.join( path, executable ) )
    if exe:
      return exe
  return None


def _GetWindowsExecutable( filename ):
  def _GetPossibleWindowsExecutable( filename ):
    pathext = [ ext.lower() for ext in
                os.environ.get( 'PATHEXT', '' ).split( os.pathsep ) ]
    base, extension = os.path.splitext( filename )
    if extension.lower() in pathext:
      return [ filename ]
    else:
      return [ base + ext for ext in pathext ]

  for exe in _GetPossibleWindowsExecutable( filename ):
    if os.path.isfile( exe ):
      return exe
  return None


def GetExecutable( filename ):
  if OnWindows():
    return _GetWindowsExecutable( filename )

  if ( os.path.isfile( filename )
       and os.access( filename, EXECUTABLE_FILE_MASK ) ):
    return filename
  return None


def OnWindows():
  return sys.platform == 'win32'


def ReadFile( filepath ):
  with open( filepath, encoding = 'utf8' ) as f:
    return f.read()


def CloseStandardStreams( handle ):
  if not handle:
    return
  for stream in [ handle.stdin, handle.stdout, handle.stderr ]:
    if stream:
      stream.close()


def ProcessIsRunning( handle ):
  return handle is not None and handle.poll() is None


def WaitUntilProcessIsTerminated( handle, timeout = 5 ):
  expiration = time.time() + timeout
  while True:
    if time.time() > expiration:
      raise RuntimeError( 'Waited process to terminate for {0} seconds, '
                          'aborting.'.format( timeout ) )
    if not ProcessIsRunning( handle ):
      return
    time.sleep( 0.1 )


# ycmd.server_utils
# Exit statuses returned by the CompatibleWithCurrentCore function:
#  - CORE_COMPATIBLE_STATUS: ycm_core is compatible;
#  - CORE_UNEXPECTED_STATUS: unexpected error while loading ycm_core;
#  - CORE_MISSING_STATUS   : ycm_core is missing;
#  - CORE_PYTHON2_STATUS   : ycm_core is compiled with Python 2 but loaded with
#    Python 3;
#  - CORE_PYTHON3_STATUS   : ycm_core is compiled with Python 3 but loaded with
#    Python 2;
#  - CORE_OUTDATED_STATUS  : ycm_core version is outdated.
# Values 1 and 2 are not used because 1 is for general errors and 2 has often a
# special meaning for Unix programs. See
# https://docs.python.org/2/library/sys.html#sys.exit
CORE_UNEXPECTED_STATUS  = 3
CORE_MISSING_STATUS     = 4
CORE_PYTHON2_STATUS     = 5
CORE_PYTHON3_STATUS     = 6
CORE_OUTDATED_STATUS    = 7


# ===================================


# ycmd.responses
CONFIRM_CONF_FILE_MESSAGE = ('Found {0}. Load? \n\n(Question can be turned '
                             'off with options, see YCM docs)')

NO_DIAGNOSTIC_SUPPORT_MESSAGE = ( 'YCM has no diagnostics support for this '
  'filetype; refer to Syntastic docs if using Syntastic.')


class ServerError( Exception ):
  def __init__( self, message ):
    super( ServerError, self ).__init__( message )


class NoDiagnosticSupport( ServerError ):
  def __init__( self ):
    super( NoDiagnosticSupport, self ).__init__( NO_DIAGNOSTIC_SUPPORT_MESSAGE )


# location.column_number_ is a byte offset
def BuildLocationData( location ):
  return {
    'line_num': location.line_number_,
    'column_num': location.column_number_,
    'filepath': ( os.path.normpath( location.filename_ )
                  if location.filename_ else '' ),
  }



def BuildRangeData( source_range ):
  return {
    'start': BuildLocationData( source_range.start_ ),
    'end': BuildLocationData( source_range.end_ ),
  }


def BuildDiagnosticData( diagnostic ):
  kind = ( diagnostic.kind_.name if hasattr( diagnostic.kind_, 'name' )
           else diagnostic.kind_ )

  return {
    'ranges': [ BuildRangeData( x ) for x in diagnostic.ranges_ ],
    'location': BuildLocationData( diagnostic.location_ ),
    'location_extent': BuildRangeData( diagnostic.location_extent_ ),
    'text': diagnostic.text_,
    'kind': kind,
    'fixit_available': len( diagnostic.fixits_ ) > 0,
  }


class Diagnostic( object ):
  def __init__( self,
                ranges,
                location,
                location_extent,
                text,
                kind,
                fixits = [] ):
    self.ranges_ = ranges
    self.location_ = location
    self.location_extent_ = location_extent
    self.text_ = text
    self.kind_ = kind
    self.fixits_ = fixits


class Location( object ):
  """Source code location for a diagnostic or FixIt (aka Refactor)."""

  def __init__( self, line, column, filename ):
    """Line is 1-based line, column is 1-based column byte offset, filename is
    absolute path of the file"""
    self.line_number_ = line
    self.column_number_ = column
    if filename:
      self.filename_ = os.path.realpath( filename )
    else:
      # When the filename passed (e.g. by a server) can't be recognized or
      # parsed, we send an empty filename. This at least allows the client to
      # know there _is_ a reference, but not exactly where it is. This can
      # happen with the Java completer which sometimes returns references using
      # a custom/undocumented URI scheme. Typically, such URIs point to .class
      # files or other binary data which clients can't display anyway.
      # FIXME: Sending a location with an empty filename could be considered a
      # strict breach of our own protocol. Perhaps completers should be required
      # to simply skip such a location.
      self.filename_ = filename


class Range( object ):
  """Source code range relating to a diagnostic or FixIt (aka Refactor)."""

  def __init__( self, start, end ):
    "start of type Location, end of type Location"""
    self.start_ = start
    self.end_ = end


class UnknownExtraConf( ServerError ):
  def __init__( self, extra_conf_file ):
    message = CONFIRM_CONF_FILE_MESSAGE.format( extra_conf_file )
    super( UnknownExtraConf, self ).__init__( message )
    self.extra_conf_file = extra_conf_file


# ycmd.request_validation
# Throws an exception if request doesn't have all the required fields.
# TODO: Accept a request_type param so that we can also verify missing
# command_arguments and completer_target fields if necessary.
def EnsureRequestValid( request_json ):
  required_fields = { 'line_num', 'column_num', 'filepath', 'file_data' }
  missing = { x for x in required_fields if x not in request_json }

  if 'filepath' not in missing and 'file_data' not in missing:
    missing.update( _MissingFieldsForFileData( request_json ) )
  if not missing:
    return True
  message = '\n'.join( _FieldMissingMessage( field ) for field in missing )
  raise ServerError( message )


def _FieldMissingMessage( field ):
  return 'Request missing required field: {0}'.format( field )


def _SingleFileDataFieldSpec( request_json, field ):
  return '{0}["{1}"]'.format( _FilepathInFileDataSpec( request_json ), field )


def _MissingFieldsForFileData( request_json ):
  missing = set()
  data_for_file = request_json[ 'file_data' ].get( request_json[ 'filepath' ] )
  if data_for_file:
    required_data = [ 'filetypes', 'contents' ]
    for required in required_data:
      if required not in data_for_file:
        missing.add( _SingleFileDataFieldSpec( request_json, required ) )
    filetypes = data_for_file.get( 'filetypes', [] )
    if not filetypes:
      missing.add( '{0}[0]'.format(
          _SingleFileDataFieldSpec( request_json, 'filetypes' ) ) )
  else:
    missing.add( _FilepathInFileDataSpec( request_json ) )
  return missing


def _FilepathInFileDataSpec( request_json ):
  return 'file_data["{0}"]'.format( request_json[ 'filepath' ] )


# ycmd.request_wrap
# TODO: Change the custom computed (and other) keys to be actual properties on
# the object.
class RequestWrap( object ):
  def __init__( self, request, validate = True ):
    if validate:
      EnsureRequestValid( request )
    self._request = request

    # Maps the keys returned by this objects __getitem__ to a # tuple of
    # ( getter_method, setter_method ). Values computed by getter_method (or set
    # by setter_method) are cached in _cached_computed.  setter_method may be
    # None for read-only items.
    self._computed_key = {
      # Unicode string representation of the current line. If the line requested
      # is not in the file, returns ''.
      'line_value': ( self._CurrentLine, None ),

      # The calculated start column, as a codepoint offset into the
      # unicode string line_value
      'start_codepoint': ( self._GetCompletionStartCodepoint,
                           self._SetCompletionStartCodepoint ),

      # The 'column_num' as a unicode codepoint offset
      'column_codepoint': ( lambda: ByteOffsetToCodepointOffset(
                              self[ 'line_bytes' ],
                              self[ 'column_num' ] ),
                            None ),

      # Bytes string representation of the current line
      'line_bytes': ( lambda: ToBytes( self[ 'line_value' ] ),
                      None ),

      # The calculated start column, as a byte offset into the UTF-8 encoded
      # bytes returned by line_bytes
      'start_column': ( self._GetCompletionStartColumn,
                        self._SetCompletionStartColumn ),

      # Note: column_num is the byte offset into the UTF-8 encoded bytes
      # returned by line_bytes

      # unicode string representation of the 'query' after the beginning
      # of the identifier to be completed
      'query': ( self._Query, None ),

      # Unicode string representation of the line value up to the character
      # before the start of 'query'
      'prefix': ( self._Prefix, None ),

      'filetypes': ( self._Filetypes, None ),

      'first_filetype': ( self._FirstFiletype, None ),

      'force_semantic': ( self._GetForceSemantic, None ),

      'lines': ( self._CurrentLines, None ),

      'extra_conf_data': ( self._GetExtraConfData, None )
    }
    self._cached_computed = {}


  def __getitem__( self, key ):
    if key in self._cached_computed:
      return self._cached_computed[ key ]
    if key in self._computed_key:
      getter, _ = self._computed_key[ key ]
      value = getter()
      self._cached_computed[ key ] = value
      return value
    return self._request[ key ]


  def __setitem__( self, key, value ):
    if key in self._computed_key:
      _, setter = self._computed_key[ key ]
      if setter:
        setter( value )
        return

    raise ValueError( 'Key "{0}" is read-only'.format( key ) )


  def __contains__( self, key ):
    return key in self._computed_key or key in self._request


  def __eq__( self, other ):
    if ( self[ 'filepath' ]         != other[ 'filepath' ] or
         self[ 'filetypes' ]        != other[ 'filetypes' ] or
         self[ 'line_num' ]         != other[ 'line_num' ] or
         self[ 'start_column' ]     != other[ 'start_column' ] or
         self[ 'prefix' ]           != other[ 'prefix' ] or
         self[ 'force_semantic' ]   != other[ 'force_semantic' ] or
         self[ 'extra_conf_data' ]  != other[ 'extra_conf_data' ] or
         len( self[ 'file_data' ] ) != len( other[ 'file_data' ] ) ):
      return False

    for filename, file_data in iteritems( self[ 'file_data' ] ):
      if filename == self[ 'filepath' ]:
        lines = self[ 'lines' ]
        other_lines = other[ 'lines' ]
        if len( lines ) != len( other_lines ):
          return False

        line_num = self[ 'line_num' ]
        if ( lines[ : line_num - 1 ] != other_lines[ : line_num - 1 ] or
             lines[ line_num : ] != other_lines[ line_num : ] ):
          return False

      elif ( filename not in other[ 'file_data' ] or
             file_data != other[ 'file_data' ][ filename ] ):
        return False

    return True


  def get( self, key, default = None ):
    try:
      return self[ key ]
    except KeyError:
      return default


  def _CurrentLines( self ):
    current_file = self[ 'filepath' ]
    contents = self[ 'file_data' ][ current_file ][ 'contents' ]
    return SplitLines( contents )


  def _CurrentLine( self ):
    try:
      return self[ 'lines' ][ self[ 'line_num' ] - 1 ]
    except IndexError:
      _logger.exception( 'Client returned invalid line number {0} '
                         'for file {1}. Assuming empty.'.format(
                           self[ 'line_num' ],
                           self[ 'filepath' ] ) )
      return ''


  def _GetCompletionStartColumn( self ):
    return CompletionStartColumn( self[ 'line_value' ],
                                  self[ 'column_num' ],
                                  self[ 'first_filetype' ] )


  def _SetCompletionStartColumn( self, column_num ):
    self._cached_computed[ 'start_column' ] = column_num

    # Note: We must pre-compute (and cache) the codepoint equivalent. This is
    # because the value calculated by the getter (_GetCompletionStartCodepoint)
    # would be based on self[ 'column_codepoint' ] which would be incorrect; it
    # does not know that the user has forced this value to be independent of the
    # column.
    self._cached_computed[ 'start_codepoint' ] = ByteOffsetToCodepointOffset(
      self[ 'line_value' ],
      column_num )

    # The same applies to the 'prefix' (the bit before the start column) and the
    # 'query' (the bit after the start column up to the cursor column). They are
    # dependent on the 'start_codepoint' so we must reset them.
    self._cached_computed.pop( 'prefix', None )
    self._cached_computed.pop( 'query', None )


  def _GetCompletionStartCodepoint( self ):
    return CompletionStartCodepoint( self[ 'line_value' ],
                                     self[ 'column_num' ],
                                     self[ 'first_filetype' ] )


  def _SetCompletionStartCodepoint( self, codepoint_offset ):
    self._cached_computed[ 'start_codepoint' ] = codepoint_offset

    # Note: We must pre-compute (and cache) the byte equivalent. This is because
    # the value calculated by the getter (_GetCompletionStartColumn) would be
    # based on self[ 'column_num' ], which would be incorrect; it does not know
    # that the user has forced this value to be independent of the column.
    self._cached_computed[ 'start_column' ] = CodepointOffsetToByteOffset(
      self[ 'line_value' ],
      codepoint_offset )

    # The same applies to the 'prefix' (the bit before the start column) and the
    # 'query' (the bit after the start column up to the cursor column). They are
    # dependent on the 'start_codepoint' so we must reset them.
    self._cached_computed.pop( 'prefix', None )
    self._cached_computed.pop( 'query', None )


  def _Query( self ):
    return self[ 'line_value' ][
        self[ 'start_codepoint' ] - 1 : self[ 'column_codepoint' ] - 1
    ]


  def _Prefix( self ):
    return self[ 'line_value' ][ : ( self[ 'start_codepoint' ] - 1 ) ]


  def _FirstFiletype( self ):
    try:
      return self[ 'filetypes' ][ 0 ]
    except (KeyError, IndexError):
      return None


  def _Filetypes( self ):
    path = self[ 'filepath' ]
    return self[ 'file_data' ][ path ][ 'filetypes' ]


  def _GetForceSemantic( self ):
    return bool( self._request.get( 'force_semantic', False ) )


  def _GetExtraConfData( self ):
    return HashableDict( self._request.get( 'extra_conf_data', {} ) )


def CompletionStartColumn( line_value, column_num, filetype ):
  """Returns the 1-based byte index where the completion query should start.
  So if the user enters:
    foo.bar^
  with the cursor being at the location of the caret (so the character *AFTER*
  'r'), then the starting column would be the index of the letter 'b'.

  NOTE: if the line contains multi-byte characters, then the result is not
  the 'character' index (see CompletionStartCodepoint for that), and therefore
  it is not safe to perform any character-relevant arithmetic on the result
  of this method."""
  return CodepointOffsetToByteOffset(
      ToUnicode( line_value ),
      CompletionStartCodepoint( line_value, column_num, filetype ) )


def CompletionStartCodepoint( line_value, column_num, filetype ):
  """Returns the 1-based codepoint index where the completion query should
  start.  So if the user enters:
    ƒøø.∫å®^
  with the cursor being at the location of the caret (so the character *AFTER*
  '®'), then the starting column would be the index of the character '∫'
  (i.e. 5, not its byte index)."""

  # NOTE: column_num and other numbers on the wire are byte indices, but we need
  # to walk codepoints for identifier checks.
  codepoint_column_num = ByteOffsetToCodepointOffset( line_value, column_num )

  unicode_line_value = ToUnicode( line_value )
  # -1 and then +1 to account for difference betwen 0-based and 1-based
  # indices/columns
  codepoint_start_column = StartOfLongestIdentifierEndingAtIndex(
      unicode_line_value, codepoint_column_num - 1, filetype ) + 1

  return codepoint_start_column


def _PrepareTrigger( trigger ):
  trigger = ToUnicode( trigger )
  if trigger.startswith( TRIGGER_REGEX_PREFIX ):
    return re.compile( trigger[ len( TRIGGER_REGEX_PREFIX ) : ], re.UNICODE )
  return re.compile( re.escape( trigger ), re.UNICODE )


def _FiletypeTriggerDictFromSpec( trigger_dict_spec ):
  triggers_for_filetype = defaultdict( set )

  for key, triggers in iteritems( trigger_dict_spec ):
    filetypes = key.split( ',' )
    for filetype in filetypes:
      regexes = [ _PrepareTrigger( x ) for x in triggers ]
      triggers_for_filetype[ filetype ].update( regexes )


  return triggers_for_filetype


def _FiletypeDictUnion( dict_one, dict_two ):
  """Returns a new filetype dict that's a union of the provided two dicts.
  Dict params are supposed to be type defaultdict(set)."""
  def UpdateDict( first, second ):
    for key, value in iteritems( second ):
      first[ key ].update( value )

  final_dict = defaultdict( set )
  UpdateDict( final_dict, dict_one )
  UpdateDict( final_dict, dict_two )
  return final_dict


def _RegexTriggerMatches( trigger,
                          line_value,
                          start_codepoint,
                          column_codepoint ):
  for match in trigger.finditer( line_value ):
    # By definition of 'start_codepoint', we know that the character just before
    # 'start_codepoint' is not an identifier character but all characters
    # between 'start_codepoint' and 'column_codepoint' are. This means that if
    # our trigger ends with an identifier character, its tail must match between
    # 'start_codepoint' and 'column_codepoint', 'start_codepoint' excluded. But
    # if it doesn't, its tail must match exactly at 'start_codepoint'. Both
    # cases are mutually exclusive hence the following condition.
    if start_codepoint <= match.end() and match.end() <= column_codepoint:
      return True
  return False


def _MatchingSemanticTrigger( line_value, start_codepoint, column_codepoint,
                              trigger_list ):
  if start_codepoint < 0 or column_codepoint < 0:
    return None

  line_length = len( line_value )
  if not line_length or start_codepoint > line_length:
    return None

  # Ignore characters after user's caret column
  line_value = line_value[ : column_codepoint ]

  for trigger in trigger_list:
    if _RegexTriggerMatches( trigger,
                             line_value,
                             start_codepoint,
                             column_codepoint ):
      return trigger
  return None


class PreparedTriggers( object ):
  def __init__( self, user_trigger_map = None, filetype_set = None ):
    user_prepared_triggers = ( _FiletypeTriggerDictFromSpec(
        dict( user_trigger_map ) ) if user_trigger_map else
        defaultdict( set ) )
    final_triggers = _FiletypeDictUnion( PREPARED_DEFAULT_FILETYPE_TRIGGERS,
                                         user_prepared_triggers )
    if filetype_set:
      final_triggers = { k: v for k, v in iteritems( final_triggers )
                         if k in filetype_set }

    self._filetype_to_prepared_triggers = final_triggers


  def MatchingTriggerForFiletype( self,
                                  current_line,
                                  start_codepoint,
                                  column_codepoint,
                                  filetype ):
    try:
      triggers = self._filetype_to_prepared_triggers[ filetype ]
    except KeyError:
      return None
    return _MatchingSemanticTrigger( current_line,
                                     start_codepoint,
                                     column_codepoint,
                                     triggers )


  def MatchesForFiletype( self,
                          current_line,
                          start_codepoint,
                          column_codepoint,
                          filetype ):
    return self.MatchingTriggerForFiletype( current_line,
                                            start_codepoint,
                                            column_codepoint,
                                            filetype ) is not None


class Completer( with_metaclass( abc.ABCMeta, object ) ):
  """A base class for all Completers in YCM.

  Here's several important things you need to know if you're writing a custom
  Completer. The following are functions that the Vim part of YCM will be
  calling on your Completer:

  *Important note about unicode and byte offsets*

    Useful background: http://utf8everywhere.org

    Internally, all Python strings are unicode string objects, unless otherwise
    converted to 'bytes' using ToBytes. In particular, the line_value and
    file_data.contents entries in the request_data are unicode strings.

    However, offsets in the API (such as column_num and start_column) are *byte*
    offsets into a utf-8 encoded version of the contents of the line or buffer.
    Therefore it is *never* safe to perform 'character' arithmetic
    (such as '-1' to get the previous 'character') using these byte offsets, and
    they cannot *ever* be used to index into line_value or buffer contents
    unicode strings.

    It is therefore important to ensure that you use the right type of offsets
    for the right type of calculation:
     - use codepoint offsets and a unicode string for 'character' calculations
     - use byte offsets and utf-8 encoded bytes for all other manipulations

    ycmd provides the following ways of accessing the source data and offsets:

    For working with utf-8 encoded bytes:
     - request_data[ 'line_bytes' ] - the line as utf-8 encoded bytes.
     - request_data[ 'start_column' ] and request_data[ 'column_num' ].

    For working with 'character' manipulations (unicode strings and codepoint
    offsets):
     - request_data[ 'line_value' ] - the line as a unicode string.
     - request_data[ 'start_codepoint' ] and request_data[ 'column_codepoint' ].

    For converting between the two:
     - utils.ToBytes
     - utils.ByteOffsetToCodepointOffset
     - utils.ToUnicode
     - utils.CodepointOffsetToByteOffset

    Note: The above use of codepoints for 'character' manipulations is not
    strictly correct. There are unicode 'characters' which consume multiple
    codepoints. However, it is currently considered viable to use a single
    codepoint = a single character until such a time as we improve support for
    unicode identifiers. The purpose of the above rule is to prevent crashes and
    random encoding exceptions, not to fully support unicode identifiers.

  *END: Important note about unicode and byte offsets*

  ShouldUseNow() is called with the start column of where a potential completion
  string should start and the current line (string) the cursor is on. For
  instance, if the user's input is 'foo.bar' and the cursor is on the 'r' in
  'bar', start_column will be the 1-based byte index of 'b' in the line. Your
  implementation of ShouldUseNow() should return True if your semantic completer
  should be used and False otherwise.

  This is important to get right. You want to return False if you can't provide
  completions because then the identifier completer will kick in, and that's
  better than nothing.

  Note that it's HIGHLY likely that you want to override the ShouldUseNowInner()
  function instead of ShouldUseNow() directly (although chances are that you
  probably won't have any need to override either). ShouldUseNow() will call
  your *Inner version of the function and will also make sure that the
  completion cache is taken into account. You'll see this pattern repeated
  throughout the Completer API; YCM calls the "main" version of the function and
  that function calls the *Inner version while taking into account the cache.

  The cache is important and is a nice performance boost. When the user types in
  "foo.", your completer will return a list of all member functions and
  variables that can be accessed on the "foo" object. The Completer API caches
  this list. The user will then continue typing, let's say "foo.ba". On every
  keystroke after the dot, the Completer API will take the cache into account
  and will NOT re-query your completer but will in fact provide fuzzy-search on
  the candidate strings that were stored in the cache.

  ComputeCandidates() is the main entry point when the user types. For
  "foo.bar", the user query is "bar" and completions matching this string should
  be shown. It should return the list of candidates.  The format of the result
  can be a list of strings or a more complicated list of dictionaries. Use
  ycmd.responses.BuildCompletionData to build the detailed response. See
  clang_completer.py to see how its used in practice.

  Again, you probably want to override ComputeCandidatesInner().

  You also need to implement the SupportedFiletypes() function which should
  return a list of strings, where the strings are Vim filetypes your completer
  supports.

  clang_completer.py is a good example of a "complicated" completer. A good
  example of a simple completer is ultisnips_completer.py.

  The On* functions are provided for your convenience. They are called when
  their specific events occur. For instance, the identifier completer collects
  all the identifiers in the file in OnFileReadyToParse() which gets called when
  the user stops typing for 2 seconds (Vim's CursorHold and CursorHoldI events).

  One special function is OnUserCommand. It is called when the user uses the
  command :YcmCompleter and is passed all extra arguments used on command
  invocation (e.g. OnUserCommand(['first argument', 'second'])).  This can be
  used for completer-specific commands such as reloading external configuration.
  Do not override this function. Instead, you need to implement the
  GetSubcommandsMap method. It should return a map between the user commands
  and the methods of your completer. See the documentation of this method for
  more informations on how to implement it.

  Override the Shutdown() member function if your Completer subclass needs to do
  custom cleanup logic on server shutdown.

  If the completer server provides unsolicited messages, such as used in
  Language Server Protocol, then you can override the PollForMessagesInner
  method. This method is called by the client in the "long poll" fashion to
  receive unsolicited messages. The method should block until a message is
  available and return a message response when one becomes available, or True if
  no message becomes available before the timeout. The return value must be one
  of the following:
   - a list of messages to send to the client
   - True if a timeout occurred, and the poll should be restarted
   - False if an error occurred, and no further polling should be attempted

  If your completer uses an external server process, then it can be useful to
  implement the ServerIsHealthy member function to handle the /healthy request.
  This is very useful for the test suite.

  If your server is based on the Language Server Protocol (LSP), take a look at
  language_server/language_server_completer, which provides most of the work
  necessary to get a LSP-based completion engine up and running."""

  def __init__( self, user_options ):
    self.user_options = user_options
    self.min_num_chars = user_options[ 'min_num_of_chars_for_completion' ]
    self.prepared_triggers = (
        PreparedTriggers(
            user_trigger_map = user_options[ 'semantic_triggers' ],
            filetype_set = set( self.SupportedFiletypes() ) )
        if user_options[ 'auto_trigger' ] else None )
    self._completions_cache = CompletionsCache()
    self._max_candidates = user_options[ 'max_num_candidates' ]


  # It's highly likely you DON'T want to override this function but the *Inner
  # version of it.
  def ShouldUseNow( self, request_data ):
    if not self.ShouldUseNowInner( request_data ):
      self._completions_cache.Invalidate()
      return False

    # We have to do the cache valid check and get the completions as part of one
    # call because we have to ensure a different thread doesn't change the cache
    # data.
    cache_completions = self._completions_cache.GetCompletionsIfCacheValid(
      request_data )

    # If None, then the cache isn't valid and we know we should return true
    if cache_completions is None:
      return True
    else:
      previous_results_were_valid = bool( cache_completions )
      return previous_results_were_valid


  def ShouldUseNowInner( self, request_data ):
    if not self.prepared_triggers:
      return False
    current_line = request_data[ 'line_value' ]
    start_codepoint = request_data[ 'start_codepoint' ] - 1
    column_codepoint = request_data[ 'column_codepoint' ] - 1
    filetype = self._CurrentFiletype( request_data[ 'filetypes' ] )

    return self.prepared_triggers.MatchesForFiletype(
        current_line, start_codepoint, column_codepoint, filetype )


  def QueryLengthAboveMinThreshold( self, request_data ):
    # Note: calculation in 'characters' not bytes.
    query_length = ( request_data[ 'column_codepoint' ] -
                     request_data[ 'start_codepoint' ] )

    return query_length >= self.min_num_chars


  # It's highly likely you DON'T want to override this function but the *Inner
  # version of it.
  def ComputeCandidates( self, request_data ):
    if ( not request_data[ 'force_semantic' ] and
         not self.ShouldUseNow( request_data ) ):
      return []

    candidates = self._GetCandidatesFromSubclass( request_data )
    return self.FilterAndSortCandidates( candidates, request_data[ 'query' ] )


  def _GetCandidatesFromSubclass( self, request_data ):
    cache_completions = self._completions_cache.GetCompletionsIfCacheValid(
      request_data )

    if cache_completions:
      return cache_completions

    raw_completions = self.ComputeCandidatesInner( request_data )
    self._completions_cache.Update( request_data, raw_completions )
    return raw_completions


  def ComputeCandidatesInner( self, request_data ):
    pass # pragma: no cover


  def DefinedSubcommands( self ):
    subcommands = sorted( self.GetSubcommandsMap().keys() )
    try:
      # We don't want expose this subcommand because it is not really needed
      # for the user but it is useful in tests for tearing down the server
      subcommands.remove( 'StopServer' )
    except ValueError:
      pass
    return subcommands


  def GetSubcommandsMap( self ):
    """This method should return a dictionary where each key represents the
    completer command name and its value is a lambda function of this form:

      ( self, request_data, args ) -> method

    where "method" is the call to the completer method with corresponding
    parameters. See the already implemented completers for examples.

    Arguments:
     - request_data : the request data supplied by the client
     - args: any additional command arguments (after the command name). Usually
             empty.
    """
    return {}


  def UserCommandsHelpMessage( self ):
    subcommands = self.DefinedSubcommands()
    if subcommands:
      return ( 'Supported commands are:\n' +
               '\n'.join( subcommands ) +
               '\nSee the docs for information on what they do.' )
    else:
      return 'This Completer has no supported subcommands.'


  def FilterAndSortCandidates( self, candidates, query ):
    if not candidates:
      return []

    # We need to handle both an omni_completer style completer and a server
    # style completer
    if isinstance( candidates, dict ) and 'words' in candidates:
      candidates = candidates[ 'words' ]

    sort_property = ''
    if isinstance( candidates[ 0 ], dict ):
      if 'word' in candidates[ 0 ]:
        sort_property = 'word'
      elif 'insertion_text' in candidates[ 0 ]:
        sort_property = 'insertion_text'

    return self.FilterAndSortCandidatesInner( candidates, sort_property, query )


  def FilterAndSortCandidatesInner( self, candidates, sort_property, query ):
    return completer_utils.FilterAndSortCandidatesWrap(
      candidates, sort_property, query, self._max_candidates )


  def OnFileReadyToParse( self, request_data ):
    pass # pragma: no cover


  def OnBufferVisit( self, request_data ):
    pass # pragma: no cover


  def OnBufferUnload( self, request_data ):
    pass # pragma: no cover


  def OnInsertLeave( self, request_data ):
    pass # pragma: no cover


  def OnUserCommand( self, arguments, request_data ):
    if not arguments:
      raise ValueError( self.UserCommandsHelpMessage() )

    command_map = self.GetSubcommandsMap()

    try:
      command = command_map[ arguments[ 0 ] ]
    except KeyError:
      raise ValueError( self.UserCommandsHelpMessage() )

    return command( self, request_data, arguments[ 1: ] )


  def OnCurrentIdentifierFinished( self, request_data ):
    pass # pragma: no cover


  def GetDiagnosticsForCurrentFile( self, request_data ):
    raise NoDiagnosticSupport


  def GetDetailedDiagnostic( self, request_data ):
    raise NoDiagnosticSupport


  def _CurrentFiletype( self, filetypes ):
    supported = self.SupportedFiletypes()

    for filetype in filetypes:
      if filetype in supported:
        return filetype

    return filetypes[0]


  @abc.abstractmethod
  def SupportedFiletypes( self ):
    return set()


  def DebugInfo( self, request_data ):
    return ''


  def Shutdown( self ):
    pass # pragma: no cover


  def ServerIsReady( self ):
    return self.ServerIsHealthy()


  def ServerIsHealthy( self ):
    """Called by the /healthy handler to check if the underlying completion
    server is started and ready to receive requests. Returns bool."""
    return True


  def PollForMessages( self, request_data ):
    return self.PollForMessagesInner( request_data, MESSAGE_POLL_TIMEOUT )


  def PollForMessagesInner( self, request_data, timeout ):
    # Most completers don't implement this. It's only required where unsolicited
    # messages or diagnostics are supported, such as in the Language Server
    # Protocol. As such, the default implementation just returns False, meaning
    # that unsolicited messages are not supported for this filetype.
    return False


class CompletionsCache( object ):
  """Cache of computed completions for a particular request."""

  def __init__( self ):
    self._access_lock = threading.Lock()
    self.Invalidate()


  def Invalidate( self ):
    with self._access_lock:
      self._request_data = None
      self._completions = None


  def Update( self, request_data, completions ):
    with self._access_lock:
      self._request_data = request_data
      self._completions = completions


  def GetCompletionsIfCacheValid( self, request_data ):
    with self._access_lock:
      if self._request_data and self._request_data == request_data:
        return self._completions
      return None


PREPARED_DEFAULT_FILETYPE_TRIGGERS = _FiletypeTriggerDictFromSpec(
    DEFAULT_FILETYPE_TRIGGERS )
