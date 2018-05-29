# Copyright (C) 2018 ycmd contributors
#
# This file is part of YouCompleteMe.#
# YouCompleteMe is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# YouCompleteMe is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with YouCompleteMe.  If not, see <http://www.gnu.org/licenses/>.

from __future__ import unicode_literals
from __future__ import print_function
from __future__ import division
from __future__ import absolute_import
# Not installing aliases from python-future; it's unreliable and slow.
from builtins import * # noqa

import collections
import copy
import json
import tempfile
import os
import subprocess
import socket
import sys
import threading
import time
from future.utils import PY2

EXECUTABLE_FILE_MASK = os.F_OK | os.X_OK

# Creation flag to disable creating a console window on Windows. See
# https://msdn.microsoft.com/en-us/library/windows/desktop/ms684863.aspx
CREATE_NO_WINDOW = 0x08000000


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


def CreateLogfile( prefix = '' ):
  with tempfile.NamedTemporaryFile( prefix = prefix,
                                    suffix = '.log',
                                    delete = False ) as logfile:
    return logfile.name


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
