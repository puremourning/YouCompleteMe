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

import os


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
