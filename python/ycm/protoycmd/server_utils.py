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
import re
import sys

PYTHON_STDLIB_ZIP_REGEX = re.compile( "python[23][0-9].zip" )

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


def AncestorFolders( path ):
  folder = os.path.normpath( path )
  while True:
    parent = os.path.dirname( folder )
    if parent == folder:
      break
    folder = parent
    yield folder


def PathToNearestThirdPartyFolder( path ):
  for folder in AncestorFolders( path ):
    path_to_third_party = os.path.join( folder, 'third_party' )
    if os.path.isdir( path_to_third_party ):
      return path_to_third_party
  return None


def IsStandardLibraryFolder( path ):
  return ( ( os.path.isfile( path )
             and PYTHON_STDLIB_ZIP_REGEX.match( os.path.basename( path ) ) )
           or os.path.isfile( os.path.join( path, 'os.py' ) ) )


def IsVirtualEnvLibraryFolder( path ):
  return os.path.isfile( os.path.join( path, 'orig-prefix.txt' ) )


def GetStandardLibraryIndexInSysPath():
  for path in sys.path:
    if ( IsStandardLibraryFolder( path ) and
         not IsVirtualEnvLibraryFolder( path ) ):
      return sys.path.index( path )
  raise RuntimeError( 'Could not find standard library path in Python path.' )


def AddNearestThirdPartyFoldersToSysPath( filepath ):
  path_to_third_party = PathToNearestThirdPartyFolder( filepath )
  if not path_to_third_party:
    raise RuntimeError(
        'No third_party folder found for: {0}'.format( filepath ) )

  # NOTE: Any hacks for loading modules that can't be imported without custom
  # logic need to be reproduced in run_tests.py as well.
  for folder in os.listdir( path_to_third_party ):
    # python-future needs special handling. Not only does it store the modules
    # under its 'src' folder, but SOME of its modules are only meant to be
    # accessible under py2, not py3. This is because these modules (like
    # `queue`) are implementations of modules present in the py3 standard
    # library. Furthermore, we need to be sure that they are not overridden by
    # already installed packages (for example, the 'builtins' module from
    # 'pies2overrides' or a different version of 'python-future'). To work
    # around these issues, we place the python-future just after the Python
    # standard library so that its modules can be overridden by standard
    # modules but not by installed packages.
    if folder == 'python-future':
      folder = os.path.join( folder, 'src' )
      sys.path.insert( GetStandardLibraryIndexInSysPath() + 1,
                       os.path.realpath( os.path.join( path_to_third_party,
                                                       folder ) ) )
      continue

    if folder == 'cregex':
      folder = os.path.join( folder,
                             'regex_{}'.format( sys.version_info[ 0 ] ) )

    sys.path.insert( 0, os.path.realpath( os.path.join( path_to_third_party,
                                                        folder ) ) )
