# Copyright (C) 2017 YouCompleteMe contributors
#
# This file is part of YouCompleteMe.
#
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
from future import standard_library
standard_library.install_aliases()
from builtins import *  # noqa

from ycm.vimsupport import PostVimMessage

from ycm.client.base_request import ( BaseRequest, BuildRequestData,
                                      JsonFromFuture, HandleServerException )

import logging

_logger = logging.getLogger( __name__ )

# Looooong poll
TIMEOUT_SECONDS = 60


class MessagesPoll( BaseRequest ):
  def __init__( self ):
    super( MessagesPoll, self ).__init__()
    self._request_data = BuildRequestData()
    self._response_future = None


  def _SendRequest( self ):
    self._response_future = self.PostDataToHandlerAsync(
      self._request_data,
      'receive_messages',
      timeout = TIMEOUT_SECONDS )
    return


  def Poll( self ):
    """This should be called regularly to check for new messages. Use
    HandleMessages to get any messages received. Returns True if Poll should be
    caled again in a while. Returns False when the completer or server indicated
    that further polling should not be done for the requested filetype"""

    if self._response_future is None:
      # First poll
      self._SendRequest()
      return True

    if not self._response_future.done():
      # Nothing yet...
      return True

    # TODO: Specifically handle an error which says that the server completer
    # doesn't support this message. Resending the query would be pointless in
    # that case.
    with HandleServerException( truncate = True ):
      response = JsonFromFuture( self._response_future )

      if not isinstance( response, bool ):
        if 'message' in response:
          PostVimMessage( response[ 'message' ], warning=False, truncate=True )
      elif not response:
        # Don't keep polling for this filetype
        # TODO: Implement that in the client
        return False

      # Start the next poll (only if the last poll didn't raise an exception)
      self._SendRequest()

    return True


