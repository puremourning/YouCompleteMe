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
    HandleMessages to get any messages received."""

    if self._response_future is None:
      # First poll
      self._SendRequest()
      return

    if not self._response_future.done():
      # Nothing yet...
      return

    with HandleServerException( truncate = True ):
      response = JsonFromFuture( self._response_future )

      if not isinstance( response, bool ):
        if 'message' in response:
          PostVimMessage( response[ 'message' ], warning=False, truncate=True )

    # Start the next poll
    self._SendRequest()
