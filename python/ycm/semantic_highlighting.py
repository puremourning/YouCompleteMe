# Copyright (C) 2020, YouCompleteMe Contributors
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


from ycm.client.semantic_tokens_request import SemanticTokensRequest
from ycm import vimsupport


HIGHLIGHT_GROUP = {
  'namespace': 'Type',
  'type': 'Type',
  'class': 'Structure',
  'enum': 'Structure',
  'interface': 'Structure',
  'struct': 'Structure',
  'typeParameter': 'Identifier',
  'parameter': 'Identifier',
  'variable': 'Identifier',
  'property': 'Identifier',
  'enumMember': 'Identifier',
  'event': 'Identifier',
  'function': 'Function',
  'member': 'Identifier',
  'macro': 'Macro',
  'keyword': 'Keyword',
  'modifier': 'Keyword',
  'comment': 'Comment',
  'string': 'String',
  'number': 'Number',
  'regexp': 'String',
  'operator': 'Operator',
}


def Initialise():
  for token_type, group in HIGHLIGHT_GROUP.items():
    vimsupport.AddTextPropertyType( f'YCM_HL_{ token_type }',
                                    highlight = group )


class SemanticHighlighting:
  """Stores the semantic highlighting state for a Vim buffer"""

  def __init__( self, bufnr, user_options ):
    self._request = None
    self._props = []
    self._bufnr = bufnr


  def SendRequest( self, request_data ):
    if self._request and not self.IsResponseReady():
      return

    self._request = SemanticTokensRequest( request_data )
    self._request.Start()

    # FIXME: Force waiting for the response
    self._request.Response()

  def IsResponseReady( self ):
    return self._request is not None and self._request.Done()

  def Update( self ):
    if not self.IsResponseReady():
      return

    # We requested a snapshot
    response = self._request.Response()
    tokens = response.get( 'tokens', [] )

    self.Clear()

    for token in tokens:
      if token[ 'type' ] not in HIGHLIGHT_GROUP:
        continue

      prop_type = f"YCM_HL_{ token[ 'type' ] }"
      self._props.append( ( vimsupport.AddTextProperty( self._bufnr,
                                                        prop_type,
                                                        token[ 'range' ] ),
                            prop_type ) )


  def Clear( self ):
    for prop_id, prop_type in self._props:
      vimsupport.ClearTextProperty( self._bufnr, prop_id, prop_type )

    self._props = []
