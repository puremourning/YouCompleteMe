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
  'parameter': 'Normal',
  'variable': 'Normal',
  'property': 'Normal',
  'enumMember': 'Identifier',
  'enumConstant': 'Constant',
  'event': 'Identifier',
  'function': 'Function',
  'member': 'Normal',
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
  vimsupport.AddTextPropertyType( 'YCM_HL_UNKNOWN', highlight = 'WarningMsg' )
  for token_type, group in HIGHLIGHT_GROUP.items():
    vimsupport.AddTextPropertyType( f'YCM_HL_{ token_type }',
                                    highlight = group )


# Use my birthday becuase why not
NEXT_TEXT_PROP_ID = 70784

def NextPropID():
  global NEXT_TEXT_PROP_ID
  try:
    return NEXT_TEXT_PROP_ID
  finally:
    NEXT_TEXT_PROP_ID += 1



class SemanticHighlighting:
  """Stores the semantic highlighting state for a Vim buffer"""

  def __init__( self, bufnr, user_options ):
    self._request = None
    self._bufnr = bufnr
    self._prop_id = NextPropID()


  def SendRequest( self, request_data ):
    if self._request and not self.IsResponseReady():
      return

    self._request = SemanticTokensRequest( request_data )
    self._request.Start()

  def IsResponseReady( self ):
    return self._request is not None and self._request.Done()

  def Update( self ):
    if not self.IsResponseReady():
      return

    # We requested a snapshot
    response = self._request.Response()
    self._request = None

    tokens = response.get( 'tokens', [] )

    prev_prop_id = self._prop_id
    self._prop_id = NextPropID()

    for token in tokens:
      if token[ 'type' ] not in HIGHLIGHT_GROUP:
        continue
      prop_type = f"YCM_HL_{ token[ 'type' ] }"
      vimsupport.AddTextProperty( self._bufnr,
                                  self._prop_id,
                                  prop_type,
                                  token[ 'range' ] )

    vimsupport.ClearTextProperties( self._bufnr, prev_prop_id )
