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

from collections import defaultdict
from future import iteritems
from utils import re, ToUnicode


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

TRIGGER_REGEX_PREFIX = 're!'


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


PREPARED_DEFAULT_FILETYPE_TRIGGERS = _FiletypeTriggerDictFromSpec(
    DEFAULT_FILETYPE_TRIGGERS )


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
