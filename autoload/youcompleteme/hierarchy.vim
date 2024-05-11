" Copyright (C) 2021 YouCompleteMe contributors
"
" This file is part of YouCompleteMe.
"
" YouCompleteMe is free software: you can redistribute it and/or modify
" it under the terms of the GNU General Public License as published by
" the Free Software Foundation, either version 3 of the License, or
" (at your option) any later version.
"
" YouCompleteMe is distributed in the hope that it will be useful,
" but WITHOUT ANY WARRANTY; without even the implied warranty of
" MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
" GNU General Public License for more details.
"
" You should have received a copy of the GNU General Public License
" along with YouCompleteMe.  If not, see <http://www.gnu.org/licenses/>.

" This is basic vim plugin boilerplate
let s:save_cpo = &cpoptions
set cpoptions&vim

scriptencoding utf-8

let s:popup_id = -1
let s:lines_and_handles = v:none
" 1-based index of the selected item in the popup
" -1 means none set
"  0 means nothing, (Invalid)
let s:select = -1
let s:kind = ''

let s:ingored_keys = [
      \ "\<CursorHold>",
      \ "\<MouseMove>",
      \ ]

function! youcompleteme#hierarchy#StartRequest( kind )
  py3 ycm_state.ResetCurrentHierarchy()
  if a:kind == 'call'
    let lines_and_handles = py3eval(
      \ 'ycm_state.InitializeCurrentHierarchy( ycm_state.SendCommandRequest( ' .
      \ '[ "CallHierarchy" ], "", False, 0, 0 ), ' .
      \ 'vim.eval( "a:kind" ) )' )
  else
    let lines_and_handles = py3eval( 
      \ 'ycm_state.InitializeCurrentHierarchy( ycm_state.SendCommandRequest( ' .
      \ '[ "TypeHierarchy" ], "", False, 0, 0 ), ' .
      \ 'vim.eval( "a:kind" ) )' )
  endif
  if len( lines_and_handles )
    let s:lines_and_handles = lines_and_handles
    let s:kind = a:kind
    let s:select = 1
    call s:SetUpMenu()
  endif
endfunction

function! s:MenuFilter( winid, key )
  if a:key == "\<S-Tab>"
    " ROot changes if we're showing super-tree of a sub-tree of the root
    " (indeicated by the handle being positive)
    let will_change_root = s:lines_and_handles[ s:select - 1 ][ 1 ] > 0
    call popup_close(
          \ s:popup_id,
          \ [ s:select - 1, 'resolve_up', will_change_root ] )
    return 1
  endif
  if a:key == "\<Tab>"
    " Root changes if we're showing sub-tree of a super-tree of the root
    " (indeicated by the handle being negative)
    let will_change_root = s:lines_and_handles[ s:select - 1 ][ 1 ] < 0
    call popup_close(
          \ s:popup_id,
          \ [ s:select - 1, 'resolve_down', will_change_root ] )
    return 1
  endif
  if a:key == "\<CR>"
    call popup_close( s:popup_id, [ s:select - 1, 'jump', v:none ] )
    return 1
  endif
  if a:key == "\<Up>" || a:key == "\<C-p>" || a:key == "\<C-k>" || a:key == "k"
    let s:select -= 1
    if s:select < 1
      let s:select = 1
    endif
    call win_execute( s:popup_id,
                    \ 'call cursor( [' . string( s:select ) . ', 1 ] )' )
    return 1
  endif
  if a:key == "\<Down>" || a:key == "\<C-n>" || a:key == "\<C-j>" || a:key == "j"
    let s:select += 1
    if s:select > len( s:lines_and_handles )
      let s:select = len( s:lines_and_handles )
    endif
    call win_execute( s:popup_id,
                    \ 'call cursor( [' . string( s:select ) . ', 1 ] )' )
    return 1
  endif
  if index( s:ingored_keys, a:key ) >= 0
    return 0
  endif
  " Close the popup on any other key press
  call popup_close( s:popup_id, [ s:select - 1, 'cancel', v:none ] )
  if a:key == "\<Esc>" || a:key == "\<C-c>"
    return 1
  endif
  return 0
endfunction

function! s:MenuCallback( winid, result )
  let operation = a:result[ 1 ]
  let selection = a:result[ 0 ]
  if operation == 'resolve_down'
    call s:ResolveItem( selection, 'down', a:result[ 2 ] )
  elseif operation == 'resolve_up'
    call s:ResolveItem( selection, 'up', a:result[ 2 ] )
  else
    if operation == 'jump'
      let handle = s:lines_and_handles[ selection ][ 1 ]
      py3 ycm_state.JumpToHierarchyItem( vimsupport.GetIntValue( "handle" ) )
    endif
    py3 ycm_state.ResetCurrentHierarchy()
    let s:kind = ''
    let s:select = 1
  endif
endfunction

function! s:SetUpMenu()
  let s:popup_id = popup_menu( [], #{
    \   filter: funcref( 's:MenuFilter' ),
    \   callback: funcref( 's:MenuCallback' ),
    \   wrap: 0,
    \   minwidth: &columns * 90/100,
    \   maxwidth: &columns * 90/100,
    \   maxheight: &lines * 75/100,
    \   scrollbar: 1,
    \   padding: [ 0, 0, 0, 0 ],
    \ } )
  let menu_lines = []
  let popup_width = popup_getpos( s:popup_id ).core_width
  let tabstop = popup_width / 3
  for [ item, handle ] in s:lines_and_handles
    let name = repeat( ' ', item.indent ) .. item.icon .. item.symbol
    " TODO: Explain (understand) why it's -2 not -1 for the space (padding?)
    let line = name[ : tabstop -2 ]
          \ . "\t"
          \ .. item.filepath[ : tabstop -2 ]
          \ . "\t"
          \ .. item.description[ : tabstop - 2 ]
    call add( menu_lines, line )
  endfor
  call popup_settext( s:popup_id, menu_lines )
  call win_execute( s:popup_id,
                  \ 'setlocal tabstop=' . tabstop )
  call win_execute( s:popup_id,
                  \ 'call cursor( [' . string( s:select ) . ', 1 ] )' )
endfunction

function! s:ResolveItem( choice, direction, will_change_root )
  let handle = s:lines_and_handles[ a:choice ][ 1 ]
  if py3eval(
      \ 'ycm_state.ShouldResolveItem( vimsupport.GetIntValue( "handle" ), vim.eval( "a:direction" ) )' )
    let lines_and_handles_with_offset = py3eval(
        \ 'ycm_state.UpdateCurrentHierarchy( ' .
        \ 'vimsupport.GetIntValue( "handle" ), ' .
        \ 'vim.eval( "a:direction" ) )' )
    let s:lines_and_handles = lines_and_handles_with_offset[ 0 ]
    if a:will_change_root
      " When re-rooting the tree, put the cursor on the new "root" item, as this
      " helps with orientation. This behaviour is consistent with an expansion
      " where we _don't_ re-root the tree, so feels more natural than anything
      " else.
      " The new root is the element with indent of 0.
      let s:select = 1 + indexof( s:lines_and_handles,
            \                     { i, v -> v[0].indent == 0 } )
    else
      let s:select += lines_and_handles_with_offset[ 1 ]
    endif
  endif
  call s:SetUpMenu()
endfunction