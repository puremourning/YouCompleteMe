function! SetUp()
  let g:ycm_use_clangd = 1
  call youcompleteme#test#setup#SetUp()
  nmap <leader><leader>w <Plug>(YCMFindSymbolInWorkspace)
  nmap <leader><leader>d <Plug>(YCMFindSymbolInDocument)
endfunction

function! TearDown()
endfunction

function! Test_WorkspaceSymbol_Basic()
  call youcompleteme#test#setup#OpenFile(
        \ '/test/testdata/cpp/complete_with_sig_help.cc', {} )

  let original_win = winnr()
  let b = bufnr()
  let l = winlayout()

  let popup_id = -1

  function! PutQuery( ... )
    " Wait for the current buffer to be a prompt buffer
    call WaitForAssert( { -> assert_equal( 'prompt', &buftype ) } )
    call WaitForAssert( { -> assert_equal( 'i', mode() ) } )

    call WaitForAssert( { -> assert_true(
          \ youcompleteme#finder#GetState().id != -1 ) } )

    " TODO: Wait for the popup to be displayed, and check the contents
    call FeedAndCheckAgain( 'thisisathing', funcref( 'SelectItem' ) )
  endfunction

  function SelectItem( ... )
    let id = youcompleteme#finder#GetState().id
    let o = popup_getoptions( id )

    call WaitForAssert( { ->
          \ assert_equal( ' [X] Search for symbol: thisisathing ',
          \ o.title  ) },
          \ 10000 )

    call WaitForAssert( { -> assert_equal( 1, line( '$', id ) ) } )

    call feedkeys( "\<CR>" )
  endfunction

  " <Leader> is \ - this calls <Plug>(YCMFindSymbolInWorkspace)
  call FeedAndCheckMain( '\\w', funcref( 'PutQuery' ) )

  call WaitForAssert( { -> assert_equal( l, winlayout() ) } )
  call WaitForAssert( { -> assert_equal( original_win, winnr() ) } )
  call assert_equal( b, bufnr() )
  call assert_equal( [ 0, 5, 7, 0 ], getpos( '.' ) )

  delfunct PutQuery
  delfunct SelectItem
  %bwipe!
endfunction

function! Test_DocumentSymbols_Basic()
  call youcompleteme#test#setup#OpenFile(
        \ '/test/testdata/cpp/complete_with_sig_help.cc', {} )

  let original_win = winnr()
  let b = bufnr()
  let l = winlayout()

  let popup_id = -1

  function! PutQuery( ... )
    " Wait for the current buffer to be a prompt buffer
    call WaitForAssert( { -> assert_equal( 'prompt', &buftype ) } )
    call WaitForAssert( { -> assert_equal( 'i', mode() ) } )

    call WaitForAssert( { -> assert_true(
          \ youcompleteme#finder#GetState().id != -1 ) } )

    " TODO: Wait for the popup to be displayed, and check the contents
    call FeedAndCheckAgain( 'thisisathing', funcref( 'SelectItem' ) )
  endfunction

  function SelectItem( ... )
    let id = youcompleteme#finder#GetState().id
    let o = popup_getoptions( id )

    call WaitForAssert( { ->
          \ assert_equal( ' [X] Search for symbol: thisisathing ',
          \ o.title  ) },
          \ 10000 )

    call WaitForAssert( { -> assert_equal( 1, line( '$', id ) ) } )

    call feedkeys( "\<CR>" )
  endfunction

  " <Leader> is \ - this calls <Plug>(YCMFindSymbolInDocument)
  call FeedAndCheckMain( '\\d', funcref( 'PutQuery' ) )

  call WaitForAssert( { -> assert_equal( l, winlayout() ) } )
  call WaitForAssert( { -> assert_equal( original_win, winnr() ) } )
  call assert_equal( b, bufnr() )
  " NOTE: cland returns the position of the decl here not the identifier. This
  " is why it's position 3 not 7 as in the Test_WorkspaceSymbol_Basic
  call assert_equal( [ 0, 5, 3, 0 ], getpos( '.' ) )

  delfunct PutQuery
  delfunct SelectItem
  %bwipe!
endfunction

function! Test_Cancel_DocumentSymbol()
  call youcompleteme#test#setup#OpenFile(
        \ '/test/testdata/cpp/complete_with_sig_help.cc', {} )

  let original_win = winnr()
  let b = bufnr()
  let l = winlayout()

  " Jump to a different position so that we can ensure we return to the same
  " place
  normal! G
  let p = getpos( '.' )

  let popup_id = -1

  function! PutQuery( ... )
    " Wait for the current buffer to be a prompt buffer
    call WaitForAssert( { -> assert_equal( 'prompt', &buftype ) } )
    call WaitForAssert( { -> assert_equal( 'i', mode() ) } )

    call WaitForAssert( { -> assert_true(
          \ youcompleteme#finder#GetState().id != -1 ) } )

    call FeedAndCheckAgain( 'thisisathing', funcref( 'SelectItem' ) )
  endfunction

  function SelectItem( ... )
    let id = youcompleteme#finder#GetState().id
    let o = popup_getoptions( id )

    call WaitForAssert( { ->
          \ assert_equal( ' [X] Search for symbol: thisisathing ',
          \ o.title  ) },
          \ 10000 )

    call WaitForAssert( { -> assert_equal( 1, line( '$', id ) ) } )

    " Cancel - this should stopinsert
    call feedkeys( "\<C-c>" )
  endfunction

  " <Leader> is \ - this calls <Plug>(YCMFindSymbolInDocument)
  call FeedAndCheckMain( '\\d', funcref( 'PutQuery' ) )

  call WaitForAssert( { -> assert_equal( l, winlayout() ) } )
  call WaitForAssert( { -> assert_equal( original_win, winnr() ) } )
  call assert_equal( b, bufnr() )

  " Retuned to just where we started
  call assert_equal( p, getpos( '.' ) )

  delfunct PutQuery
  delfunct SelectItem
  %bwipe!
endfunction

function! Test_EmptySearch()
  call youcompleteme#test#setup#OpenFile(
        \ '/test/testdata/cpp/complete_with_sig_help.cc', {} )

  let original_win = winnr()
  let b = bufnr()
  let l = winlayout()

  let popup_id = -1

  function! PutQuery( ... )
    " Wait for the current buffer to be a prompt buffer
    call WaitForAssert( { -> assert_equal( 'prompt', &buftype ) } )
    call WaitForAssert( { -> assert_equal( 'i', mode() ) } )

    call WaitForAssert( { -> assert_true(
          \ youcompleteme#finder#GetState().id != -1 ) } )

    " TODO: Wait for the popup to be displayed, and check the contents
    call FeedAndCheckAgain( 'nothingshouldmatchthis',
                          \ funcref( 'SelectNothing' ) )
  endfunction

  function SelectNothing( ... )
    let id = youcompleteme#finder#GetState().id
    let o = popup_getoptions( id )

    call WaitForAssert( { ->
          \ assert_equal( ' [X] Search for symbol: nothingshouldmatchthis ',
          \ o.title  ) },
          \ 10000 )

    call WaitForAssert( { -> assert_equal( 1, line( '$', id ) ) } )

    call assert_equal( 'No results', getbufline( winbufnr( id ), '$' )[ 0 ] )
    call FeedAndCheckAgain( "\<CR>", funcref( 'ChangeSearch' ) )
  endfunction

  function ChangeSearch( ... )
    let id = youcompleteme#finder#GetState().id
    let o = popup_getoptions( id )

    " Hitting enter with nothing to select clears the prompt, because prompt
    " buffer
    call WaitForAssert( { ->
          \ assert_equal( ' [X] Search for symbol:  ',
          \ o.title  ) },
          \ 10000 )
    call assert_equal( 'No results', getbufline( winbufnr( id ), '$' )[ 0 ] )

    call assert_equal( -1, youcompleteme#finder#GetState().selected )

    call FeedAndCheckAgain( 'tiat', funcref( 'TestUpDownSelect' ) )
  endfunction

  function TestUpDownSelect( ... )
    let id = youcompleteme#finder#GetState().id
    let o = popup_getoptions( id )

    call WaitForAssert( { ->
          \ assert_equal( ' [X] Search for symbol: tiat ',
          \ o.title  ) },
          \ 10000 )
    call WaitForAssert( { -> assert_equal( 2, line( '$', id ) ) } )

    " FIXME: Doing all these tests with only 2 entries means that it's not
    " really checking the behaviour completely accurately, we should at least
    " use 3, but that would require crafting a new test file, which is nonzero
    " effort. Well, it's probably as much effort as writing this comment...

    " Check down movement
    call assert_equal( 0, youcompleteme#finder#GetState().selected )

    call feedkeys( "\<C-j>", 'xt' )
    call assert_equal( 1, youcompleteme#finder#GetState().selected )

    call feedkeys( "\<Down>", 'xt' )
    call assert_equal( 0, youcompleteme#finder#GetState().selected )

    call feedkeys( "\<Tab>", 'xt' )
    call assert_equal( 1, youcompleteme#finder#GetState().selected )

    call feedkeys( "\<C-n>", 'xt' )
    call assert_equal( 0, youcompleteme#finder#GetState().selected )

    " Check up movement and wrapping
    call feedkeys( "\<C-k>", 'xt' )
    call assert_equal( 1, youcompleteme#finder#GetState().selected )

    call feedkeys( "\<Up>", 'xt' )
    call assert_equal( 0, youcompleteme#finder#GetState().selected )

    call feedkeys( "\<S-Tab>", 'xt' )
    call assert_equal( 1, youcompleteme#finder#GetState().selected )

    call feedkeys( "\<C-p>", 'xt' )
    call assert_equal( 0, youcompleteme#finder#GetState().selected )

    call feedkeys( "\<Tab>", 'xt' )
    call assert_equal( 1, youcompleteme#finder#GetState().selected )

    call feedkeys( "\<Home>", 'xt' )
    call assert_equal( 0, youcompleteme#finder#GetState().selected )

    call feedkeys( "\<End>", 'xt' )
    call assert_equal( 1, youcompleteme#finder#GetState().selected )

    call feedkeys( "\<End>", 'xt' )
    call assert_equal( 1, youcompleteme#finder#GetState().selected )

    call feedkeys( "\<PageUp>", 'xt' )
    call assert_equal( 0, youcompleteme#finder#GetState().selected )

    call feedkeys( "\<PageDown>", 'xt' )
    call assert_equal( 1, youcompleteme#finder#GetState().selected )

    call feedkeys( "\<CR>" )
  endfunction

  " <Leader> is \ - this calls <Plug>(YCMFindSymbolInWorkspace)
  call FeedAndCheckMain( '\\w', funcref( 'PutQuery' ) )

  call WaitForAssert( { -> assert_equal( l, winlayout() ) } )
  call WaitForAssert( { -> assert_equal( original_win, winnr() ) } )
  call assert_equal( b, bufnr() )
  call assert_equal( [ 0, 5, 7, 0 ], getpos( '.' ) )

  delfunct PutQuery
  delfunct SelectNothing
  delfunct ChangeSearch
  delfunct TestUpDownSelect
  %bwipe!
endfunction

function! Test_LeaveWindow_CancelSearch()
  call youcompleteme#test#setup#OpenFile(
        \ '/test/testdata/cpp/complete_with_sig_help.cc', {} )

  let original_win = winnr()
  let b = bufnr()
  let l = winlayout()

  " Jump to a different position so that we can ensure we return to the same
  " place
  normal! G
  let p = getpos( '.' )

  let popup_id = -1

  function! PutQuery( ... )
    " Wait for the current buffer to be a prompt buffer
    call WaitForAssert( { -> assert_equal( 'prompt', &buftype ) } )
    call WaitForAssert( { -> assert_equal( 'i', mode() ) } )

    call WaitForAssert( { -> assert_true(
          \ youcompleteme#finder#GetState().id != -1 ) } )

    call feedkeys( "\<C-w>w" )
  endfunction

  " <Leader> is \ - this calls <Plug>(YCMFindSymbolInWorkspace)
  call FeedAndCheckMain( '\\w', funcref( 'PutQuery' ) )

  call WaitForAssert( { -> assert_equal( l, winlayout() ) } )
  call WaitForAssert( { -> assert_equal( original_win, winnr() ) } )
  call assert_equal( b, bufnr() )

  " Retuned to just where we started
  call assert_equal( p, getpos( '.' ) )

  delfunct PutQuery
  %bwipe!
endfunction
