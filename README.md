YouCompleteMe: a code-completion engine for Vim
===============================================

This is a fork of [YouCompleteMe][] providing a special support for C and C++.

It understands argument locations to provide prototype information of what is
expected to be inserted. The following GIF shows it in action (click it for
higher resolution):

<a href="https://s3.amazonaws.com/f.cl.ly/items/1e2F0A123h331c1G0L0R/SadBart.gif">
  ![YouCompleteMe GIF](https://s3.amazonaws.com/f.cl.ly/items/2P0b0c3N2m2m2l2L273B/SadBart-Small.gif)
</a>

Installation
------------

### Requirements

- Clang 3.7 revision 227309 (there's no Clang 3.7 release yet).
- Better on Vim 7.3.867 or newer.

Installation is only supported through a system's libclang.

For an automatic installation using a plugin manager you could put this on your
`.vimrc`:

```vim
Plug 'oblitum/YouCompleteMe', { 'do': './install.sh --clang-completer --system-libclang' }
```
<sub> This example uses [VIM-PLUG][]. </sub>

For a manual installation you should run this in the plugin's directory:

```
❯❯❯ ./install.sh --clang-completer --system-libclang
```

Depending on your system (OS X for example), you may need to set some flags so
that the build picks the correct Clang headers and binary. For a Clang
installation at `/opt/local` you may try:

```
❯❯❯ CPATH=/opt/local/include CC=/opt/local/bin/clang ./install.sh --clang-completer --system-libclang
```

Particularities
---------------

- There are no default mappings for `<TAB>` and `<S-TAB>` to browse the
popup-menu. Since this fork enables whitespace to come after triggers while
still showing up the popup-menu, `<TAB>` and `<S-TAB>` have a better use
producing whitespace by default than browsing the popup-menu. By default
the arrow keys are enabled, and there's also the original Vim keys for browsing
the popup-menu: `<C-N>` and `<C-P>`.

- For argument hints a little bit faster than official Clang take a look at
  [this change][faster-candidates] I'm maintaining at
  [a branch in my own fork][oblitum-clang]. You can use it if you care about
  some milliseconds.

Limitations
-----------

This is a new capability of the libclang API which I have provided and there's
still work do be done:

- Variadic templates.
- Member initializers.
- Template parameters.
- Anything else, let me know.

<sub> Notice that libclang doesn't support completing type-dependent call
expressions. </sub>

Expectations
------------

The expectation for this fork is that these changes lands in the official one or
that the newer libclang features gets used in there.
Once this happens it'll probably cease to exist.

Thanks
------

- Strahinja Val Markovic
- Manuel Klimek
- Xavier Deguillard

Contact
-------

If you have bug reports or feature suggestions, please use the [issue
tracker][tracker].

The latest version of the plugin is available at
<https://github.com/oblitum/YouCompleteMe/>.  
The author's homepage is <http://nosubstance.me>.

The latest version of the original plugin is available at
<http://valloric.github.io/YouCompleteMe/>.  
The original author's homepage is <http://val.markovic.io>.  

Project Management
------------------

This open-source fork is run by me, Francisco Lopes. I've contributed to Clang
and made the necessary plugin changes in my free-time. Manuel Klimek was the
reviewer for the changes accepted in Clang.

The original notice on this section was:

> This open-source project is run by me, Strahinja Val Markovic. I also happen
> to work for Google and the code I write here is under Google copyright (for
> the sake of simplicity and other reasons). This does **NOT** mean that this is
> an official Google product (it isn't) or that Google has (or wants to have)
> anything to do with it.

License
-------

This software is licensed under the [GPL v3 license][gpl].  
© 2015 Francisco Lopes.  
© 2013 Google Inc.

[YouCompleteMe]: https://github.com/Valloric/YouCompleteMe
[VIM-PLUG]: https://github.com/junegunn/vim-plug
[gpl]: http://www.gnu.org/copyleft/gpl.html
[tracker]: https://github.com/oblitum/YouCompleteMe/issues?state=open
[faster-candidates]: https://github.com/oblitum/clang/compare/faster-overload-candidates
[oblitum-clang]: https://github.com/oblitum/clang/tree/faster-overload-candidates
