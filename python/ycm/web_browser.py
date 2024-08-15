import vim
import json
from ycm import vimsupport
from ycmd import utils

from urllib import parse

def LaunchWebBrowser(url, selection ):
  url_parts = parse.urlparse(url)
  if url_parts.scheme == 'file':
    if selection:
      vimsupport.JumpToLocation( url_parts.path,
                                 selection[ 'start' ][ 'line' ] + 1,
                                 selection[ 'start' ][ 'character' ] + 1,
                                 '',
                                 'same-buffer')
    else:
      vimsupport.OpenFilename( url_parts.path, { 'focus': True } )
    return

  # Launch the web browser / default system handler for the URL.
  if utils.OnMac():
    command = [ '/bin/zsh', '-c', f"open '{url}'" ]
  elif utils.OnWindows():
    command = [ 'cmd.exe', '/c', f"start '{url}'" ]
  else:
    command = [ '/bin/sh', '-c', f"xdg-open '{url}'" ]

  vim.eval( f'job_start( {json.dumps(command)} )' )
