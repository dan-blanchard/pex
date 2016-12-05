from __future__ import absolute_import

import locale
import logging
import os
import sys
from tempfile import mkdtemp

from pip import autocomplete, check_isolated, deprecation, parseopts, PipError
from pip.exceptions import CommandError
from pip.index import FormatControl
from pip.req import RequirementSet
from pip.commands.download import DownloadCommand
from pip.utils import ensure_dir, normalize_path
from pip.utils.build import BuildDirectory
from pip.utils.filesystem import check_path_owner
from pip.wheel import WheelCache, WheelBuilder
try:
    import wheel
except ImportError:
    wheel = None

from pex.pex_builder import PEXBuilder
from pex.pex import PEX


logger = logging.getLogger(__name__)


class PexCommand(DownloadCommand):
  """
  Download packages and bundle them up into a PEX.

  Downloads from:

  - PyPI (and other indexes) using requirement specifiers.
  - VCS project urls.
  - Local project directories.
  - Local or remote source archives.

  pip also supports downloading from "requirements files", which provide
  an easy way to specify a whole environment to be downloaded.
  """
  name = 'pex'

  usage = """
    %prog [options] < <requirement specifier> [package-index-options] ...
    %prog [options] -r <requirements file> [package-index-options] ...
    %prog [options] [-e] <vcs project url> ...
    %prog [options] [-e] <local project path> ...
    %prog [options] <archive url/path> ..."""

  summary = 'Download packages.'

  def __init__(self, *args, **kw):
    super(PexCommand, self).__init__(*args, **kw)

    cmd_opts = self.cmd_opts

    cmd_opts.remove_option('--dest')

    cmd_opts.add_option(
        '-d', '--dest', '--destination-dir', '--destination-directory',
        dest='download_dir',
        metavar='dir',
        default=mkdtemp(),
        help=("Download packages into <dir>."),
    )

    cmd_opts.add_option(
        '-o', '--output-file',
        dest='pex_name',
        default=None,
        help='The name of the generated .pex file: Omiting this will run PEX '
             'immediately and not save it to a file.')

    cmd_opts.add_option(
        '-m', '--entry-point',
        dest='entry_point',
        metavar='MODULE[:SYMBOL]',
        default=None,
        help='Set the entry point to module or module:symbol.  If just specifying module, pex '
             'behaves like python -m, e.g. python -m SimpleHTTPServer.  If specifying '
             'module:symbol, pex imports that symbol and invokes it as if it were main.')

    cmd_opts.add_option(
        '--script', '--console-script',
        dest='script',
        default=None,
        metavar='SCRIPT_NAME',
        help='Set the entry point as to the script or console_script as defined by a any of the '
             'distributions in the pex.  For example: "pex -c fab fabric" or "pex -c mturk boto".')

    cmd_opts.add_option(
        '--python-shebang',
        dest='python_shebang',
        default=None,
        help='The exact shebang (#!...) line to add at the top of the PEX file minus the '
             '#!.  This overrides the default behavior, which picks an environment python '
             'interpreter compatible with the one used to build the PEX file.')


  def run(self, options, args):
      options.ignore_installed = True

      if options.python_version:
        python_versions = [options.python_version]
      else:
        python_versions = None

      dist_restriction_set = any([
        options.python_version,
        options.platform,
        options.abi,
        options.implementation,
      ])
      binary_only = FormatControl(set(), set([':all:']))
      if dist_restriction_set and options.format_control != binary_only:
        raise CommandError(
          "--only-binary=:all: must be set and --no-binary must not "
          "be set (or must be set to :none:) when restricting platform "
          "and interpreter constraints using --python-version, "
          "--platform, --abi, or --implementation."
        )

      options.src_dir = os.path.abspath(options.src_dir)
      options.download_dir = normalize_path(options.download_dir)

      ensure_dir(options.download_dir)

      with self._build_session(options) as session:
        finder = self._build_package_finder(
          options=options,
          session=session,
          platform=options.platform,
          python_versions=python_versions,
          abi=options.abi,
          implementation=options.implementation,
        )
        build_delete = (not (options.no_clean or options.build_dir))
        wheel_cache = WheelCache(options.cache_dir, options.format_control)
        if options.cache_dir and not check_path_owner(options.cache_dir):
          logger.warning(
            "The directory '%s' or its parent directory is not owned "
            "by the current user and caching wheels has been "
            "disabled. check the permissions and owner of that "
            "directory. If executing pip with sudo, you may want "
            "sudo's -H flag.",
            options.cache_dir,
          )
          options.cache_dir = None

        with BuildDirectory(options.build_dir,
                            delete=build_delete) as build_dir:

          requirement_set = RequirementSet(
            build_dir=build_dir,
            src_dir=options.src_dir,
            download_dir=options.download_dir,
            ignore_installed=True,
            ignore_dependencies=options.ignore_dependencies,
            session=session,
            isolated=options.isolated_mode,
            require_hashes=options.require_hashes,
            wheel_cache=wheel_cache,
          )
          self.populate_requirement_set(
            requirement_set,
            args,
            options,
            finder,
            session,
            self.name,
            None
          )

          if not requirement_set.has_requirements:
            return

          requirement_set.prepare_files(finder)

          downloaded = ' '.join([
            req.name for req in requirement_set.successfully_downloaded
          ])
          if downloaded:
            logger.info(
              'Successfully downloaded %s', downloaded
            )

          if wheel and options.format_control != binary_only:
              # build wheels before install.
              wb = WheelBuilder(
                  requirement_set,
                  finder,
                  build_options=[],
                  global_options=[],
              )
              # Ignore the result: a failed wheel will be
              # installed from the sdist/vcs whatever.
              wb.build(autobuilding=True)

          pex_builder = PEXBuilder(requirement_set=requirement_set)

          pex_info = pex_builder.info
          pex_info.zip_safe = False
          pex_info.always_write_cache = False
          pex_info.ignore_errors = False
          pex_info.inherit_path = False
          # pex_info.zip_safe = options.zip_safe
          # pex_info.always_write_cache = options.always_write_cache
          # pex_info.ignore_errors = options.ignore_errors
          # pex_info.inherit_path = options.inherit_path

          for dist in requirement_set.successfully_downloaded:
            logger.debug('  %s', dist)
            # This is a bit hacky, but there doesn't seem to be another way to
            # get the wheel filename at the path where it will now exist
            dist_file = os.path.basename(dist.link.url.split('#')[0])
            dist_path = os.path.join(options.download_dir, dist_file)
            # Add wheels to pex
            pex_builder.add_dist_location(dist_path)
            pex_builder.add_requirement(dist.req)

          if options.entry_point and options.script:
            raise ValueError('Must specify at most one entry point or script.')

          if options.entry_point:
            pex_builder.set_entry_point(options.entry_point)
          elif options.script:
            pex_builder.set_script(options.script)

          if options.python_shebang:
            pex_builder.set_shebang(options.python_shebang)
          else:
            pex_builder.set_shebang('#!/usr/bin/env python')

          if options.pex_name is not None:
            logger.info('Saving PEX file to %s', options.pex_name)
            tmp_name = options.pex_name + '~'
            # safe_delete(tmp_name)
            pex_builder.build(tmp_name)
            os.rename(tmp_name, options.pex_name)
            return 0

          pex_builder.freeze()

          pex = PEX(pex_builder.path())

          # Clean up
          if not options.no_clean:
            requirement_set.cleanup_files()

          sys.exit(pex.run())

      return requirement_set

def main(args=None):
    if args is None:
        args = sys.argv[1:]

    # Configure our deprecation warnings to be sent through loggers
    deprecation.install_warning_logger()

    autocomplete()

    command = PexCommand()

    try:
        options, args = command.parse_args(args)
    except PipError as exc:
        sys.stderr.write("ERROR: %s" % exc)
        sys.stderr.write(os.linesep)
        sys.exit(1)

    # Needed for locale.getpreferredencoding(False) to work
    # in pip.utils.encoding.auto_decode
    try:
        locale.setlocale(locale.LC_ALL, '')
    except locale.Error as e:
        # setlocale can apparently crash if locale are uninitialized
        logger.debug("Ignoring error %s when setting locale", e)
    return command.run(options, args)
