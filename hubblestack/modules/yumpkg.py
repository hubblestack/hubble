# -*- coding: utf-8 -*-
"""
Support for YUM/DNF

.. important::
    If you feel that Salt should be using this module to manage packages on a
    minion, and it is using a different module (or gives an error similar to
    *'pkg.install' is not available*), see :ref:`here
    <module-provider-override>`.

... note::
    DNF is fully supported as of version 2015.5.10 and 2015.8.4 (partial
    support for DNF was initially added in 2015.8.0), and DNF is used
    automatically in place of YUM in Fedora 22 and newer.
"""

# Import python libs
import logging

try:
    import yum

    HAS_YUM = True
except ImportError:
    HAS_YUM = False

import hubblestack.utils.args
import hubblestack.utils.data
import hubblestack.utils.pkg
import hubblestack.utils.pkg.rpm
import hubblestack.utils.systemd
import hubblestack.utils.environment

log = logging.getLogger(__name__)

__HOLD_PATTERN = r"[\w+]+(?:[.-][^-]+)*"

# Define the module's virtual name
__virtualname__ = "pkg"


def __virtual__():
    """
    Confine this module to yum based systems
    """
    if __opts__.get("yum_provider") == "yumpkg_api":
        return (False, "Module yumpkg: yumpkg_api provider not available")
    try:
        os_grain = __grains__["os"].lower()
        os_family = __grains__["os_family"].lower()
    except Exception:
        return (False, "Module yumpkg: no yum based system detected")

    enabled = ("amazon", "xcp", "xenserver", "virtuozzolinux", "virtuozzo")

    if os_family == "rocky" or os_family == "redhat" or os_grain in enabled:
        return __virtualname__
    return (False, "Module yumpkg: no yum based system detected")


def list_pkgs(versions_as_list=False, **kwargs):
    """
    List the packages currently installed as a dict. By default, the dict
    contains versions as a comma separated string::

        {'<package_name>': '<version>[,<version>...]'}

    versions_as_list:
        If set to true, the versions are provided as a list

        {'<package_name>': ['<version>', '<version>']}

    attr:
        If a list of package attributes is specified, returned value will
        contain them in addition to version, eg.::

        {'<package_name>': [{'version' : 'version', 'arch' : 'arch'}]}

        Valid attributes are: ``epoch``, ``version``, ``release``, ``arch``,
        ``install_date``, ``install_date_time_t``.

        If ``all`` is specified, all valid attributes will be returned.

            .. versionadded:: 2018.3.0
    """
    versions_as_list = hubblestack.utils.data.is_true(versions_as_list)
    # not yet implemented or not applicable
    if any([hubblestack.utils.data.is_true(kwargs.get(x)) for x in ("removed", "purge_desired")]):
        return {}

    attr = kwargs.get("attr")
    if attr is not None:
        attr = hubblestack.utils.args.split_input(attr)

    contextkey = "pkg.list_pkgs"

    if contextkey not in __context__:
        ret = {}
        cmd = [
            "rpm",
            "-qa",
            "--queryformat",
            hubblestack.utils.pkg.rpm.QUERYFORMAT.replace("%{REPOID}", "(none)") + "\n",
        ]
        output = __mods__["cmd.run"](cmd, python_shell=False, output_loglevel="trace")
        for line in output.splitlines():
            pkginfo = hubblestack.utils.pkg.rpm.parse_pkginfo(line, osarch=__grains__["osarch"])
            if pkginfo is not None:
                # see rpm version string rules
                # available at https://goo.gl/UGKPNd
                pkgver = pkginfo.version
                epoch = ""
                release = ""
                if ":" in pkgver:
                    epoch, pkgver = pkgver.split(":", 1)
                if "-" in pkgver:
                    pkgver, release = pkgver.split("-", 1)
                all_attr = {
                    "epoch": epoch,
                    "version": pkgver,
                    "release": release,
                    "arch": pkginfo.arch,
                    "install_date": pkginfo.install_date,
                    "install_date_time_t": pkginfo.install_date_time_t,
                }
                __mods__["pkg_resource.add_pkg"](ret, pkginfo.name, all_attr)

        for pkgname in ret:
            ret[pkgname] = sorted(ret[pkgname], key=lambda d: d["version"])

        __context__[contextkey] = ret

    return __mods__["pkg_resource.format_pkg_list"](__context__[contextkey], versions_as_list, attr)


def version(*names, **kwargs):
    """
    Returns a string representing the package version or an empty string if not
    installed. If more than one package name is specified, a dict of
    name/version pairs is returned.
    """
    return __mods__["pkg_resource.version"](*names, **kwargs)


def version_cmp(pkg1, pkg2, ignore_epoch=False):
    """
    .. versionadded:: 2015.5.4

    Do a cmp-style comparison on two packages. Return -1 if pkg1 < pkg2, 0 if
    pkg1 == pkg2, and 1 if pkg1 > pkg2. Return None if there was a problem
    making the comparison.

    ignore_epoch : False
        Set to ``True`` to ignore the epoch when comparing versions

        .. versionadded:: 2015.8.10,2016.3.2
    """

    return __mods__["lowpkg.version_cmp"](pkg1, pkg2, ignore_epoch=ignore_epoch)


def refresh_db(**kwargs):
    """
    Check the yum repos for updated packages

    Returns:

    - ``True``: Updates are available
    - ``False``: An error occurred
    - ``None``: No updates are available

    repo
        Refresh just the specified repo

    disablerepo
        Do not refresh the specified repo

    enablerepo
        Refresh a disabled repo using this option

    branch
        Add the specified branch when refreshing

    disableexcludes
        Disable the excludes defined in your config files. Takes one of three
        options:
        - ``all`` - disable all excludes
        - ``main`` - disable excludes defined in [main] in yum.conf
        - ``repoid`` - disable excludes defined for that repo

    setopt
        A comma-separated or Python list of key=value options. This list will
        be expanded and ``--setopt`` prepended to each in the yum/dnf command
        that is run.

        .. versionadded:: 2019.2.0
    """
    # Remove rtag file to keep multiple refreshes from happening in pkg states
    hubblestack.utils.pkg.clear_rtag(__opts__)
    retcodes = {
        100: True,
        0: None,
        1: False,
    }

    ret = True
    check_update_ = kwargs.pop("check_update", True)
    options = _get_options(**kwargs)

    clean_cmd = ["--quiet", "--assumeyes", "clean", "expire-cache"]
    clean_cmd.extend(options)
    _call_yum(clean_cmd, ignore_retcode=True)

    if check_update_:
        update_cmd = ["--quiet", "--assumeyes", "check-update"]
        if __grains__.get("os_family") == "RedHat" and __grains__.get("osmajorrelease") == 7:
            # This feature is disabled because
            # it is not used by Salt and adds a
            # lot of extra time to the command with
            # large repos like EPEL
            update_cmd.append("--setopt=autocheck_running_kernel=false")
        update_cmd.extend(options)
        ret = retcodes.get(_call_yum(update_cmd, ignore_retcode=True)["retcode"], False)

    return ret


def _call_yum(args, **kwargs):
    """
    Call yum/dnf.
    """
    params = {
        "output_loglevel": "trace",
        "python_shell": False,
        "env": hubblestack.utils.environment.get_module_environment(globals()),
    }
    params.update(kwargs)
    cmd = []
    if hubblestack.utils.systemd.has_scope(__context__) and __mods__["config.get"]("systemd.scope", True):
        cmd.extend(["systemd-run", "--scope"])
    cmd.append(_yum())
    cmd.extend(args)

    return __mods__["cmd.run_all"](cmd, **params)


def _yum():
    """
    Determine package manager name (yum or dnf),
    depending on the system version.
    """
    contextkey = "yum_bin"
    if contextkey not in __context__:
        if "fedora" in __grains__["os"].lower() and int(__grains__["osrelease"]) >= 22:
            __context__[contextkey] = "dnf"
        else:
            __context__[contextkey] = "yum"
    return __context__[contextkey]
