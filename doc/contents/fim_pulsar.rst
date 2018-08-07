File Integrity Monitoring/FIM (Linux) (Pulsar)
==============================================

Pulsar is designed to monitor for file system events, acting as a real-time
File Integrity Monitoring (FIM) agent. Pulsar uses python-inotify to watch for
these events and report them to your destination of choice.

Module Documentation
--------------------

:doc:`modules/pulsar`

Usage
-----

Once Pulsar is configured there isn’t anything you need to do to interact with
it. It simply runs quietly in the background and sends you alerts.

.. note::

    Running pulsar outside of hubble's scheduler will never return results.
    This is because the first time you run pulsar it will set up the watches in
    inotify, but no events will have been generated. Only subsequent runs under
    the same process can receive events.

Configuration
-------------

The list of files and directories that pulsar watches is defined in
salt://hubblestack_pulsar/hubblestack_pulsar_config.yaml::

    /lib: { recurse: True, auto_add: True }
    /bin: { recurse: True, auto_add: True }
    /sbin: { recurse: True, auto_add: True }
    /boot: { recurse: True, auto_add: True }
    /lib64: { recurse: True, auto_add: True }
    /usr/lib: { recurse: True, auto_add: True }
    /usr/bin: { recurse: True, auto_add: True }
    /usr/sbin: { recurse: True, auto_add: True }
    /usr/lib64: { recurse: True, auto_add: True }
    /usr/libexec: { recurse: True, auto_add: True }
    /usr/local/etc: { recurse: True, auto_add: True }
    /usr/local/bin: { recurse: True, auto_add: True }
    /usr/local/lib: { recurse: True, auto_add: True }
    /usr/local/sbin: { recurse: True, auto_add: True }
    /usr/local/libexec: { recurse: True, auto_add: True }
    /opt/bin: { recurse: True, auto_add: True }
    /opt/osquery: { recurse: True, auto_add: True }
    /opt/hubble: { recurse: True, auto_add: True }
    /etc:
      exclude:
        - /etc/passwd.lock
        - /etc/shadow.lock
        - /etc/gshadow.lock
        - /etc/group.lock
        - /etc/passwd+
        - /etc/passwd-
        - /etc/shadow+
        - /etc/shadow-
        - /etc/group+
        - /etc/group-
        - /etc/gshadow+
        - /etc/gshadow-
        - /etc/cas/timestamp
        - /etc/resolv.conf.tmp
        - /etc/pki/nssdb/key4.db-journal
        - /etc/pki/nssdb/cert9.db-journal
        - /etc/salt/gpgkeys/random_seed
        - /etc/blkid/blkid.tab.old
        - \/etc\/blkid\/blkid\.tab\-\w{6}$:
            regex: True
        - \/etc\/passwd\.\d*$:
            regex: True
        - \/etc\/group\.\d*$:
            regex: True
        - \/etc\/shadow\.\d*$:
            regex: True
        - \/etc\/gshadow\.\d*$:
            regex: True
      recurse: True
      auto_add: True
    return: splunk_pulsar_return
    checksum: sha256
    stats: True
    batch: True

Note some of the available options: you can recurse through directories,
auto_add new files and directories as they are created, or exclude based on
glob or regex patterns.

topfiles
^^^^^^^^

Pulsar supports organizing query groups across files, and combining/targeting
them via a ``top.pulsar`` file (similar to topfiles in SaltStack)::

    pulsar:
      '*':
        - hubblestack_pulsar_config

Each entry under ``pulsar`` is a SaltStack style `compound match`_ that
describes which hosts should receive the list of queries. All queries are
merged, and conflicts go to the last-defined file.

The files referenced are relative to ``salt://hubblestack_pulsar/`` and
leave off the ``.yaml`` extension.

You can also specify an alternate ``top.pulsar`` file.

For more details, see the module documentation: :doc:`modules/pulsar`

.. _compound match: https://docs.saltstack.com/en/latest/topics/targeting/compound.html
