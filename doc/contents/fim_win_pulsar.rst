File Integrity Monitoring/FIM (Windows) (Pulsar)
================================================

Pulsar for Windows is designed to monitor for file system events, acting as a
real-time File Integrity Monitoring (FIM) agent. On Windows systems, pulsar
uses ntfs journaling watch for these events and report them to your destination
of choice.

Module Documentation
--------------------

:doc:`modules/win_pulsar`

Usage
-----

Once Pulsar is configured there isn’t anything you need to do to interact with
it. It simply runs quietly in the background and sends you alerts.

.. note::

    Running pulsar outside of hubble's scheduler will never return results.
    This is because the first time you run pulsar it will set up the watches in
    inotify, but no events will have been generated. Only subsequent runs under
    the same process can receive events.

.. todo::

    UM WHERE ARE THE DOCS
