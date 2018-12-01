Auditing (Nova)
===============

Hubble supports success/fail auditing via a number of included modules. The
codename for the audit piece of hubble is "Nova".

Module Documentation
--------------------

:doc:`modules/nova`

Usage
-----

There are two primary entry points for the Nova module:

``hubble.audit``

    audits the agent using the YAML profile(s) you provide as comma-separated
    arguments.

    ``hubble.audit`` takes a number of optional arguments. The first is a
    comma-separated list of paths. These paths can be files or directories
    within the ``hubblestack_nova_profiles`` directory, with the ``.yaml``
    suffix removed. For information on the other arguments, please see
    :doc:`modules/nova`.

    If ``hubble.audit`` is run without targeting any audit configs or
    directories, it will instead run ``hubble.top`` with no arguments.

    ``hubble.audit`` will return a list of audits which were successful, and a
    list of audits which failed.

``hubble.top``

    audits the agent using the ``top.nova`` configuration. By default, the
    ``top.nova`` should be located in the fileserver at
    ``salt://hubblestack_nova_profiles/top.nova``, but a different path can be
    defined.

Here are some example calls for ``hubble.audit``::

    # Run the cve scanner and the CIS profile:
    hubble hubble.audit cve.scan-v2,cis.centos-7-level-1-scored-v1
    # Run hubble.top with the default topfile (top.nova)
    hubble hubble.top
    # Run all yaml configs and tags under salt://hubblestack_nova_profiles/foo/ and salt://hubblestack_nova_profiles/bar, but only run audits with tags starting with "CIS"
    hubble hubble.audit foo,bar tags='CIS*'

Configuration
-------------

For Nova module, configurations can be done via Nova topfiles. Nova topfiles
look very similar to saltstack topfiles, except the top-level key is always
nova, as nova doesn’t have environments.

**hubblestack_data/hubblestack_nova_profiles/top.nova**::

    nova:
      '*':
        - cve.scan-v2
        - network.ssh
        - network.smtp
      'web*':
        - cis.centos-7-level-1-scored-v1
        - cis.centos-7-level-2-scored-v1
      'G@os_family:debian':
        - network.ssh
        - cis.debian-7-level-1-scored: 'CIS*'

Additionally, all nova topfile matches are compound matches, so you never need
to define a match type like you do in saltstack topfiles. Each list item is a
string representing the dot-separated location of a yaml file which will be run
with ``hubble.audit``. You can also specify a tag glob to use as a filter for
just that yaml file, using a colon after the yaml file (turning it into a
dictionary). See the last two lines in the yaml above for examples.

Examples::

    hubble hubble.top
    hubble hubble.top foo/bar/top.nova
    hubble hubble.top foo/bar.nova verbose=True

In some cases, your organization may want to skip certain audit checks for
certain hosts. This is supported via compensating control configuration.

You can skip a check globally by adding a ``control: <reason>`` key to the
check itself. This key should be added at the same level as description and
trigger pieces of a check. In this case, the check will never run, and will
output under the Controlled results key.

Nova also supports separate control profiles, for more fine-grained control
using topfiles. You can use a separate YAML top-level key called control.
Generally, you’ll put this top-level key inside of a separate YAML file and
only include it in the top-data for the hosts for which it is relevant.

For these separate control configs, the audits will always run, whether they
are controlled or not. However, controlled audits which fail will be converted
from Failure to Controlled in a post-processing operation.

The control config syntax is as follows:

**hubblestack_data/hubblestack_nova_profiles/example_control/example.yaml**::

    control:
      - CIS-2.1.4: This is the reason we control the check
      - some_other_tag:
          reason: This is the reason we control the check
      - a_third_tag_with_no_reason

Note that providing a reason for the control is optional. Any of the three
formats shown in the yaml list above will work.

Once you have your compensating control config, just target the yaml to the
hosts you want to control using your topfile. In this case, all the audits will
still run, but if any of the controlled checks fail, they will be removed from
Failure and added to Controlled, and will be treated as a Success for the
purposes of compliance percentage.  To use the above control, you would add the
following to your ``top.nova`` file::

    nova:
      '*':
        - example_control.example

It is quite possible you may want to send the NOVA audit results to a collection system. 
This can be accomplished by using returners, which are included with Hubble. Currently, 
there are returners available for **splunk**, **logstash**, **graylog**, and **sqlite**.
Hubble supports using multiple returners from the same node so sending data to multiple 
collectors is possible. Each individual returner has distinct options that need to be 
set prior to their use. You can find general config options for each returner at the top 
of each file located here
https://github.com/hubblestack/hubble/tree/develop/hubblestack/extmods/returners.

**Specify a returner when running Hubble from the command line:**

.. code-block::

    hubble hubble.audit --r RETURN
    hubble hubble.audit --return RETURN

You can also define schedules for returners in the Hubble config file, which is typically
located at ``/etc/hubble/hubble``.

