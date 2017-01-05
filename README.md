# Hubble

An alternate version of Hubblestack which can be run without an existing
SaltStack infrastructure.

# Installation/testing

```bash
git clone git@github.com:hubblestack/hubble
cd hubble
python setup.py clean && python setup.py install
hubble
```

Note that you sometimes have to run the setup.py line twice if you see an error
like this one:

```
zipimport.ZipImportError: bad local file header in /usr/lib/python2.7/site-packages/hubblestack-2.0-py2.7.egg
```

You can do `hubble -h` to see the available options. Here's a sample working
config you can place in `/etc/hubble/hubble`. Note that you'll need to install
python-pygit2 to get gitfs working:

```
gitfs_remotes:
  - https://github.com/hubblestack/hubble.git:
fileserver_backend:
  - roots
  - git
```

## Single invocation

Hubble supports one-off invocations of specific functions:

```
[root@host1 hubble-v2]# hubble nova.audit cis.centos-7-level-1-scored-v2-1-0 tags=CIS-3.\*
{'Compliance': '45%',
 'Failure': [{'CIS-3.4.2': 'Ensure /etc/hosts.allow is configured'},
             {'CIS-3.4.3': 'Ensure /etc/hosts.deny is configured'},
             {'CIS-3.6.2': 'Ensure default deny firewall policy'},
             {'CIS-3.6.3': 'Ensure loopback traffic is configured'},
             {'CIS-3.6.1_running': 'Ensure iptables is installed'},
             {'CIS-3.2.4': 'Ensure suspicious packets are logged'},
             {'CIS-3.2.2': 'Ensure ICMP redirects are not accepted'},
             {'CIS-3.2.3': 'Ensure secure ICMP redirects are not accepted'},
             {'CIS-3.1.2': 'Ensure packet redirect sending is disabled'},
             {'CIS-3.3.1': 'Ensure IPv6 router advertisements are not accepted'},
             {'CIS-3.3.2': 'Ensure IPv6 redirects are not accepted'}],
 'Success': [{'CIS-3.6.1_installed': 'Ensure iptables is installed'},
             {'CIS-3.4.1': 'Ensure TCP Wrappers is installed'},
             {'CIS-3.4.5': 'Ensure permissions on /etc/hosts.deny are 644'},
             {'CIS-3.4.4': 'Ensure permissions on /etc/hosts.allow are configured'},
             {'CIS-3.2.5': 'Ensure broadcast ICMP requests are ignored'},
             {'CIS-3.2.6': None},
             {'CIS-3.2.1': 'Ensure source routed packets are not accepted'},
             {'CIS-3.1.1': 'Ensure IP forwarding is disabled'},
             {'CIS-3.2.8': 'Ensure TCP SYN Cookies is enabled'}]}
```

## Scheduler

Hubble supports scheduled jobs. See the docstring for `schedule` for
more information, but it follows the basic structure of salt scheduled jobs.
The schedule config should be placed in `/etc/hubble/hubble` along with any
other hubble config:

```
schedule:
  job1:
    function: hubble.audit
    seconds: 60
    splay: 30
    args:
      - cis.centos-7-level-1-scored-v2-1-0
    kwargs:
      verbose: True
      show_profile: True
    returner: splunk_nova_return
    run_on_start: True
```

Note that you need to have your splunk_nova_return configured in order to use
the above block:

```
hubblestack:
  nova:
    returner:
      splunk:
        token: <token>
        indexer: <hec endpoint>
        sourcetype: hubble_audit
        index: <index>
```
