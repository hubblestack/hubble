Table of Contents
=================

   * [HUBBLE](#hubble)
      * [Packaging / Installing](#packaging--installing)
         * [Installing using setup.py](#installing-using-setuppy)
         * [Building standalone packages (CentOS)](#building-standalone-packages-centos)
         * [Building standalone packages (Debian)](#building-standalone-packages-debian)
         * [Buidling Hubble packages through Dockerfile](#buidling-hubble-packages-through-dockerfile)
      * [Nova](#nova)
         * [Usage](#usage)
         * [Configuration](#configuration)
      * [Nebula](#nebula)
         * [Usage](#usage-1)
         * [Configuration](#configuration-1)
      * [Pulsar](#pulsar)
         * [Usage](#usage-2)
         * [Configuration](#configuration-2)
            * [Excluding Paths](#excluding-paths)
            * [Pulsar topfile top.pulsar](#pulsar-topfile-toppulsar)

# HUBBLE

Hubble is a modular, open-source, security & compliance auditing framework which is built on SaltStack. It is alternate version of Hubblestack which can be run without an existing SaltStack infrastructure. Hubble provides on-demand profile-based auditing, real-time security event notifications, alerting and reporting. It also reports the security information to Splunk. This document describes installation, configuration and general use of Hubble.

## Packaging / Installing
### Installing using setup.py
```sh
sudo yum install git -y
git clone https://github.com/hubblestack/hubble
cd hubble
sudo python setup.py install
```
Installs a hubble "binary" into `/usr/bin/`.

A config template has been placed in `/etc/hubble/hubble`. Modify it to your specifications and needs. You can do `hubble -h` to see the available options.

The first two commands you should run to make sure things are set up correctly are `hubble --version` and `hubble test.ping`.

### Buidling Hubble packages through Dockerfile
Dockerfile aims to make building Hubble v2 packages easier. Dockerfiles can be found at `hubblestack/hubble/pkg`. 
To build an image
```sh
1. copy pkg/scripts/pyinstaller-requirements.txt to directory with this Dockerfile
2. docker build -t <image_name> 
```
To run the container
```sh
docker run -it --rm <image_name>
```

## Nova
Nova is Hubble's auditing system.
### Usage
There are four primary functions for Nova module:
- `hubble.sync` : syncs the `hubblestack_nova_profiles/` and `hubblestack_nova/` directories to the host(s).
- `hubble.load` : loads the synced audit hosts and their yaml configuration files.
- `hubble.audit` : audits the minion(s) using the YAML profile(s) you provide as comma-separated arguments. hubble.audit takes two optional arguments. The first is a comma-separated list of paths. These paths can be files or directories within the `hubblestack_nova_profiles` directory. The second argument allows for toggling Nova configuration, such as verbosity, level of detail, etc. If `hubble.audit` is run without targeting any audit configs or directories, it will instead run `hubble.top` with no arguments. `hubble.audit` will return a list of audits which were successful, and a list of audits which failed.
- `hubble.top` : audits the minion(s) using the top.nova configuration.

## Using released packages

Various pre-built packages targeting several popular operating systems can be found under [Releases](/hubblestack/hubble/releases).

# Usage

Here are some example calls for `hubble.audit`:
```sh
# Run the cve scanner and the CIS profile:
hubble hubble.audit cve.scan-v2,cis.centos-7-level-1-scored-v1
# Run hubble.top with the default topfile (top.nova)
hubble hubble.top
# Run all yaml configs and tags under salt://hubblestack_nova_profiles/foo/ and salt://hubblestack_nova_profiles/bar, but only run audits with tags starting with "CIS"
hubble hubble.audit foo,bar tags='CIS*'
```
### Configuration
For Nova module, configurations can be done via Nova topfiles. Nova topfiles look very similar to saltstack topfiles, except the top-level key is always nova, as nova doesn’t have environments.

**hubblestack/hubblestack_data/top.nova**
```sh
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
```
Additionally, all nova topfile matches are compound matches, so you never need to define a match type like you do in saltstack topfiles. Each list item is a string representing the dot-separated location of a yaml file which will be run with `hubble.audit`. You can also specify a tag glob to use as a filter for just that yaml file, using a colon after the yaml file (turning it into a dictionary). See the last two lines in the yaml above for examples.

Examples:
```sh
hubble hubble.top
hubble hubble.top foo/bar/top.nova
hubble hubble.top foo/bar.nova verbose=True
```

In some cases, your organization may want to skip certain audit checks for certain hosts. This is supported via compensating control configuration.

You can skip a check globally by adding a `control: <reason>` key to the check itself. This key should be added at the same level as description and trigger pieces of a check. In this case, the check will never run, and will output under the Controlled results key.

Nova also supports separate control profiles, for more fine-grained control using topfiles. You can use a separate YAML top-level key called control. Generally, you’ll put this top-level key inside of a separate YAML file and only include it in the top-data for the hosts for which it is relevant.

For these separate control configs, the audits will always run, whether they are controlled or not. However, controlled audits which fail will be converted from Failure to Controlled in a post-processing operation.

The control config syntax is as follows:
```sh
control:
  - CIS-2.1.4: This is the reason we control the check
  - some_other_tag:
      reason: This is the reason we control the check
  - a_third_tag_with_no_reason
 ```
Note that providing a reason for the control is optional. Any of the three formats shown in the yaml list above will work.

Once you have your compensating control config, just target the yaml to the hosts you want to control using your topfile. In this case, all the audits will still run, but if any of the controlled checks fail, they will be removed from Failure and added to Controlled, and will be treated as a Success for the purposes of compliance percentage.

## Nebula 
Nebula is Hubble’s Insight system, which ties into osquery, allowing you to query your infrastructure as if it were a database. This system can be used to take scheduled snapshots of your systems.

Nebula leverages the osquery_nebula execution module which requires the osquery binary to be installed. More information about osquery can be found at `https://osquery.io`.

### Usage

Nebula queries have been designed to give detailed insight into system activity. The queries can be found in the following file.

**hubblestack_nebula/hubblestack_nebula_queries.yaml**
```sh
fifteen_min:
  - query_name: running_procs
    query: SELECT p.name AS process, p.pid AS process_id, p.cmdline, p.cwd, p.on_disk, p.resident_size AS mem_used, p.parent, g.groupname, u.username AS user, p.path, h.md5, h.sha1, h.sha256 FROM processes AS p LEFT JOIN users AS u ON p.uid=u.uid LEFT JOIN groups AS g ON p.gid=g.gid LEFT JOIN hash AS h ON p.path=h.path;
  - query_name: established_outbound
    query: SELECT t.iso_8601 AS _time, pos.family, h.*, ltrim(pos.local_address, ':f') AS src, pos.local_port AS src_port, pos.remote_port AS dest_port, ltrim(remote_address, ':f') AS dest, name, p.path AS file_path, cmdline, pos.protocol, lp.protocol FROM process_open_sockets AS pos JOIN processes AS p ON p.pid=pos.pid LEFT JOIN time AS t LEFT JOIN (SELECT * FROM listening_ports) AS lp ON lp.port=pos.local_port AND lp.protocol=pos.protocol LEFT JOIN hash AS h ON h.path=p.path WHERE NOT remote_address='' AND NOT remote_address='::' AND NOT remote_address='0.0.0.0' AND NOT remote_address='127.0.0.1' AND port is NULL;
  - query_name: listening_procs
    query:  SELECT t.iso_8601 AS _time, h.md5 AS md5, p.pid, name, ltrim(address, ':f') AS address, port, p.path AS file_path, cmdline, root, parent FROM listening_ports AS lp LEFT JOIN processes AS p ON lp.pid=p.pid LEFT JOIN time AS t LEFT JOIN hash AS h ON h.path=p.path WHERE NOT address='127.0.0.1';
  - query_name: suid_binaries
    query: SELECT sb.*, t.iso_8601 AS _time FROM suid_bin AS sb JOIN time AS t;
hour:
  - query_name: crontab
    query: SELECT c.*,t.iso_8601 AS _time FROM crontab AS c JOIN time AS t;
day:
  - query_name: rpm_packages
    query: SELECT rpm.name, rpm.version, rpm.release, rpm.source AS package_source, rpm.size, rpm.sha1, rpm.arch, t.iso_8601 FROM rpm_packages AS rpm JOIN time AS t;
```

Nebula query data is best tracked in a central logging or similar system. However, if you would like to run the queries manually you can call the nebula execution module.
```sh
query_group : Group of queries to run
verbose : Defaults to False. If set to True, more information (such as the query which was run) will be included in the result.
```
Examples:
```sh
hubble nebula.queries day
hubble nebula.queries hour [verbose=True]
hubble nebula.queries fifteen-min
```
### Configuration
For Nebula module, configurations can be done via Nebula topfiles. Nebula topfile functionality is similar to Nova topfiles.

**top.nebula topfile**

```sh
nebula:
  '*':
    - hubblestack_nebula_queries
  'sample_team':
    - sample_team_nebula_queries
```
Nebula topfile, `nebula.top` by default has `hubblestack_nebula_queries.yaml` which consists queries as explained in the above usage section and if specific queries are required by teams then those queries can be added in a another yaml file and include it in `nebula.top` topfile. Place this new yaml file at the path `hubblestack/hubblestack_data/hubblestack_nebula`

Examples for running `nebula.top`:
```sh
hubble nebula.top hour
hubble nebula.top foo/bar/top.nova hour
hubble nebula.top fifteen_min verbose=True
```
## Pulsar

Pulsar is designed to monitor for file system events, acting as a real-time File Integrity Monitoring (FIM) agent. Pulsar is composed of a custom Salt beacon that watches for these events and hooks into the returner system for alerting and reporting. In other words, you can recieve real-time alerts for unscheduled file system modifications anywhere you want to recieve them. We’ve designed Pulsar to be lightweight and does not affect the system performance. It simply watches for events and directly sends them to one of the Pulsar returner destinations.

### Usage
Once Pulsar is configured there isn’t anything you need to do to interact with it. It simply runs quietly in the background and sends you alerts.

### Configuration
The Pulsar configuration can be found at `hubblestack_pulsar_config.yaml` file. Every environment will have different needs and requirements, and we understand that, so we’ve designed Pulsar to be flexible.

**hubblestack_pulsar_config.yaml**
```sh
/etc: { recurse: True, auto_add: True }
/bin: { recurse: True, auto_add: True }
/sbin: { recurse: True, auto_add: True }
/boot: { recurse: True, auto_add: True }
/usr/bin: { recurse: True, auto_add: True }
/usr/sbin: { recurse: True, auto_add: True }
/usr/local/bin: { recurse: True, auto_add: True }
/usr/local/sbin: { recurse: True, auto_add: True }
return: slack_pulsar
checksum: sha256
stats: True
batch: False
```

Pulsar runs on schdule which can be found at `/etc/hubble/hubble`

**/etc/hubble/hubble**
```sh
schedule:
  pulsar:
    function: pulsar.process
    seconds: 1
    returner: splunk_pulsar_return
    run_on_start: True
  pulsar_canary:
    function: pulsar.canary
    seconds: 86400
  job1:
    function: hubble.audit
    seconds: 60
    splay: 30
    args:
      - cis.centos-7-level-1-scored-v2-1-0
    kwargs:
      verbose: True
    returner: splunk_nova_return
    run_on_start: True
```

In order to receive Pulsar notifications you’ll need to install the custom returners found in the Quasar repository. 

Example of using the Slack Pulsar returner to recieve FIM notifications:
```sh
slack_pulsar:
  as_user: true
  username: calculon
  channel: channel
  api_key: xoxb-xxxxxxxxxxx-xxxxxxxxxxxxxxxxxxxxxxxx
```
#### Excluding Paths
There may be certain paths that you want to exclude from this real-time FIM tool. This can be done using the exclude: keyword beneath any defined path in `hubblestack_pulsar_config.yaml` file.

/var:
  recurse: True
  auto_add: True
  exclude:
    - /var/log
    - /var/spool
    - /var/cache
    - /var/lock

For Pulsar module, configurations can be done via Pulsar topfiles when teams needs to add specific configurations or exclusions as discussed above.

#### Pulsar topfile `top.pulsar`

For Pulsar module, configurations can be done via Pulsar topfiles

```sh
pulsar:
  '*':
    - hubblestack_pulsar_config
  'sample_team':
    - sample_team_hubblestack_pulsar_config
```
Pulsar topfile by default has 'hubblestack_pulsar_config' which consists of default configurations and if specific configurations are required by teams then those can be added in another yaml file and include it in 'pulsar.top' topfile. Place this new yaml file at the path `hubblestack/hubblestack_data/hubblestack_pulsar`

Examples for running pulsar.top:
```sh
hubble pulsar.top
hubble pulsar.top verbose=True
```
