Insights and Data Gathering (Nebula)
====================================

Hubble can gather incredible amounts of raw data from your hosts for later
analysis. The codename for the insights piece of hubble is Nebula. It primarily
uses `osquery <https://osquery.io>`_ which allows you to query your system as
if it were a database.

Module Documentation
--------------------

:doc:`modules/nebula_osquery`

Usage
-----

Nebula queries are formatted into query groups which allow you to schedule
sets of queries to run at different cadences. The names of these groups are
arbitrary, but the queries provided in `hubblestack_data`_ are grouped by
timing::

    fifteen_min:
      running_procs:
        query: SELECT t.unix_time AS query_time, p.name AS process, p.pid AS process_id, p.pgroup AS process_group, p.cmdline, p.cwd, p.on_disk, p.resident_size AS mem_used, p.user_time, p.system_time, (SELECT strftime('%s','now')-ut.total_seconds+p.start_time FROM uptime AS ut) AS process_start_time, p.parent, pp.name AS parent_name, g.groupname AS 'group', g.gid AS group_id, u.username AS user, u.uid AS user_id, eu.username AS effective_username, eg.groupname AS effective_groupname, p.path, h.md5 AS md5, h.sha1 AS sha1, h.sha256 AS sha256, '__JSONIFY__'||(SELECT json_group_array(json_object('fd',pof.fd, 'path',pof.path)) FROM process_open_files AS pof WHERE pof.pid=p.pid GROUP BY pof.pid) AS open_files, '__JSONIFY__'||(SELECT json_group_array(json_object('variable_name',pe.key, 'value',pe.value)) FROM process_envs AS pe WHERE pe.pid=p.pid GROUP BY pe.pid) AS environment FROM processes AS p LEFT JOIN processes AS pp ON p.parent=pp.pid LEFT JOIN users AS u ON p.uid=u.uid LEFT JOIN users AS eu ON p.euid=eu.uid LEFT JOIN groups AS g ON p.gid=g.gid LEFT JOIN groups AS eg ON p.gid=eg.gid LEFT JOIN hash AS h ON p.path=h.path LEFT JOIN time AS t WHERE p.parent IS NOT 2 AND (process NOTNULL OR p.parent NOTNULL);
      established_outbound:
        query: SELECT t.unix_time AS query_time, CASE pos.family WHEN 2 THEN 'ipv4' WHEN 10 THEN 'ipv6' ELSE pos.family END AS family, h.md5 AS md5, h.sha1 AS sha1, h.sha256 AS sha256, h.directory AS directory, ltrim(pos.local_address, ':f') AS src_connection_ip, pos.local_port AS src_connection_port, pos.remote_port AS dest_connection_port, ltrim(pos.remote_address, ':f') AS dest_connection_ip, p.name AS name, p.pid AS pid, p.parent AS parent_pid, pp.name AS parent_process, p.path AS file_path, f.size AS file_size, p.cmdline AS cmdline, u.uid AS uid, u.username AS username, CASE pos.protocol WHEN 6 THEN 'tcp' WHEN 17 THEN 'udp' ELSE pos.protocol END AS transport FROM process_open_sockets AS pos JOIN processes AS p ON p.pid=pos.pid LEFT JOIN processes AS pp ON p.parent=pp.pid LEFT JOIN users AS u ON p.uid=u.uid LEFT JOIN time AS t LEFT JOIN hash AS h ON h.path=p.path LEFT JOIN file AS f ON f.path=p.path WHERE NOT pos.remote_address='' AND NOT pos.remote_address='::' AND NOT pos.remote_address='0.0.0.0' AND NOT pos.remote_address='127.0.0.1' AND (pos.local_port,pos.protocol) NOT IN (SELECT lp.port, lp.protocol FROM listening_ports AS lp);
    hour:
      crontab:
        query: SELECT t.unix_time AS query_time, c.event, c.minute, c.hour, c.day_of_month, c.month, c.day_of_week, c.command, c.path AS cron_file FROM crontab AS c JOIN time AS t;
      login_history:
        query: SELECT t.unix_time AS query_time, l.username AS user, l.tty, l.pid, l.type AS utmp_type, CASE l.type WHEN 1 THEN 'RUN_LVL' WHEN 2 THEN 'BOOT_TIME' WHEN 3 THEN 'NEW_TIME' WHEN 4 THEN 'OLD_TIME' WHEN 5 THEN 'INIT_PROCESS' WHEN 6 THEN 'LOGIN_PROCESS' WHEN 7 THEN 'USER_PROCESS' WHEN 8 THEN 'DEAD_PROCESS' ELSE l.type END AS utmp_type_name, l.host AS src, l.time FROM last AS l LEFT JOIN time AS t WHERE l.time > strftime('%s','now') - 3600;
      docker_running_containers:
        query: SELECT t.unix_time AS query_time, dc.id AS container_id, dc.name AS container_name, dc.image AS image_name, di.created AS image_created_time, di.size_bytes AS image_size, di.tags AS image_tags, dc.image_id AS image_id, dc.command AS container_command, dc.created AS container_start_time, dc.state AS container_state, dc.status AS status, '__JSONIFY__'||(SELECT json_group_array(json_object('key',dcl.key, 'value',dcl.value)) FROM docker_container_labels AS dcl WHERE dcl.id=dc.id GROUP BY dcl.id) AS container_labels, '__JSONIFY__'||(SELECT json_group_array(json_object('mount_type',dcm.type, 'mount_name',dcm.name, 'mount_host_path',dcm.source,  'mount_container_path',dcm.destination, 'mount_driver',dcm.driver, 'mount_mode',dcm.mode, 'mount_rw',dcm.rw, 'mount_progpagation',dcm.propagation)) FROM docker_container_mounts AS dcm WHERE dcm.id=dc.id GROUP BY dcm.id) AS container_mounts, '__JSONIFY__'||(SELECT json_group_array(json_object('port_type',dcport.type, 'port',dcport.port, 'host_ip',dcport.host_ip,  'host_port',dcport.host_port)) FROM docker_container_ports AS dcport WHERE dcport.id=dc.id GROUP BY dcport.id) AS container_ports, '__JSONIFY__'||(SELECT json_group_array(json_object('network_name',dcnet.name, 'network_id',dcnet.network_id, 'endpoint_id',dcnet.endpoint_id, 'gateway',dcnet.gateway, 'container_ip',dcnet.ip_address, 'container_ip_prefix_len',dcnet.ip_prefix_len, 'ipv6_gateway',dcnet.ipv6_gateway, 'container_ipv6_address',dcnet.ipv6_address, 'container_ipv6_prefix_len',dcnet.ipv6_prefix_len, 'container_mac_address',dcnet.mac_address)) FROM docker_container_networks AS dcnet WHERE dcnet.id=dc.id GROUP BY dcnet.id) AS container_networks FROM docker_containers AS dc JOIN docker_images AS di ON di.id=dc.image_id LEFT JOIN time AS t;
    day:
      rpm_packages:
        query: SELECT t.unix_time AS query_time, rpm.name, rpm.version, rpm.release, rpm.source AS package_source, rpm.size, rpm.sha1, rpm.arch FROM rpm_packages AS rpm JOIN time AS t;
      os_info:
        query: SELECT t.unix_time AS query_time, os.* FROM os_version AS os LEFT JOIN time AS t;
      interface_addresses:
        query: SELECT t.unix_time AS query_time, ia.interface, ia.address, id.mac FROM interface_addresses AS ia JOIN interface_details AS id ON ia.interface=id.interface LEFT JOIN time AS t WHERE NOT ia.interface='lo';

Nebula query data is very verbose, and is really meant to be sent to a central
aggregation location such as splunk or logstash for further processing.
However, if you would like to run the queries manually you can call the :doc:`nebula
execution module <modules/nebula_osquery>`::

    hubble nebula.queries day
    hubble nebula.queries hour verbose=True

topfiles
--------

Nebula supports organizing query groups across files, and combining/targeting
them via a ``top.nebula`` file (similar to topfiles in SaltStack)::

    nebula:
      - '*':
          - hubblestack_nebula_queries
      - 'G@splunk_index:some_team':
          - some_team

Each entry under ``nebula`` is a SaltStack style `compound match`_ that
describes which hosts should receive the list of queries. All queries are
merged, and conflicts go to the last-defined file.

The files referenced are relative to ``salt://hubblestack_nebula_v2/`` and
leave off the ``.yaml`` extension.

You can also specify an alternate ``top.nebula`` file.

For more details, see the module documentation: :doc:`modules/nebula_osquery`

.. _hubblestack_data: https://github.com/hubblestack/hubblestack_data/blob/develop/hubblestack_nebula_v2/hubblestack_nebula_queries.yaml
.. _compound match: https://docs.saltstack.com/en/latest/topics/targeting/compound.html
