import hubblestack.extmods.fdg.command_line_parser as command_line_parser
import logging

log = logging.getLogger(__name__)


def test_match_key_alias_in_middle_of_cmdline():
    """
    Key alias is in the middle of commandLine
    Expected Status : True
    """
    log.info("Executing test_match_key_alias_in_middle_of_cmdline")
    command_line = {"cmdline" : "dockerd --config-file=\"/etc/docker/daemon.json\" --log-level=\"debug\""}
    key_aliases = ["config-file"]
    params = {
        'key_aliases': key_aliases,
        'delimiter': '='
    }
    val = command_line_parser.parse_cmdline(params=params, chained=command_line)
    log.debug("return value is %s", val)
    expected_value = (True, ["/etc/docker/daemon.json"])
    assert val == expected_value


def test_match_key_alias_at_end_of_cmdline():
    """
        Key alias is at the end of commandLine
        Expected Status : True
    """
    log.info("Executing test_match_key_alias_at_end_of_cmdline")
    command_line = {"cmdline":"dockerd --config-file=\"/etc/docker/daemon.json\" --log-level=\"debug\""}
    key_aliases = ["log-level"]
    params = {
        'key_aliases': key_aliases,
        'delimiter': '='
    }
    val = command_line_parser.parse_cmdline(params=params, chained=command_line)
    log.debug("return value is %s", val)
    expected_value = (True, ["debug"])
    assert val == expected_value


def test_key_alias_not_found_in_cmdline():
    """
        Key alias is not found in the commandLine
        Expected Status : True
    """
    log.info("Executing test_key_alias_not_found_in_cmdline")
    command_line = {"cmdline":"dockerd --config-file=\"/etc/docker/daemon.json\" --log-level=\"debug\""}
    key_aliases = ["not_found"]
    params = {
        'key_aliases': key_aliases,
        'delimiter': '='
    }
    val = command_line_parser.parse_cmdline(params=params, chained=command_line)
    log.debug("return value is %s", val)
    expected_value = (True, [])
    assert val == expected_value


def test_multiple_return_values():
    """
        commandline has multiple values corresponding to the key
        Expected Status : True
    """
    log.info("Executing test_multiple_return_values")
    command_line = {"cmdline" : "docker run -v=\"a:b\" --volume=\"d:e\" --log-level=\"debug\""}
    key_aliases = ["v", "volume"]
    params = {
              'key_aliases': key_aliases,
              'delimiter': '='
              }
    val = command_line_parser.parse_cmdline(params = params, chained=command_line)
    log.debug("return value is %s", val)
    expected_value = (True, ["a:b", "d:e"])
    assert val == expected_value


def test_multiple_key_aliases():
    """
        result has results for multiple keys
        Expected Status : True
    """
    log.info("Executing test_multiple_key_aliases")
    command_line = {"cmdline":"docker run -v=\"a:b\" -v=\"d:e\" --log-level=\"debug\""}
    key_aliases = ["volume", "v"]
    params = {
        'key_aliases': key_aliases,
        'delimiter': '='
    }
    val = command_line_parser.parse_cmdline(params=params, chained=command_line)
    log.debug("return value is %s", val)
    expected_value = (True, ["a:b", "d:e"])
    assert val == expected_value


def test_values_with_single_quotes():
    """
        values in command line have single-quotes
        Expected Status : True
    """
    log.info("Executing test_values_with_single_quotes")
    command_line = {"cmdline":"docker run -v=\'a:b\' -v=\'d:e\' --log-level=\'debug\'"}
    key_aliases = ["volume", "v"]
    params = {
        'key_aliases': key_aliases,
        'delimiter': '='
    }
    val = command_line_parser.parse_cmdline(params=params, chained=command_line)
    log.debug("return value is %s", val)
    expected_value = (True, ["a:b", "d:e"])
    assert val[0] == expected_value[0]
    assert val[1] == expected_value[1]


def test_second_regex():
    """
        Match is done through second regex in code
        Expected Status : True
    """
    log.info("Executing test_second_regex")
    command_line = {"cmdline" : "docker run -it -v a:b -v d:e"}
    key_aliases = ["volume", "v"]
    params = {
        'key_aliases': key_aliases,
        'delimiter': ' '
    }
    val = command_line_parser.parse_cmdline(params=params, chained=command_line)
    log.debug("return value is %s", val)
    expected_value = (True, ["a:b", "d:e"])
    assert val == expected_value


def test_do_not_match_partial_matching_key_alias():
    """
        Partial match of key is not done. Here the commandline string is substring of key
        Expected Status : True
    """
    log.info("Executing test_do_not_match_partial_matching_key_alias")
    command_line = {"cmdline" : "dockerd --config-file=\"/etc/docker/daemon.json\" --log-level=\"debug\""}
    key_aliases = ["prefix_log-level"]
    params = {
        'key_aliases': key_aliases,
        'delimiter': '='
    }
    val = command_line_parser.parse_cmdline(params=params, chained=command_line)
    log.debug("return value is %s", val)
    expected_value = (True, [])
    assert val == expected_value


def test_do_not_match_partial_matching_key_alias_short():
    """
        Partial match of key is not done. Here the key is substring of commandline string
        Expected Status : True
    """
    log.info("Executing test_do_not_match_partial_matching_key_alias")
    command_line = {"cmdline" : "dockerd --config-file=\"/etc/docker/daemon.json\" --log-level=\"debug\""}
    key_aliases = ["level"]
    params = {
        'key_aliases': key_aliases,
        'delimiter': '='
    }
    val = command_line_parser.parse_cmdline(params=params, chained=command_line)
    log.debug("return value is %s", val)
    expected_value = (True, [])
    assert val == expected_value


def test_curl_example():
    """
        Test performed on curl syntax
        Expected Status : True
    """
    log.info("Executing test_curl_example")
    command_line = {"cmdline" : "curl -X POST http://www.yourwebsite.com/login/ -d 'username=yourusername&password=yourpassword'"}
    key_aliases = ["d"]
    params = {
        'key_aliases': key_aliases,
        'delimiter': ' '
    }
    val = command_line_parser.parse_cmdline(params=params, chained=command_line)
    log.debug("return value is %s", val)
    expected_value = (True, ["username=yourusername&password=yourpassword"])
    assert val == expected_value


def test_curl_example_different_position():
    """
        Test performed on curl syntax. Tweaking commandline
        Expected Status : True
    """
    log.info("Executing test_curl_example")
    command_line = {"cmdline" : "curl -X POST -d 'username=yourusername&password=yourpassword' http://www.yourwebsite.com/login/"}
    key_aliases = ["d"]
    params = {
        'key_aliases': key_aliases,
        'delimiter': ' '
    }
    val = command_line_parser.parse_cmdline(params=params, chained=command_line)
    log.debug("return value is %s", val)
    expected_value = (True, ["username=yourusername&password=yourpassword"])
    assert val == expected_value


def test_curl_quote_in_value():
    """
        The value has a single quote and must be present in final result.
        Expected Status : True
    """
    log.info("Executing test_curl_example")
    command_line = {"cmdline" : "curl -X POST -d \"username=your'susername&password=yourpassword\" http://www.yourwebsite.com/login/"}
    key_aliases = ["d"]
    params = {
        'key_aliases': key_aliases,
        'delimiter': ' '
    }
    val = command_line_parser.parse_cmdline(params=params, chained=command_line)
    log.debug("return value is %s", val)
    expected_value = (True, ["username=your'susername&password=yourpassword"])
    assert val == expected_value


def test_with_special_chars_in_value():
    """
        Test done with header value in Curl
        Expected Status : True
    """
    log.info("Executing test_curl_example")
    command_line = {"cmdline" : "curl -H \"X-Header: value\" https://www.keycdn.com"}
    key_aliases = ["-H"]
    params = {
        'key_aliases': key_aliases,
        'delimiter': ' '
    }
    val = command_line_parser.parse_cmdline(params=params, chained=command_line)
    log.debug("return value is %s", val)
    expected_value = (True, ["X-Header: value"])
    assert val == expected_value


def test_key_alias_with_space():
    """
        Key alias has spaces
        Expected Status : True
    """
    log.info("Executing test_key_alias_with_space")
    command_line = {"cmdline" : "docker network inspect 9f9408b2d29e"}
    key_aliases = ["network inspect"]
    params = {
        'key_aliases': key_aliases,
        'delimiter': ' '
    }
    val = command_line_parser.parse_cmdline(params=params, chained=command_line)
    log.debug("return value is %s", val)
    expected_value = (True, ["9f9408b2d29e"])
    assert val == expected_value


def test_long_option_with_complex_value():
    """
        value has special chars
        Expected Status : True
    """
    log.info("Executing test_long_option_with_space")
    command_line = {"cmdline" : "docker run --cidfile /tmp/docker_test.cid ubuntu echo \"test\""}
    key_aliases = ["cidfile"]
    params = {
        'key_aliases': key_aliases,
        'delimiter': ' '
    }
    val = command_line_parser.parse_cmdline(params=params, chained=command_line)
    log.debug("return value is %s", val)
    expected_value = (True, ["/tmp/docker_test.cid"])
    assert val == expected_value


def test_value_with_assignment_operator():
    """
        Value has assignment operator.
        Expected Status : True
    """
    log.info("Executing test_value_with_assignment_operator")
    command_line = {"cmdline" : "docker run -it --storage-opt size=120G fedora /bin/bash"}
    key_aliases = ["storage-opt"]
    params = {
        'key_aliases': key_aliases,
        'delimiter': ' '
    }
    val = command_line_parser.parse_cmdline(params=params, chained=command_line)
    log.debug("return value is %s", val)
    expected_value = (True, ["size=120G"])
    assert val == expected_value


def test_value_is_a_list():
    """
        Value is a list
        Expected Status : True
    """
    log.info("Executing test_value_is_a_list")
    command_line = {"cmdline" : "tool_name --key:[\"value1\", \"value2\"]"}
    key_aliases = ["key"]
    params = {
        'key_aliases': key_aliases,
        'delimiter': ':'
    }
    val = command_line_parser.parse_cmdline(params=params, chained=command_line)
    log.debug("return value is %s", val)
    expected_value = (True, ["[\"value1\", \"value2\"]"])
    assert val == expected_value


def test_java_example1():
    """
        Test done on java syntax.
        Expected Status : True
    """
    log.info("Executing test_java_example1")
    command_line = {"cmdline" : "nlserver watchdog -svc -noconsole -pidfile:/var/run/nlserver6.pid"}
    key_aliases = ["pidfile"]
    params = {
        'key_aliases': key_aliases,
        'delimiter': ':'
    }
    val = command_line_parser.parse_cmdline(params=params, chained=command_line)
    log.debug("return value is %s", val)
    expected_value = (True, ["/var/run/nlserver6.pid"])
    assert val == expected_value


def test_java_example2():
    """
        Test done on java syntax. Key has colon.
        Expected Status : True
    """
    log.info("Executing test_java_example2")
    command_line = {"cmdline" : "/etc/alternatives/jre/bin/java -Xmx1024m -XX:OnOutOfMemoryError=kill -9 %p -XX:MinHeapFreeRatio=10 -server " \
                   "-cp /usr/share/aws/emr/instance-controller/lib/*:/home/hadoop/conf -Dlog4j.defaultInitOverride aws157.instancecontroller.Main"}
    key_aliases = ["XX:MinHeapFreeRatio"]
    params = {
        'key_aliases': key_aliases,
        'delimiter': '='
    }
    val = command_line_parser.parse_cmdline(params=params, chained=command_line)
    log.debug("return value is %s", val)
    expected_value = (True, ["10"])
    assert val == expected_value


def test_java_example3():
    """
        Test done on java syntax. Value has assignment operator
        Expected Status : True
    """
    log.info("Executing test_java_example3")
    command_line = {"cmdline" : "/apps/api-etms/jdk1.8.0_241/bin/java -XX:PermSize=128m -XX:MaxPermSize=256m -jar /apps/api-etms/usage-tracking-services-launchpad.jar"}
    key_aliases = ["XX:PermSize"]
    params = {
        'key_aliases': key_aliases,
        'delimiter': '='
    }
    val = command_line_parser.parse_cmdline(params=params, chained=command_line)
    log.debug("return value is %s", val)
    expected_value = (True, ["128m"])
    assert val == expected_value


def test_java_example4():
    """
        Test done on java syntax. value has extension
        Expected Status : True
    """
    log.info("Executing test_java_example4")
    command_line = {"cmdline" : "/apps/api-etms/jdk1.8.0_241/bin/java -XX:PermSize=128m -XX:MaxPermSize=256m -jar /apps/api-etms/usage-tracking-services-launchpad.jar"}
    key_aliases = ["jar"]
    params = {
        'key_aliases': key_aliases,
        'delimiter': ' '
    }
    val = command_line_parser.parse_cmdline(params=params, chained=command_line)
    log.debug("return value is %s", val)
    expected_value = (True, ["/apps/api-etms/usage-tracking-services-launchpad.jar"])
    assert val == expected_value


def test_java_example5():
    """
        Test done on java syntax. commandline has many other similar key value pairs.
        Expected Status : True
    """
    log.info("Executing test_java_example5")
    command_line = {"cmdline" : "/opt/oobe/jdk1.8.0_202/bin/java -Djava.util.logging.config.file=/opt/oobe/oobe-tomcat-9.0.31/conf/logging.properties " \
                   "-Djava.util.logging.manager=org.apache.juli.ClassLoaderLogManager -Djdk.tls.ephemeralDHKeySize=2048 " \
                   "-Djava.protocol.handler.pkgs=org.apache.catalina.webresources -Dorg.apache.catalina.security.SecurityListener.UMASK=0027 " \
                   "-javaagent:/opt/oobe/newrelic-java-5.10.0/newrelic.jar -Xmx10310m -Xms512m -XX:+UseG1GC -XX:+UseStringDeduplication " \
                   "-XX:+HeapDumpOnOutOfMemoryError -XX:HeapDumpPath=/mnt/efs/dumps/i-0b23463e49967f3e4/dumpOnExit.hprof -XX:+UnlockDiagnosticVMOptions " \
                   "-XX:+DebugNonSafepoints -XX:+UnlockCommercialFeatures -XX:+FlightRecorder " \
                   "-XX:FlightRecorderOptions=defaultrecording=true,disk=true,maxage=2h,dumponexit=true," \
                   "dumponexitpath=/mnt/efs/dumps/i-0b23463e49967f3e4/JFRdump.jfr,loglevel=info,repository=/mnt/efs/dumps/i-0b23463e49967f3e4/temp/ " \
                   "-Dcom.sun.management.jmxremote -Dcom.sun.management.jmxremote.port=15000 -Dcom.sun.management.jmxremote.ssl=false " \
                   "-Dcom.sun.management.jmxremote.authenticate=false -Dsun.net.inetaddr.ttl=30 -Dinstance.id=tomcat " \
                   "-Dcom.adobe.ffc.config=/opt/ffc/ffc-package/config/prod -Dcom.adobe.ffc.environment=prod -Dcom.adobe.ffc.scripts=/opt/ffc/ffc-package/scripts " \
                   "-Dserver.log.dir=/opt/oobe/oobe-tomcat-9.0.31/logs -Djboss.server.log.dir=/opt/oobe/oobe-tomcat-9.0.31/logs " \
                   "-Dlog4j.configurationFile=file:///opt/ffc/ffc-package/config/prod/log4j2.xml -DLog4jContextSelector=org.apache.logging.log4j.core.async.AsyncLoggerContextSelector " \
                   "-Dcom.netflix.servo.DefaultMonitorRegistry.registryClass=com.netflix.servo.jmx.JmxMonitorRegistry " \
                   "-Dignore.endorsed.dirs= -classpath /opt/oobe/apache-tomcat-9.0.31/bin/bootstrap.jar:/opt/oobe/apache-tomcat-9.0.31/bin/tomcat-juli.jar " \
                   "-Dcatalina.base=/opt/oobe/oobe-tomcat-9.0.31 -Dcatalina.home=/opt/oobe/apache-tomcat-9.0.31 " \
                   "-Djava.io.tmpdir=/opt/oobe/oobe-tomcat-9.0.31/temp org.apache.catalina.startup.Bootstrap start"}

    key_aliases = ["Djdk.tls.ephemeralDHKeySize"]
    params = {
        'key_aliases': key_aliases,
        'delimiter': '='
    }
    val = command_line_parser.parse_cmdline(params=params, chained=command_line)
    log.debug("return value is %s", val)
    expected_value = (True, ["2048"])
    assert val == expected_value


def test_value_with_multiple_special_chars():
    """
        Value has word separator (comma)
        Expected Status : True
    """
    log.info("Executing test_value_with_multiple_special_chars")
    command_line = {"cmdline" : "docker run -d --tmpfs /run:rw,noexec,nosuid,size=65536k my_image"}
    key_aliases = ["tmpfs"]
    params = {
        'key_aliases': key_aliases,
        'delimiter': ' '
    }
    val = command_line_parser.parse_cmdline(params=params, chained=command_line)
    log.debug("return value is %s", val)
    expected_value = (True, ["/run:rw,noexec,nosuid,size=65536k"])
    assert val == expected_value


def test_key_value_inside_dict():
    """
        key value pair is inside a dict
        Expected Status : True
    """
    log.info("Executing test_key_value_inside_dict")
    command_line = {"cmdline" : "tool_name --key={\"subkey1\":\"value1\", \"subkey2\":\"value2\"}"}
    key_aliases = ["subkey1"]
    params = {
        'key_aliases': key_aliases,
        'delimiter': ':'
    }
    val = command_line_parser.parse_cmdline(params=params, chained=command_line)
    log.debug("return value is %s", val)
    expected_value = (True, ["value1"])
    assert val == expected_value


def test_value_with_special_char():
    """
        value is a URL
        Expected Status : True
    """
    log.info("Executing test_value_with_special_char")
    command_line = {"cmdline" : "/configmap-reload --volume-dir=/etc/prometheus --webhook-url=http://localhost:9090/-/reload"}
    key_aliases = ["webhook-url"]
    params = {
        'key_aliases': key_aliases,
        'delimiter': '='
    }
    val = command_line_parser.parse_cmdline(params=params, chained=command_line)
    log.debug("return value is %s", val)
    expected_value = (True, ["http://localhost:9090/-/reload"])
    assert val == expected_value


def test_value_with_brackets():
    """
        Value is a dict
        Expected Status : True
    """
    log.info("Executing test_value_with_regex")
    command_line = {"cmdline" : 'mesos-journald-logger --journald_labels={"labels":[{"key":"DCOS_PACKAGE_IS_FRAMEWORK","value":"false"}]} --logrotate_max_size={"size":"50MB"}'}
    key_aliases = ["journald_labels"]
    params = {
        'key_aliases': key_aliases,
        'delimiter': '='
    }
    val = command_line_parser.parse_cmdline(params=params, chained=command_line)
    log.debug("return value is %s", val)
    expected_value = (True, ['{"labels":[{"key":"DCOS_PACKAGE_IS_FRAMEWORK","value":"false"}]}'])
    assert val == expected_value


def test_value_has_regex():
    """
        Value is a regex
        Expected Status : True
    """
    log.info("Executing test_value_with_regex")
    command_line = {"cmdline" : '/bin/node_exporter --collector.diskstats.ignored-devices=^(dm-\d+|ram|loop|fd|(h|s|v|xv)d[a-z]|nvme\d+n\d+p)\d+$'}
    key_aliases = ["collector.diskstats.ignored-devices"]
    params = {
        'key_aliases': key_aliases,
        'delimiter': '='
    }
    val = command_line_parser.parse_cmdline(params=params, chained=command_line)
    log.debug("return value is %s", val)
    expected_value = (True, ['^(dm-\d+|ram|loop|fd|(h|s|v|xv)d[a-z]|nvme\d+n\d+p)\d+$'])
    assert val == expected_value


def test_value_has_regex2():
    """
        Value is a regex (test2)
        Expected Status : True
    """
    log.info("Executing test_value_with_regex")
    command_line = {"cmdline" : "/bin/sh -c nice -n 15 ionice -c2 -n7 clamscan -r -d /var/lib/clamav --infected --exclude-dir='^/proc|^/sys|^/dev|^/mnt|^/export|^/var/lib/mysql|^/volr' / > /var/log/clamav/clamscan.log"}
    key_aliases = ["exclude-dir"]
    params = {
        'key_aliases': key_aliases,
        'delimiter': '='
    }
    val = command_line_parser.parse_cmdline(params=params, chained=command_line)
    log.debug("return value is %s", val)
    expected_value = (True, ['^/proc|^/sys|^/dev|^/mnt|^/export|^/var/lib/mysql|^/volr'])
    assert val == expected_value


def test_fetch_bracketed_value():
    """
        fetch_bracketed_value function is tested against a positive value.
    """
    log.info("Executing test_fetch_bracketed_value")
    value = "[dummy]"
    val = command_line_parser._fetch_bracketed_value(value)
    log.debug("return value is %s", val)
    expected_value = ('[dummy]')
    assert val == expected_value


def test_no_params():
    """
        Params are not given
        Expected Status : False
    """
    log.info("Executing test_no_params")
    command_line = {"cmdline" : ""}
    val = command_line_parser.parse_cmdline(params='', chained=command_line)
    log.debug("return value is %s", val)
    assert not val[0]


def test_no_keys_given():
    """
        Keys are not given
        Expected Status : False
    """
    log.info("Executing test_no_keys_given")
    command_line = {"cmdline" : ""}
    params = {
        'key_aliases': '',
        'delimiter': '='
    }
    val = command_line_parser.parse_cmdline(params=params, chained=command_line)
    log.debug("return value is %s", val)
    assert not val[0]


def test_no_chained_value_given():
    """
        chained value is not given
        Expected Status : False
    """
    log.info("Executing test_no_chained_value_given")
    key_aliases = ["exclude-dir"]
    params = {
        'key_aliases': key_aliases,
        'delimiter': '='
    }
    val = command_line_parser.parse_cmdline(params=params, chained='')
    log.debug("return value is %s", val)
    assert not val[0]


def test_wrong_chained_value_format():
    """
        command_line dict has no key 'cmdline'
        Expected Status : False
    """
    log.info("Executing test_wrong_chained_value_format")
    command_line = {"command_line": "docker run -d --tmpfs /run:rw,noexec,nosuid,size=65536k my_image"}
    key_aliases = ["exclude-dir"]
    params = {
        'key_aliases': key_aliases,
        'delimiter': '='
    }
    val = command_line_parser.parse_cmdline(params=params, chained=command_line)
    log.debug("return value is %s", val)
    assert not val[0]


def test_no_delimiter():
    """
        No delimiter given
        Expected Status : False
    """
    log.info("Executing test_match_key_alias_in_middle_of_cmdline")
    command_line = {"cmdline" : "dockerd --config-file=\"/etc/docker/daemon.json\" --log-level=\"debug\""}
    key_aliases = ["config-file"]
    params = {
        'key_aliases': key_aliases
    }
    val = command_line_parser.parse_cmdline(params=params, chained=command_line)
    log.debug("return value is %s", val)
    assert not val[0]


def test_extra_spaces():
    """
        Extra spaces present between key value
        Expected Status : True
    """
    log.info("Executing test_extra_spaces")
    command_line = {"cmdline" : "docker run -v        a:b"}
    key_aliases = ["v"]
    params = {
        'key_aliases': key_aliases,
        'delimiter': ' '
    }
    val = command_line_parser.parse_cmdline(params=params, chained=command_line)
    log.debug("return value is %s", val)
    expected_value = (True, [('a:b')])
    assert val == expected_value


def test_extra_spaces_different_delimiter():
    """
        Extra spaces present between key value
        Expected Status : True
    """
    log.info("Executing test_extra_spaces")
    command_line = {"cmdline" : "docker run -v    =     a:b"}
    key_aliases = ["v"]
    params = {
        'key_aliases': key_aliases,
        'delimiter': '='
    }
    val = command_line_parser.parse_cmdline(params=params, chained=command_line)
    log.debug("return value is %s", val)
    expected_value = (True, [('a:b')])
    assert val == expected_value

