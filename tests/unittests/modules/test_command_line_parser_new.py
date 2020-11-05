from unittest import TestCase
import pytest

from hubblestack.extmods.hubble_mods import command_line_parser
from hubblestack.utils.hubble_error import HubbleCheckValidationError


class TestCommandLineParser(TestCase):
    """
    Unit tests for command_line_parser module
    """

    def testValidateParams1(self):
        """
        Mandatory param passed. Test should pass
        """
        block_id = "test-1"
        block_dict = {'args':{
            'key_aliases': ['config-file'],
            'delimiter': ' '
        }}
        chain_args = {'result': {
            'cmdline': 'app --config-file=abc test'
        }}
        extra_args = {'chaining_args': chain_args}
        command_line_parser.validate_params(block_id, block_dict, extra_args)

    def testValidateParams2(self):
        """
        Mandatory param name not passed. Test should raise HubbleCheckValidationError
        """
        block_id = "test-1"
        block_dict = {'args':{
        }}
        chain_args = None

        with pytest.raises(HubbleCheckValidationError) as exception:
            command_line_parser.validate_params(block_id, block_dict, chain_args)
            pytest.fail('Should not have passed')
        self.assertTrue('No cmdline provided' in str(exception.value))

    def testFilteredLogs1(self):
        """
        Check filtered logs output
        """
        block_id = "test-1"
        block_dict = {'args':{
            'key_aliases': ['config-file'],
            'delimiter': ' '
        }}
        chain_args = {'result': {
            'cmdline': 'app --config-file=abc test'
        }}
        extra_args = {'chaining_args': chain_args}
        expected_dict = {
            'command_line': 'app --config-file=abc test',
            'key_aliases': ['config-file'],
            'delimiter': ' '
        }
        result = command_line_parser.get_filtered_params_to_log(block_id, block_dict, extra_args)
        self.assertDictEqual(expected_dict, result)

    def testExecute1(self):
        """
        should pass
        """
        block_id = "test-1"
        block_dict = {'args':{
            'key_aliases': ['config-file'],
            'delimiter': '='
        }}
        chain_args = {'result': {
            'cmdline': 'app --config-file=abc test'
        }}
        extra_args = {'chaining_args': chain_args}
        status, result_dict = command_line_parser.execute(block_id, block_dict, extra_args)
        self.assertTrue(status)
        self.assertEqual(result_dict['result'], ['abc'])

    def testExecute2(self):
        """
        Passing cmdline from args
        should pass
        """
        block_id = "test-1"
        block_dict = {'args':{
            'cmdline': 'app --config-file=abc test',
            'key_aliases': ['config-file'],
            'delimiter': '='
        }}
        status, result_dict = command_line_parser.execute(block_id, block_dict)
        self.assertTrue(status)
        self.assertEqual(result_dict['result'], ['abc'])

    def test_match_key_alias_in_middle_of_cmdline(self):
        """
        Key alias is in the middle of commandLine
        Expected Status : True
        """
        command_line = {"cmdline" : "dockerd --config-file=\"/etc/docker/daemon.json\" --log-level=\"debug\""}
        key_aliases = ["config-file"]
        block_id = "test-1"
        block_dict = {'args':{
            'key_aliases': key_aliases,
            'delimiter': '='
        }}
        chain_args = {'result': command_line}
        extra_args = {'chaining_args': chain_args}
        status, val = command_line_parser.execute(block_id, block_dict, extra_args)

        expected_value = ["/etc/docker/daemon.json"]
        assert val['result'] == expected_value

    def test_match_key_alias_at_end_of_cmdline(self):
        """
        Key alias is at the end of commandLine
        Expected Status : True
        """
        command_line = {"cmdline":"dockerd --config-file=\"/etc/docker/daemon.json\" --log-level=\"debug\""}
        key_aliases = ["log-level"]
        params = {
            'key_aliases': key_aliases,
            'delimiter': '='
        }
        block_dict = {'args':params}
        chain_args = {'result': command_line}
        extra_args = {'chaining_args': chain_args}
        status, val = command_line_parser.execute("test-1", block_dict, extra_args)
        expected_value = ["debug"]
        assert val['result'] == expected_value

    def test_key_alias_not_found_in_cmdline(self):
        """
        Key alias is not found in the commandLine
        Expected Status : True
        """
        command_line = {"cmdline":"dockerd --config-file=\"/etc/docker/daemon.json\" --log-level=\"debug\""}
        key_aliases = ["not_found"]
        params = {
            'key_aliases': key_aliases,
            'delimiter': '='
        }
        block_dict = {'args':params}
        chain_args = {'result': command_line}
        extra_args = {'chaining_args': chain_args}
        status, val = command_line_parser.execute("test-1", block_dict, extra_args)
        expected_value = []
        assert val['result'] == expected_value

    def test_multiple_return_values(self):
        """
        commandline has multiple values corresponding to the key
        Expected Status : True
        """
        command_line = {"cmdline" : "docker run -v=\"a:b\" --volume=\"d:e\" --log-level=\"debug\""}
        key_aliases = ["v", "volume"]
        params = {
                'key_aliases': key_aliases,
                'delimiter': '='
                }
        block_dict = {'args':params}
        chain_args = {'result': command_line}
        extra_args = {'chaining_args': chain_args}
        status, val = command_line_parser.execute("test-1", block_dict, extra_args)
        expected_value = ["a:b", "d:e"]
        assert val['result'] == expected_value


    def test_multiple_key_aliases(self):
        """
            result has results for multiple keys
            Expected Status : True
        """
        command_line = {"cmdline":"docker run -v=\"a:b\" -v=\"d:e\" --log-level=\"debug\""}
        key_aliases = ["volume", "v"]
        params = {
            'key_aliases': key_aliases,
            'delimiter': '='
        }
        block_dict = {'args':params}
        chain_args = {'result': command_line}
        extra_args = {'chaining_args': chain_args}
        status, val = command_line_parser.execute("test-1", block_dict, extra_args)
        expected_value = ["a:b", "d:e"]
        assert val['result'] == expected_value


    def test_values_with_single_quotes(self):
        """
            values in command line have single-quotes
            Expected Status : True
        """
        command_line = {"cmdline":"docker run -v=\'a:b\' -v=\'d:e\' --log-level=\'debug\'"}
        key_aliases = ["volume", "v"]
        params = {
            'key_aliases': key_aliases,
            'delimiter': '='
        }
        block_dict = {'args':params}
        chain_args = {'result': command_line}
        extra_args = {'chaining_args': chain_args}
        status, val = command_line_parser.execute("test-1", block_dict, extra_args)
        expected_value = ["a:b", "d:e"]
        assert val['result'][0] == expected_value[0]
        assert val['result'][1] == expected_value[1]


    def test_second_regex(self):
        """
            Match is done through second regex in code
            Expected Status : True
        """
        command_line = {"cmdline" : "docker run -it -v a:b -v d:e"}
        key_aliases = ["volume", "v"]
        params = {
            'key_aliases': key_aliases,
            'delimiter': ' '
        }
        block_dict = {'args':params}
        chain_args = {'result': command_line}
        extra_args = {'chaining_args': chain_args}
        status, val = command_line_parser.execute("test-1", block_dict, extra_args)
        expected_value = ["a:b", "d:e"]
        assert val['result'] == expected_value


    def test_do_not_match_partial_matching_key_alias(self):
        """
            Partial match of key is not done. Here the commandline string is substring of key
            Expected Status : True
        """
        command_line = {"cmdline" : "dockerd --config-file=\"/etc/docker/daemon.json\" --log-level=\"debug\""}
        key_aliases = ["prefix_log-level"]
        params = {
            'key_aliases': key_aliases,
            'delimiter': '='
        }
        block_dict = {'args':params}
        chain_args = {'result': command_line}
        extra_args = {'chaining_args': chain_args}
        status, val = command_line_parser.execute("test-1", block_dict, extra_args)
        expected_value = []
        assert val['result'] == expected_value


    def test_do_not_match_partial_matching_key_alias_short(self):
        """
            Partial match of key is not done. Here the key is substring of commandline string
            Expected Status : True
        """
        command_line = {"cmdline" : "dockerd --config-file=\"/etc/docker/daemon.json\" --log-level=\"debug\""}
        key_aliases = ["level"]
        params = {
            'key_aliases': key_aliases,
            'delimiter': '='
        }
        block_dict = {'args':params}
        chain_args = {'result': command_line}
        extra_args = {'chaining_args': chain_args}
        status, val = command_line_parser.execute("test-1", block_dict, extra_args)
        expected_value = []
        assert val['result'] == expected_value


    def test_curl_example(self):
        """
            Test performed on curl syntax
            Expected Status : True
        """
        command_line = {"cmdline" : "curl -X POST http://www.yourwebsite.com/login/ -d 'username=yourusername&password=yourpassword'"}
        key_aliases = ["d"]
        params = {
            'key_aliases': key_aliases,
            'delimiter': ' '
        }
        block_dict = {'args':params}
        chain_args = {'result': command_line}
        extra_args = {'chaining_args': chain_args}
        status, val = command_line_parser.execute("test-1", block_dict, extra_args)
        expected_value = ["username=yourusername&password=yourpassword"]
        assert val['result'] == expected_value


    def test_curl_example_different_position(self):
        """
            Test performed on curl syntax. Tweaking commandline
            Expected Status : True
        """
        command_line = {"cmdline" : "curl -X POST -d 'username=yourusername&password=yourpassword' http://www.yourwebsite.com/login/"}
        key_aliases = ["d"]
        params = {
            'key_aliases': key_aliases,
            'delimiter': ' '
        }
        block_dict = {'args':params}
        chain_args = {'result': command_line}
        extra_args = {'chaining_args': chain_args}
        status, val = command_line_parser.execute("test-1", block_dict, extra_args)
        expected_value = ["username=yourusername&password=yourpassword"]
        assert val['result'] == expected_value


    def test_curl_quote_in_value(self):
        """
            The value has a single quote and must be present in final result.
            Expected Status : True
        """
        command_line = {"cmdline" : "curl -X POST -d \"username=your'susername&password=yourpassword\" http://www.yourwebsite.com/login/"}
        key_aliases = ["d"]
        params = {
            'key_aliases': key_aliases,
            'delimiter': ' '
        }
        block_dict = {'args':params}
        chain_args = {'result': command_line}
        extra_args = {'chaining_args': chain_args}
        status, val = command_line_parser.execute("test-1", block_dict, extra_args)
        expected_value = ["username=your'susername&password=yourpassword"]
        assert val['result'] == expected_value


    def test_with_special_chars_in_value(self):
        """
            Test done with header value in Curl
            Expected Status : True
        """
        command_line = {"cmdline" : "curl -H \"X-Header: value\" https://www.keycdn.com"}
        key_aliases = ["-H"]
        params = {
            'key_aliases': key_aliases,
            'delimiter': ' '
        }
        block_dict = {'args':params}
        chain_args = {'result': command_line}
        extra_args = {'chaining_args': chain_args}
        status, val = command_line_parser.execute("test-1", block_dict, extra_args)
        expected_value = ["X-Header: value"]
        assert val['result'] == expected_value


    def test_key_alias_with_space(self):
        """
        Key alias has spaces
        Expected Status : True
        """
        command_line = {"cmdline" : "docker network inspect 9f9408b2d29e"}
        key_aliases = ["network inspect"]
        params = {
            'key_aliases': key_aliases,
            'delimiter': ' '
        }
        block_dict = {'args':params}
        chain_args = {'result': command_line}
        extra_args = {'chaining_args': chain_args}
        status, val = command_line_parser.execute("test-1", block_dict, extra_args)
        expected_value = ["9f9408b2d29e"]
        assert val['result'] == expected_value


    def test_long_option_with_complex_value(self):
        """
        value has special chars
        Expected Status : True
        """
        command_line = {"cmdline" : "docker run --cidfile /tmp/docker_test.cid ubuntu echo \"test\""}
        key_aliases = ["cidfile"]
        params = {
            'key_aliases': key_aliases,
            'delimiter': ' '
        }
        block_dict = {'args':params}
        chain_args = {'result': command_line}
        extra_args = {'chaining_args': chain_args}
        status, val = command_line_parser.execute("test-1", block_dict, extra_args)
        expected_value = ["/tmp/docker_test.cid"]
        assert val['result'] == expected_value


    def test_value_with_assignment_operator(self):
        """
        Value has assignment operator.
        Expected Status : True
        """
        command_line = {"cmdline" : "docker run -it --storage-opt size=120G fedora /bin/bash"}
        key_aliases = ["storage-opt"]
        params = {
            'key_aliases': key_aliases,
            'delimiter': ' '
        }
        block_dict = {'args':params}
        chain_args = {'result': command_line}
        extra_args = {'chaining_args': chain_args}
        status, val = command_line_parser.execute("test-1", block_dict, extra_args)
        expected_value = ["size=120G"]
        assert val['result'] == expected_value


    def test_value_is_a_list(self):
        """
        Value is a list
        Expected Status : True
        """
        command_line = {"cmdline" : "tool_name --key:[\"value1\", \"value2\"]"}
        key_aliases = ["key"]
        params = {
            'key_aliases': key_aliases,
            'delimiter': ':'
        }
        block_dict = {'args':params}
        chain_args = {'result': command_line}
        extra_args = {'chaining_args': chain_args}
        status, val = command_line_parser.execute("test-1", block_dict, extra_args)
        expected_value = ["[\"value1\", \"value2\"]"]
        assert val['result'] == expected_value


    def test_java_example1(self):
        """
        Test done on java syntax.
        Expected Status : True
        """
        command_line = {"cmdline" : "nlserver watchdog -svc -noconsole -pidfile:/var/run/nlserver6.pid"}
        key_aliases = ["pidfile"]
        params = {
            'key_aliases': key_aliases,
            'delimiter': ':'
        }
        block_dict = {'args':params}
        chain_args = {'result': command_line}
        extra_args = {'chaining_args': chain_args}
        status, val = command_line_parser.execute("test-1", block_dict, extra_args)
        expected_value = ["/var/run/nlserver6.pid"]
        assert val['result'] == expected_value


    def test_java_example2(self):
        """
        Test done on java syntax. Key has colon.
        Expected Status : True
        """
        command_line = {"cmdline" : "/etc/alternatives/jre/bin/java -Xmx1024m -XX:OnOutOfMemoryError=kill -9 %p -XX:MinHeapFreeRatio=10 -server " \
                    "-cp /usr/share/aws/emr/instance-controller/lib/*:/home/hadoop/conf -Dlog4j.defaultInitOverride aws157.instancecontroller.Main"}
        key_aliases = ["XX:MinHeapFreeRatio"]
        params = {
            'key_aliases': key_aliases,
            'delimiter': '='
        }
        block_dict = {'args':params}
        chain_args = {'result': command_line}
        extra_args = {'chaining_args': chain_args}
        status, val = command_line_parser.execute("test-1", block_dict, extra_args)
        expected_value = ["10"]
        assert val['result'] == expected_value


    def test_java_example3(self):
        """
        Test done on java syntax. Value has assignment operator
        Expected Status : True
        """
        command_line = {"cmdline" : "/apps/api-etms/jdk1.8.0_241/bin/java -XX:PermSize=128m -XX:MaxPermSize=256m -jar /apps/api-etms/usage-tracking-services-launchpad.jar"}
        key_aliases = ["XX:PermSize"]
        params = {
            'key_aliases': key_aliases,
            'delimiter': '='
        }
        block_dict = {'args':params}
        chain_args = {'result': command_line}
        extra_args = {'chaining_args': chain_args}
        status, val = command_line_parser.execute("test-1", block_dict, extra_args)
        expected_value = ["128m"]
        assert val['result'] == expected_value


    def test_java_example4(self):
        """
        Test done on java syntax. value has extension
        Expected Status : True
        """
        command_line = {"cmdline" : "/apps/api-etms/jdk1.8.0_241/bin/java -XX:PermSize=128m -XX:MaxPermSize=256m -jar /apps/api-etms/usage-tracking-services-launchpad.jar"}
        key_aliases = ["jar"]
        params = {
            'key_aliases': key_aliases,
            'delimiter': ' '
        }
        block_dict = {'args':params}
        chain_args = {'result': command_line}
        extra_args = {'chaining_args': chain_args}
        status, val = command_line_parser.execute("test-1", block_dict, extra_args)
        expected_value = ["/apps/api-etms/usage-tracking-services-launchpad.jar"]
        assert val['result'] == expected_value


    def test_java_example5(self):
        """
        Test done on java syntax. commandline has many other similar key value pairs.
        Expected Status : True
        """
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
        block_dict = {'args':params}
        chain_args = {'result': command_line}
        extra_args = {'chaining_args': chain_args}
        status, val = command_line_parser.execute("test-1", block_dict, extra_args)
        expected_value = ["2048"]
        assert val['result'] == expected_value


    def test_value_with_multiple_special_chars(self):
        """
        Value has word separator (comma)
        Expected Status : True
        """
        command_line = {"cmdline" : "docker run -d --tmpfs /run:rw,noexec,nosuid,size=65536k my_image"}
        key_aliases = ["tmpfs"]
        params = {
            'key_aliases': key_aliases,
            'delimiter': ' '
        }
        block_dict = {'args':params}
        chain_args = {'result': command_line}
        extra_args = {'chaining_args': chain_args}
        status, val = command_line_parser.execute("test-1", block_dict, extra_args)
        expected_value = ["/run:rw,noexec,nosuid,size=65536k"]
        assert val['result'] == expected_value


    def test_key_value_inside_dict(self):
        """
        key value pair is inside a dict
        Expected Status : True
        """
        command_line = {"cmdline" : "tool_name --key={\"subkey1\":\"value1\", \"subkey2\":\"value2\"}"}
        key_aliases = ["subkey1"]
        params = {
            'key_aliases': key_aliases,
            'delimiter': ':'
        }
        block_dict = {'args':params}
        chain_args = {'result': command_line}
        extra_args = {'chaining_args': chain_args}
        status, val = command_line_parser.execute("test-1", block_dict, extra_args)
        expected_value = ["value1"]
        assert val['result'] == expected_value


    def test_value_with_special_char(self):
        """
        value is a URL
        Expected Status : True
        """
        command_line = {"cmdline" : "/configmap-reload --volume-dir=/etc/prometheus --webhook-url=http://localhost:9090/-/reload"}
        key_aliases = ["webhook-url"]
        params = {
            'key_aliases': key_aliases,
            'delimiter': '='
        }
        block_dict = {'args':params}
        chain_args = {'result': command_line}
        extra_args = {'chaining_args': chain_args}
        status, val = command_line_parser.execute("test-1", block_dict, extra_args)
        expected_value = ["http://localhost:9090/-/reload"]
        assert val['result'] == expected_value


    def test_value_with_brackets(self):
        """
        Value is a dict
        Expected Status : True
        """
        command_line = {"cmdline" : 'mesos-journald-logger --journald_labels={"labels":[{"key":"DCOS_PACKAGE_IS_FRAMEWORK","value":"false"}]} --logrotate_max_size={"size":"50MB"}'}
        key_aliases = ["journald_labels"]
        params = {
            'key_aliases': key_aliases,
            'delimiter': '='
        }
        block_dict = {'args':params}
        chain_args = {'result': command_line}
        extra_args = {'chaining_args': chain_args}
        status, val = command_line_parser.execute("test-1", block_dict, extra_args)
        expected_value = ['{"labels":[{"key":"DCOS_PACKAGE_IS_FRAMEWORK","value":"false"}]}']
        assert val['result'] == expected_value


    def test_value_has_regex(self):
        """
        Value is a regex
        Expected Status : True
        """
        command_line = {"cmdline" : '/bin/node_exporter --collector.diskstats.ignored-devices=^(dm-\d+|ram|loop|fd|(h|s|v|xv)d[a-z]|nvme\d+n\d+p)\d+$'}
        key_aliases = ["collector.diskstats.ignored-devices"]
        params = {
            'key_aliases': key_aliases,
            'delimiter': '='
        }
        block_dict = {'args':params}
        chain_args = {'result': command_line}
        extra_args = {'chaining_args': chain_args}
        status, val = command_line_parser.execute("test-1", block_dict, extra_args)
        expected_value = ['^(dm-\d+|ram|loop|fd|(h|s|v|xv)d[a-z]|nvme\d+n\d+p)\d+$']
        assert val['result'] == expected_value


    def test_value_has_regex2(self):
        """
        Value is a regex (test2)
        Expected Status : True
        """
        command_line = {"cmdline" : "/bin/sh -c nice -n 15 ionice -c2 -n7 clamscan -r -d /var/lib/clamav --infected --exclude-dir='^/proc|^/sys|^/dev|^/mnt|^/export|^/var/lib/mysql|^/volr' / > /var/log/clamav/clamscan.log"}
        key_aliases = ["exclude-dir"]
        params = {
            'key_aliases': key_aliases,
            'delimiter': '='
        }
        block_dict = {'args':params}
        chain_args = {'result': command_line}
        extra_args = {'chaining_args': chain_args}
        status, val = command_line_parser.execute("test-1", block_dict, extra_args)
        expected_value = ['^/proc|^/sys|^/dev|^/mnt|^/export|^/var/lib/mysql|^/volr']
        assert val['result'] == expected_value


    def test_fetch_bracketed_value(self):
        """
            fetch_bracketed_value function is tested against a positive value.
        """
        value = "[dummy]"
        val = command_line_parser._fetch_bracketed_value(value)
        expected_value = ('[dummy]')
        assert val == expected_value

    def test_no_keys_given(self):
        """
        Keys are not given
        Expected Status : False
        """
        command_line = {"cmdline" : ""}
        params = {
            'key_aliases': '',
            'delimiter': '='
        }
        block_dict = {'args':params}
        chain_args = {'result': command_line}
        extra_args = {'chaining_args': chain_args}
        status, val = command_line_parser.execute("test-1", block_dict, extra_args)
        assert val['result'] == []

    def test_extra_spaces(self):
        """
        Extra spaces present between key value
        Expected Status : True
        """
        command_line = {"cmdline" : "docker run -v        a:b"}
        key_aliases = ["v"]
        params = {
            'key_aliases': key_aliases,
            'delimiter': ' '
        }
        block_dict = {'args':params}
        chain_args = {'result': command_line}
        extra_args = {'chaining_args': chain_args}
        status, val = command_line_parser.execute("test-1", block_dict, extra_args)
        expected_value = [('a:b')]
        assert val['result'] == expected_value


    def test_extra_spaces_different_delimiter(self):
        """
        Extra spaces present between key value
        Expected Status : True
        """
        command_line = {"cmdline" : "docker run -v    =     a:b"}
        key_aliases = ["v"]
        params = {
            'key_aliases': key_aliases,
            'delimiter': '='
        }
        block_dict = {'args':params}
        chain_args = {'result': command_line}
        extra_args = {'chaining_args': chain_args}
        status, val = command_line_parser.execute("test-1", block_dict, extra_args)
        expected_value = [('a:b')]
        assert val['result'] == expected_value
