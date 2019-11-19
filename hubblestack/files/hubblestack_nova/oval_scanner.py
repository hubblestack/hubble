"""
This is a Hubble Nova CVE scanner that uses an OVAL source file.

Written by Wes Miser
Contributions by Michael Robinson and Proofpoint, Inc.

To use this scanner, a yaml file must exist within the
hubblestack_nova_profiles directory, preferably within the cve folder.  The
contents of the file should be as follows (notice everything under oval_scanner
is indented):

oval_scanner:
  opt_baseurl: <valid http/https url>
  opt_remote_sourcefile: <valid source file>
  opt_local_sourcefile: <valid source file residing on the client>
  opt_output_file: <write the vulnerability results to a file on the client>

oval_scanner is the primary key.  Each opt key's value under the primary key
is optional and does not need to be specified.  If opt_baseurl,
opt_remote_sourcefile, and opt_local_sourcefile values are not specified, the
scanner will automatically pull the appropriate OVAL source definition file from
the supported distro's public repository.  opt_local_sourcefile will override
opt_baseurl and opt_remote_sourcefile even if their values are specified.

top.nova must also reference the yaml file.  Note that other CVE scanners
must be disabled or conflicts will ensue.  The contents of top.nova can look as
follows:

nova:
  'G@kernel:Linux and not G@osfinger:*CoreOS*':
    ## - cve.vulners <-- ensure other CVE scanners are not active
    - cve.oval <-- assuming the yaml is oval.yaml in this example

When run, the scanner will parse the source OVAL file into a readable
dictionary, maps OVAL defintions directly to OVAL object and OVAL state
references based on OVAL test reference data of the definition, and then makes
a comparison to the local packages installed on the system to identify potential
vulnerabilities.

This scanner currently only supports the Linux platform.
"""



import xml.etree.ElementTree as ET
import json
import requests
import logging
import salt.utils.platform


def __virtual__():
    return not salt.utils.platform.is_windows() 


def audit(data_list, tags, labels, debug=False, **kwargs):
    """Hubble audit function"""
    ret = {'Success': [], 'Failure': []}
    for profile, data in data_list:
        if 'oval_scanner' in data:
            # Distro facts
            distro_name = __grains__.get('os').lower()
            distro_release = __grains__.get('osmajorrelease')
            distro_codename = __grains__.get('lsb_distrib_codename')
            logging.debug("distro_name: {0}, distro_release: {1}, distro_codename: {2}".format(distro_name, distro_release, distro_codename))
            supported_dist = ('ubuntu', 'debian', 'centos', 'redhat')
            if distro_name not in (supported_dist):
                logging.info('The oval CVE scanner does not currently support {0}'.format(distro_name.capitalize()))
                return ret
            local_pkgs = __salt__['pkg.list_pkgs']()
            # Scanner options
            opt_baseurl = data['oval_scanner']['opt_baseurl']
            opt_remote_sourcefile = data['oval_scanner']['opt_remote_sourcefile']
            opt_local_sourcefile = data['oval_scanner']['opt_local_sourcefile']
            opt_output_file = data['oval_scanner']['opt_output_file']
            # Build report
            source_content = get_source_content(distro_name, distro_release, distro_codename, opt_baseurl, opt_remote_sourcefile, opt_local_sourcefile)
            oval_definition = build_oval(source_content)
            oval_and_maps = map_oval_ids(oval_definition)
            vulns = create_vulns(oval_and_maps)
            report = get_impact_report(vulns, local_pkgs, distro_name)
            # Write report to file if specified
            if opt_output_file:
                write_report_to_file(opt_output_file, report)
            # Return Hubble formatted output
            hubble_out = parse_impact_report(report, local_pkgs, ret)
            return hubble_out
    return ret


def parse_impact_report(report, local_pkgs, hubble_format, impacted_pkgs=[]):
    """Parse into Hubble friendly format"""
    for key, value in report.items():
        pkg_desc = 'Vulnerable Package(s): '
        for pkg in value['installed']:
            pkg_desc += '{0}-{1}, '.format(pkg['name'], pkg['version'])
            if pkg['name'] not in impacted_pkgs:
                impacted_pkgs.append(pkg['name'])
        impact_desc = pkg_desc.strip().rstrip(',')
        impact_data = {'tag': key, 'description': impact_desc, 'detail': value}
        hubble_format['Failure'].append(impact_data)
    sec_pkgs = len(local_pkgs) - len(impacted_pkgs)
    secure_desc = '{0} out of {1}'.format(sec_pkgs, len(local_pkgs))
    secure_data = {'tag': 'Secure Package(s)', 'description': secure_desc}
    hubble_format['Success'].append(secure_data)
    return hubble_format


def write_report_to_file(opt_output_file, report):
    """Write report to local disk"""
    logging.info('Writing CVE data to {0}'.format(opt_output_file))
    with open(opt_output_file, 'w') as outfile:
        outfile.write(json.dumps(report, indent=2, sort_keys=True))


def get_impact_report(vulns, local_pkgs, distro_name):
    """Get impact report"""
    logging.debug('get_impact_report')
    report = build_impact(vulns, local_pkgs, distro_name)
    logging.debug(json.dumps(report, indent=4, sort_keys=True))
    return report


# Build an impact report
def build_impact(vulns, local_pkgs, distro_name, result={}):
    """Build impacts based on pkg comparisons"""
    logging.debug('build_impact')
    for data in vulns.values():
        for pkg in data['pkg']:
            name = pkg['name']
            ver = pkg['version']
            if name in local_pkgs:
                title = data['title']
                cve = data['cve']
                if 'severity' in data:
                  severity = data['severity']
                else:
                  severity = 'N/A'
                if distro_name in ('centos', 'redhat'):
                    advisory = data['rhsa']
                else:
                    if 'advisories' in data:
                      advisory = data['advisories']
                    else:
                      advisory = cve
                impact = get_impact(local_pkgs[name], name, ver, title, cve, advisory, severity)
                if impact:
                    result = build_impact_report(impact)
    return result


def build_impact_report(impact, report={}):
    """Build a report based on impacts"""
    logging.debug('build_impact_report')
    for adv, detail in impact.items():
        if adv not in report:
            report[adv] = {
                'updated_pkg': [],
                'installed': [],
                'severity': detail['severity'],
                'cve': detail['cve'],
                'advisory': detail['advisory']
            }
        report[adv]['updated_pkg'].append(detail['updated_pkg'])
        report[adv]['installed'].append(detail['installed'])
    return report


def get_impact(local_ver, name, ver, title, cve, advisory, severity):
    """Compare local package ver to vulnerability ver in rpm distros"""
    logging.debug('get_rpm_impact')
    impact = {}
    if __salt__['pkg.version_cmp'](ver, local_ver) > 0:
        impact[title] = {
            'updated_pkg': {'name': name, 'version': ver},
            'installed': {'name': name, 'version': local_ver},
            'severity': severity,
            'advisory': advisory,
            'cve': cve
        }
    return impact


# Create vulnerability dictionary
def create_vulns(oval_and_maps, vulns={}):
    """Create vuln dict that maps definitions directly to objects and states"""
    logging.debug('create_vulns')
    id_maps = oval_and_maps[0]
    oval = oval_and_maps[1]
    for definition, data in id_maps.items():
        if definition in oval['definitions']:
            vulns[definition] = oval['definitions'][definition]
            vulns[definition]['pkg'] = []
            vuln_pkg = vulns[definition]['pkg']
            objects = data['objects']
            for obj in objects:
                pkg_group = None
                if 'name' in oval['objects'][obj['object_id']]:
                    name = oval['objects'][obj['object_id']]['name']
                    if name in oval['vars']:
                        pkg_group = oval['vars'][name]['pkg_names']
                else:
                    continue
                if 'version' in oval['states'][obj['state_id']]:
                    version = oval['states'][obj['state_id']]['version']
                else:
                    continue
                if name not in oval['vars']:
                    vuln_pkg.append({'name': name, 'version': version})
                if pkg_group:
                    for pkg in pkg_group:
                        vuln_pkg.append({'name': pkg, 'version': version})
    return vulns


# Map oval definitions to oval objects and states
def map_oval_ids(oval, id_maps={}):
    """For every test, grab only tests with both state and obj references"""
    logging.debug('map_oval_ids')
    for definition, data in oval['definitions'].items():
        id_maps[definition] = {'objects': []}
        objects = id_maps[definition]['objects']
        tests = data['tests']
        for test in tests:
            test_def = oval['tests'][test]
            if 'state_ref' in test_def:
                state_id = test_def['state_ref']
            else:
                continue
            if 'object_ref' in test_def:
                object_id = test_def['object_ref']
            else:
                continue
            objects.append({'object_id': object_id, 'state_id': state_id})
    oval_and_maps = (id_maps, oval)
    return oval_and_maps


# Build oval from source
def build_oval(source_content, oval={}):
    """Build oval dict from ElementTree content"""
    logging.debug('build_oval')
    namespace = {
        'oval': 'http://oval.mitre.org/XMLSchema/oval-definitions-5',
        'linux': 'http://oval.mitre.org/XMLSchema/oval-definitions-5#linux',
        'common': 'http://oval.mitre.org/XMLSchema/oval-common-5'
    }
    root = build_element_tree(source_content)
    oval['generator'] = build_generator(root, namespace)
    oval['definitions'] = build_definitions(root, namespace)
    oval['tests'] = build_tests(root, namespace)
    oval['objects'] = build_objects(root, namespace)
    oval['states'] = build_states(root, namespace)
    oval['vars'] = build_vars(root, namespace)
    return oval


def build_generator(root, namespace, gen={}):
    """Build generator dict from oval source"""
    logging.debug('build_generator')
    generator = root.find('oval:generator', namespace)
    if is_et(generator):
        prod_name = generator.find('common:product_name', namespace)
        prod_version = generator.find('common:product_version', namespace)
        schema_version = generator.find('common:schema_version', namespace)
        timestamp = generator.find('common:timestamp', namespace)
        if is_et(prod_name):
            gen['product_name'] = prod_name.text
        if is_et(prod_version):
            gen['product_version'] = prod_version.text
        if is_et(schema_version):
            gen['schema_version'] = schema_version.text
        if is_et(timestamp):
            gen['timestamp'] = timestamp.text
    return gen


def build_definitions(root, namespace, defs={}):
    """Build element definitions from source into oval dict"""
    logging.debug('build_definitions')
    definitions = root.find('oval:definitions', namespace)
    if is_et(definitions):
        for definition in definitions:
            primary_key = definition.attrib['id']
            metadata = definition.find('oval:metadata', namespace)
            title = metadata.find('oval:title', namespace).text
            defs[primary_key] = {}
            definition_data = defs[primary_key]
            definition_data['title'] = title
            definition_data['cve'] = []
            definition_data['tests'] = []
            references = metadata.findall('oval:reference', namespace)
            for reference in references:
                ref_id = reference.attrib['ref_id']
                ref_url = reference.attrib['ref_url']
                source = reference.attrib['source']
                if source in ('RHSA', 'RHBA', 'RHEA'):
                    definition_data['rhsa'] = {ref_id: ref_url}
                elif source in ('CVE'):
                    definition_data['cve'].append({ref_id: ref_url})
            advisory = metadata.find('oval:advisory', namespace)
            if is_et(advisory):
                severity = advisory.find('oval:severity', namespace).text
                definition_data['severity'] = severity
                adv_refs = advisory.findall('oval:ref', namespace)
                advisories = []
                for ref in adv_refs:
                    advisories.append(ref.text)
                definition_data['advisories'] = advisories
            for criterion in definition.iter():
                if is_et(criterion) and 'test_ref' in criterion.attrib:
                    definition_data['tests'].append(criterion.attrib['test_ref'])
    return defs


def build_tests(root, namespace, tsts={}):
    """Build element tests from source into oval dict"""
    logging.debug('build_tests')
    tests = root.find('oval:tests', namespace)
    if is_et(tests):
        for test in tests:
            primary_key = test.attrib['id']
            comment = test.attrib['comment']
            test_object = test.find('linux:object', namespace)
            test_state = test.find('linux:state', namespace)
            tsts[primary_key] = {}
            test_data = tsts[primary_key]
            test_data['comment'] = comment
            if is_et(test_object) and 'object_ref' in test_object.attrib:
                test_data['object_ref'] = test_object.attrib['object_ref']
            if is_et(test_state) and 'state_ref' in test_state.attrib:
                test_data['state_ref'] = test_state.attrib['state_ref']
    return tsts


def build_objects(root, namespace, objs={}):
    """Build element objects from source into oval dict"""
    logging.debug('build_objects')
    objects = root.find('oval:objects', namespace)
    if is_et(objects):
        for obj in objects:
            primary_key = obj.attrib['id']
            objs[primary_key] = {}
            build_data = objs[primary_key]
            object_name = obj.find('linux:name', namespace)
            if is_et(object_name):
                if object_name.text:
                    name = object_name.text
                elif object_name.attrib['var_ref']:
                    name = object_name.attrib['var_ref']
                build_data['name'] = name
    return objs


def build_states(root, namespace, stes={}):
    """Build element states from source into oval dict"""
    logging.debug('build_states')
    states = root.find('oval:states', namespace)
    if is_et(states):
        for state in states:
            primary_key = state.attrib['id']
            stes[primary_key] = {}
            state_data = stes[primary_key]
            evr = state.find('linux:evr', namespace)
            if is_et(evr):
                state_data['version'] = evr.text
                if 'operation' in evr.attrib:
                    state_data['operation'] = evr.attrib['operation']
    return stes


def build_vars(root, namespace, vrs={}):
    """Build element vars from source into oval dict (aka Ubuntu pkg names)"""
    logging.debug('build_vars')
    vars = root.find('oval:variables', namespace)
    if is_et(vars):
        for vr in vars:
            primary_key = vr.attrib['id']
            vrs[primary_key] = {}
            var_data = vrs[primary_key]
            var_data['pkg_names'] = []
            for names in vr:
                name_elements = names.iter()
                for value in name_elements:
                    var_data['pkg_names'].append(value.text)
    return vrs


def is_et(item):
    """Determine if specific item is a valid ElementTree element"""
    return isinstance(item, ET.Element)


def build_element_tree(source_content):
    """Build an element tree from source content"""
    logging.debug('build_element_tree')
    return ET.fromstring(source_content)


# Get oval source
def get_source_content(distro_name, distro_release, distro_codename, base_url, source_file, local_file=None):
    """Get content from the source"""
    logging.debug('get_source_content')
    if not local_file:
        url = get_definition_source(base_url, source_file, distro_name, distro_release, distro_codename)
        logging.info('Reading remote file: {0}, this could take some time...'.format(url))
        source = requests.get(url).content
        return source
    else:
        logging.info('Found local file: {0}'.format(local_file))
        with open(local_file, 'rb') as f:
            return f.read()


def get_definition_source(base_url, source_file, distro_name, distro_release, distro_codename):
    """Determine the source"""
    logging.debug('get_definition_source')
    if distro_name in ('centos', 'redhat'):
        source = source_file or 'com.redhat.rhsa-RHEL{0}.xml'.format(distro_release)
        base = base_url or 'https://www.redhat.com/security/data/oval/'
    elif distro_name in ('ubuntu'):
        source = source_file or 'com.ubuntu.{0}.cve.oval.xml'.format(distro_codename)
        base = base_url or 'https://people.canonical.com/~ubuntu-security/oval/'
    elif distro_name in ('debian'):
        source = source_file or 'oval-definitions-{0}.xml'.format(distro_codename)
        base = base_url or 'https://www.debian.org/security/oval/'
    url = base + source
    return url
