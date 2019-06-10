#!/usr/bin/env python3

'''

This is a standalone oval scanner that can be run on CentOS and Ubuntu systems.

Written by Wes Miser
Contributions by Michael Robinson and Proofpoint, Inc.

By default, unless specified otherwise, the script will pull an oval
definition file from RedHat's or Ubuntu's public repository.

The script will parse the source file into a readable dictionary, maps
defintions directly to object and state references based on test reference data
of the definition, and then makes a comparison to the local packages installed
on the system to identify potential CVEs/RHSAs.

'''

import xml.etree.ElementTree as ET
import subprocess
import re
import json
import requests
import distro
import logging
from argparse import ArgumentParser
from pkg_resources import parse_version


def main():
    '''Main function'''
    parser = ArgumentParser(description='Ubuntu/Centos OVAL Scanner')
    parser.add_argument('--file', '-f', required=False, default=None, help='Read local xml file')
    parser.add_argument('--output', '-o', required=False, default=None, help='Write the report to disk')
    parser.add_argument('--baseurl', '-b', required=False, default=None, help='Base URL to read remote file')
    parser.add_argument('--sourcefile', '-s', required=False, default=None, help='Name of file at remote url')
    parser.add_argument('--debug', '-d', required=False, action='store_true', default=None, help='Turn on DEBUG logging')

    opts = parser.parse_args()

    if opts.debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    distro_name, distro_release, distro_codename = distro.linux_distribution(full_distribution_name=False)

    source_content = get_source_content(distro_name, distro_release, distro_codename, opts.baseurl, opts.sourcefile, opts.file)
    oval_definition = build_oval(source_content)
    oval_and_maps = map_oval_ids(oval_definition)
    vulns = create_vulns(oval_and_maps)
    local_pkgs = get_local_pkg_list(distro_name)

    report = get_impact_report(vulns, local_pkgs, distro_name)
    if opts.output:
        with open(opts.output, 'w') as outfile:
            outfile.write(json.dumps(report, indent=4, sort_keys=True))
    else:
        print(json.dumps(report, indent=4, sort_keys=True))


def get_impact_report(vulns, local_pkgs, distro_name):
    '''Get impact report'''
    logging.debug('get_impact_report')
    report = build_impact(vulns, local_pkgs, distro_name)
    logging.debug(json.dumps(report, indent=4, sort_keys=True))
    return report


# Build an impact report
def build_impact(vulns, local_pkgs, distro_name):
    '''Build impacts based on pkg comparisons'''
    logging.debug('build_impact')
    for data in vulns.values():
        for pkg in data['pkg']:
            name = pkg['name']
            ver = pkg['version']
            if name in local_pkgs:
                title = data['title']
                cve = data['cve']
                severity = data['severity']
                if distro_name == 'centos':
                    rhsa = data['rhsa']
                    impact = get_centos_impact(local_pkgs[name], name, ver, title, cve, rhsa, severity)
                elif distro_name == 'ubuntu':
                    impact = get_ubuntu_impact(local_pkgs[name], name, ver, title, cve, severity)
                if impact:
                    result = build_impact_report(impact)
    return result


def build_impact_report(impact, report={}):
    '''Build a report based on impacts'''
    logging.debug('build_impact_report')
    for adv, detail in impact.items():
        if adv not in report:
            report[adv] = {
                'impacted': [],
                'installed': [],
                'severity': detail['severity'],
                'cve': detail['cve']
            }
        report[adv]['impacted'].append(detail['impacted'])
        report[adv]['installed'].append(detail['installed'])
        if 'rhsa' in detail:
            report[adv]['rhsa'] = detail['rhsa']
    return report


# Package parsers
def get_ubuntu_impact(local_ver, name, ver, title, cve, severity):
    '''Compare local package versions to vulnerability versions in Ubuntu'''
    logging.debug('get_ubuntu_impact')
    impact = {}
    comparison = ['dpkg', '--compare-versions', local_ver, 'lt', ver]
    impacted = run_comparison(comparison)
    if impacted == 0:
        impact[title] = {
            'impacted': {'name': name, 'version': ver},
            'installed': {'name': name, 'version': local_ver},
            'severity': severity,
            'cve': cve
        }
        logging.debug(impact[title])
    return impact


def get_centos_impact(local_ver, name, ver, title, cve, rhsa, severity):
    '''Compare local package versions to vulnerability versions in CentOS'''
    logging.debug('get_centos_impact')
    impact = {}
    gen_rel = '.el'
    # local version
    full_local = local_ver.split(gen_rel)
    nice_local_ver = full_local[0]
    raw_local_rel = full_local[1]
    strip_centos = raw_local_rel.split('.centos')
    local_rel = strip_centos[0]
    # impcated version
    full_vuln = ver.split(gen_rel)
    nice_vuln_ver = full_vuln[0]
    vuln_rel = full_vuln[1]
    if (
        not re.search(gen_rel, local_ver, re.IGNORECASE)
        and parse_version(local_ver) < parse_version(ver)
    ) or (
        parse_version(nice_local_ver) < parse_version(nice_vuln_ver)
        and parse_version(local_rel) <= parse_version(vuln_rel)
    ):
        impact[title] = {
            'impacted': {'name': name, 'version': ver},
            'installed': {'name': name, 'version': local_ver},
            'severity': severity,
            'rhsa': rhsa,
            'cve': cve
        }
    return impact


def run_comparison(comparison):
    '''Ubuntu package comparision function'''
    logging.debug('run_comparison')
    process = subprocess.call(comparison, stdout=subprocess.PIPE)
    return process


# Create vulnerability dictionary
def create_vulns(oval_and_maps, vulns={}):
    '''Create vuln dict that maps definitions directly to objects and states'''
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
                if 'name' in oval['objects'][obj['object_id']]:
                    name = oval['objects'][obj['object_id']]['name']
                else:
                    continue
                if 'version' in oval['states'][obj['state_id']]:
                    version = oval['states'][obj['state_id']]['version']
                else:
                    continue
                vuln_pkg.append({'name': name, 'version': version})
    return vulns


# Map oval definitions to oval objects and states
def map_oval_ids(oval, id_maps={}):
    '''For every test, grab only tests with both state and obj references'''
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


# Get installed packages
def get_local_pkg_list(distro_name, local_pkg_list={}):
    '''Build a dict of locally installed packages'''
    logging.debug('get_local_package')
    if distro_name == 'centos':
        cmd = [
            'rpm',
            '--nosignature',
            '--nodigest',
            '-qa',
            '--qf',
            '%{N} %{epochnum}:%{V}-%{R}\n'
        ]
    elif distro_name == 'ubuntu':
        cmd = ['dpkg-query', '-W', '-f=${Package}\t${Version}\n']
    output = get_local_pkgs(cmd)
    pkg_list = proper_pkg(output, distro_name)
    for pkg_detail in pkg_list:
        local_pkg_list[pkg_detail[0]] = pkg_detail[1]
    return local_pkg_list


def proper_pkg(output, distro_name, pkg_list=[]):
    '''Return locally installed packages into a name/version format'''
    logging.debug('proper_pkg')
    for line in output:
        pkg_str = line.decode('utf-8').rstrip('\n')
        if distro_name == 'centos':
            pkg = re.split(' ', pkg_str)
        elif distro_name == 'ubuntu':
            pkg = re.split(r'\t+', pkg_str)
        pkg_list.append(pkg)
    logging.debug(pkg_list)
    return pkg_list


def get_local_pkgs(cmd):
    '''Execute system command to grab locally installed packages'''
    logging.debug('get_local_pkgs')
    packages = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    return packages.stdout.readlines()


# Build oval from source
def build_oval(source_content, oval={}):
    '''Build oval dict from ElementTree content'''
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
    return oval


def build_generator(root, namespace, gen={}):
    '''Build generator dict from oval source'''
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
    '''Build element definitions from source into oval dict'''
    logging.debug('build_definitions')
    definitions = root.find('oval:definitions', namespace)
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
            if source == 'RHSA':
                definition_data['rhsa'] = {ref_id: ref_url}
            elif source == 'CVE':
                definition_data['cve'].append({ref_id: ref_url})
        advisory = metadata.find('oval:advisory', namespace)
        if is_et(advisory):
            severity = advisory.find('oval:severity', namespace).text
            definition_data['severity'] = severity
        for criterion in definition.iter():
            if is_et(criterion) and 'test_ref' in criterion.attrib:
                definition_data['tests'].append(criterion.attrib['test_ref'])
    return defs


def build_tests(root, namespace, tsts={}):
    '''Build element tests from source into oval dict'''
    logging.debug('build_tests')
    tests = root.find('oval:tests', namespace)
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
    '''Build element objects from source into oval dict'''
    logging.debug('build_objects')
    objects = root.find('oval:objects', namespace)
    for obj in objects:
        primary_key = obj.attrib['id']
        objs[primary_key] = {}
        build_data = objs[primary_key]
        object_name = obj.find('linux:name', namespace)
        if is_et(object_name):
            name = object_name.text
            build_data['name'] = name
    return objs


def build_states(root, namespace, stes={}):
    '''Build element states from source into oval dict'''
    logging.debug('build_states')
    states = root.find('oval:states', namespace)
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


def is_et(item):
    '''Determine if specific item is a valid ElementTree element'''
    return isinstance(item, ET.Element)


def build_element_tree(source_content):
    '''Build an element tree from source content'''
    logging.debug('build_element_tree')
    return ET.fromstring(source_content)


# Get oval source
def get_source_content(distro_name, distro_release, distro_codename, base_url, source_file, local_file=None):
    '''Get content from the source'''
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
    '''Determine the source'''
    logging.debug('get_definition_source')
    if distro_name == 'centos':
        source = source_file or 'Red_Hat_Enterprise_Linux_{0}.xml'.format(distro_release)
        base = base_url or 'https://www.redhat.com/security/data/oval/'
    elif distro_name == 'ubuntu':
        source = source_file or 'com.ubuntu.{0}.cve.oval.xml'.format(distro_codename)
        base = base_url or 'https://people.canonical.com/~ubuntu-security/oval/'
    url = base + source
    return url


if __name__ == '__main__':
    main()
