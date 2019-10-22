# Updates yaml with PDF Table of Contents.  Create new file with changes to most recent file labeled with CIS document version


from glob import glob
import os
import PyPDF2
import re
import yaml

from salt.ext.six.moves import input

new_yaml = {}


def ItemAdder(title, server, key, tag, match, vtype, desc,):
    tempdict = {}
    tempdict[title] = {'data': {server: [{key: {'tag': tag, 'match_ouput': match, 'value_type': vtype}}]}, 'description': desc}
    return tempdict


# ask for PDF file (figure out good way to use XLS file)
filename = []
print("Which PDF file are we checking against (alternatly place in same folder as script and this will happen automatically)")
files = os.listdir(os.getcwd())
pdffiles = glob(os.path.join(os.getcwd(), "*.pdf"))
if pdffiles:
    if len(pdffiles) >= 2:
        print("There is more than 1 pdf in the folder")
        truefile = False
        while not truefile:
            filename = input('Path to PDF: ')
            if os.path.isfile(filename):
                truefile = True
            else:
                print("that file does not exist")
    else:
        filename = pdffiles
else:
    truefile = False
    while not truefile:
        filename = input('Path to PDF: ')
        if os.path.isfile(filename):
            truefile = True
        else:
            print("that file does not exist")

# read in PDF
initialstring = ''
if isinstance(filename, list):
    filename = filename[0]
pdffileobj = open(filename, 'rb')
pdfreader = PyPDF2.PdfFileReader(pdffileobj)
for x in range(0, 29):
    pageobj = pdfreader.getPage(x)
    initialstring = initialstring + pageobj.extractText()

# keep only the Table of Contents
toc = re.search('Table of Contents(.+?)Appendix', initialstring, re.DOTALL).group(1)

# clean up all the uneeded info
toc = toc.replace('..', '')
toc = toc.replace('\n', '')
toc = toc.replace(':', '-')

# Convert Table of Contents to dictionary
toc_dict = {}
reall = re.findall('(\d*\.\d*\.\d.+?\(L\d\))(.+?Scored\))', toc)
# toc_tup = [(x[:-4], y[:-8]) for x, y in reall if '(L2)' not in x]
for x, y in reall:
    if '(L2)' not in x and '(DC only)' not in x:
        toc_dict[x[0:-4].strip()] = y[0:-8].strip()


# get yaml file
yamlname = []
print("Which YAML file are we checking against (alternatly place in same folder as script and this will happen automatically)")
yamlfiles = glob(os.path.join(os.getcwd(), "*.yaml"))
if yamlfiles:
    if len(yamlfiles) >= 2:
        print("There is more than 1 pdf in the folder")
        truefile = False
        while not truefile:
            yamlname = input('Path to YAML: ')
            if os.path.isfile(filename):
                truefile = True
            else:
                print("that file does not exist")
    else:
        yamlname = yamlfiles
else:
    truefile = False
    while not truefile:
        yamlname = input('Path to yaml: ')
        if os.path.isfile(filename):
            truefile = True
        else:
            print("that file does not exist")

# Read in Yaml
if isinstance(yamlname, list):
    yamlname = yamlname[0]

with open(yamlname, 'r') as stream:
    hubyaml = yaml.safe_load(stream)

# flatenize the yaml
flat_yaml = {}
for toplist, toplevel in hubyaml.items():
    # toplist windows sections win_secedit, toplevel is data inside toplist
    for audit_dict, audit_info in toplevel.items():
        # audit_dict = blacklist & whitelist data inside each toplist, audit_info = title dictionary
        for audit_title, audit_data1 in audit_info.items():
            # audit_title is title of the check, audit_data is data dictionary
            audit_data = audit_data1.get('data', {})
            audit_description = audit_data1.get('description', {})
            if '(l1)' in audit_description.lower():
                audit_description = audit_description[4:]
            for audit_osfinger, audit_key1 in audit_data.items():
                # osfinger server version
                for audit_other1 in audit_key1:
                    for audit_key, audit_other in audit_other1.items():
                        # flatenize!
                        stag = audit_other['tag'].replace('CIS-', '')
                        flat_yaml[stag] = {'value_type': audit_other['value_type'], 'match_output': audit_other['match_output'], 'section': toplist, 'tlist': audit_dict, 'check_title': audit_title, 'description': audit_description, 'os': audit_osfinger, 'audit_key': audit_key}


# go through each dictionary item and check yaml for tag
orderedtags = sorted(toc_dict)
for item in orderedtags:
    item = item.encode('ascii')
    if item in flat_yaml:
        section = flat_yaml[item]['section']
        tlist = flat_yaml[item]['tlist']
        osf = flat_yaml[item]['os']
        # check to see if descriptions match
        yaml_side = flat_yaml[item]['description'].lower().strip()
        pdf_side = toc_dict[item].lower().strip()
        if yaml_side == pdf_side:
            print("tag {} exists, and descriptions match!!!".format(item))
            # found verbatim, move into the new yaml
            test = new_yaml.get(section, '')
            if tlist not in test:
                if test == '':
                    new_yaml[section] = {tlist: {}}
                else:
                    new_yaml[section][tlist] = {}
            new_yaml[section][tlist].update(ItemAdder(flat_yaml[item]['check_title'], flat_yaml[item]['os'], flat_yaml[item]['audit_key'], item, flat_yaml[item]['match_output'], flat_yaml[item]['value_type'], toc_dict[item].encode('ascii')))
        else:
            print("tag {} exists, but descriptions do not match".format(item))
            print("\tyaml side-\t{}".format(yaml_side))
            print("\tpdf side-\t{}".format(pdf_side))
            # check for unique section of tag (in case of missing 1 or 2 characters)
            if "'" in pdf_side:
                unique = re.search("'.+?'", pdf_side).group(0).strip("'")
            else:
                unique = re.search("\s.+?is", pdf_side).group(0).strip()
            unique_check = re.search(unique, yaml_side)
            if unique_check:
                print("tag {} exists, and unique part of description matches".format(item))
                # if not found verbatim, but found partial, change desc to be verbatm and tag name
                test = new_yaml.get(section, '')
                if tlist not in test:
                    if test == '':
                        new_yaml[section] = {tlist: {}}
                    else:
                        new_yaml[section][tlist] = {}
                new_yaml[section][tlist].update(ItemAdder(flat_yaml[item]['check_title'], flat_yaml[item]['os'], flat_yaml[item]['audit_key'], item, flat_yaml[item]['match_output'], flat_yaml[item]['value_type'], toc_dict[item].encode('ascii')))
            else:
                # if not match, check all of yaml for description
                for tag in orderedtags:
                    pdf_recurse = toc_dict[tag].lower().strip()
                    unique_recurse = re.search(unique, yaml_side)
                    if unique_recurse:
                        print("----found description for tag {} in tag {}".format(item, tag))
                        test = new_yaml.get(section, '')
                        if tlist not in test:
                            if test == '':
                                new_yaml[section] = {tlist: {}}
                            else:
                                new_yaml[section][tlist] = {}
                        new_yaml[section][tlist].update(ItemAdder(flat_yaml[tag]['check_title'], flat_yaml[tag]['os'], flat_yaml[tag]['audit_key'], item, flat_yaml[tag]['match_output'], flat_yaml[tag]['value_type'], toc_dict[item].encode('ascii')))
                        break
                print("didn't find the descriptoin for tag {} anywhere in current yaml".format(item))
                test = new_yaml.get(section, '')
                if tlist not in test:
                    if test == '':
                        new_yaml[section] = {tlist: {}}
                    else:
                        new_yaml[section][tlist] = {}
                new_yaml[section][tlist].update(ItemAdder(flat_yaml[item]['check_title'], 'zz descs didnt match', flat_yaml[item]['audit_key'], item, flat_yaml[item]['match_output'], flat_yaml[item]['value_type'], toc_dict[item].encode('ascii')))

    else:
        print("!!tag {} isn't in current yaml file".format(item))
        # if not found anything, create new space with blanks for important documents
        cdescription = toc_dict[item].encode('ascii')
        if "'" in cdescription:
            ctitle = re.search("'.+?'", cdescription).group(0).strip("'").replace(' ', '_')
        else:
            ctitle = re.search("\s.+?is", cdescription).group(0).strip().replace(' ', '_')

        test = new_yaml.get(section, '')
        if tlist not in test:
            if test == '':
                new_yaml[section] = {tlist: {}}
            else:
                new_yaml[section][tlist] = {}
        new_yaml[section][tlist].update(ItemAdder(ctitle, osf, 'zz', item, 'zz', 'zz', cdescription))

# write new yaml file
yml_outfile = os.getcwd() + '/new_template.yaml'
with open(yml_outfile, 'w') as outfile:
    yaml.dump(new_yaml, outfile, default_flow_style=False, allow_unicode=True)
