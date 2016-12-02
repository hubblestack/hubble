# Hubble
The infamous HubbleStack written in Python to run autonomously (independent of SaltStack).

# Installation/testing

```bash
git clone git@github.com:dmcteer/hubble hubblev2
cd hubblev2
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
gitpython or pygit2 to get gitfs working:

```
gitfs_remotes:
  - git://github.com/hubblestack/Nova.git:
    - base: v2016.10.2
  - git://github.com/hubblestack/Nebula.git:
    - base: v2016.10.2
  - git://github.com/hubblestack/Pulsar.git:
    - base: v2016.10.3
  - git://github.com/hubblestack/Quasar.git:
    - base: v2016.10.4
fileserver_backend:
  - root
  - git
```
