import sys
import os
myPath = os.path.abspath(os.getcwd())
sys.path.insert(0, myPath)
import hubblestack.extmods.modules.pulsar as pulsar
from salt.exceptions import CommandExecutionError

import shutil
import six
import pyinotify

if os.environ.get('DEBUG_SHOW_PULSAR_LOGS'):
    import logging
    root_logger = logging.getLogger()
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    root_logger.addHandler(ch)

class TestPulsar():

    def test_virtual(self):
        var = pulsar.__virtual__()
        assert var is True

    def test_enqueue(self):
        pulsar.__context__ = {}
        var = pulsar._enqueue
        assert var != 0

    def test_get_notifier(self):
        pulsar.__context__ = {}
        var = pulsar._get_notifier
        assert var != 0

    def test_dict_update_for_merge_dict(self):
        dest = {'key1': 'val1'}
        upd = {'key_2': 'val_2'}
        test_dict = {'key1': 'val1', 'key_2': 'val_2'}
        var = pulsar._dict_update(dest, upd, recursive_update=True, merge_lists=False)
        assert var == test_dict

    def test_dict_update_for_classic_dictUpdate(self):
        dest = {'key1': 'val1'}
        upd = {'key_2': 'val_2'}
        test_dict = {'key1': 'val1', 'key_2': 'val_2'}
        var = pulsar._dict_update(dest, upd, recursive_update=False, merge_lists=False)
        assert var == test_dict

    def test_dict_update_for_dest_TypeError(self):
        dest = 'TestValue1'
        upd = {'key_1': 'val_1', 'key_2': 'val_2'}
        try:
            var = pulsar._dict_update(dest, upd, recursive_update=True, merge_lists=False)
        except TypeError:
            pass

    def test_dict_update_for_upd_TypeError(self):
        dest = {'key_1': 'val_1', 'key_2': 'val_2'}
        upd = 'TestValue2'
        try:
            var = pulsar._dict_update(dest, upd, recursive_update=True, merge_lists=False)
        except TypeError:
            pass

    def test_dict_update_recurssive(self):
        ret = {}
        dest = {'data':
                {'blacklist': {'talk1': {'data': {'Ubuntu-16.04': [{'/etc/inetd.conf': {'pattern': '^talk', 'tag': 'CIS-5.1.4'}}, {'/etc/inetd.conf': {'pattern': '^ntalk', 'tag': 'CIS-5.1.4'}}]}, 'description': 'Ensure talk server is not enabled'}},
                 'whitelist': {'ssh_ignore_rhosts': {'data': {'Ubuntu-16.04': [{'/etc/ssh/sshd_config': {'pattern': 'IgnoreRhosts', 'tag': 'CIS-9.3.6', 'match_output': 'yes'}}]}, 'description': 'Set SSH IgnoreRhosts to Yes'}}}}
        upd = {'data':
               {'blacklist': {'talk2': {'data': {'Ubuntu-16.04': [{'/etc/inetd.conf': {'pattern': '^talk', 'tag': 'CIS-5.1.4'}}, {'/etc/inetd.conf': {'pattern': '^ntalk', 'tag': 'CIS-5.1.4'}}]}, 'description': 'Ensure talk server is not enabled'}}}}
        data_list = [dest, upd]
        for data in data_list:
            val = pulsar._dict_update(dest, data, recursive_update=True, merge_lists=True)
        assert (len(val['data']['blacklist'])) == 2

    def test_process(self):
        configfile = 'tests/unittests/resources/hubblestack_pulsar_config.yaml'
        verbose = False

        def config_get(value, default):
            return default
        __salt__ = {}
        __salt__['config.get'] = config_get
        pulsar.__salt__ = __salt__
        pulsar.__opts__ = {}
        pulsar.__context__ = {}
        var = pulsar.process(configfile, verbose)
        pulsar.__salt__ = {}
        assert len(var) == 0
        assert isinstance(var, list)

    def test_top_result_for_list(self):
        topfile = 'tests/unittests/resources/top.pulsar'

        def cp_cache_file(value):
            return 'tests/unittests/resources/top.pulsar'

        def match_compound(value):
            return value
        __salt__ = {}
        __salt__['cp.cache_file'] = cp_cache_file
        __salt__['match.compound'] = match_compound
        pulsar.__salt__ = __salt__
        get_top_data_config = pulsar.get_top_data(topfile)
        configs = ['salt://hubblestack_pulsar/' + config.replace('.', '/') + '.yaml'
                   for config in get_top_data_config]
        assert configs[0] == 'salt://hubblestack_pulsar/hubblestack_pulsar_config.yaml'

    def test_get_top_data(self):
        topfile = 'tests/unittests/resources/top.pulsar'

        def cp_cache_file(topfile):
            return topfile

        def match_compound(value):
            return value
        __salt__ = {}
        __salt__['cp.cache_file'] = cp_cache_file
        __salt__['match.compound'] = match_compound
        pulsar.__salt__ = __salt__
        result = pulsar.get_top_data(topfile)
        pulsar.__salt__ = {}
        assert isinstance(result, list)
        assert result[0] == 'hubblestack_pulsar_config'

    def test_get_top_data_for_CommandExecutionError(self):
        topfile = '/testfile'

        def cp_cache_file(topfile):
            return '/testfile'

        def match_compound(value):
            return value
        __salt__ = {}
        __salt__['cp.cache_file'] = cp_cache_file
        __salt__['match.compound'] = match_compound
        pulsar.__salt__ = __salt__
        try:
            result = pulsar.get_top_data(topfile)
            pulsar.__salt__ = {}
        except CommandExecutionError:
            pass

class TestPulsar2():
    tdir   = 'blah'
    tfile  = os.path.join(tdir, 'file')
    atdir  = os.path.abspath(tdir)
    atfile = os.path.abspath(tfile)

    def reset(self, **kw):
        def config_get(value, default):
            return default

        if 'paths' not in kw:
            kw['paths'] = []

        __salt__ = {}
        __salt__['config.get'] = config_get
        pulsar.__salt__ = __salt__
        pulsar.__opts__ = {'pulsar': kw}
        pulsar.__context__ = c = {}
        self.nuke_tdir()

        pulsar._get_notifier() # sets up the dequeue

        self.events = []
        self.N = c['pulsar.notifier']
        self.wm = self.N._watch_manager
        self.wm.update_config()

    def process(self):
        self.events.extend([ "{change}(path)".format(**x) for x in pulsar.process() ])

    def nuke_tdir(self):
        if os.path.isdir(self.tdir):
            shutil.rmtree(self.tdir)

    def mk_tdir_and_write_tfile(self, fname=None, to_write='supz\n'):
        if fname is None:
            fname = self.tfile
        if not os.path.isdir(self.tdir):
            os.mkdir(self.tdir)
        with open(self.tfile, 'w') as fh:
            fh.write(to_write)

    def mk_subdir_files(self, *f, **kw):
        if len(f) == 1 and isinstance(f[0], (list,tuple)):
            f = f[0]
        for _f in f:
            _f = _f if _f.startswith(self.tdir + '/') else os.path.join(self.tdir, _f)
            s = _f.split('/')
            if s:
                fn = s.pop()
                b = ''
                for i in s:
                    b = os.path.join(b,i)
                    if not os.path.isdir(i):
                        os.mkdir(b)
                k = ('{}_out', 'out_{}', '{}_to_write', 'to_write')
                for _k in k:
                    to_write = kw.get(_k.format(fn))
                    if to_write is not None:
                        break
                if to_write is None:
                    to_write = 'supz\n'
                fn = os.path.join(b, fn)
                with open(fn, 'a') as fh:
                    fh.write(to_write if to_write is not None else 'supz\n')

    def more_fname(self, number, base=None):
        if base is None:
            base = self.tfile
        return '{0}_{1}'.format(base, number)

    def mk_more_files(self, count=1, to_write='supz-{0}\n'):
        for i in range(count):
            with open(self.more_fname(i), 'w') as fh:
                fh.write(to_write.format(count))

    def test_listify_anything(self):
        la = pulsar.PulsarWatchManager._listify_anything
        def lla(x,e):
            assert len( la(x) ) == e
        def sla(x,e):
            assert str(sorted(la(x))) == str(sorted(e))
        lla(None, 0)
        lla([None], 0)
        lla(set([None]), 0)
        lla(set(), 0)
        lla([], 0)
        lla([[],[],(),{},None,[None]], 0)

        m = [[1],[2],(1,),(5),{2},None,[None],{'one':1}]
        lla(m, 4)
        sla(m, [1,2,5,'one'])

    def test_add_watch(self, modality='add-watch'):
        o = {}
        kw = { self.atdir: o }

        if modality in ('watch_new_files', 'watch_files'):
            o[modality] = True

        self.reset(**kw)

        # NOTE: without new_files and/or without watch_files parent_db should
        # remain empty, and we shouldn't get a watch on tfile

        os.mkdir(self.tdir)

        if modality == 'add-watch':
            self.wm.add_watch(self.tdir, pulsar.DEFAULT_MASK)

        elif modality in ('watch', 'watch_new_files', 'watch_files'):
            self.wm.watch(self.tdir)

        else:
            raise Exception("unknown modality")

        self.process()
        assert len(self.events) == 0
        assert self.wm.watch_db.get(self.tdir) is None
        assert self.wm.watch_db.get(self.atdir) > 0
        assert len(self.wm.watch_db) == 1
        assert not isinstance(self.wm.parent_db.get(self.atdir), set)

        self.mk_tdir_and_write_tfile() # write supz to tfile

        self.process()
        assert len(self.events) == 2
        assert self.events[0].startswith('IN_CREATE')
        assert self.events[1].startswith('IN_MODIFY')

        if modality in ('watch_files', 'watch_new_files'):
            assert len(self.wm.watch_db) == 2
            assert isinstance(self.wm.parent_db.get(self.atdir), set)
        else:
            assert len(self.wm.watch_db) == 1
            assert not isinstance(self.wm.parent_db.get(self.atdir), set)

        self.nuke_tdir()

    def test_watch(self):
        self.test_add_watch(modality='watch')

    def test_watch_new_files(self):
        self.test_add_watch(modality='watch_new_files')

    def test_recurse_without_watch_files(self):
        c1 = {self.atdir: { 'recurse': False }}
        c2 = {self.atdir: { 'recurse': True  }}

        self.reset(**c1)
        self.mk_subdir_files('blah1','a/b/c/blah2')
        self.wm.watch(self.tdir)
        self.wm.prune()
        s1 = set(self.wm.watch_db)

        self.reset(**c2)
        self.mk_subdir_files('blah1','a/b/c/blah2')
        self.wm.watch(self.tdir)
        self.wm.prune()
        s2 = set(self.wm.watch_db)

        s0a = set([self.atdir])
        s0b = [self.atdir]
        for i in 'abc':
            s0b.append( os.path.join(s0b[-1], i) )
        s0b = set(s0b)

        assert s1 == s0a
        assert s2 == s0b

    def config_make_files_watch_process_reconfig(self, config, reconfig=None, mk_files=0):
        """
            create a config (arg0),
            make tdir and tfile,
            watch the tdir,
            store watch_db in s0,
            make additional files (default: 0),
            execute process(),
            store watch_db in s1,
            reconfigure using reconfig param (named param or arg1) (default: None)
            execute process(),
            store watch_db in s2
            return s0, s1, s2 as a tuple
        """
        self.reset(**config)
        self.mk_tdir_and_write_tfile()
        self.wm.watch(self.tdir)
        s0 = set(self.wm.watch_db)
        if mk_files > 0:
            self.mk_more_files(count=mk_files)
        self.process()
        s1 = set(self.wm.watch_db)
        if reconfig is None:
            del self.wm.cm.nc_config[ self.atdir ]
        else:
            self.wm.cm.nc_config[ self.atdir ] = reconfig
        self.process()
        s2 = set(self.wm.watch_db)
        return s0,s1,s2

    def test_pruning_watch_files_false(self):
        s0,s1,s2 = self.config_make_files_watch_process_reconfig({self.atdir:{}}, None, mk_files=2)
        assert s0 == set([self.atdir])
        assert s1 == set([self.atdir])
        assert s2 == set()

    def test_pruning_watch_new_files_then_false(self):
        c1 = {self.atdir: { 'watch_new_files': True }}
        c2 = {self.atdir: { 'watch_new_files': False }}
        s0,s1,s2 = self.config_make_files_watch_process_reconfig(c1,c2, mk_files=2)
        f1 = self.more_fname(0, base=self.atfile)
        f2 = self.more_fname(1, base=self.atfile)
        assert s0 == set([self.atdir])
        assert s1 == set([self.atdir, f1, f2])
        assert s2 == set([self.atdir])

    def test_pruning_watch_files_then_false(self):
        c1 = {self.atdir: { 'watch_files': True }}
        c2 = {self.atdir: { 'watch_files': False }}
        s0,s1,s2 = self.config_make_files_watch_process_reconfig(c1,c2, mk_files=2)
        f1 = self.more_fname(0, base=self.atfile)
        f2 = self.more_fname(1, base=self.atfile)
        assert s0 == set([self.atdir, self.atfile])
        assert s1 == set([self.atdir, self.atfile, f1, f2])
        assert s2 == set([self.atdir])

    def test_pruning_watch_new_files_then_nothing(self):
        c1 = {self.atdir: { 'watch_new_files': True }}
        s0,s1,s2 = self.config_make_files_watch_process_reconfig(c1,None, mk_files=2)
        f1 = self.more_fname(0, base=self.atfile)
        f2 = self.more_fname(1, base=self.atfile)
        assert s0 == set([self.atdir])
        assert s1 == set([self.atdir, f1, f2])
        assert s2 == set()

    def test_pruning_watch_files_then_nothing(self):
        c1 = {self.atdir: { 'watch_files': True }}
        s0,s1,s2 = self.config_make_files_watch_process_reconfig(c1,None, mk_files=2)
        f1 = self.more_fname(0, base=self.atfile)
        f2 = self.more_fname(1, base=self.atfile)
        assert s0 == set([self.atdir, self.atfile])
        assert s1 == set([self.atdir, f1, f2, self.atfile])
        assert s2 == set()
