"""
Test the fim (pulsar) internals for various correctness
"""

import os
import shutil
import logging
import six

from salt.exceptions import CommandExecutionError
import hubblestack.extmods.modules.pulsar as pulsar

log = logging.getLogger(__name__)

class TestPulsar(object):
    """ An older set of pulsar tests """

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

        def config_get(_, default):
            ''' pretend salt[config.get] '''
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

        def cp_cache_file(_):
            ''' pretend salt[cp.cache_file] '''
            return 'tests/unittests/resources/top.pulsar'

        def match_compound(value):
            ''' pretend match.compound '''
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
            ''' pretend salt[cp.cache_file] '''
            return topfile

        def match_compound(value):
            ''' pretend match.compound '''
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

        def cp_cache_file(_):
            ''' pretend salt[cp.cache_file] '''
            return '/testfile'

        def match_compound(value):
            ''' pretend match.compound '''
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

class TestPulsar2(object):
    """ A slightly newer set of pulsar internals tets """

    tdir   = 'blah'
    tfile  = os.path.join(tdir, 'file')
    atdir  = os.path.abspath(tdir)
    atfile = os.path.abspath(tfile)

    def reset(self, **kwargs):
        def config_get(_, default):
            ''' pretend salt[config.get] '''
            return default

        if 'paths' not in kwargs:
            kwargs['paths'] = []

        def cp_cache_file(_):
            ''' pretend salt[cp.cache_file] '''
            return 'tests/unittests/resources/top.pulsar'

        __salt__ = {}
        __salt__['config.get'] = config_get
        __salt__['cp.cache_file'] = cp_cache_file
        pulsar.__salt__ = __salt__
        pulsar.__opts__ = {'pulsar': kwargs}
        pulsar.__context__ = {}
        self.nuke_tdir()

        pulsar._get_notifier() # sets up the dequeue

        self.events = []
        self.notifier = pulsar.__context__['pulsar.notifier']
        self.watch_manager = self.notifier._watch_manager
        self.watch_manager.update_config()

    def process(self):
        self.events.extend([ "{change}({path})".format(**x) for x in pulsar.process() ])

    def get_clear_events(self):
        ret = self.events
        self.events = list()
        return ret

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

    def mk_subdir_files(self, *files, **kwargs):
        if len(files) == 1 and isinstance(files[0], (list, tuple)):
            files = files[0]
        for file in files:
            file = file if file.startswith(self.tdir + '/') else os.path.join(self.tdir, file)
            split_file = file.split('/')
            if split_file:
                output_fname = split_file.pop()
                dir_to_make = ''
                for i in split_file:
                    dir_to_make = os.path.join(dir_to_make, i)
                    if not os.path.isdir(i):
                        os.mkdir(dir_to_make)
                forms = ('{}_out', 'out_{}', '{}_to_write', 'to_write')
                for form in forms:
                    to_write = kwargs.get(form.format(output_fname))
                    if to_write is not None:
                        break
                if to_write is None:
                    to_write = 'supz\n'
                output_fname = os.path.join(dir_to_make, output_fname)
                with open(output_fname, 'a') as fh:
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
        listify_fn = pulsar.PulsarWatchManager._listify_anything

        def assert_len_listify_is(list_arg, expected):
            """ compact comparifier """
            assert len( listify_fn(list_arg) ) == expected

        def assert_str_listify_is(list_arg, expected):
            """ compact comparifier """
            def boo(x):
                return str(x)
            assert str(sorted(listify_fn(list_arg), key=boo)) == str(sorted(expected, key=boo))

        assert_len_listify_is(None, 0)
        assert_len_listify_is([None], 0)
        assert_len_listify_is(set([None]), 0)
        assert_len_listify_is(set(), 0)
        assert_len_listify_is([], 0)
        assert_len_listify_is([[],[],(),{}, None,[None]], 0)

        oogly_list = [[1],[2],(1,),(5),{2}, None,[None],{'one':1}]
        assert_len_listify_is(oogly_list, 4)
        assert_str_listify_is(oogly_list, [1,2,5,'one'])

    def test_add_watch(self, modality='add-watch'):
        options = {}
        kwargs = { self.atdir: options }

        if modality in ('watch_new_files', 'watch_files'):
            options[modality] = True

        self.reset(**kwargs)

        # NOTE: without new_files and/or without watch_files parent_db should
        # remain empty, and we shouldn't get a watch on tfile

        os.mkdir(self.tdir)

        if modality == 'add-watch':
            self.watch_manager.add_watch(self.tdir, pulsar.DEFAULT_MASK)

        elif modality in ('watch', 'watch_new_files', 'watch_files'):
            self.watch_manager.watch(self.tdir)

        else:
            raise Exception("unknown modality")

        self.process()
        assert len(self.events) == 0
        assert self.watch_manager.watch_db.get(self.tdir) is None
        assert self.watch_manager.watch_db.get(self.atdir) > 0
        assert len(self.watch_manager.watch_db) == 1
        assert not isinstance(self.watch_manager.parent_db.get(self.atdir), set)

        self.mk_tdir_and_write_tfile() # write supz to tfile

        self.process()
        assert len(self.events) == 2
        assert self.events[0].startswith('IN_CREATE')
        assert self.events[1].startswith('IN_MODIFY')

        if modality in ('watch_files', 'watch_new_files'):
            assert len(self.watch_manager.watch_db) == 2
            assert isinstance(self.watch_manager.parent_db.get(self.atdir), set)
        else:
            assert len(self.watch_manager.watch_db) == 1
            assert not isinstance(self.watch_manager.parent_db.get(self.atdir), set)

        self.nuke_tdir()

    def test_watch(self):
        self.test_add_watch(modality='watch')

    def test_watch_new_files(self):
        self.test_add_watch(modality='watch_new_files')

    def test_recurse_without_watch_files(self):
        config1 = {self.atdir: { 'recurse': False }}
        config2 = {self.atdir: { 'recurse': True  }}

        self.reset(**config1)
        self.mk_subdir_files('blah1','a/b/c/blah2')
        self.watch_manager.watch(self.tdir)
        self.watch_manager.prune()
        set1 = set(self.watch_manager.watch_db)

        self.reset(**config2)
        self.mk_subdir_files('blah1','a/b/c/blah2')
        self.watch_manager.watch(self.tdir)
        self.watch_manager.prune()
        set2 = set(self.watch_manager.watch_db)

        set0_a = set([self.atdir])
        set0_b = [self.atdir]
        for i in 'abc':
            set0_b.append( os.path.join(set0_b[-1], i) )
        set0_b = set(set0_b)

        assert set1 == set0_a
        assert set2 == set0_b

    def config_make_files_watch_process_reconfig(self, config, reconfig=None, mk_files=0):
        """
            create a config (arg0),
            make tdir and tfile,
            watch the tdir,
            store watch_db in set0,
            make additional files (default: 0),
            execute process(),
            store watch_db in set1,
            reconfigure using reconfig param (named param or arg1) (default: None)
            execute process(),
            store watch_db in set2
            return set0, set1, set2 as a tuple
        """
        self.reset(**config)
        self.mk_tdir_and_write_tfile()
        self.watch_manager.watch(self.tdir)
        set0 = set(self.watch_manager.watch_db)
        if mk_files > 0:
            self.mk_more_files(count=mk_files)
        self.process()
        set1 = set(self.watch_manager.watch_db)
        if reconfig is None:
            del self.watch_manager.cm.nc_config[ self.atdir ]
        else:
            self.watch_manager.cm.nc_config[ self.atdir ] = reconfig
        self.process()
        set2 = set(self.watch_manager.watch_db)
        return set0, set1, set2

    def test_pruning_watch_files_false(self):
        set0, set1, set2 = self.config_make_files_watch_process_reconfig({self.atdir:{}}, None, mk_files=2)
        assert set0 == set([self.atdir])
        assert set1 == set([self.atdir])
        assert set2 == set()

    def test_pruning_watch_new_files_then_false(self):
        config1 = {self.atdir: { 'watch_new_files': True }}
        config2 = {self.atdir: { 'watch_new_files': False }}
        set0, set1, set2 = self.config_make_files_watch_process_reconfig(config1, config2, mk_files=2)
        fname1 = self.more_fname(0, base=self.atfile)
        fname2 = self.more_fname(1, base=self.atfile)
        assert set0 == set([self.atdir])
        assert set1 == set([self.atdir, fname1, fname2])
        assert set2 == set([self.atdir])

    def test_pruning_watch_files_then_false(self):
        config1 = {self.atdir: { 'watch_files': True }}
        config2 = {self.atdir: { 'watch_files': False }}
        set0, set1, set2 = self.config_make_files_watch_process_reconfig(config1, config2, mk_files=2)
        fname1 = self.more_fname(0, base=self.atfile)
        fname2 = self.more_fname(1, base=self.atfile)
        assert set0 == set([self.atdir, self.atfile])
        assert set1 == set([self.atdir, self.atfile, fname1, fname2])
        assert set2 == set([self.atdir])

    def test_pruning_watch_new_files_then_nothing(self):
        config1 = {self.atdir: { 'watch_new_files': True }}
        set0, set1, set2 = self.config_make_files_watch_process_reconfig(config1, None, mk_files=2)
        fname1 = self.more_fname(0, base=self.atfile)
        fname2 = self.more_fname(1, base=self.atfile)
        assert set0 == set([self.atdir])
        assert set1 == set([self.atdir, fname1, fname2])
        assert set2 == set()

    def test_pruning_watch_files_then_nothing(self):
        config1 = {self.atdir: { 'watch_files': True }}
        set0, set1, set2 = self.config_make_files_watch_process_reconfig(config1, None, mk_files=2)
        fname1 = self.more_fname(0, base=self.atfile)
        fname2 = self.more_fname(1, base=self.atfile)
        assert set0 == set([self.atdir, self.atfile])
        assert set1 == set([self.atdir, fname1, fname2, self.atfile])
        assert set2 == set()

    def test_watch_files_events(self):
        config = {self.atdir: { 'watch_files': True }}
        self.reset(**config)
        self.mk_tdir_and_write_tfile()

        set0 = set(self.watch_manager.watch_db)

        pulsar.process()
        set1 = set(self.watch_manager.watch_db)
        levents1 = len(self.events)
        assert set0 == set()
        assert set1 == set([self.atdir, self.atfile])
        assert levents1 == 0

        with open(self.atfile, 'a') as fh:
            fh.write('supz\n')
        self.process()
        set_ = set(self.watch_manager.watch_db)
        events_ = self.get_clear_events()
        assert set_ == set1
        assert events_ == ['IN_MODIFY({})'.format(self.atfile)]

        os.unlink(self.atfile)
        self.process()
        set_ = set(self.watch_manager.watch_db)
        events_ = self.get_clear_events()
        assert set_ == set([self.atdir])
        assert events_ == ['IN_DELETE({})'.format(self.atfile)]

        with open(self.atfile, 'a') as fh:
            fh.write('supz\n')
        self.process()
        set_ = set(self.watch_manager.watch_db)
        events_ = self.get_clear_events()
        assert set_ == set1
        assert events_ == ['IN_CREATE({})'.format(self.atfile)]

        with open(self.atfile, 'a') as fh:
            fh.write('supz\n')
        self.process()
        set_ = set(self.watch_manager.watch_db)
        events_ = self.get_clear_events()
        assert set_ == set1
        assert events_ == ['IN_MODIFY({})'.format(self.atfile)]

    def test_single_file_events(self):
        config = {self.atfile: dict()}
        self.reset(**config)
        self.mk_tdir_and_write_tfile()

        set0 = set(self.watch_manager.watch_db)
        assert set0 == set()

        pulsar.process()
        set1 = set(self.watch_manager.watch_db)
        levents1 = len(self.events)
        assert set1 == set([self.atfile])
        assert levents1 == 0

        with open(self.atfile, 'a') as fh:
            fh.write('supz\n')
        self.process()
        set2 = set(self.watch_manager.watch_db)
        events2 = self.get_clear_events()
        assert set2 == set1
        assert events2 == ['IN_MODIFY({})'.format(self.atfile)]

        os.unlink(self.atfile)
        self.process()
        set_ = set(self.watch_manager.watch_db)
        events_ = self.get_clear_events()
        assert set_ == set() # this is DELETE_SELF now (technically)
        assert events_ == ['IN_DELETE({})'.format(self.atfile)]

        with open(self.atfile, 'a') as fh:
            fh.write('supz\n')
        self.process()
        set_ = set(self.watch_manager.watch_db)
        events_ = self.get_clear_events()
        assert set_ == set1
        assert events_ == ['IN_CREATE({})'.format(self.atfile)]

        with open(self.atfile, 'a') as fh:
            fh.write('supz\n')
        self.process()
        set_ = set(self.watch_manager.watch_db)
        events_ = self.get_clear_events()
        assert set_ == set1
        assert events_ == ['IN_MODIFY({})'.format(self.atfile)]

    def test_fim_single_file(self):
        config = {self.atfile: {}}
        self.reset(**config)
        self.mk_tdir_and_write_tfile()
        self.watch_manager.watch(self.tfile)

        set0 = set(self.watch_manager.watch_db)
        levents0 = len(self.events)
        # we should be watching 1 file, no events

        self.process()
        set1 = set(self.watch_manager.watch_db)
        levents1 = len(self.events)
        # we should be watching 1 file, no events

        with open(self.atfile, 'a') as fh:
            fh.write('supz\n')

        self.process()
        set2 = set(self.watch_manager.watch_db)
        levents2 = len(self.events)
        # we should still be watching 1 file, 1 event

        os.unlink(self.atfile)

        self.process()
        set3 = set(self.watch_manager.watch_db)
        levents3 = len(self.events)
        # we should now be watching 0 files, 2 events

        assert levents0 == 0
        assert levents1 == 0
        assert levents2 == 1
        assert levents3 == 2
        assert set0 == set([self.atfile])
        assert set1 == set([self.atfile])
        assert set2 == set([self.atfile])
        assert set3 == set()
        ### BASELINE ###

        # the relevant connundrum: if we put the file back, this config should
        # somehow know to re-watch the atfile
        # at the time of this writing, this test fails
        with open(self.atfile, 'a') as fh:
            fh.write('supz\n')

        self.process()
        set4 = set(self.watch_manager.watch_db)
        levents4 = len(self.events)

        assert set4 == set([self.atfile])
        assert levents4 == 3 # XXX: 4? CREATE? CREATE_MODIFY? CREATE+MODIFY??
