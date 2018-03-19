import os, shutil
import hubblestack.extmods.modules.pulsar as pulsar
import pyinotify
import six

if os.environ.get('DEBUG_WM'):
    import logging
    root_logger = logging.getLogger()
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    root_logger.addHandler(ch)

class TestPulsarWatchManager():
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

    def nuke_tdir(self):
        if os.path.isdir(self.tdir):
            shutil.rmtree(self.tdir)

    def mk_tdir_and_write_tfile(self):
        if not os.path.isdir(self.tdir):
            os.mkdir(self.tdir)
        with open(self.tfile, 'w') as fh:
            fh.write('supz')

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

        self.events.extend( pulsar.process() )
        assert len(self.events) == 0
        assert self.wm.watch_db.get(self.tdir) is None
        assert self.wm.watch_db.get(self.atdir) > 0
        assert len(self.wm.watch_db) == 1
        assert not isinstance(self.wm.parent_db.get(self.atdir), set)

        self.mk_tdir_and_write_tfile() # write supz to tfile

        self.events.extend( pulsar.process() )
        assert len(self.events) == 1
        assert self.events[0]['change'] == 'IN_CREATE'

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

    def test_pruning(self):
        import os
        o = {}
        kw = { self.atdir: { 'watch_files': True } }
        self.reset(**kw)
        self.mk_tdir_and_write_tfile()
        self.wm.watch(self.tdir)
        s0 = set([ self.atdir, self.atfile ])
        assert set(self.wm.watch_db) == s0

        del self.wm.cm.nc_config[ self.atdir ]
        self.wm.prune()

        s1 = set()
        assert set(self.wm.watch_db) == s1
