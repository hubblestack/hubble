import os, shutil
import hubblestack.extmods.modules.pulsar as pulsar
import pyinotify

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
        self.nuke_tdir()

        self.events = []
        def _append(revent):
            self.events.append(revent)

        self.wm = pulsar.PulsarWatchManager()
        self.wm.update_config()
        self.N  = pyinotify.Notifier(self.wm, _append)

    def nuke_tdir(self):
        if os.path.isdir(self.tdir):
            shutil.rmtree(self.tdir)

    def supz(self):
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
        self.reset()

        # NOTE: without new_files and/or without watch_files parent_db should
        # remain empty, and we shouldn't get a watch on tfile

        os.mkdir(self.tdir)
        if modality == 'add-watch':
            self.wm.add_watch(self.tdir, pulsar.DEFAULT_MASK)
        elif modality == 'watch':
            self.wm.watch(self.tdir)
        else:
            raise Exception("unknown modality")

        assert self.wm.watch_db.get(self.tdir) is None
        assert self.wm.watch_db.get(self.atdir) > 0
        assert len(self.wm.watch_db) == 1
        assert not isinstance(self.wm.parent_db.get(self.atdir), set)

        if self.N.check_events(1):
            self.N.read_events()
            self.N.process_events()

        assert len(self.events) == 0

        self.supz() # write supz to tfile

        if self.N.check_events(1):
            self.N.read_events()
            self.N.process_events()

        assert len(self.events) == 2
        assert self.events[0].maskname == 'IN_CREATE'
        assert self.events[1].maskname == 'IN_MODIFY'
        assert len(self.wm.watch_db) == 1
        assert not isinstance(self.wm.parent_db.get(self.atdir), set)

        self.nuke_tdir()

    def test_watch(self):
        self.test_add_watch(modality='watch')

    def test_watch_files(self):
        kw = { self.atdir: { 'watch_files': True } }
        self.reset(**kw)

        self.supz() # write supz so tfile

        self.wm.watch(self.tdir)

        assert len(self.wm.watch_db) == 2
        assert len(self.wm.parent_db[self.atdir]) == 1
        assert self.atfile in self.wm.watch_db
        assert self.atfile in self.wm.parent_db[self.atdir]
