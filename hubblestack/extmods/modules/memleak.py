# coding: utf-8

import tracemalloc
import logging
import objgraph
import re
import gc
import os
import time
from hubblestack.hec.dq import DiskQueue

__virtualname__ = 'memleak'
log = logging.getLogger(__virtualname__)
STATE = dict(growth=True, new_item_refmaps=0)

# if the salt.loader replaces this, fine; if not, /var/cache/hubble is fine too
__opts__ = { 'cachedir': '/var/cache/hubble' }

def __virtual__():
    return True

def _now():
    return int(time.time())

def _apply_tags(tags, *events):
    if tags is not None:
        if not isinstance(tags, (list,tuple)):
            tags = [ x for x in tags.split() if x ]
    for item in events:
        item['tags'] = tags

def growth(collect=True, shortnames=False, tags=None):
    log.debug('growth(%s, %s)', collect, shortnames)
    if collect:
        log.debug(' forcing garbage collection')
        gc.collect()

    pid = os.getpid()
    growth = objgraph.growth(shortnames=shortnames)

    if STATE['growth']:
        log.debug(' first query')
        STATE['growth'] = False

    elif growth:
        log.debug(' found growth')
        growth = [ {'time': _now(), 'pid': pid, 'type': t, 'count': c, 'delta': d} for t, c, d in  growth ]
        _apply_tags(tags, *growth)
        return { 'sourcetype': 'memleak.growth', 'events': growth }

    else:
        log.debug(' no new growth found')

def _obj_name(x):
    try:
        return '{0.__module__}.{0.__name__}'.format(x)
    except AttributeError:
        pass
    try:
        return '{0.__name__}'.format(x)
    except AttributeError:
        pass
    return '{t}#{i:02x}'.format(t=type(x).__name__, i=id(x))

def new_item_refmaps(collect=True, types=None, skip=2, max_per_type=10, max_total=50, tags=None):
    log.debug('new_item_refmaps(%s)', collect)
    if collect:
        log.debug(' forcing garbage collection')
        gc.collect()

    pid = os.getpid()
    log.debug(' finding new_ids')
    new_ids = objgraph.get_new_ids() # dict of sets

    if STATE['new_item_refmaps'] < skip:
        log.debug(' query #%d < %d; not analyzing yet', STATE['new_item_refmaps'], skip)
        STATE['new_item_refmaps'] += 1

    else:
        done = False
        events = list()
        if types is None:
            types = new_ids.keys()
        total_count = 0
        for type in types:
            type_count = 0
            log.debug(' finding backref chains for items of type=%s', type)
            for item_id in new_ids.get(type, []):
                item = objgraph.at(item_id)
                name = _obj_name(item)
                log.debug('  finding backrefs chain for item=%s', name)
                refmap = objgraph.find_backref_chain(item, objgraph.is_proper_module)
                refmap = [ _obj_name(x) for x in refmap ]
                events.append({'time': _now(), 'pid': pid, 'type': type, 'name': name, 'chain': refmap})
                total_count += 1
                type_count += 1
                if type_count > max_per_type:
                    log.debug('reached max_per_type=%d limit', max_per_type)
                    done = True
                if total_count > max_total:
                    log.debug('reached max_total=%d limit', max_total)
                    done = True
                if done:
                    break
            if done:
                break
        if events:
            _apply_tags(tags, *events)
            return { 'sourcetype': 'memleak.new_item_refmaps', 'events': events }

def _queue():
    qloc = os.path.join(__opts__.get('cachedir', '/var/cache/hubble'), 'memleak-storage')
    return DiskQueue(qloc, size=1024*1024*10)

def reveal_withobj_nir():
    queue = _queue()
    events = list()
    while True:
        item = queue.get()
        if not item:
            break
        events.append(item)
    return { 'sourcetype': 'memleak.new_item_refmaps', 'events': events }

def with_nir(name, max_per_type=10, max_total=50, types=None):
    class WithWrap(object):
        def __enter__(self):
            gc.collect()
            objgraph.get_new_ids()

        def __exit__(self):
            res = new_item_refmaps(max_per_type=max_per_type,
                max_total=max_total, tags='nir:{0}'.format(name))
            _queue().put(res)
    return WithWrap()

def _build_snapdiff_filters(inc,exc):
    log.debug('building snapdiff filters: inc=%s, exc=%s', inc, exc)
    if not inc and not exc:
        return ( tracemalloc.Filter(True, "*/salt/*"),
            tracemalloc.Filter(True, "*/hubblestack/*"),
            tracemalloc.Filter(False, "*/hubblestack/*/memleak*") )
    # NOTE: originally, this section below was appended with the filters above
    # That seems not to "work" in the sense that you get an awful lot more
    # returns than you really want by the patterns given in inc/exc.
    # Instead, we leave it to the configure-er to fully describe what they want.
    ret = list()
    other = ( (True, inc), (False, exc) )
    for tf,lori in other:
        if lori:
            if isinstance(lori, (list,tuple)):
                ret.extend([tracemalloc.Filter(tf, x) for x in lori])
            else:
                ret.append(tracemalloc.Filter(tf, lori))
    return ret

def _do_snapdiff_tracemalloc(filter):
    snap = tracemalloc.take_snapshot()
    return dict(snap=snap.filter_traces(filter), t=_now())

# eg: /usr/local/python/hubble.python/lib/python2.7/site-packages/salt_ssh-2019.2.0-py2.7.egg/salt/log/handlers/__init__.py
_sdp_r = re.compile(r'(?:(?:site|dist)-packages|hubble-libs)/(.+)/(.+\.py)$')
def snapdiff_tracemalloc(max_traces=None, sort_by=lambda x: -x['size'], group_by='filename',
        compare_to='first', include_fglob=None, exclude_fglob=None):
    ''' track memory allocations (requires tracemalloc, which requires python
        patches in python2.7, but not in python3).

        params:
            max_traces :- if specified, limites the number of events to this number
            sort_by    :- key-function for sorting among: 'size', 'size_diff', 'count', 'count_diff'
                          after filtering and reducing the returns, sort them this way
                          default: lambda x: -x['size']
                          set to None to disable
                          (probably only matters when max_traces are set)
            group_by   :- must be one of 'filename' or 'lineno'
                          when comparing and generating stats, group size/counts by this key
            compare_to :- must be one of 'first' or 'last'
                          compare to the start of time ('first') or the last invocation ('last')
                          'last' compares are something like d(mallocs)/dx
        optional filter params:
          If either of these is specified, no other default filters will be applied.
            include_fglob :- default: '*'
            exclude_fglob :- default: 'hubblestack/*/memleak*'
    '''
    if not hasattr(tracemalloc, '_d'):
        tracemalloc._d = dict()
    _d = tracemalloc._d
    filter = _build_snapdiff_filters(include_fglob, exclude_fglob)
    if _d.get('first') is None:
        tracemalloc.start(1) # default is 1 frame in the stack trace
        _d['first'] = _d['last'] = _do_snapdiff_tracemalloc(filter)
        return
    cur = _do_snapdiff_tracemalloc(filter)
    stats = cur['snap'].compare_to(_d[compare_to]['snap'], group_by, cumulative=True)
    _d['last'] = cur
    def fmt_s(s):
        ret = {'time': cur['t'], 'fst': _d['first']['t'], 'count': s.count, 'count_diff': s.count_diff,
            'size': s.size, 'size_diff': s.size_diff, 'fname': '???.??', 'lineno': '?'}
        for tb in s.traceback:
            # NOTE: there's normally only one tb in the traceback, see
            # tracemalloc.start(nframes=1); this is more of a way to avoid
            # exceptions and shorten the filename
            m = _sdp_r.search(tb.filename)
            if m:
                ret['fname'] = m.group(1) + '/' + m.group(2)
                ret['lineno'] = tb.lineno
                return ret
    l0 = len(stats)
    log.info('fst=%d found %d stats', _d['first']['t'], l0)
    stats = [ fmt_s(s) for s in stats ]
    stats = [ s for s in stats if s ]
    if callable(sort_by):
        stats = sorted(stats, key=sort_by)
    l1 = len(stats)
    if l1 != l0:
        log.info('fst=%s reduced to %d stats by filters', _d['first']['t'], l1)
    if stats:
        if max_traces and max_traces > 0:
            stats = stats[:max_traces]
            l2 = len(stats)
            if l2 not in (l0, l1):
                log.info('fst=%s reduced to %d stats by max_traces=%d', _d['first']['t'], l2, max_traces)
        return { 'sourcetype': 'memleak.snapdiff_tracemalloc', 'events': stats }
