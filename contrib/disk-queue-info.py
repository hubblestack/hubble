#!/usr/bin/env python

from __future__ import print_function

import os
import argparse
import json
from json.decoder import WHITESPACE
from hubblestack.hec.dq import DiskQueue

def get_args(*a):
    parser = argparse.ArgumentParser(description='hubble disk queue info extractor')
    parser.add_argument("cachedir", nargs='+')
    parser.add_argument('-p', '--peek', '--print', action='store_true',
        help='attempt to dump all the bytes found in queue in the order they would be dequeued')
    parser.add_argument('-e', '--evil-decode', action='store_true',
        help='attempt to decode all json found in queue (implies -p) and pretty-print them')
    parser.add_argument('-c', '--with-color', action='store_true',
        help='attempt to pull in pygments and colorize the output of -e (implies -p and -e)')
    parser.add_argument('-m', '--show-meta', action='store_true',
        help='attempt to show meta-data as a comment in peek mode or a spurious _META_ field in evil mode')
    args = parser.parse_args(*a)
    if args.with_color:
        args.evil_decode = True
    if args.evil_decode:
        args.peek = True
    return args

def show_info(dirname):
    dq = DiskQueue(dirname)
    print("QUEUE={} ITEMS={} SIZE={}".format(dirname, dq.cn, dq.sz))

def evil_decode(docbytes):
    decoder = json.JSONDecoder()
    idx = WHITESPACE.match(docbytes, 0).end()
    while idx < len(docbytes):
        try:
            obj, end = decoder.raw_decode(docbytes, idx)
            yield obj
            idx = WHITESPACE.match(docbytes, end).end()
        except ValueError as e:
            print('docbytes:\n', docbytes)
            raise

def read_entries(dirname, evil=False, color=False, meta=False):
    dq = DiskQueue(dirname)
    for item,meta in dq.iter_peek():
        if evil:
            for obj in evil_decode(item):
                if meta:
                    obj['_META_'] = meta
                obj = json.dumps(obj, sort_keys=True, indent=2)
                if color:
                    try:
                        from pygments import highlight, lexers, formatters
                        obj = highlight(obj, lexers.JsonLexer(),
                            formatters.TerminalFormatter())
                    except ImportError:
                        pass
                print(obj)
        else:
            if meta:
                print('# ', json.dumps(meta))
            print(item)

def main(args):
    for dirname in args.cachedir:
        try:
            if not os.path.isdir(dirname):
                raise Exception("directory does not exist")
            if args.peek:
                read_entries(dirname, evil=args.evil_decode, color=args.with_color, meta=args.show_meta)
            else:
                show_info(dirname)
        except Exception as e:
            print("# Exception while reading {}: {}".format(dirname, repr(e)))

if __name__ == '__main__':
    try:
        main(get_args())
    except KeyboardInterrupt:
        pass
