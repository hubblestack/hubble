#!/usr/bin/env python
# coding: UTF-8

from threading import Thread
from queue import Queue
from time import sleep

class Worker(object):
    def __init__(self, name):
        self.name = name
        self.q = Queue()
        self.t = Thread(target=self._work)
        self.t.daemon = True
        self.t.start()

    def process_item(self, item):
        print("{0.name} dealing with {1}".format(self, item))
        sleep(0.5)

    def _work(self):
        while True:
            item = self.q.get()
            self.process_item(item)
            self.q.task_done()

    def add(self, item):
        self.q.put(item)

    def join(self):
        self.q.join()

if __name__ == "__main__":
    w = Worker('blah')
    for i in range(3):
        w.add("supz-{0}".format(i))
        w.add("mang-{0}".format(i))
    w.join()
