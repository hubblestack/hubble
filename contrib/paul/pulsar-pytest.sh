#!/usr/bin/env bash


export DEBUG_WM=1
export PYTHONPATH=.

pytest --tb=short -xv tests/unittests/test_pulsar_watch_manager.py 
