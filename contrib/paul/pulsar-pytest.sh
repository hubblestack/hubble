#!/usr/bin/env bash


export DEBUG_SHOW_PULSAR_LOGS=1
export PYTHONPATH=.

pytest --tb=short -xv tests/unittests/test_pulsar.py
