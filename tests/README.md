# Hubble Unittests

## Running unit tests

Follow the steps to run unit tests for Hubble
```
yum install git wget vim python python-setuptools -y
git clone https://github.com/rashmip29/hubble
cd hubble 
git checkout hubble_unit_tests
pip install -r test-requirements.txt
py.test (this will run all the test files in /tests/unittests/)
py.test tests/unittests/test_pulsar.py (this will run the test file mentioned)
```

## Adding new unit test

The files in `/tests/unittests/` are unit tests. We are using pytest framework to write unit tests. If you want to add new tests please use the same framework. The new unit tests can be added at the path `/tests/unittests/`.

[Python Unit Testing](https://wiki.corp.adobe.com/display/CoreServicesTeam/Python+Unit+Testing) CST wiki is helpful to understand pytest framework and to write new unit tests.
