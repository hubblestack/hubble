#!/usr/bin/env python
# coding: utf-8

import hubblestack.returners.splunk_fdg_return as sfr

def test01():
    """
    Exactly how to resolve these sourcetypes caused some discussion:
        https://github.com/hubblestack/hubble/pull/738
    Here are the discussed items:
    """
    assert sfr._file_url_to_sourcetype('salt://fdg/test.fdg') == 'hubble_fdg_test'
    assert sfr._file_url_to_sourcetype('salt://////fdg///////test.fdg') == 'hubble_fdg_fdg_test'
    assert sfr._file_url_to_sourcetype('/tmp/file/a/b/c/test.fdg') == 'hubble_fdg_tmp_file_a_b_c_test'
    assert sfr._file_url_to_sourcetype('/opt/tmpfdg_test/2fdg_cert_test.fdg') == 'hubble_fdg_opt_tmpfdg_test_2fdg_cert_test'
