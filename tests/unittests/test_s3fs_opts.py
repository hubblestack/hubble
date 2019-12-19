#!/usr/bin/env python
# coding: utf-8

import hubblestack.extmods.fileserver.s3fs as hs_s3fs

def test_s3fs_opts(__opts__):
    hs_s3fs.__opts__ = __opts__
    s3fs_opts = hs_s3fs._get_s3_key()

    assert s3fs_opts['https_enable'] is True
    assert s3fs_opts['verify_ssl']   is True
    assert s3fs_opts['location']     is None
    assert s3fs_opts['path_style']   is None
    assert s3fs_opts['service_url']  is None
    assert s3fs_opts['keyid']        is None
    assert s3fs_opts['key']          is None
    assert s3fs_opts['kms_keyid']    is None

    __opts__['s3.location'] = a = 'us-east-1'
    __opts__['s3.key'] = b = '1234512345123451234512345123451234512345'

    s3fs_opts = hs_s3fs._get_s3_key()
    assert s3fs_opts['location'] == a
    assert s3fs_opts['key']      == b

