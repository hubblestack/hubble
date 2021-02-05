#!/usr/bin/env python
# coding: utf-8

import hubblestack.extmods.fileserver.s3fs as hs_s3fs

def test_s3fs_opts(__opts__):
    hs_s3fs.__opts__ = __opts__
    key, keyid, service_url, verify_ssl, kms_keyid, location, path_style, https_enable, cache_expire = hs_s3fs._get_s3_key()

    assert https_enable is True
    assert verify_ssl   is True
    assert location     is None
    assert path_style   is None
    assert service_url  is None
    assert keyid        is None
    assert key          is None
    assert kms_keyid    is None
    assert cache_expire == 1800

    __opts__['s3.location'] = a = 'us-east-1'
    __opts__['s3.key'] = b = '1234512345123451234512345123451234512345'

    key, keyid, service_url, verify_ssl, kms_keyid, location, path_style, https_enable, cache_expire = hs_s3fs._get_s3_key()
    assert location == a
    assert key      == b
