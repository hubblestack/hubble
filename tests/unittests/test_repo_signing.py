#!/usr/bin/env python
# coding: utf-8

import os, sys
from pytest import fixture
import hubblestack.utils.signing as sig

@fixture(scope='module', params=['rsa', '448', '25519'])
def cdbt(request):
    yield request.param

@fixture(scope='function')
def no_ppc():
    def nuke():
        for i in ('py', 'pyc'):
            if os.path.isfile('hubblestack/pre_packaged_certificates.{}'.format(i)):
                os.unlink('hubblestack/pre_packaged_certificates.{}'.format(i))
    nuke()
    if 'hubblestack.pre_packaged_certificates' in sys.modules:
        del sys.modules['hubblestack.pre_packaged_certificates']
    yield True
    nuke()

@fixture(scope='session')
def targets():
    _t = [ 'tests/unittests/resources/test-{}.file'.format(i) for i in 'abcd' ]
    for fname in _t:
        if not os.path.isfile(fname):
            with open(fname, 'w') as fh:
                fh.write(fname + ', lol\n')
    return _t

def cdb(fname, t, n, fmt='{t}-{n}'):
    sdname = fmt.format(t=t, n=n)
    base = os.path.join('tests/unittests/resources/pretend-certs', sdname)
    return os.path.join(base, fname)

V = sig.STATUS.VERIFIED
U = sig.STATUS.UNKNOWN
F = sig.STATUS.FAIL

def test_read_certs(no_ppc, cdbt):
    fname = cdb('bundle.pem', cdbt, 1)
    fnam2 = cdb('ca-root.crt', cdbt, 1)

    with open(fname, 'r') as fh:
        dat = fh.read()

    file_read = tuple(sig.read_certs(fname))
    str__read = tuple(sig.read_certs(dat))

    def dc(cobj):
        return sig.ossl.dump_certificate(sig.ossl.FILETYPE_PEM, cobj)

    assert len(file_read) == 2 == len(str__read)
    for i in range(len(file_read)):
        assert dc(file_read[i]) == dc(str__read[i])

    three_certs = tuple(sig.read_certs(fnam2, fname))
    assert len(three_certs) == 3

    fname = cdb('public-1.crt', cdbt, 1)
    file_read = tuple(sig.read_certs(fname))
    assert len(file_read) == 1

    fname = cdb('private-1.key', cdbt, 1)
    file_read = tuple(sig.read_certs(fname))
    assert len(file_read) == 1

def test_x509_basics(no_ppc, cdbt):
    """
    ca-root signed both of the intermediate-1/2 certs

    rsa1:intermediate-1 signed the rsa1:public-1.crt
    rsa1:intermediate-2 signed the rsa1:public-2.crt

    rsa2:public-1.crt is signed by an unrelated untrusted ca-root
    """

    def acert(x, y):
        return sig.X509AwareCertBucket(x,y).authenticate_cert()

    # we can verify that both intermediate certs relate to this ca-root
    assert acert(cdb('intermediate-1.crt', cdbt, 1), cdb('ca-root.crt', cdbt, 1)) == V
    assert acert(cdb('intermediate-2.crt', cdbt, 1), cdb('ca-root.crt', cdbt, 1)) == V

    # the intermediate certs can't be verified without the root cert
    # (they can't be verified, but that's all we can really say)
    assert acert(cdb('public-1.crt', cdbt, 1), cdb('intermediate-1.crt', cdbt, 1)) == U
    assert acert(cdb('public-1.crt', cdbt, 1), cdb('intermediate-2.crt', cdbt, 1)) == U

    assert acert(cdb('public-2.crt', cdbt, 1), cdb('intermediate-1.crt', cdbt, 1)) == U
    assert acert(cdb('public-2.crt', cdbt, 1), cdb('intermediate-2.crt', cdbt, 1)) == U

    # with the root cert, the two intermediate certs can verify their child certs only
    # (we can't verify public-1 with intermediate-2, but we can tell it's from
    # the right modulo group, so we can't say the cert is bad either)
    ri1 = (cdb('ca-root.crt', cdbt, 1), cdb('intermediate-1.crt', cdbt, 1))
    ri2 = (cdb('ca-root.crt', cdbt, 1), cdb('intermediate-2.crt', cdbt, 1))
    assert acert(cdb('public-1.crt', cdbt, 1), ri1) == V
    assert acert(cdb('public-1.crt', cdbt, 1), ri2) == U

    assert acert(cdb('public-2.crt', cdbt, 1), ri1) == U
    assert acert(cdb('public-2.crt', cdbt, 1), ri2) == V

    # with the root cert, the bundle (both intermediates) can verify either child key
    bndl = (cdb('ca-root.crt', cdbt, 1), cdb('bundle.pem', cdbt, 1))
    assert acert(cdb('public-1.crt', cdbt, 1), bndl) == V
    assert acert(cdb('public-2.crt', cdbt, 1), bndl) == V

    # rsa2:public-1 and rsa2:private-1 are from a totally different ca-root
    # this should give us a real actual FAIL condition *iff* the CN matches.
    #
    # NOTE: that the fail condition will not manifest unless teh issuer CN
    # matches between the rsa1/ and rsa2/ certificate databases. If the CN of
    # the issuer differs, the code will be 20 (issuer not found) rather than
    # 7 (signature failed)
    assert acert(cdb('public-1.crt', cdbt, 2), bndl) == F

def test_msign_and_verify_files(__salt__, targets, no_ppc, cdbt):
    inverse = {2:1, 1:2}
    sig.Options.ca_crt = (cdb('ca-root.crt', cdbt, 1), cdb('bundle.pem', cdbt, 1))

    for i in (1,2):
        # setup key-{i} and sign the repo
        sig.Options.public_crt  = cdb('public-{}.crt'.format(i), cdbt, 1)
        sig.Options.private_key = cdb('private-{}.key'.format(i), cdbt, 1)
        __salt__['signing.msign'](*targets)

        # verify that we trust the files
        res = sig.verify_files(targets, public_crt=sig.Options.public_crt, ca_crt=sig.Options.ca_crt)
        for thing in [ 'MANIFEST' ] + list(targets):
            assert thing in res and res[thing] == V

        # let's mess with one file and see how we do
        with open(targets[-1], 'a') as fh:
            fh.write('hi there!\n')
        res2 = sig.verify_files(targets, public_crt=sig.Options.public_crt, ca_crt=sig.Options.ca_crt)
        assert targets[-1] in res2 and res2[targets[-1]] == F # we ruined it
        assert targets[0]  in res2 and res2[targets[0]]  == V # still good

        # swap our configs to use the other public key
        # but don't resign the file; uh oh, these aren't signed right now!!
        sig.Options.public_crt  = cdb('public-{}.crt'.format(inverse[i]), cdbt, 1)
        sig.Options.private_key = cdb('private-{}.key'.format(inverse[i]), cdbt, 1)

        res = sig.verify_files(targets, public_crt=sig.Options.public_crt, ca_crt=sig.Options.ca_crt)
        for thing in [ 'MANIFEST' ] + list(targets):
            assert thing in res and res[thing] == F

def test_cert_outside_ca(__salt__, targets, no_ppc, cdbt):
    # the public/private-3 keypair is not from the same modulo group
    # as the other keys. we should get a FAIL result here
    sig.Options.ca_crt = (cdb('ca-root.crt', cdbt, 1), cdb('bundle.pem', cdbt, 1))
    sig.Options.public_crt  = cdb('public-1.crt', cdbt, 2)
    sig.Options.private_key = cdb('private-1.key', cdbt, 2)
    __salt__['signing.msign'](*targets)
    res = sig.verify_files(targets, public_crt=sig.Options.public_crt, ca_crt=sig.Options.ca_crt)
    for thing in [ 'MANIFEST' ] + list(targets):
        assert thing in res and res[thing] == F

def test_no_ca_given(__salt__, targets, no_ppc, cdbt):
    # the public/private-3 is from some unknown CA
    # ... so if we don't specify any CA, then our result should be unknown
    sig.Options.ca_crt = ''
    sig.Options.public_crt  = cdb('public-1.crt', cdbt, 2)
    sig.Options.private_key = cdb('private-1.key', cdbt, 2)
    __salt__['signing.msign'](*targets)
    res = sig.verify_files(targets, public_crt=sig.Options.public_crt, ca_crt=sig.Options.ca_crt)
    for thing in [ 'MANIFEST' ] + list(targets):
        assert thing in res and res[thing] == U

def test_no_SIGNATURE(__salt__, targets, no_ppc, cdbt):
    # the public/private-3 is from some unknown CA
    # ... so if we don't specify any CA, then our result should be unknown
    sig.Options.ca_crt = (cdb('ca-root.crt', cdbt, 1), cdb('bundle.pem', cdbt, 1))
    sig.Options.public_crt  = cdb('public-1.crt', cdbt, 1)
    sig.Options.private_key = cdb('private-1.key', cdbt, 1)
    __salt__['signing.msign'](*targets)
    os.unlink('SIGNATURE')
    res = sig.verify_files(targets, public_crt=sig.Options.public_crt, ca_crt=sig.Options.ca_crt)
    for thing in [ 'MANIFEST' ] + list(targets):
        assert thing in res and res[thing] == U

def test_no_MANIFEST(__salt__, targets, no_ppc, cdbt):
    # If we have a SIGNATURE without a MANIFEST, we should fail, because our
    # MANIFEST hash will not match the signed hash -- a sig without manifest is
    # probably a really bad sign and also a rare condition anyway. Also,
    # without the manifest, the most we can say about the rest of the files is
    # UNKNOWN
    sig.Options.ca_crt = (cdb('ca-root.crt', cdbt, 1), cdb('bundle.pem', cdbt, 1))
    sig.Options.public_crt  = cdb('public-1.crt', cdbt, 1)
    sig.Options.private_key = cdb('private-1.key', cdbt, 1)
    __salt__['signing.msign'](*targets)
    os.unlink('MANIFEST')
    res = sig.verify_files(targets, public_crt=sig.Options.public_crt, ca_crt=sig.Options.ca_crt)
    assert 'MANIFEST' in res and res['MANIFEST'] == F
    for thing in list(targets):
        assert thing in res and res[thing] == U

def test_no_MANIFEST_or_SIGNATURE(__salt__, targets, no_ppc, cdbt):
    # if we have a SIGNATURE without a MANIFEST, we should fail
    # because our MANIFEST hash will not match the signed hash
    # (a sig without manifest is probably a really bad sign and also a rare condition anyway)
    sig.Options.ca_crt = (cdb('ca-root.crt', cdbt, 1), cdb('bundle.pem', cdbt, 1))
    sig.Options.public_crt  = cdb('public-1.crt', cdbt, 1)
    sig.Options.private_key = cdb('private-1.key', cdbt, 1)
    __salt__['signing.msign'](*targets) # re-sign just to make sure the two files are present
    os.unlink('MANIFEST') # but remove them
    os.unlink('SIGNATURE') # bahleeted
    res = sig.verify_files(targets, public_crt=sig.Options.public_crt, ca_crt=sig.Options.ca_crt)
    len(res) == 0

def pretend_finder(path, saltenv, **kwargs):
    full = rel = os.path.normpath(path)
    if not os.path.isfile(rel):
        full = os.path.join('tests/unittests/resources', rel)
    full = os.path.realpath(full)
    if os.path.isfile(full):
        return {'path': full, 'rel': rel}
    return {'path': '?pf?', 'rel': '?pf?'} # not found for real: ?pf?

wrapped_finder = sig.find_wrapf( # but due to verification trouble, ?wf?
    not_found={'path': '?wf?', 'rel': '?wf?'})(pretend_finder)

def test_fs_find_wrapper_correct_required(__salt__, targets, no_ppc, cdbt):
    btargets = [ (os.path.basename(x),x) for x in targets ]
    sig.Options.ca_crt = (cdb('ca-root.crt', cdbt, 1), cdb('bundle.pem', cdbt, 1))
    sig.Options.require_verify = True

    for i in (1,2):
        sig.Options.public_crt = cdb('public-{}.crt'.format(i), cdbt, 1)
        sig.Options.private_key = cdb('private-{}.key'.format(i), cdbt, 1)
        __salt__['signing.msign'](*targets)

        for btarget,target in btargets:
            full = os.path.realpath(target)
            assert pretend_finder(btarget, 'base').get('path') == full
            assert wrapped_finder(btarget, 'base').get('path') == full

def test_fs_find_wrapper_correct_optional(__salt__, targets, no_ppc, cdbt):
    btargets = [ (os.path.basename(x),x) for x in targets ]
    sig.Options.ca_crt = (cdb('ca-root.crt', cdbt, 1), cdb('bundle.pem', cdbt, 1))
    sig.Options.require_verify = False

    for i in (1,2):
        sig.Options.public_crt = cdb('public-{}.crt'.format(i), cdbt, 1)
        sig.Options.private_key = cdb('private-{}.key'.format(i), cdbt, 1)
        __salt__['signing.msign'](*targets)

        for btarget,target in btargets:
            full = os.path.realpath(target)
            assert pretend_finder(btarget, 'base').get('path') == full
            assert wrapped_finder(btarget, 'base').get('path') == full

def test_fs_find_wrapper_unknown_required(__salt__, targets, no_ppc, cdbt):
    btargets = [ (os.path.basename(x),x) for x in targets ]
    sig.Options.ca_crt = ''
    sig.Options.require_verify = True

    for i in (1,2):
        sig.Options.public_crt = cdb('public-{}.crt'.format(i), cdbt, 1)
        sig.Options.private_key = cdb('private-{}.key'.format(i), cdbt, 1)
        __salt__['signing.msign'](*targets)

        for btarget,target in btargets:
            full = os.path.realpath(target)
            assert pretend_finder(btarget, 'base').get('path') == full
            assert wrapped_finder(btarget, 'base').get('path') == '?wf?'

def test_fs_find_wrapper_unknown_optional(__salt__, targets, no_ppc, cdbt):
    btargets = [ (os.path.basename(x),x) for x in targets ]
    sig.Options.ca_crt = ''
    sig.Options.require_verify = False

    for i in (1,2):
        sig.Options.public_crt = cdb('public-{}.crt'.format(i), cdbt, 1)
        sig.Options.private_key = cdb('private-{}.key'.format(i), cdbt, 1)
        __salt__['signing.msign'](*targets)

        for btarget,target in btargets:
            full = os.path.realpath(target)
            assert pretend_finder(btarget, 'base').get('path') == full
            assert wrapped_finder(btarget, 'base').get('path') == full

def test_fs_find_wrapper_incorrect_required(__salt__, targets, no_ppc, cdbt):
    btargets = [ (os.path.basename(x),x) for x in targets ]
    sig.Options.ca_crt = ''
    sig.Options.require_verify = True

    for i in (1,2):
        sig.Options.public_crt = cdb('public-{}.crt'.format(i), cdbt, 1)
        sig.Options.private_key = cdb('private-{}.key'.format(i), cdbt, 1)
        __salt__['signing.msign'](*targets)
        sig.Options.public_crt = cdb('public-{}.crt'.format(3), cdbt, 1)

        for btarget,target in btargets:
            full = os.path.realpath(target)
            assert pretend_finder(btarget, 'base').get('path') == full
            assert wrapped_finder(btarget, 'base').get('path') == '?wf?'

def test_fs_find_wrapper_incorrect_optional(__salt__, targets, no_ppc, cdbt):
    btargets = [ (os.path.basename(x),x) for x in targets ]
    sig.Options.ca_crt = ''
    sig.Options.require_verify = False

    for i in (1,2):
        sig.Options.public_crt = cdb('public-{}.crt'.format(i), cdbt, 1)
        sig.Options.private_key = cdb('private-{}.key'.format(i), cdbt, 1)
        __salt__['signing.msign'](*targets)
        sig.Options.public_crt = cdb('public-3.crt', cdbt, 2)

        for btarget,target in btargets:
            full = os.path.realpath(target)
            assert pretend_finder(btarget, 'base').get('path') == full
            assert wrapped_finder(btarget, 'base').get('path') == '?wf?'

def test_bundled_certs(no_ppc, cdbt):
    # no_ppc ensures there's no pre_packaged_certificates;
    # we then load pretend-certs/public-1, pretend-certs/ca-root and
    # pretend-certs/bundle into x1.
    bndl = (cdb('ca-root.crt', cdbt, 1), cdb('bundle.pem', cdbt, 1))
    x1 = sig.X509AwareCertBucket(cdb('public-1.crt', cdbt, 1), bndl)

    with open('hubblestack/pre_packaged_certificates.py', 'w') as ofh:
        ofh.write('ca_crt = """\n')
        with open(cdb('ca-root.crt', cdbt, 2)) as ifh:
            for line in ifh:
                ofh.write(line)
        ofh.write('"""\n')
        ofh.flush()

    import hubblestack.pre_packaged_certificates as ppc

    # now there definitely is a pre_packaged_certificates file
    # we lie to X509 and say we want pretend-certs/ca-root.crt
    # but because that's defined in pre_packaged_certificates, it loads that
    # instead.
    bndl = (cdb('ca-root.crt', cdbt, 1), cdb('bundle.pem', cdbt, 1))
    x2 = sig.X509AwareCertBucket(cdb('public-1.crt', cdbt, 1), bndl)

    for x,y in zip(x1.trusted, x2.trusted):
        x_fingerprint, x_subject = x.split()
        y_fingerprint, y_subject = y.split()
        assert x_subject == y_subject
        if 'CN=car' in x_subject:
            assert x_fingerprint != y_fingerprint
        else:
            assert x_fingerprint == y_fingerprint

def test_msign_and_verify_signature(__salt__, targets, no_ppc, cdbt):
    sig.Options.ca_crt = (cdb('ca-root.crt', cdbt, 1), cdb('bundle.pem', cdbt, 1))

    sig.Options.public_crt  = cdb('public-1.crt', cdbt, 1)
    sig.Options.private_key = cdb('private-1.key', cdbt, 1)

    __salt__['signing.msign'](*targets)
    res = sig.verify_signature('MANIFEST', 'SIGNATURE',
        public_crt=sig.Options.public_crt, ca_crt=sig.Options.ca_crt)

    assert res == sig.STATUS.VERIFIED

    sig.Options.public_crt  = cdb('public-1.crt', cdbt, 1)
    sig.Options.private_key = cdb('private-2.key', cdbt, 1)

    __salt__['signing.msign'](*targets)
    res = sig.verify_signature('MANIFEST', 'SIGNATURE',
        public_crt=sig.Options.public_crt, ca_crt=sig.Options.ca_crt)

    assert res == sig.STATUS.FAIL

    sig.Options.public_crt  = cdb('public-1.crt', cdbt, 2)
    sig.Options.private_key = cdb('private-1.key', cdbt, 2)

    __salt__['signing.msign'](*targets)
    res = sig.verify_signature('MANIFEST', 'SIGNATURE',
        public_crt=sig.Options.public_crt, ca_crt=sig.Options.ca_crt)

    assert res == sig.STATUS.FAIL


def test_like_a_daemon_with_bundle(__salt__, no_ppc, cdbt):
    sig.Options.ca_crt = (cdb('ca-root.crt', cdbt, 1), cdb('bundle.pem', cdbt, 1))
    sig.Options.public_crt = cdb('public-1.crt', cdbt, 1)
    sig.Options.private_key = cdb('private-1.key', cdbt, 1)

    __salt__['signing.msign']('tests/unittests/conftest.py')
    res = __salt__['signing.verify']('tests/unittests/conftest.py')
    assert len(res) == 2
    for item in res:
        assert res[item] == sig.STATUS.VERIFIED
