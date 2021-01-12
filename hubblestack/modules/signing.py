#!/usr/bin/env python
# coding: utf-8

import os
import logging
import hubblestack.utils.signing as HuS

log = logging.getLogger(__name__)

__virtualname__ = 'signing'

def __virtual__():
    return True

def msign(*targets, **kw):
    """
    Sign a files and directories. Will overwrite whatever's already in MANIFEST.
    Arguments: files and/or directories
    KW Arguments:
        mfname :- the MANIFEST filename (default ./MANIFEST)
        sfname :- the SIGNATURE filename (default ./SIGNATURE)
        private_key :- the private key to use for the signature (default
            /etc/hubble/sign/private.key)
    """
    mfname = kw.get('mfname', 'MANIFEST')
    sfname = kw.get('sfname', 'SIGNATURE')
    private_key = kw.get('private_key', HuS.Options.private_key)

    HuS.manifest(targets, mfname=mfname)
    HuS.sign_target(mfname, sfname, private_key=private_key)

def verify(*targets, **kw):
    """
    Verify files
    Arguments: files and/or directories
    KW Arguments:
        mfname :- the MANIFEST filename (default ./MANIFEST)
        sfname :- the SIGNATURE filename (default ./SIGNATURE)
        cfname :- the CERTIFICATES filename (default ./CERTIFICATES)

        public_crt :- the signing key (default: /etc/hubble/sign/public.crt)
        ca_crt :- the trust chain for the public_crt (default: /etc/hubble/sign/ca-root.crt)
                  can optionally be a list of cert files; in which case, the
                  first file is trusted, and additional files are assumed to be
                  intermediates and are only trusted if a trust path can be
                  found.
    """

    mfname = kw.get('mfname', 'MANIFEST')
    sfname = kw.get('sfname', 'SIGNATURE')
    cfname = kw.get('cfname', 'CERTIFICATES')
    public_crt = kw.get('public_crt', HuS.Options.public_crt)
    ca_crt = kw.get('ca_crt', HuS.Options.ca_crt)
    pwd = os.path.abspath(os.path.curdir)

    log.debug('signing.verify(targets=%s, mfname=%s, sfname=%s, public_crt=%s, ca_crt=%s, cfname=%s, pwd=%s)',
        targets, mfname, sfname, public_crt, ca_crt, cfname, pwd)

    return dict(HuS.verify_files(targets, mfname=mfname, sfname=sfname,
        public_crt=public_crt, ca_crt=ca_crt, extra_crt=cfname))

def enumerate():
    """ enumerate installed certificates """

    x509 = HuS.X509AwareCertBucket()
    return [ ' '.join(x.split()[1:]) for x in x509.trusted ]
