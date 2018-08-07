Getting Started with HubbleStack
================================

Installation
------------

.. _install_packages:

Installation Using Released Packages (Recommended)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Various pre-built packages targeting several popular operating systems can be
found under `Releases <https://github.com/hubblestack/hubble/releases>`_.

Alternative Installations and Packaging
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Building Hubble packages through Dockerfile
"""""""""""""""""""""""""""""""""""""""""""

Dockerfile aims to build the Hubble v2 packages easier. Dockerfiles for the
distribution you want to build can be found at the path ``/pkg``. For example,
dockerfile for centos6 distribution is at the path ``/pkg/centos6/``

To build an image::

    docker build -t <image_name>

To run the container (which will output the package file in your current
directory)::

    docker run -it --rm -v `pwd`:/data <image_name>

Installing using setup.py
"""""""""""""""""""""""""

::

    sudo yum install git python-setuptools -y
    git clone https://github.com/hubblestack/hubble
    cd hubble
    sudo python setup.py install

If there are errors installing, it may mean that your setuptools is out of
date. Try this::

    easy_install pip
    pip install -U setuptools

``setup.py`` installs a hubble "binary" into ``/usr/bin/``.

A config template has been placed in ``/etc/hubble/hubble``. Modify it to your
specifications and needs. You can do ``hubble -h`` to see the available runtime
options.

The first two commands you should run to make sure things are set up correctly
are ``hubble --version`` and ``hubble test.ping``.


Basic Usage
-----------

Hubble runs as a standalone agent on each server you wish to monitor. To get
started, install Hubble using one of the above installation options. Once
Hubble is installed, check that everything is working correctly:

#. Run ``hubble test.ping``. This should return true.
#. Run ``hubble hubble.audit``. You should see the results of the default audit
   profiles run against the box

Quickstart via Docker container
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Get up and running with any supported distribution by installing net-tools in a
running docker container.  ``docker run -it {distro:tag} sh`` the desired
agent, then use the appropriate package manager to install net-tools:

To run centos:7 container::

    docker run -it centos:7 sh

To install net-tools::

    yum install net-tools

Follow instructions above in :ref:`install_packages`.
