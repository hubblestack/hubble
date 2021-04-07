# Hubble Packages
The Hubble package builds as an installer that can be shipped and directly installed on a host. This folder contains information about how the Hubble installer is built.

## LINUX
**osquery:** Osquery is a major part of hubble package and needs to be packaged inside the hubble build. This is a pre-requirement to building hubble packages. You must either use the Dockerfile present in the **osquery** folder to build the osquery tar file or provide your own custom built osquery tar file to the later steps.

Production and dev builds for Hubble use different Dockerfiles which are placed in different folders.

**dev:** Prior to building production level packages, development builds are created and tested for functionality. The **dev** folder further contains operating system specific folders. Each of the specific OS folder contains files required to create a hubble installer. You must place the osquery tar file next to the Dockerfile and supply the argument **OSQUERY_TAR_FILENAME** to the Dockerfile with the actual tar filename as its value.

**production:** The production level build folders are kept in this folder and are segregated according to the operating systems. Build steps remain the same. Here also you must place the osquery tar file next to the Dockerfile and supply the argument **OSQUERY_TAR_FILENAME** to the Dockerfile with the actual tar filename as its value.

Steps to use the Dockerfile and create Hubble packages are mentioned in the respective Dockerfiles themselves.

## WINDOWS
Windows package can simply be built using the Dockerfile in the **windows** folder. The windows Hubble build does not require a separate osquery package, since the osquery here is installed using chocolatey.

Steps to use the Dockerfile and create Hubble package are mentioned in the Dockerfile itself.

Note: Debian7 is no longer supported by Hubble and hence is kept separately in an **abandoned** folder.
