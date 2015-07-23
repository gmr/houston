Example Houston Configuration
=============================
The files in this repository are for the automated deployment of application
stacks to [CoreOS](https://coreos.com) servers running [fleet](https://github.com/coreos/fleet), 
using [Houston](https://github.com/aweber/houston).

This is a contrived example and is not expected to work out of the box, but instead is intended to demonstrate a starting point.

**Files**

- ``manifest.yaml``: The core houston manifest with environment and service dependency information

**Directories**

- ``files``: Cloud-Init style file manifests for deploying of files as part of service deployment
- ``units/service``: Application/service units
- ``units/shared``: Non-service units
