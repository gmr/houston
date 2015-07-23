Houston
=======
Easy docker stack deployment to `CoreOS <https://coreos.com>`_ clusters using
`Fleet <http://github.com/coreos/fleet>`_ and `Consul <https://www.consul.io>`_.

Houston installs as a command-line application and is meant to be used for automated
deployment of Dockerized application stacks.

Houston deployments allow for files to be placed onto the host OS, the deployment
of dependency containers, confirmed startup of a container using Consul, and
teardown of previous container versions in a single run.


|Version| |Downloads| |Status| |Coverage| |License|

Installation
------------

Houston may be installed via the `Python package index <http://pypi.python.org>`_
with the tool of your choice:

.. code:: bash

    pip install houston

Documentation
-------------

Documentation is available on `ReadTheDocs <https://houston.readthedocs.org/en/latest>`_.

There is also an `example configuration directory <example/>`_.

Deployment Types
----------------
Houston has 3 deployment types: global, shared stacks, and services. All three types allow for file archive deployments [1]_ using a `cloud-init style <http://cloudinit.readthedocs.org/en/latest/topics/examples.html#writing-out-arbitrary-files>`_ ``write_files`` section.

 - Global deployments place a single list of units intended to be shared across all or a majority of CoreOS instances.
 - A shared stack deployment is like the a global deployment but it is more targeted
 - Service deployments allow for the deployment of a single unit and the shared units that it is dependent upon

Usage Example
-------------
Example of deploying a full stack application:

.. code:: bash

   houston -c config -e test-us-east-1 example 7b7d061b
   INFO     Deploying example-file-deploy@11bede3c.service
   INFO     Deploying example-memcached@1.4.24.service
   INFO     Deploying example-nginx@35f9e1f3.service
   INFO     Deploying example-consul-template-nginx@d3bac01d.service
   INFO     Deploying example-pgbouncer@f20fb494.service
   INFO     Deploying example-consul-template-pgbouncer@d3bac01d.service
   INFO     Deploying example-datadog@ff444e66.service
   INFO     Deploying example@7b7d061b.service
   INFO     example@7b7d061b.service has started
   INFO     Validated service is running with Consul
   INFO     Destroying example@b67b4317.service
   INFO     Deployment of example 7b7d061b and its dependencies successful.
   INFO     Eagle, looking great. You're Go.

When executed, houston creates a tarball of files from the `service's file manifest <example/files/blog.yaml>`_
and uploads it to Consul's KV database. It then deploys a dynamically created systemd unit to fleet,
which pulls the tarball from Consul and extracts the files to the CoreOS filesystem.

In the next step, it iterates through the dependency containers specified in the
`manifest <examples/manifest.yaml>`_, submitting and starting each unit, waiting
until a unit is listed as ``active`` in systemd for all nodes, and then
moves on to the next.

One the dependency containers have started, it starts the example service,
waiting for systemd to report it as active. It then queries Consul for the version
of the service that has started, ensuring that it is running on all the expected
nodes that fleet says it has deployed it to.

Once a deployment has been confirmed, it looks at all units submitted to fleet,
checking to see if there are other versions of containers running than what it deployed.
If so, it will destroy those other containers with fleet.

Finally it will check to see if any other file archive versions exist in Consul's for the
service, removing them if so.

One of the more interesting parts for managing stack deployment is the namespacing
of the shared stack elements in fleet, so that updating one stack does not impact
another.  For example, in the configuration, a service may be referred to as only
``pgbouncer:f20fb494``, but when deployed it will be prefixed and versioned
appropriately as ``example-pgbouncer@f20fb494`` if the service name is ``example``.

Version History
---------------

Available at https://houston.readthedocs.org/en/latest/history.html

.. |Version| image:: https://img.shields.io/pypi/v/houston.svg?
   :target: https://pypi.python.org/pypi/houston

.. |Status| image:: https://img.shields.io/travis/aweber/houston.svg?
   :target: https://travis-ci.org/aweber/houston

.. |Coverage| image:: https://img.shields.io/codecov/c/github/aweber/houston.svg?
   :target: https://codecov.io/github/aweber/houston?branch=master

.. |Downloads| image:: https://img.shields.io/pypi/dm/houston.svg?
   :target: https://pypi.python.org/pypi/houston

.. |License| image:: https://img.shields.io/pypi/l/houston.svg?
   :target: https://houston.readthedocs.org

.. [1] Global file deployments happen after the unit files are deployed so that Consul can be up and running prior to the placement of the global files.
