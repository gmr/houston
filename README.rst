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

Documentation is available on `ReadTheDocs <https://rabbitpy.readthedocs.org>`_.

There is also an `example configuration directory <example/>`_.

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

When executed, houston has created a tarball of files from the `service's file manifest <example/files/blog.yaml>`_
and uploaded it to Consul's KV database. It then deployed a dynamically created systemd Unit to fleet,
which pulls the tarball from Consul and extracts the files to the CoreOS filesystem.

Once it has verified that job has deployed, it then iterated through the dependent
containers specified in the `manifest <examples/manifest.yaml>`_, submitting and
starting each job, waiting until it is listed as ``active`` in systemd, and then
moves on to the next. It then started the example service, waiting for systemd
to report it as active. Once confirmed, it then stopped any versions of the example
service that do not match the deployment.

One of the more interesting parts for managing stack deployment is the namespacing
of the shared stack elements in fleet, so that updating one stack does not impact
another.  For example, in the configuration, a service may be referred to as only
``pgbouncer:f20fb494``, but when deployed it will be prefixed and versioned
appropriately.

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
