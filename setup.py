import setuptools
import sys

tests_require = ['nose', 'mock']
if sys.version_info < (2, 7, 0):
    tests_require.append('unittest2')

desc = 'Application deployment on CoreOS clusters using fleetd and Consul'

classifiers = ['Development Status :: 3 - Alpha',
               'Environment :: Console',
               'Intended Audience :: Developers',
               'License :: OSI Approved :: BSD License',
               'Operating System :: OS Independent',
               'Programming Language :: Python :: 2',
               'Programming Language :: Python :: 2.6',
               'Programming Language :: Python :: 2.7',
               'Programming Language :: Python :: 3',
               'Programming Language :: Python :: 3.2',
               'Programming Language :: Python :: 3.3',
               'Programming Language :: Python :: 3.4',
               'Programming Language :: Python :: Implementation :: CPython',
               'Programming Language :: Python :: Implementation :: PyPy',
               'Topic :: Communications',
               'Topic :: Internet',
               'Topic :: System :: Boot :: Init',
               'Topic :: System :: Clustering',
               'Topic :: System :: Operating System',
               'Topic :: System :: Software Distribution']

setuptools.setup(name='houston',
                 version='0.2.0',
                 description=desc,
                 long_description=open('README.rst').read(),
                 author='Gavin M. Roy',
                 author_email='gavinr@aweber.com',
                 url='http://houston.readthedocs.org',
                 packages=['houston'],
                 package_data={'': ['LICENSE', 'README.rst']},
                 include_package_data=True,
                 install_requires=['consulate', 'fleetpy', 'pyyaml'],
                 tests_require=tests_require,
                 license='BSD',
                 classifiers=classifiers,
                 entry_points={'console_scripts': ['houston=houston.cli:run']},
                 zip_safe=True)
