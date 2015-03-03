from setuptools import setup, find_packages
import sys, os

version = '1.0.0'

install_requires = [
    'pypcap',
    'dpkt',
]
if sys.version_info < (2, 7):
    install_requires.append('argparse')

setup(name='redis-sniffer',
      version=version,
      description="A redis sniffer & analyzer",
      long_description=open('README.md').read(),
      classifiers=['Topic :: Database',
                   'Topic :: Utilities',
                   'Topic :: System :: Systems Administration',
                   'Programming Language :: Python',],
      keywords='',
      author='Jesse Lesperance',
      author_email='jesse@jplesperance.me',
      url='https://github.com/jplesperance/redis-sniffer',
      license='MIT',
      packages=find_packages(exclude=['ez_setup', 'examples', 'tests']),
      include_package_data=True,
      zip_safe=False,
      install_requires=install_requires,
      entry_points={
          'console_scripts': [
              'redis-sniffer = redis_sniffer.sniffer:main',
          ],
      },
      dependency_links=[
          'http://github.com/xupeng/pypcap.git',
          'http://dpkt.googlecode.com/files/dpkt-1.7.tar.gz#egg=dpkt-1.7',
      ]
      )
