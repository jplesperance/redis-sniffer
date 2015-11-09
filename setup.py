from setuptools import setup, find_packages
import sys

version='1.1.0'

install_requires = [
    'pypcap',
    'dpkt',
    'hiredis',
]

if sys.version_info < (2, 7):
    install_requires.append('argparse')

setup(name='redis-sniffer',
      version=version,
      description="A redis sniffing & event logging utility",
      long_description=open('README.md').read(),
      classifiers=['Topic :: Database',
                   'Topic :: Utilities',
                   'Topic :: System :: Systems Administration',
                   'Programming Language :: Python'],
      keywords='Redis',
      author='Jesse Lesperance',
      author_email='jesse@jplesperance.me',
      url='https://github.com/eternalprojects/redis-sniffer',
      license='MIT',
      packages=find_packages(exclude=['ez_setup', 'examples', 'tests']),
      include_package_data=True,
      zip_safe=False,
      install_requires=install_requires,
      entry_points={
          'console_scripts': [
              'redis-sniffer = redis_sniffer.main:main',
          ],
      },
     )
