# SPDX-FileCopyrightText: 2023 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0

import os.path
import sys

try:
    from setuptools import find_packages, setup
except ImportError:
    sys.exit('missing setuptools package')


# https://packaging.python.org/en/latest/guides/single-sourcing-package-version/
def read(rel_path):
    here = os.path.abspath(os.path.dirname(__file__))
    with open(os.path.join(here, rel_path), 'r') as fp:
        return fp.read()


def get_version(rel_path):
    for line in read(rel_path).splitlines():
        if line.startswith('__version__'):
            delim = '"' if '"' in line else "'"
            return line.split(delim)[1]
    else:
        raise RuntimeError('Unable to find version string.')


def get_long_description():
    with open('README.md', 'r') as f:
        text = f.read()
    return text


setup(
    name='esp-idf-sbom',
    version=get_version('esp_idf_sbom/__init__.py'),
    author='Espressif Systems',
    author_email='',
    description='SPDX SBOM generator for ESP-IDF projects',
    long_description_content_type='text/markdown',
    long_description=get_long_description(),
    url='https://github.com/espressif/esp-idf-sbom',
    packages=find_packages(),
    python_requires='>=3.7',
    keywords=['espressif', 'embedded', 'spdx', 'sbom'],
    install_requires=[
        'PyYAML',
        'schema',
        'license-expression',
        'rich',
        'pyparsing>=2.2.2',
    ],
    extras_require={
        'dev': [
            'pytest',
            'commitizen',
            'spdx-tools>=v0.8.0rc1',
            'jsonschema',
        ],
    },
    classifiers=[
        'Development Status :: 1 - Planning',
        'Intended Audience :: Developers',
        'Natural Language :: English',
        'Environment :: Console',
        'Topic :: Software Development :: Embedded Systems',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Operating System :: POSIX',
        'Operating System :: Microsoft :: Windows',
        'Operating System :: MacOS :: MacOS X',
    ],
    entry_points={
        'console_scripts': [
            'esp-idf-sbom = esp_idf_sbom.sbom:main',
        ]
    }
)
