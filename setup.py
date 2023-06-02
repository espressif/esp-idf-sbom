from setuptools import setup
from setuptools import find_packages


VERSION = '1.0.0'
DESCRIPTION = 'Short description PYPI'
LONG_DESCRIPTION = '''
## Long description PYPI (PYPI documentation page)

'''

setup(
    name="esp-idf-sbom",
    version=VERSION,
    author="Espressif Systems",
    author_email="roland@espressif.com",
    description=DESCRIPTION,
    long_description_content_type="text/markdown",
    long_description=LONG_DESCRIPTION,
    url="https://github.com/espressif/esp-idf-sbom",
    packages=find_packages(),
    install_requires=[],
    keywords=['python', 'espressif'],
    classifiers=[
        "Development Status :: 1 - Planning",
        "Intended Audience :: Developers",
        "Natural Language :: English",
        "Environment :: Console",
        "Topic :: Software Development :: Embedded Systems",
        "License :: OSI Approved :: GNU General Public License v2 or later (GPLv2+)",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Operating System :: POSIX",
        "Operating System :: Microsoft :: Windows",
        "Operating System :: MacOS :: MacOS X",
    ],
)
