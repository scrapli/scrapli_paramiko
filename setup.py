#!/usr/bin/env python
"""scrapli_paramiko - paramiko transport plugin for scrapli"""
import setuptools

from scrapli_paramiko import __version__

__author__ = "Carl Montanari"


with open("README.md", "r", encoding="utf-8") as f:
    README = f.read()

setuptools.setup(
    name="scrapli_paramiko",
    version=__version__,
    author=__author__,
    author_email="carl.r.montanari@gmail.com",
    description="paramiko transport plugin for the scrapli SSH|Telnet screen scraping library",
    long_description=README,
    long_description_content_type="text/markdown",
    url="https://github.com/carlmontanari/scrapli_paramiko",
    packages=setuptools.find_packages(),
    install_requires=["paramiko>=2.6.0"],
    extras_require={},
    classifiers=[
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Operating System :: POSIX :: Linux",
        "Operating System :: MacOS",
    ],
    python_requires=">=3.6",
)
