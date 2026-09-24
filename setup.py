#!/usr/bin/env python3
"""
Setup script for sr-sec-py-sns-logger
Python module for structured security logging to AWS SNS
"""

from setuptools import setup, find_packages
import os

# Read the README file
with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

# Read version from __init__.py
version = "2.0.3"
with open("__init__.py", "r", encoding="utf-8") as f:
    for line in f:
        if line.startswith("__version__"):
            version = line.split('"')[1]
            break

setup(
    name="sr-sec-py-sns-logger",
    version=version,
    author="Sunrun Security Team",
    description="Python module for structured security logging to AWS SNS",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/SunRun/sr-sec-py-sns-logger",
    project_urls={
        "Repository": "https://github.com/SunRun/sr-sec-py-sns-logger",
        "Documentation": "https://github.com/SunRun/sr-sec-py-sns-logger/blob/master/README.md",
    },
    py_modules=[
        "security_logging_sns",
        "security_log_fields",
        "sns_publisher",
        "context_helpers",
        "lambda_helpers",
    ],
    python_requires=">=3.7",
    install_requires=[
        "boto3>=1.26.0",
    ],
    extras_require={
        "test": [
            "pytest>=7.0.0",
            "moto>=4.0.0",
        ],
    },
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    keywords="security logging aws sns audit",
)
