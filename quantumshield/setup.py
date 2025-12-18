"""Setup script for QuantumShield."""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="quantumshield",
    version="1.0.0",
    author="QuantumShield Team",
    author_email="team@quantumshield.io",
    description="AI-Powered Next-Generation IPS/Firewall System",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/quantumshield/quantumshield",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    python_requires=">=3.10",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "quantumshield=quantumshield.cli.main:main",
        ],
    },
    include_package_data=True,
    package_data={
        "quantumshield": [
            "config/**/*",
            "config/**/**/*",
        ],
    },
)

