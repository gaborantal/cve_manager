import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="cvemanager",
    version="0.0.1",
    author="Gabor Antal",
    author_email="antalgabor1993@gmail.com",
    description="A script for managing cves",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/gaborantal/cve_manager",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
    entry_points={
        'console_scripts': [
            'cvemanager=cvemanager.main:main',
        ],
    },
)