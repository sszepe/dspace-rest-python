import setuptools

with open("README.md", "r", encoding="utf_8") as fh:
    long_description = fh.read()

setuptools.setup(
    name="dspace-rest-client",
    version="0.1.12",
    author="Kim Shepherd",
    author_email="kim@the-library-code.de",
    description="A DSpace 7 REST API client library",
    license="BSD-3-Clause",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/the-library-code/dspace-rest-client",
    project_urls={
        "Documentation": "https://github.com/the-library-code/dspace-rest-python/blob/main/README.md",
        "GitHub": "https://github.com/the-library-code/dspace-rest-python",
        "Changelog": "https://github.com/the-library-code/dspace-rest-python/blob/main/CHANGELOG.md",
    },
    classifiers=[
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "License :: OSI Approved :: BSD License",
        "Operating System :: OS Independent",
    ],
    packages=["dspace_rest_client"],
    install_requires=["requests >= 2.27.1",
                      "pysolr >= 3.9.0"],
    python_requires=">=3.8.0",
)
