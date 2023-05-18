import setuptools

setuptools.setup(
        name="docker-image-save",
        version="0.1",
        author="Adam Olech",
        author_email="aolech@antmicro.com",
        description="Download and tar Docker images without Docker.",
        url="https://github.com/antmicro/dockersave",
        packages=["dockersave"],
        python_requires='>=3.6',
        entry_points={
            "console_scripts": ["dockersave = dockersave.cli:main"]
            },
        install_requires=["requests"],
        )
