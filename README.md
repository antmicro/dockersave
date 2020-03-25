# dockersave

`dockersave` is a tool for downloading Docker images from the registry to a tar file.
It DOES NOT depend on Docker, therefore it is suitable for use in minimal systems where Docker would be considered a bloat dependency.

## Installation

In order to install `dockersave`, please follow the steps below.

1. Clone this repository by running `git clone https://github.com/antmicro/dockersave`.
1. Change your current working directory to `dockersave`.
1. Run `sudo pip install .` - this will resolve the dependencies and install the tool.

### Static compilation

The target of the tool is microservices, containers and embedded systems.
As those tend to be as minimal and concise as possible, and we're trying to reduce the bloat, installing Python might not be an option.
To address this need we tested the scenario of compiling our tool to bytecode and making it statically linked.

In order to proceed, you need to have the following tools on your machine:
1. `patchelf` - usually installable using the package manager of your distribution.
1. `pyinstaller` - install using `pip`.
1. `staticx` - use `pip` like above and see the project [repository](https://github.com/JonathonReinhart/staticx) for reference.
1. `requests` - Python library installable either using your package manager or `pip`.

After you've made sure all the prerequisites are installed, follow the steps below.

1. Clone the repository.
1. Change your current working directory to `dockersave`.
1. Compile the tool by running `pyinstaller -F dockersave/cli.py`.
1. Perform static linking by running `staticx dist/cli dockersave-static`.
1. The resulting binary is `dockersave-static`.

> **WARNING**: Only amd64 binaries may be generated using the method described above.

## Usage

The tool can be used either by the command-line interface or as a Python module.

### CLI

There are many useful arguments available but in order to use the core functionality it suffices to provide the image name just like one normally would when performing operations in Docker.

```
$ dockersave debian
$ ls
library-debian-latest.tar
```

It's worth to note that currently there's no progress bar and, depending on the size of the image and number of layers, it might take some time to download and process the intermediate files.

Should there be any during downloading failure, the user will be notified.

The tool assumes that the user attempts to a registry over HTTPS.
If need be to use an insecure registry (HTTP), please provide the `--insecure` parameter.

### Download flow

Upon running the client pulls the relevant layer files along with manifests and assembles them.

After it has finished laying down the directory structure, it stores the files in an archive (the archiving process can be skipped by passing `--no-tar`).
Then, the directory structure is removed (with the step being preventable as well by means of the `--no-rm` parameter).

By default, the intermediate files along with the resulting archive will be stored in the current working directory.
This behavior can be changed by means of the `--working-dir` parameter.

> **WARNING**: The parameter `--layers-dir` can be used to change the name of a temporary directory for intermediate files, but in most cases you will NOT need it. It's solely for debugging purposes

The resulting tar file will be saved as hyphen-separated image name tokens (namespace, image, tag) unless instructed otherwise using the `--tarname` argument.

### Authentication

User may authenticate either by providing the user and password as command-line arguments (`--user` and `--password` respectively) but please be advised that this is usually a bad idea as it may leave trace in a plaintext shell history file.

For improved security, please use the `--ilogin` parameter.
The user will be asked to provide their credentials in an interactive manner.
