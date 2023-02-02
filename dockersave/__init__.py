#!/usr/bin/env python3

import requests, os, json, hashlib, tarfile, shutil, subprocess
from os.path import join
from requests.auth import HTTPBasicAuth
from dockersave.exceptions import UnsupportedManifest

json_template = {
        "id": "",
        "created": "0001-01-01T00:00:00Z",
        "container_config": {
            "Hostname": "",
            "Domainname": "",
            "User": "",
            "AttachStdin": False,
            "AttachStdout": False,
            "AttachStderr": False,
            "Tty": False,
            "OpenStdin": False,
            "StdinOnce": False,
            "Env": None,
            "Cmd": None,
            "Image": "",
            "Volumes": None,
            "WorkingDir": "",
            "Entrypoint": None,
            "OnBuild": None,
            "Labels": None
            }
        }

def get_auth_endpoint(registry_url):
    api = "{}/v2".format(registry_url)

    r = requests.get(api)

    how_to_auth = r.headers['Www-Authenticate']

    hta_split = how_to_auth.split(",")

    endpoint = hta_split[0].split("=")[1].replace('"', '')
    service = hta_split[1].split("=")[1].replace('"', '')

    return endpoint, service

def get_token(image, user=None, password=None, auth_endpoint="https://auth.docker.io/token",service="registry.docker.io"):
    scope = "repository:{}:pull".format(image)

    if user is not None and password is not None:
        r = requests.get(auth_endpoint, params = {'service':service, 'scope':scope}, auth=HTTPBasicAuth(user, password))
    else:
        r = requests.get(auth_endpoint, params = {'service':service, 'scope':scope})

    r.raise_for_status()

    return r.json()['token']

def get_manifest(image, tag, token, registry_url):
    request_url = "{}/v2/{}/manifests/{}".format(registry_url, image, tag)

    supported_fat_manifests = [
            'application/vnd.docker.distribution.manifest.list.v2+json',
            'application/vnd.oci.image.index.v1+json',
            ]

    supported_manifests = [
            'application/vnd.docker.distribution.manifest.v2+json',
            'application/vnd.oci.image.manifest.v1+json',
            ]

    for manifest_type in supported_manifests+supported_fat_manifests:
        r = requests.get(
                request_url, 
                headers={
                    'Authorization':'Bearer {}'.format(token), 
                    'Accept': manifest_type
                    }
                )

        # Image does not exist or unsupported manifest type.
        if r.status_code == 404:
            continue
        elif r.headers["content-type"] in supported_fat_manifests:
            return get_manifest(image, r.json()['manifests'][0]["digest"], token, registry_url)
        else:
            break

    r.raise_for_status()
    return r

def get_layers_digests(manifest_json):
    digests = []

    for layer in manifest_json['layers']:
        digests.append(layer['digest'])

    return digests

def get_blob(image, digest, token, registry_url):
    request_url = "{}/v2/{}/blobs/{}".format(registry_url, image, digest)

    headers = {'Authorization':'Bearer {}'.format(token)}

    r = requests.get(request_url, headers=headers)

    return r

def save_blob_chunked(image, digest, filename, token, registry_url):
    request_url = "{}/v2/{}/blobs/{}".format(registry_url, image, digest)

    headers = {'Authorization':'Bearer {}'.format(token)}

    with requests.get(request_url, headers = headers, stream=True) as r:
        r.raise_for_status()
        with open(filename, 'wb') as f:
            for chunk in r.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)

def sha256(string):
    return hashlib.sha256(string.encode()).hexdigest()

def lexer(string, secure=True):
    tokens = {
            'registry_url':'',
            'image':'',
            'tag':''
            }

    staging = string.split("/")

    if ":" in staging[-1]:
        tag_split = staging[-1].split(":") 
        tokens['tag'] = tag_split[1]
        staging[-1] = tag_split[0]
    else:
        tokens['tag'] = "latest"

    if "." in staging[0]:
        if secure:
            protocol = "https://"
        else:
            protocol = "http://"

        tokens['registry_url'] = protocol+staging.pop(0)
    else:
        tokens['registry_url'] = "https://registry-1.docker.io"

    tokens['image'] = "/".join(staging)

    if len(staging) == 1:
        tokens['image'] = "library/{}".format(tokens['image'])

    return tokens

def lexer_wrapper(string, user=None, password=None, secure=True):
    l = lexer(string)
    img = Image(l['image'], l['tag'], registry_url=l['registry_url'], user=user, password=password)
    return img

class Image:
    def __init__(self, image, tag, user=None, password=None, other_tags=False, registry_url="https://registry-1.docker.io"):
        self.image = image
        self.tag = tag
        self.registry_url = registry_url
        self.flat = "{}:{}".format(self.image, self.tag).replace("/","-").replace(":","_")

        self.user = user
        self.password = password

        try:
            self.auth = get_auth_endpoint(registry_url)
        except requests.exceptions.HTTPError:
            self.auth = None
        except KeyError:
            self.auth = None

        if self.auth is not None:
            self.token = get_token(image, user=user, password=password, auth_endpoint=self.auth[0], service=self.auth[1])
        else:
            self.token = None

        if other_tags:
            self.taglist = self.__get_tag_list()['tags']
        else:
            self.taglist = None

        self.manifest_response = get_manifest(image, tag, self.token, self.registry_url)

        self.manifest = self.manifest_response.json()

        self.digests = get_layers_digests(self.manifest)

        self.config_digest=self.manifest['config']['digest']
        self.config = get_blob(self.image, self.manifest['config']['digest'], self.token, self.registry_url).json()

    def __get_tag_list(self):
        request_url = "{}/v2/{}/tags/list".format(self.registry_url, self.image)

        headers = {'Authorization':'Bearer {}'.format(self.token)}

        r = requests.get(request_url, headers=headers)
        r.raise_for_status()

        return r.json()

    def download(self, path="", layersdir=None, tar=False, rm=False, gunzip=False, xz=False, tarname=None):
        if layersdir is None:
            layersdir = self.flat

        os.makedirs(join(path, layersdir), exist_ok=True)

        config_file = "{}.json".format(self.config_digest.replace('sha256:',''))

        fake_layers_for_json = []

        with open(join(path, layersdir, config_file), 'w') as f:
            json.dump(self.config, f)

        repositories = {self.image: {self.tag:''}}

        with open(join(path, layersdir, "repositories"), 'w') as f:
            json.dump(repositories, f)

        fake_layer_digest = ""

        for layer in self.digests:
            parent_fake_layer_digest = fake_layer_digest

            fake_layer_digest = sha256("{}\n{}".format(parent_fake_layer_digest, layer))

            fake_layers_for_json.append("{}/layer.tar".format(fake_layer_digest))

            inner_dir = join(path, layersdir, fake_layer_digest)

            os.makedirs(inner_dir, exist_ok=True)

            with open(join(inner_dir, "VERSION"), 'w') as f:
                f.write("1.0")

            layer_json = json_template

            layer_json['id'] = fake_layer_digest

            if parent_fake_layer_digest:
                layer_json['parent'] = parent_fake_layer_digest

            with open(join(inner_dir, "json"), 'w') as f:
                json.dump(layer_json, f)

            if self.token is not None:
                self.token = get_token(self.image, user=self.user, password=self.password, auth_endpoint=self.auth[0], service=self.auth[1])

            tarpath = join(inner_dir, "layer.tar")

            save_blob_chunked(self.image, layer, tarpath, self.token, self.registry_url)

            if gunzip:
                gzpath = join(inner_dir, "layer.tar.gz")
                os.rename(tarpath, gzpath)
                subprocess.run("gunzip {}".format(gzpath), shell=True, check=True)



        manifest = [
                {
                    "Config": config_file,
                    "RepoTags": ["{}:{}".format(self.image, self.tag)],
                    "Layers": fake_layers_for_json
                    }
                ]

        with open(join(path, layersdir,"manifest.json"), 'w') as f:
            json.dump(manifest, f)

        if tarname is None:
            tarname = join(path, "{}.tar".format(self.flat))
        else:
            tarname = join(path, tarname)

        if xz:
            tarmode="w:xz"
        else:
            tarmode="w"

        def slashfilter(tarinfo):
            if tarinfo.name == '':
                tarinfo.name = ".workaround"
            return tarinfo

        if tar:
            tar = tarfile.open(tarname, tarmode)
            tar.add(join(path, layersdir), arcname="", filter=slashfilter, recursive=True)
            tar.close()

        if rm:
            shutil.rmtree(join(path, layersdir), ignore_errors=True)
