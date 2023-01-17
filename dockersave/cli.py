import argparse, sys, getpass
from dockersave._version import __version__
from dockersave import Image, lexer
from requests.exceptions import HTTPError
from dockersave.exceptions import UnsupportedManifest
from shutil import which

def meta(manifest):
    from pprint import PrettyPrinter as pp
    p = pp(indent=4)
    p.pprint(manifest)

def download(args):
    l = lexer(args.image, not args.insecure)

    if args.verbose:
        from json import dumps
        print(dumps(l, indent=4, separators=(',',': ')))
    if args.ilogin:
        args.user = input("User: ")
        args.password = getpass.getpass()

    if args.gunzip:
        if not which("gunzip"):
            print("Gunzip not installed!")
            sys.exit(1)

    try:
        img = Image(
                l['image'], 
                l['tag'], 
                user=args.user, 
                password=args.password,
                other_tags=args.tags,
                registry_url=l['registry_url'])

        if args.tags:
            from pprint import PrettyPrinter as pp
            p = pp(indent=4)
            p.pprint(img.taglist)
            sys.exit(0)

        if args.metadata:
            meta(img.manifest)
            sys.exit(0)
        if args.sha:
            print(img.manifest_response.headers["Docker-Content-Digest"].strip("sha256:"))
            sys.exit(0)

        img.download(path=args.working_dir, layersdir=args.layers_dir, tar=not args.no_tar, rm=not args.no_rm, gunzip=args.gunzip, xz=args.xz, tarname=args.tarname)
    except HTTPError as e:
        print("Pulling failed: {}".format(e))
        sys.exit(1)
    except UnsupportedManifest:
        print("Unable to pull the image due to unsupported manifest!")

def get_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument('image', type=str)
    parser.add_argument('--user', type=str)
    parser.add_argument('--password', type=str)
    parser.add_argument('--working-dir', type=str, default="")
    parser.add_argument('--layers-dir', type=str)
    parser.add_argument('--no-rm', action='store_true')
    parser.add_argument('--ilogin', action='store_true')
    parser.add_argument('--no-tar', action='store_true')
    parser.add_argument('--insecure', action='store_true')
    parser.add_argument('--tarname', type=str)
    parser.add_argument('--gunzip', action='store_true')
    parser.add_argument('--xz', action='store_true')
    parser.add_argument('--verbose', action='store_true')
    parser.add_argument('--metadata', action='store_true')
    parser.add_argument('--sha', action='store_true')
    parser.add_argument('--tags', action='store_true')
    parser.add_argument('--version', action='version', version=__version__)
    parser.set_defaults(func=download)
    
    return parser

def main():
    parser = get_parser()
    args = parser.parse_args()
    args.func(args)

if __name__ == '__main__':
    main()
