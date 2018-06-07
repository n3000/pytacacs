import argparse

from pytacacs_plus import server

parser = argparse.ArgumentParser()
parser.add_argument('-c', '--config', default='/etc/pytacacs/config.cfg', help='Config file')

args = parser.parse_args()

server.run(config=args.config)
