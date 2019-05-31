#!/usr/bin/python3 -u
import argparse

from pytacacs_plus import server

parser = argparse.ArgumentParser()
parser.add_argument('-c', '--config', default='/etc/pytacacs/config.cfg', help='Config file')
parser.add_argument('-p', '--port', type=int, default=49, help='Listen port')

args = parser.parse_args()

server.run(config=args.config, port=args.port)
