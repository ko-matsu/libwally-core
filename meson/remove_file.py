# -*- coding: utf-8 -*-
import re
import sys

def remove_file(file):
    if os.path.isfile(file):
        os.remove(file)

if __name__ == '__main__':
    if len(sys.argv) <= 1:
        print('python remove_file.py <filepath> ...')
        raise ValueError("few argument!")

    for index in range(len(sys.argv)):
        if index > 0:
            remove_file(sys.argv[index])
