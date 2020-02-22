# -*- coding: utf-8 -*-
import os
import re
import shutil
import sys

def copy_file(source, destinate):
    src_data = ''
    dst_data = ''
    if os.path.isfile(source):
        with open(source) as f:
            src_data = f.read()
    if os.path.isfile(destinate):
        with open(destinate) as f:
            dst_data = f.read()
    if src_data != dst_data:
        shutil.copy(source, destinate)

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print('python copy_diff_file.py <source_filepath> <dest_filepath>')
        raise ValueError("few argument!")

    copy_file(sys.argv[1], sys.argv[2])
    print(sys.argv[2], end="")
