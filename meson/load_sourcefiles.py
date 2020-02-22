# -*- coding: utf-8 -*-
import re
import sys

def read_file(file, trim = False, offset_line = 1, lf_str = '/'):
    count = 1
    result = ''
    file_data_list = []
    with open(file) as f:
        file_data_list = f.readlines()
    for line in file_data_list:
        cur_count = count
        count += 1
        if cur_count < offset_line:
            continue
        value = line
        if trim:
            value = value.translate(str.maketrans({'\\': '', ' ': ''}))
        if lf_str == '\\':
            value = value.translate(str.maketrans({'/': '\\'}))
        if len(value) > 1:
            result += value
            # print('line = ' + value.replace('\n', ''))
    # cut the terminal linefeed.
    return re.sub('\\n+$', '', result)

if __name__ == '__main__':
    if len(sys.argv) <= 2:
        print('python load_sourcefiles.py <filepath> <lf>')
        raise ValueError("few argument!")

    print(read_file(sys.argv[1], True, 2, sys.argv[2]), end="")
