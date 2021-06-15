import getopt
import re
import sys

if __name__ == '__main__':
    try:
        options, args = getopt.getopt(sys.argv[1:], "p", ["part="])
    except getopt.GetoptError:
        sys.exit()
    parts = {'1': 'vulnerability init', '2': 'diff init', '3': 'exploit init', '4': 'dependent file download', '5': 'dependency init', '6':'rule init', '7': 'update graph'}
    part = None
    software_name = None
    cve_id = None
    for option, value in options:
        if option in ("-p", "--part"):
            print("part:", parts[value])
            part = value
    if part is None:
        print('option not exist.')
        exit()
    else:
        if part == '1':
            pass
        elif part == '2':
            pass
        elif part == '3':
            pass
        elif part == '4':
            pass
        elif part == '5':
            pass
        elif part == '6':
            pass
        elif part == '7':
            pass
        else:
            print('invalid input.')
            exit()
