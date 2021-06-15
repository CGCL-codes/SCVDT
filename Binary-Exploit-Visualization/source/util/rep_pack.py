"""
pack replayer to resotre it.
"""

import sys
import os


class rep_pack(object):
    def __init__(self, binary_path, log_path, maps_path):
        assert(isinstance(binary_path, str))
        assert(isinstance(log_path, str))
        assert(isinstance(maps_path, str))

        self._binary_path = binary_path
        self._log_path = log_path
        self._maps_path = maps_path

    def _copy(self, src, dst):
        if os.access(src, os.R_OK) and \
            os.access(dst, os.W_OK) and \
                os.path.isdir(dst):
            os.system("cp -f %s %s" % (src, dst))
            return True
        else:
            print("Failed to copy file %s to %s" % (src, dst))
            return False

    def _create_dir(self, path):
        if os.path.exists(path):
            print("Pack target dir already exists!")
            return os.path.abspath(path)
        else:
            os.system("mkdir %s" % path)
        
        if os.access(path, os.F_OK):
            return path
        else:
            raise(FileNotFoundError("Cannot create pack dir."))
            return 
        

    def _copy_and_fix_path(self, path):
        with open(self._maps_path, 'r') as f:
            maps = f.read()

        fname = self._maps_path.split("/")[-1]
        with open(path+'/'+fname, 'w') as f:
            for line in maps.split('\n'):
                obj_path = line.split(' ')[-1]
                if obj_path == '':
                    f.write(line)
                    f.write('\n')
                    continue
                if os.access(obj_path, os.F_OK):
                    if(self._copy(obj_path, path)):
                        line = line.replace(obj_path, './'+obj_path.split('/')[-1])
                f.write(line)
                f.write('\n')
        

    def pack(self, path = ""):
        assert(isinstance(path, str))
        if not path:
            path = 'packed_' + self._binary_path.split("/")[-1]+'_'+ self._maps_path.split(".")[-1]
        # create dir
        path = self._create_dir(path)
        # copy dependency
        self._copy_and_fix_path(path)
        # copy log file
        self._copy(self._log_path, path)



