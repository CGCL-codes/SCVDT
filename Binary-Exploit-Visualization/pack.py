import sys
import os


def printable_usage():
    output = "Usage:\n"
    output += "python pack.py [maps_log_path] [syscalls_path] [target_dir_path]/default\n"
    output += "if target_dir_path is 'default', [target_dir_path]=/tmp/work/record_packed"
    return output


def parse_maps(maps):
    lines = maps.split("\n")
    new_maps = ""
    paths = set()
    for i in range(len(lines)):
        line = lines[i]

        if "got bp" in line or line == "":
            new_maps += line + "\n"
            continue

        parts = line.split(" ")
        path = parts[-1]
        if path == "":
            new_maps += line + "\n"
            continue
        elif path[0] == "[":
            new_maps += line + "\n"
            continue
        else:
            for j in range(len(parts)):
                if j == len(parts)-1:
                    new_maps += "./" + parts[j].split("/")[-1]
                    break
                else:
                    new_maps += parts[j] + " "
            new_maps += "\n"
        if path not in paths:
            paths.add(path)
    return new_maps, paths


def copy_libs(paths, target_path):
    for path in paths:
        # copy_path = os.path.join(target_path, path.split("/")[-1])
        os.system("cp %s %s" % (path, target_path))
    return


def pack_maps(maps_path, target_path):
    with open(maps_path, "r") as f:
        new_maps, paths = parse_maps(f.read())
        f.close()

    with open(os.path.join(target_path, "maps"), "w") as f:
        f.write(new_maps)
        f.close()

    copy_libs(paths, target_path)


def parse_maps_dump(dumps):
    new_maps_dump = ""
    dumps = dumps.split("\n")[:-1]
    assert (len(dumps)&1 == 0)
    for i in range(0, len(dumps), 2):
        info = dumps[i]
        mem = dumps[i+1]
        parts = info.split(" ")
        path = parts[-1]
        if path == "":
            new_maps_dump += info + "\n"
            new_maps_dump += mem + "\n"
            continue
        elif path[0] == "[":
            new_maps_dump += info + "\n"
            new_maps_dump += mem + "\n"
            continue
        else:
            for j in range(len(parts)):
                if j == len(parts)-1:
                    new_maps_dump += "./" + path.split("/")[-1]
                    break
                else:
                    new_maps_dump += parts[j] + " "
            new_maps_dump += "\n" + mem + "\n"

    return new_maps_dump


def pack_maps_dump(maps_dump_path, target_path):
    with open(maps_dump_path, "r") as f:
        new_maps_dump = parse_maps_dump(f.read())
        f.close()

    with open(os.path.join(target_path, "maps.dump"), "w") as f:
        f.write(new_maps_dump)
        f.close()


def pack_syscalls_record(syscalls_path, target_path):
    os.system("cp %s %s" % (syscalls_path, target_path))


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print(printable_usage())
        exit(-1)

    maps_path = sys.argv[1]
    syscalls_path = sys.argv[2]
    target_path = sys.argv[3]
    if target_path == "default":
    	target_path = "/tmp/work/record_packed"
    	if not os.access("/tmp/work", os.F_OK):
    		os.mkdir("/tmp/work")
    if not os.access(maps_path, os.F_OK):
        print("[maps_log_path] do not exist!")
        exit(-1)
    if not os.access(syscalls_path, os.F_OK):
        print("[syscalls_path] do not exist!")
        exit(-1)
    os.system("rm -rf %s"%target_path)
    if not os.path.exists(target_path):
        os.mkdir(target_path)
        if not os.path.exists(target_path):
            print("[target_dir_path] do not exist!")
            exit(-1)
    pack_maps(maps_path, target_path)
    pack_maps_dump(maps_path+".dump", target_path)
    pack_syscalls_record(syscalls_path, target_path)
    exit(0)


