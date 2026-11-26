import os
import site
import struct

PT_GNU_STACK = 0x6474E551
PF_X = 0x1


def clear_execstack(path):
    with open(path, "r+b") as f:
        header = f.read(64)
        if header[:4] != b"\x7fELF" or header[4] != 2:
            return False
        e_phoff = struct.unpack_from("<Q", header, 32)[0]
        e_phentsize = struct.unpack_from("<H", header, 54)[0]
        e_phnum = struct.unpack_from("<H", header, 56)[0]
        changed = False
        for i in range(e_phnum):
            off = e_phoff + i * e_phentsize
            f.seek(off)
            p_type, p_flags = struct.unpack("<II", f.read(8))
            if p_type == PT_GNU_STACK and (p_flags & PF_X):
                f.seek(off + 4)
                f.write(struct.pack("<I", p_flags & ~PF_X))
                changed = True
        return changed


def main():
    roots = site.getsitepackages() + [site.getusersitepackages()]
    seen = set()
    for root in roots:
        if not root or root in seen or not os.path.isdir(root):
            continue
        seen.add(root)
        for dirpath, _dirnames, filenames in os.walk(root):
            for name in filenames:
                if ".so" in name:
                    path = os.path.join(dirpath, name)
                    try:
                        if clear_execstack(path):
                            print("patched:", path)
                    except OSError:
                        pass
    print("done")


if __name__ == "__main__":
    main()
