#!/usr/bin/env python3
"""
Patch normalize-service.py: thêm offset tracking (giống dedup .dedup_offset)
- Lưu byte offset + inode vào .normalize_offset sau mỗi dòng xử lý
- Khi restart: đọc offset file → resume đúng vị trí, không mất log, không duplicate
- LOG_START_POSITION=beginning → vẫn đọc từ đầu (dùng khi test)
- LOG_START_POSITION=end → seek to end nếu không có offset file (production default)

Chạy trên EC2: python3 patch_normalize_offset.py
"""

PATH = "/home/ubuntu/soc_ai/normalize-service.py"

OLD_FOLLOW_FILE = '''def follow_file(path, start_from_beginning=False):
    f = None; last_inode = None; first_open = True; buf = ""
    while True:
        try:
            st = os.stat(path); inode = st.st_ino
            if f is None or inode != last_inode:
                if f:
                    try: f.close()
                    except: pass
                f = open(path, "r", encoding="utf-8", errors="replace")
                last_inode = inode; buf = ""
                if first_open:
                    if not start_from_beginning:
                        f.seek(0, os.SEEK_END)
                    first_open = False
                else:
                    f.seek(0, os.SEEK_SET)
            if st.st_size < f.tell():
                f.seek(0, os.SEEK_SET); buf = ""
            chunk = f.read(4096)
            if not chunk:
                time.sleep(0.05); continue
            buf += chunk
            while "\\n" in buf:
                line, buf = buf.split("\\n", 1)
                yield line
        except FileNotFoundError:
            time.sleep(0.5)
        except Exception as e:
            print(f"[WARN] follow_file: {e}"); time.sleep(0.5)'''

NEW_FOLLOW_FILE = '''NORMALIZE_OFFSET_FILE = os.path.join(
    os.path.dirname(os.path.abspath(os.getenv("NORMALIZED_PATH", "/home/ubuntu/soc_ai/log_normalized.json"))),
    ".normalize_offset"
)


def _load_normalize_offset():
    """Đọc offset đã lưu: trả về (inode, byte_offset) hoặc (None, None)."""
    try:
        if os.path.exists(NORMALIZE_OFFSET_FILE):
            with open(NORMALIZE_OFFSET_FILE) as f:
                parts = f.read().strip().split(":")
                if len(parts) == 2:
                    return int(parts[0]), int(parts[1])
    except Exception:
        pass
    return None, None


def _save_normalize_offset(inode: int, byte_offset: int):
    """Ghi offset hiện tại ra file để resume sau restart."""
    try:
        with open(NORMALIZE_OFFSET_FILE, "w") as f:
            f.write(f"{inode}:{byte_offset}")
    except Exception as e:
        print(f"[WARN] save_normalize_offset: {e}")


def follow_file(path, start_from_beginning=False):
    """
    Follow file với offset persistence:
    - Nếu có .normalize_offset và inode khớp → resume đúng vị trí
    - Nếu start_from_beginning=True → đọc từ byte 0 (test mode)
    - Nếu không có offset + start_from_beginning=False → seek to end (production)
    Yield từng dòng hoàn chỉnh (không kèm newline).
    """
    f = None; last_inode = None; first_open = True; buf = ""
    saved_inode, saved_offset = _load_normalize_offset()

    while True:
        try:
            st = os.stat(path); inode = st.st_ino
            if f is None or inode != last_inode:
                if f:
                    try: f.close()
                    except: pass
                f = open(path, "r", encoding="utf-8", errors="replace")
                last_inode = inode; buf = ""

                if first_open:
                    if start_from_beginning:
                        # Test mode: đọc từ đầu, xóa offset cũ
                        f.seek(0, os.SEEK_SET)
                        if os.path.exists(NORMALIZE_OFFSET_FILE):
                            os.remove(NORMALIZE_OFFSET_FILE)
                        print(f"[normalize] Offset: reading from beginning (test mode)")
                    elif saved_inode == inode and saved_offset is not None:
                        # Resume từ vị trí đã lưu
                        f.seek(min(saved_offset, st.st_size), os.SEEK_SET)
                        print(f"[normalize] Offset: resumed at byte {saved_offset} (inode={inode})")
                    else:
                        # Production default: seek to end, bỏ qua log cũ
                        f.seek(0, os.SEEK_END)
                        _save_normalize_offset(inode, f.tell())
                        print(f"[normalize] Offset: starting at end (byte {f.tell()}, inode={inode})")
                    first_open = False
                else:
                    # File rotation (inode thay đổi): đọc từ đầu file mới
                    f.seek(0, os.SEEK_SET)
                    print(f"[normalize] Offset: file rotated, reading new file from beginning")

            # File bị truncate (logrotate): reset
            current_pos = f.tell()
            if st.st_size < current_pos:
                print(f"[normalize] Offset: file truncated ({st.st_size} < {current_pos}), resetting")
                f.seek(0, os.SEEK_SET); buf = ""
                _save_normalize_offset(inode, 0)

            chunk = f.read(4096)
            if not chunk:
                time.sleep(0.05); continue

            buf += chunk
            while "\\n" in buf:
                line, buf = buf.split("\\n", 1)
                # Lưu offset sau mỗi dòng hoàn chỉnh
                _save_normalize_offset(inode, f.tell() - len(buf.encode("utf-8")))
                yield line

        except FileNotFoundError:
            time.sleep(0.5)
        except Exception as e:
            print(f"[WARN] follow_file: {e}"); time.sleep(0.5)'''


def apply_patch():
    with open(PATH) as f:
        content = f.read()

    if "_load_normalize_offset" in content:
        print("⏭️  Already applied")
        return

    if OLD_FOLLOW_FILE not in content:
        print("⚠️  Pattern NOT FOUND")
        # Debug: tìm dòng gần nhất
        idx = content.find("def follow_file")
        if idx >= 0:
            print(f"   Found follow_file at char {idx}:")
            print(content[idx:idx+200])
        return

    content = content.replace(OLD_FOLLOW_FILE, NEW_FOLLOW_FILE)
    print("✅ follow_file() with offset tracking: applied")

    with open(PATH, "w") as f:
        f.write(content)

    import subprocess
    r = subprocess.run(["python3", "-m", "py_compile", PATH], capture_output=True, text=True)
    print("\n✅ Syntax OK" if r.returncode == 0 else f"\n❌ Syntax error:\n{r.stderr}")


if __name__ == "__main__":
    apply_patch()
