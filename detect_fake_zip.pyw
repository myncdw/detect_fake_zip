#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import json
import ctypes
import logging
import mmap
import os
import subprocess
import sys
import threading
import time
import queue
from pathlib import Path
from tkinter import Tk, Label
from typing import Dict, Tuple, Optional

# --------------------------------------------------------------------------- #
#                                 常量 & 配置                                #
# --------------------------------------------------------------------------- #

if getattr(sys, 'frozen', False):
    SCRIPT_DIR = Path(sys.executable).resolve().parent
else:
    SCRIPT_DIR = Path(__file__).resolve().parent

MAGIC_HEADERS_JSON = SCRIPT_DIR / "magic_headers.json"
LOG_FILE = SCRIPT_DIR / "analysis.log"


# --------------------------------------------------------------------------- #
#                                 日志配置                                   #
# --------------------------------------------------------------------------- #

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler(sys.stdout),
    ],
)

# --------------------------------------------------------------------------- #
#                                 工具函数                                   #
# --------------------------------------------------------------------------- #

def show_message(msg: str, title: str = "提示"):
    if sys.platform.startswith("win"):
        ctypes.windll.user32.MessageBoxW(0, msg, title, 0)
    else:
        print(f"{title}: {msg}")


def load_magic_headers() -> Dict[bytes, str]:
    try:
        with MAGIC_HEADERS_JSON.open("r", encoding="utf-8") as f:
            data = json.load(f)
        return {
            bytes.fromhex(k.replace(" ", "")): v
            for k, v in data.get("compressed_formats", {}).items()
        }
    except FileNotFoundError:
        logging.error("%s 未找到", MAGIC_HEADERS_JSON)
        show_message(f"配置文件 {MAGIC_HEADERS_JSON.name} 未找到！", "错误")
        return {}
    except Exception as exc:
        logging.error("读取 %s 失败：%s", MAGIC_HEADERS_JSON, exc)
        show_message(f"读取配置文件失败：{exc}", "错误")
        return {}


def find_compressed_start(
    file_path: Path, magic_headers: Dict[bytes, str]
) -> Tuple[int, Optional[str]]:
    with file_path.open("rb") as f:
        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            ustar_idx = mm.find(b"ustar")
            if ustar_idx != -1 and ustar_idx >= 257:
                return ustar_idx - 257, "tar"

            for magic, fmt in sorted(magic_headers.items(), key=lambda x: -len(x[0])):
                if fmt == "tar":
                    continue
                idx = mm.find(magic)
                if idx != -1:
                    return idx, fmt

    return -1, None


def extract_tail(file_path: Path, start_offset: int, fmt: str):
    tail_file = file_path.parent / safe_filename(file_path.stem, fmt)
    try:
        with file_path.open("rb") as src, tail_file.open("wb") as dst:
            src.seek(start_offset)
            while True:
                chunk = src.read(16 * 1024 * 1024)
                if not chunk:
                    break
                dst.write(chunk)
        logging.info("[%s] 提取成功: %s (偏移: %d 字节)",
                     file_path.name, fmt, start_offset)
        open_file(tail_file)
    except Exception as exc:
        logging.error("保存/打开失败：%s", exc)


def safe_filename(stem: str, fmt: str) -> str:
    return f"{stem}_提取.{fmt}".replace(" ", "_").replace(":", "_")


def open_file(path: Path):
    try:
        if sys.platform.startswith("win"):
            os.startfile(path)
        elif sys.platform == "darwin":
            subprocess.run(["open", str(path)], check=True)
        else:
            subprocess.run(["xdg-open", str(path)], check=True)
    except Exception as exc:
        logging.warning("打开 %s 失败：%s", path, exc)

# --------------------------------------------------------------------------- #
#                                 弹窗线程                                   #
# --------------------------------------------------------------------------- #

class ProcessingPopup(threading.Thread):
    def __init__(self, message: str = "正在处理..."):
        super().__init__(daemon=True)
        self.message = message
        self._queue: queue.Queue = queue.Queue()
        self._ready = threading.Event()

    def run(self):
        self.root = Tk()
        self.root.title("处理进度")
        w, h = 360, 100
        x = (self.root.winfo_screenwidth()  - w) // 2
        y = (self.root.winfo_screenheight() - h) // 2
        self.root.geometry(f"{w}x{h}+{x}+{y}")
        self.root.resizable(False, False)
        self.label = Label(self.root, text=self.message, font=("Arial", 11))
        self.label.pack(pady=30)
        self._ready.set()
        self.root.after(100, self._check_queue)
        self.root.mainloop()

    def _check_queue(self):
        while not self._queue.empty():
            msg = self._queue.get_nowait()
            if msg == "__close__":
                self.root.destroy()
                return
            self.label.config(text=msg)
        self.root.after(100, self._check_queue)

    def wait_ready(self):
        self._ready.wait()

    def update_message(self, msg: str):
        self._queue.put(msg)

    def close(self):
        self._queue.put("__close__")

# --------------------------------------------------------------------------- #
#                                 文件处理                                   #
# --------------------------------------------------------------------------- #

def process_file(file_path: Path, magic_headers: Dict[bytes, str],
                 popup: Optional[ProcessingPopup] = None):
    if popup:
        popup.update_message(f"提取: {file_path.name}")

    idx, fmt = find_compressed_start(file_path, magic_headers)
    if idx == -1 or fmt is None:
        logging.info("未找到压缩包标识：%s", file_path)
        return
    
    extract_tail(file_path, idx, fmt)

# --------------------------------------------------------------------------- #
#                                 程序入口                                   #
# --------------------------------------------------------------------------- #

def main():
    if len(sys.argv) != 2:
        show_message("请通过右键文件执行本程序", "提示")
        sys.exit(1)

    target = Path(sys.argv[1])
    if not target.is_file():
        show_message("请选择有效文件", "提示")
        sys.exit(1)

    magic_headers = load_magic_headers()
    if not magic_headers:
        sys.exit(1)

    popup = ProcessingPopup(f"提取: {target.name}")
    popup.start()
    popup.wait_ready()

    try:
        process_file(target, magic_headers, popup)
        popup.update_message("完成！")
        time.sleep(1.2)
    except Exception as exc:
        logging.error("处理出错：%s", exc)
        popup.update_message(f"出错：{exc}")
        time.sleep(2.0)
    finally:
        popup.close()


if __name__ == "__main__":
    main()