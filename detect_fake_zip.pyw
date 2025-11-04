#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import json
import ctypes
import logging
import os
import subprocess
import sys
import threading
import queue
from pathlib import Path
from tkinter import Tk, Label
from typing import Dict, Tuple, Optional

# --------------------------------------------------------------------------- #
#                                 常量 & 配置                                #
# --------------------------------------------------------------------------- #

# 获取当前执行文件所在目录（无论是 py 还是 exe）
if getattr(sys, 'frozen', False):
    # 打包后的情况
    SCRIPT_DIR = Path(sys.executable).resolve().parent
else:
    # 源码运行
    SCRIPT_DIR = Path(__file__).resolve().parent

MAGIC_HEADERS_JSON = SCRIPT_DIR / "magic_headers.json"
LOG_FILE = SCRIPT_DIR / "伪装分析.log"

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
    # 跨平台弹窗提示（Windows 使用 MessageBox，其余输出控制台）。
    if sys.platform.startswith("win"):
        ctypes.windll.user32.MessageBoxW(0, msg, title, 0)
    else:
        print(f"{title}: {msg}")

def load_magic_headers() -> Dict[bytes, str]:
    # 读取压缩格式文件头 JSON
    try:
        with MAGIC_HEADERS_JSON.open("r", encoding="utf-8") as f:
            data = json.load(f)

        compressed = {
            bytes.fromhex(k.replace(" ", "")): v
            for k, v in data.get("compressed_formats", {}).items()
        }

        return compressed

    except FileNotFoundError:
        logging.error("%s 未找到，请确保配置文件存在。", MAGIC_HEADERS_JSON)
        show_message(f"配置文件 {MAGIC_HEADERS_JSON.name} 未找到！", "错误")
        return {}

    except Exception as exc:
        logging.error("读取 %s 失败：%s", MAGIC_HEADERS_JSON, exc)
        show_message(f"读取配置文件失败：{exc}", "错误")
        return {}


def find_compressed_start(
    data: bytes, magic_headers: Dict[bytes, str]
) -> Tuple[int, Optional[str]]:
    # 查找压缩包起始位置，返回 (偏移量, 格式)

    # 特殊处理 tar 格式
    if len(data) >= 263 and data[257:263] == b"ustar":
        return 0, "tar"
    
    # 查找其他压缩格式
    for magic, fmt in magic_headers.items():
        idx = data.find(magic)
        if idx != -1:
            return idx, fmt
    
    return -1, None


def safe_filename(base: str, suffix: str) -> str:
    # 生成安全文件名
    return f"{base}.{suffix}".replace(" ", "_").replace(":", "_")


def open_file(path: Path):
    #  跨平台打开文件
    try:
        if sys.platform.startswith("win"):
            os.startfile(str(path.resolve()))
        elif sys.platform == "darwin":
            subprocess.run(["open", str(path.resolve())], check=True)
        else:
            subprocess.run(["xdg-open", str(path.resolve())], check=True)
    except Exception as exc:
        logging.warning("打开 %s 失败：%s", path, exc)

# --------------------------------------------------------------------------- #
#                                 弹窗线程                                   #
# --------------------------------------------------------------------------- #

class ProcessingPopup(threading.Thread):
    # Tk 弹窗线程，用于显示处理进度

    def __init__(self, message: str = "正在处理..."):
        super().__init__()
        self.message = message
        self._queue = queue.Queue()
        self._stop_event = threading.Event()

    def run(self):
        self.root = Tk()
        self.root.title("处理进度")
        w, h = 300, 100
        x = (self.root.winfo_screenwidth() - w) // 2
        y = (self.root.winfo_screenheight() - h) // 2
        self.root.geometry(f"{w}x{h}+{x}+{y}")
        self.root.resizable(False, False)

        self.label = Label(self.root, text=self.message, font=("Arial", 12))
        self.label.pack(pady=30)

        self.root.after(100, self.check_queue)
        self.root.mainloop()

    def check_queue(self):
        while not self._queue.empty():
            msg = self._queue.get()
            if msg == "__close__":
                self.root.destroy()
                return
            self.label.config(text=msg)
        if not self._stop_event.is_set():
            self.root.after(100, self.check_queue)

    def update_message(self, msg: str):
        self._queue.put(msg)

    def close(self):
        self._stop_event.set()
        self._queue.put("__close__")

# --------------------------------------------------------------------------- #
#                                 主逻辑                                       #
# --------------------------------------------------------------------------- #

def process_file(file_path: Path, popup: Optional[ProcessingPopup] = None):
    # 处理单个文件，只提取压缩包部分
    if popup:
        popup.update_message(f"提取: {file_path.name}")

    try:
        data = file_path.read_bytes()
    except Exception as exc:
        logging.error("无法读取 %s：%s", file_path, exc)
        return

    magic_headers = load_magic_headers()
    if not magic_headers:
        return  # 配置加载失败

    idx, fmt = find_compressed_start(data, magic_headers)

    # 如果未找到压缩头或偏移为0，则跳过
    if idx == -1:
        logging.info("未找到压缩包标识：%s", file_path)
        return
    if idx == 0:
        logging.info("跳过偏移为0的文件：%s (格式: %s)", file_path.name, fmt)
        return

    base_name = file_path.stem
    dir_name = file_path.parent

    # 提取压缩包部分
    tail_data = data[idx:]
    tail_file = dir_name / safe_filename(base_name, f"提取.{fmt}")

    try:
        tail_file.write_bytes(tail_data)
        logging.info(
            "[%s] 提取成功: %s (偏移: %d 字节, 大小: %d 字节)",
            file_path.name,
            fmt,
            idx,
            len(tail_data),
        )

        # 打开提取的压缩包
        open_file(tail_file)

    except Exception as exc:
        logging.error("保存/打开失败：%s", exc)

def process_path(target_path: Path):
    # 仅处理单个文件
    popup = ProcessingPopup("提取压缩包中...")
    popup.start()

    try:
        if not target_path.is_file():
            show_message("请选择单个文件运行本程序", "提示")
            logging.warning("跳过无效输入：%s (不是文件)", target_path)
            return

        popup.update_message(f"提取: {target_path.name}")
        process_file(target_path, popup)
        popup.update_message("处理完成！")
        logging.info("处理完成：%s", target_path.name)

    finally:
        if hasattr(popup, "root"):
            popup.root.after(1500, popup.close)

# --------------------------------------------------------------------------- #
#                                 程序入口                                   #
# --------------------------------------------------------------------------- #


def main():
    if len(sys.argv) != 2:
        show_message("请通过右键文件或文件夹执行本程序", "提示")
        sys.exit(1)

    target = Path(sys.argv[1])
    process_path(target)


if __name__ == "__main__":
    main()