# 🧩 Detect Fake Zip

一个用于检测并提取伪装成其他格式的压缩包的小工具。  
例如：看似是 `video.mp4`，其实内部是 `zip`、`rar`、`7z` 等压缩文件。

---

## 📦 使用方法

1. 将以下文件放在同一目录：

detect_fake_zip.exe
magic_headers.json

2. 双击运行 `detect_fake_zip.exe`，选择要检测的文件。

程序会自动检测并提取伪装压缩包，输出：

文件名.提取.zip

同时在目录中生成日志：

伪装分析.log


---

## 🖱️ 添加右键菜单（Windows）

右键文件即可快速检测伪装压缩包。

1. 将以下文件放在同一目录：

```
detect_fake_zip.exe
install.bat
remove.bat
magic_headers.json
```

2. 运行 `install.bat` 安装右键菜单。  
3. 若要移除，运行 `remove.bat`。

---

## 🧠 原理简介

程序会扫描文件的二进制内容，寻找常见压缩格式的文件头（Magic Number），
当检测到压缩包标识时，从该位置提取出真实压缩数据。
