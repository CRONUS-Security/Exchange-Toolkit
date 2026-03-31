#!/usr/bin/env python3
"""FaceAtlas Nuitka 构建脚本"""

import subprocess
import sys
import os

def build():
    """使用 Nuitka 构建可执行文件"""
    
    print("=" * 60)
    print("开始使用 Nuitka 编译 MailCrawler...")
    print("=" * 60)
    
    # Nuitka 编译命令
    cmd = [
        sys.executable, "-m", "nuitka",
        "--standalone",  # 独立模式，包含所有依赖
        "--onefile",  # 生成单个可执行文件

        # 设置 jobs
        "--jobs=4",  # 使用 4 个线程编译，视 CPU 核心数调整
        
        # 输出设置
        "--output-dir=build",
        "--output-filename=MailCrawler.exe",
        
        # Windows 设置
        # "--windows-console-mode=attach",  # 附加到控制台（用于调试），可改为 disable
        # "--enable-plugin=pyside6",  # 如果使用 PySide6，启用插件
        # "--windows-icon-from-ico=icon.ico",  # 如果有图标文件，取消注释
        
        # 包含必要的包（解决 rich 的动态导入问题）
        "--include-package=rich",
        "--include-package=rich._unicode_data",
        "--include-package-data=rich",
        
        # 包含其他核心包
        # "--include-package=PySide6",
        # "--include-package=cv2",
        # "--include-package=numpy",
        
        # 包含项目模块
        # "--include-package=core",
        # "--include-package=ui",
        
        # 包含数据文件（ONNX 模型）
        # "--include-data-dir=models=models",
        
        # 优化选项
        # "--assume-yes-for-downloads",
        # "--show-progress",
        # "--show-memory",
        
        # 移除一些警告
        # "--nowarn-mnemonic",
        
        # 主文件
        "MailCrawler.py"
    ]
    
    print(f"\n执行命令:\n{' '.join(cmd)}\n")
    
    try:
        result = subprocess.run(cmd, check=True)
        print("\n" + "=" * 60)
        print("编译成功！")
        print("可执行文件位置: build/MailCrawler.exe")
        print("=" * 60)
        return 0
    except subprocess.CalledProcessError as e:
        print("\n" + "=" * 60)
        print(f"编译失败: {e}")
        print("=" * 60)
        return 1
    except KeyboardInterrupt:
        print("\n\n用户中断编译")
        return 1

if __name__ == "__main__":
    sys.exit(build())