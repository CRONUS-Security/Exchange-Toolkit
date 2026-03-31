import subprocess
import sys
import os

def build():    
    print("=" * 60)
    print("Starting Nuitka compilation for MailCrawler...")
    print("=" * 60)
    
    # Nuitka Compilation command
    cmd = [
        sys.executable, "-m", "nuitka",
        "--standalone",  # Standalone mode, includes all dependencies
        "--onefile",  # Generate a single executable

        # Set jobs
        "--jobs=4",  # Use 4 threads for compilation, adjust based on CPU cores
        
        # Output settings
        "--output-dir=build",
        "--output-filename=MailCrawler.exe",
        
        # Windows settings
        # "--windows-console-mode=attach",  # Attach to console (for debugging), can be changed to disable
        # "--enable-plugin=pyside6",  # Enable plugin if using PySide6
        # "--windows-icon-from-ico=icon.ico",  # Uncomment if you have an icon file
        
        # Include necessary packages (resolve dynamic imports for rich)
        "--include-package=rich",
        "--include-package=rich._unicode_data",
        "--include-package-data=rich",
        
        # Include other core packages
        # "--include-package=PySide6",
        # "--include-package=cv2",
        # "--include-package=numpy",
        
        # Include project modules
        # "--include-package=core",
        # "--include-package=ui",
        
        # Include data files (ONNX models)
        # "--include-data-dir=models=models",
        
        # Optimization options
        "--assume-yes-for-downloads",
        # "--show-progress",
        # "--show-memory",
        
        # Remove some warnings
        # "--nowarn-mnemonic",
        
        # Target file
        "MailCrawler.py"
    ]
    
    print(f"\nExecuting command:\n{' '.join(cmd)}\n")
    
    try:
        result = subprocess.run(cmd, check=True)
        print("\n" + "=" * 60)
        print("Compilation successful!")
        print("Executable location: build/MailCrawler.exe")
        print("=" * 60)
        return 0
    except subprocess.CalledProcessError as e:
        print("\n" + "=" * 60)
        print(f"Compilation failed: {e}")
        print("=" * 60)
        return 1
    except KeyboardInterrupt:
        print("\n\nUser interrupted compilation")
        return 1

if __name__ == "__main__":
    sys.exit(build())