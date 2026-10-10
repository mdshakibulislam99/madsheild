import subprocess
import sys
import os

def main():
    print("Starting MadSheild server...\n")
    
    current_dir = os.path.dirname(os.path.abspath(__file__))
    
    print("MadSheild server available on http://127.0.0.1:8001")
    print("Press Ctrl+C in this terminal to stop the server.")

    subprocess.run(
        [sys.executable, "-m", "uvicorn", "madsheild.backend.main:app", "--reload", "--port", "8001"],
        cwd=current_dir
    )

if __name__ == "__main__":
    main()