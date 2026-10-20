"""MadSheild command line interface.

The launcher installed on the shell PATH calls this module, so the command
surface is ``run <command>``:

    run dev      Start the development server with automatic reloading.
    run start    Start the server without automatic reloading.
    run test     Run the backend test suite.
    run install  Create the virtual environment and install dependencies.
    run setup    Install this launcher into a directory on your PATH.
    run open     Open the running application in the default browser.
    run info     Show the resolved paths and environment details.

Only the standard library is used here so that the launcher keeps working
before the project virtual environment exists. Server and test commands are
delegated to the interpreter inside that environment.
"""

import argparse
import os
import subprocess
import sys
import venv
import webbrowser
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
BACKEND_DIR = REPO_ROOT / "madsheild" / "backend"
VENV_DIR = BACKEND_DIR / ".venv"
REQUIREMENTS = BACKEND_DIR / "requirements.txt"
APP_TARGET = "madsheild.backend.main:app"

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8001


def venv_python() -> Path:
    """Return the interpreter inside the project virtual environment."""
    if os.name == "nt":
        return VENV_DIR / "Scripts" / "python.exe"
    return VENV_DIR / "bin" / "python"


def server_python() -> str:
    """Return the interpreter used to run the server and the tests.

    The project environment is preferred so that installed dependencies are
    always visible. The current interpreter is used as a fallback, which keeps
    the error messages meaningful before ``run install`` has been executed.
    """
    candidate = venv_python()
    if candidate.exists():
        return str(candidate)
    return sys.executable


def banner(host: str, port: int) -> None:
    base = f"http://{host}:{port}"
    print("")
    print("  MadSheild development server")
    print("  ----------------------------")
    print(f"  Application   {base}/")
    print(f"  API docs      {base}/docs")
    print(f"  Health check  {base}/health")
    print("")
    print("  Press Ctrl+C to stop.")
    print("")
    # Flush before handing the terminal to the server so the banner is shown
    # immediately even when the output is redirected to a file or a pipe.
    sys.stdout.flush()


def run_server(host: str, port: int, reload_enabled: bool) -> int:
    command = [
        server_python(),
        "-m",
        "uvicorn",
        APP_TARGET,
        "--host",
        host,
        "--port",
        str(port),
    ]
    if reload_enabled:
        command.append("--reload")

    banner(host, port)
    try:
        return subprocess.call(command, cwd=str(REPO_ROOT))
    except KeyboardInterrupt:
        print("\nServer stopped.")
        return 0


def run_tests(verbose: bool) -> int:
    command = [
        server_python(),
        "-m",
        "unittest",
        "discover",
        "-s",
        "madsheild/backend/tests",
        "-p",
        "test_*.py",
    ]
    if verbose:
        command.append("-v")
    return subprocess.call(command, cwd=str(REPO_ROOT))


def install_dependencies() -> int:
    """Create the virtual environment and install the backend requirements."""
    if not VENV_DIR.exists():
        print(f"Creating virtual environment at {VENV_DIR}")
        venv.EnvBuilder(with_pip=True, clear=False).create(str(VENV_DIR))
    else:
        print(f"Reusing virtual environment at {VENV_DIR}")

    python = venv_python()
    command = [str(python), "-m", "pip", "install", "-r", str(REQUIREMENTS)]
    try:
        return subprocess.call(command, cwd=str(REPO_ROOT))
    except KeyboardInterrupt:
        print("\nInstallation interrupted.")
        return 130


def open_browser(host: str, port: int) -> int:
    url = f"http://{host}:{port}/"
    print(f"Opening {url}")
    webbrowser.open(url)
    return 0


def candidate_bin_dirs() -> list:
    """Return the writable directories on PATH that can hold the launcher."""
    directories = []
    seen = set()
    for entry in os.getenv("PATH", "").split(os.pathsep):
        if not entry:
            continue
        path = Path(entry).expanduser()
        key = str(path)
        if key in seen:
            continue
        seen.add(key)
        if path.is_dir() and os.access(str(path), os.W_OK):
            directories.append(path)
    home_bin = Path.home() / "bin"
    if home_bin.is_dir() and os.access(str(home_bin), os.W_OK):
        if str(home_bin) not in seen:
            directories.insert(0, home_bin)
    return directories


def install_launcher() -> int:
    """Install the ``run`` launcher into the first writable PATH directory."""
    source = REPO_ROOT / "run"
    if not source.exists():
        print(f"Launcher not found at {source}.", file=sys.stderr)
        return 1

    directories = candidate_bin_dirs()
    if not directories:
        print(
            "No writable directory was found on PATH.\n"
            f"Add the launcher manually:  ln -s {source} <a directory on your PATH>",
            file=sys.stderr,
        )
        return 1

    target = directories[0] / "run"
    try:
        if target.is_symlink() or target.exists():
            target.unlink()
        target.symlink_to(source)
        os.chmod(str(source), 0o755)
    except OSError as error:
        print(f"Unable to install the launcher: {error}", file=sys.stderr)
        return 1

    print(f"Installed 'run' -> {source}")
    print(f"Location: {target}")
    if str(target.parent) not in os.getenv("PATH", "").split(os.pathsep):
        print(f"Note: {target.parent} is not on PATH. Add it to your shell profile.")
    return 0


def show_info(host: str, port: int) -> int:
    python = venv_python()
    print(f"Repository root    {REPO_ROOT}")
    print(f"Virtual environment {VENV_DIR} ({'present' if python.exists() else 'missing'})")
    print(f"Interpreter        {server_python()}")
    print(f"Requirements       {REQUIREMENTS} ({'present' if REQUIREMENTS.exists() else 'missing'})")
    print(f"Application URL    http://{host}:{port}/")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="run",
        description="MadSheild launcher: start the server, run the tests and manage the environment. "
                    "Running 'run' without a command starts the development server.",
    )
    parser.add_argument("--host", default=DEFAULT_HOST, help="host interface to bind (default: %(default)s)")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="port to bind (default: %(default)s)")

    subparsers = parser.add_subparsers(dest="command")
    subparsers.add_parser("dev", help="start the development server with automatic reloading")
    subparsers.add_parser("start", help="start the server without automatic reloading")

    test_parser = subparsers.add_parser("test", help="run the backend test suite")
    test_parser.add_argument("-v", "--verbose", action="store_true", help="show individual test names")

    subparsers.add_parser("install", help="create the virtual environment and install dependencies")
    subparsers.add_parser("setup", help="install the 'run' launcher into a directory on your PATH")
    subparsers.add_parser("open", help="open the running application in the default browser")
    subparsers.add_parser("info", help="show the resolved paths and environment details")
    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    command = args.command or "dev"
    if command == "dev":
        return run_server(args.host, args.port, reload_enabled=True)
    if command == "start":
        return run_server(args.host, args.port, reload_enabled=False)
    if command == "test":
        return run_tests(args.verbose)
    if command == "install":
        return install_dependencies()
    if command == "setup":
        return install_launcher()
    if command == "open":
        return open_browser(args.host, args.port)
    if command == "info":
        return show_info(args.host, args.port)

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
