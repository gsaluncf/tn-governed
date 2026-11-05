"""Execute or stop the model process whose launch plan arrives on SSH stdin."""

import json
import os
import signal
import sys
from contextlib import suppress
from pathlib import Path


def main():
    os.umask(0o077)
    if len(sys.argv) == 3 and sys.argv[1] == "--stop":
        path = Path(sys.argv[2])
        if path.exists():
            pid = int(path.read_text())
            with suppress(ProcessLookupError):
                os.kill(pid, signal.SIGTERM)
            path.unlink(missing_ok=True)
        return
    plan = json.load(sys.stdin)
    path = Path(plan["pid_path"])
    path.parent.mkdir(parents=True, exist_ok=True)
    (path.parent / "server-config-root").mkdir(exist_ok=True)
    path.write_text(str(os.getpid()))
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith(("LLAMA_", "TN_LLAMA_"))}
    environment.update(plan["environment"], XDG_CONFIG_HOME=str(path.parent / "server-config-root"))
    args = plan["arguments"]
    os.execvpe(args[0], args, environment)


if __name__ == "__main__":
    main()
