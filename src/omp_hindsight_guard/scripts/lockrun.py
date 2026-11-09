"""Run a command while holding an exclusive lock on a file: `lockrun.py LOCKFILE COMMAND [ARGS...]`.

The lock is a kernel flock on LOCKFILE, held by this process and inherited by the command it becomes (exec), so it
is released when the last of them ends, however it ends: there is no pid file to misjudge and no file to delete.
The lock file itself is created 0600 and never removed. Exit status 1 when another process holds the lock.
"""

import fcntl
import os
import sys


def main(argv: list[str]) -> int:
	if len(argv) < 3:
		print("usage: lockrun.py LOCKFILE COMMAND [ARGS...]", file=sys.stderr)
		return 2
	lock, command = argv[1], argv[2:]
	try:
		fd = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
	except OSError as err:
		print(
			f"cannot open the lock file {lock} ({err.strerror}); if it is a directory left by an older version, remove it",
			file=sys.stderr,
		)
		return 1
	try:
		fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
	except OSError:
		print("another backup is running; nothing done", file=sys.stderr)
		return 1
	os.set_inheritable(fd, True)
	os.environ["OHG_BACKUP_LOCK_HELD"] = lock
	os.execvp(command[0], command)
	return 1  # not reached


if __name__ == "__main__":
	sys.exit(main(sys.argv))
