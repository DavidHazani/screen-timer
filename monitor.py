import threading
import time
from typing import Callable

import psutil


class ProcessMonitor:
	"""Background monitor to enforce screen time on a whitelist of processes.

	- If timer is inactive, any matching process is terminated and on_block callback is called.
	- If timer is active and expires, caller should stop timer; monitor will also terminate matches if told timer is inactive.
	"""

	def __init__(
		self,
		get_whitelist: Callable[[], list[str]],
		is_timer_active: Callable[[], bool],
		on_block: Callable[[str], None] | None = None,
		poll_interval_seconds: float = 2.0,
	):
		self._get_whitelist = get_whitelist
		self._is_timer_active = is_timer_active
		self._on_block = on_block
		self._poll_interval_seconds = poll_interval_seconds
		self._thread: threading.Thread | None = None
		self._stop_event = threading.Event()

	def start(self) -> None:
		if self._thread and self._thread.is_alive():
			return
		self._stop_event.clear()
		self._thread = threading.Thread(target=self._run, name="ProcessMonitorThread", daemon=True)
		self._thread.start()

	def stop(self) -> None:
		self._stop_event.set()
		if self._thread and self._thread.is_alive():
			self._thread.join(timeout=5)

	def _run(self) -> None:
		while not self._stop_event.is_set():
			try:
				self._enforce()
			except Exception:
				# Best-effort monitor; do not crash the app on psutil errors
				pass
			finally:
				time.sleep(self._poll_interval_seconds)

	def _enforce(self) -> None:
		whitelist = set(p.lower() for p in self._get_whitelist())
		if not whitelist:
			return
		timer_active = self._is_timer_active()
		if timer_active:
			return
		for proc in psutil.process_iter(attrs=["name", "pid"]):
			name = (proc.info.get("name") or "").lower()
			if not name:
				continue
			if name in whitelist:
				try:
					proc.terminate()
					try:
						proc.wait(timeout=3)
					except psutil.TimeoutExpired:
						proc.kill()
					if self._on_block:
						self._on_block(proc.info.get("name") or name)
				except (psutil.NoSuchProcess, psutil.AccessDenied):
					continue










