import threading
import time
from datetime import datetime, timedelta
from tkinter import Tk, StringVar, IntVar, ttk, messagebox, Toplevel
import ctypes
import os
from ctypes import wintypes
import webbrowser

import psutil  # Ensures availability at runtime when packaged

from db import (
	init_db,
	list_users,
	add_user,
	rename_user,
	delete_user,
	get_last_session,
	get_hall_of_shame,
	start_session,
	end_session,
	get_whitelist,
	add_to_whitelist,
	remove_from_whitelist,
    increment_usage,
    get_usage_per_user_game,
    get_usage_by_user_totals,
)
from monitor import ProcessMonitor


def _acquire_single_instance():
    try:
        kernel32 = ctypes.windll.kernel32
        user32 = ctypes.windll.user32
        CreateMutexW = kernel32.CreateMutexW
        GetLastError = kernel32.GetLastError
        CloseHandle = kernel32.CloseHandle

        CreateMutexW.argtypes = [wintypes.LPVOID, wintypes.BOOL, wintypes.LPCWSTR]
        CreateMutexW.restype = wintypes.HANDLE

        mutex_name = "Global\\ScreenTimerSingleton"
        hmutex = CreateMutexW(None, True, mutex_name)
        if not hmutex:
            return None
        ERROR_ALREADY_EXISTS = 183
        if GetLastError() == ERROR_ALREADY_EXISTS:
            # Already running
            try:
                user32.MessageBoxW(0, "האפליקציה כבר רצה.", "מתזמן מסך", 0x00000010)
            except Exception:
                pass
            CloseHandle(hmutex)
            return None
        return hmutex
    except Exception:
        return None


class ScreenTimerApp:
	def __init__(self, root: Tk):
		self.root = root
		self.root.title("מתזמן מסך")
		self.root.geometry("560x340")
		self._ico_path = None
		self._try_set_app_icon()

		init_db()

		self.users = list_users()
		self.user_name_to_id = {row["name"]: row["id"] for row in self.users}

		self.selected_user = StringVar(value="")
		self.selected_duration = IntVar(value=30)  # minutes
		self.remaining_label_var = StringVar(value="זמן שנשאר: 00:00:00")
		self.last_user_var = StringVar(value="משחק אחרון: -")
		self.hall_of_shame_var = StringVar(value="מי בזבז מלנתא זמן: -")
		self.whitelist_count_var = StringVar(value="תהליכים מנוטרים: 0")

		self._timer_active = False
		self._timer_lock = threading.Lock()
		self._session_id: int | None = None
		self._session_start_utc: datetime | None = None
		self._session_end_utc: datetime | None = None
		self._countdown_thread: threading.Thread | None = None
		self._stop_countdown = threading.Event()
		self._stop_sampler = threading.Event()
		self._sampler_thread: threading.Thread | None = None
		self._save_prompt_open = False
		self._paused = False
		self._pause_started_utc: datetime | None = None
		self._total_paused_seconds: int = 0

		self._build_ui()
		self._refresh_status()

		# Block window close (kids can't exit the timer)
		self.root.protocol("WM_DELETE_WINDOW", self._on_close_requested)

		self.monitor = ProcessMonitor(
			get_whitelist=get_whitelist,
			is_timer_active=self.is_timer_active,
			on_block=self._on_process_blocked,
			poll_interval_seconds=2.0,
		)
		self.monitor.start()
		self._update_start_button_state()

	def _try_set_app_icon(self) -> None:
		try:
			app_dir = os.path.dirname(os.path.abspath(__file__))
			ico_path = os.path.join(app_dir, "app.ico")
			if os.path.isfile(ico_path):
				self._ico_path = ico_path
				self.root.iconbitmap(ico_path)
		except Exception:
			pass

	def _build_ui(self) -> None:
		root = self.root
		pad = {"padx": 8, "pady": 8}

		# Top status frame
		status = ttk.LabelFrame(root, text="מצב")
		status.pack(fill="x", **pad)
		row1 = ttk.Frame(status)
		row1.pack(fill="x", **pad)
		lbl_last = ttk.Label(row1, textvariable=self.last_user_var)
		lbl_last.pack(side="left")
		lbl_shame = ttk.Label(row1, textvariable=self.hall_of_shame_var)
		lbl_shame.pack(side="right")

		row2 = ttk.Frame(status)
		row2.pack(fill="x", **pad)
		lbl_remaining = ttk.Label(row2, textvariable=self.remaining_label_var, font=("Segoe UI", 12, "bold"))
		lbl_remaining.pack(side="left")
		lbl_wl = ttk.Label(row2, textvariable=self.whitelist_count_var)
		lbl_wl.pack(side="right")

		# Controls frame
		controls = ttk.LabelFrame(root, text="יאללה זה הזמן מסך שלי")
		controls.pack(fill="x", **pad)

		# User selector
		rowu = ttk.Frame(controls)
		rowu.pack(fill="x", **pad)
		(ttk.Label(rowu, text="שחקן:")).pack(side="left")
		self.user_combo = ttk.Combobox(rowu, state="readonly", values=[u["name"] for u in self.users], textvariable=self.selected_user, width=20)
		self.user_combo.pack(side="left", padx=8)
		self.user_combo.bind("<<ComboboxSelected>>", lambda e: self._update_start_button_state())
		# Removed direct add user; use Users management window

		# Duration selector
		rowd = ttk.Frame(controls)
		rowd.pack(fill="x", **pad)
		(ttk.Label(rowd, text="זמן מוקצב:")).pack(side="left")
		durations = [
			("10 דקות", 10),
			("20 דקות", 20),
			("30 דקות", 30),
			("40 דקות", 40),
			("שעה", 60), 
			("שעה וחצי", 90),
			("שעתיים", 120),
			("שלוש שעות", 180),
		]
		self.duration_combo = ttk.Combobox(rowd, state="readonly", values=[d[0] for d in durations], width=20)
		self.duration_combo.current(2)
		self.duration_combo.pack(side="left", padx=8)
		self.duration_combo.bind("<<ComboboxSelected>>", lambda e: self._on_duration_change(durations))
		self._on_duration_change(durations)

		# Start/Stop
		rows = ttk.Frame(controls)
		rows.pack(fill="x", **pad)
		self.btn_start = ttk.Button(rows, text="יאללה תורי לשחק", command=self.start_timer, state="disabled")
		self.btn_start.pack(side="left")
		self.btn_stop = ttk.Button(rows, text="סיימתי את התור", command=self.stop_timer, state="disabled")
		self.btn_stop.pack(side="left", padx=8)

		# Whitelist quick info and manage
		roww = ttk.Frame(controls)
		roww.pack(fill="x", **pad)
		btn_manage = ttk.Button(roww, text="ניהול תהליכים לניטור", command=self._manage_whitelist)
		btn_manage.pack(side="left")
		btn_users = ttk.Button(roww, text="ניהול משתמשים", command=self._manage_users)
		btn_users.pack(side="left", padx=8)
		btn_stats = ttk.Button(roww, text="סטטיסטיקה", command=self._open_stats)
		btn_stats.pack(side="left", padx=8)
		btn_shame = ttk.Button(roww, text="היכל הבושה", command=self._open_shame)
		btn_shame.pack(side="left")

		# Footer (About)
		footer = ttk.Frame(root)
		footer.pack(fill="x", side="bottom", **pad)
		lbl_rights = ttk.Label(footer, text="כל הזכויות שמורות לדוד חזני וילדיו")
		lbl_rights.pack(side="left")
		def open_mail(evt =None):
			try:
				webbrowser.open("mailto:david.hazn@gmail.com")
			except Exception:
				pass
		lbl_contact = ttk.Label(footer, text="david.hazn@gmail.com", foreground="#0066cc")
		lbl_contact.pack(side="right")
		lbl_contact.bind("<Button-1>", open_mail)

	def _on_duration_change(self, durations: list[tuple[str, int]]) -> None:
		label = self.duration_combo.get()
		for l, minutes in durations:
			if l == label:
				self.selected_duration.set(minutes)
				break

	def _refresh_status(self) -> None:
		# Last session
		last = get_last_session()
		if last:
			name = last["user_name"]
			actual = last["actual_seconds"] or 0
			self.last_user_var.set(f"משחק אחרון: {name}, {self._fmt_seconds(actual)}")
		else:
			self.last_user_var.set("משחק אחרון: -")

		# Hall of shame (top cumulative)
		shame = get_hall_of_shame()
		if shame:
			self.hall_of_shame_var.set(
				f"מי בזבז מלנתא זמן: {shame['name']} ({self._fmt_seconds(int(shame['total_seconds']))})"
			)
		else:
			self.hall_of_shame_var.set("מי בזבז מלנא זמן: -")

		# Whitelist count
		self.whitelist_count_var.set(f"תהליכים מנוטרים: {len(get_whitelist())}")

	def _fmt_seconds(self, s: int) -> str:
		h = s // 3600
		m = (s % 3600) // 60
		sec = s % 60
		return f"{h:02d}:{m:02d}:{sec:02d}"

	def is_timer_active(self) -> bool:
		with self._timer_lock:
			return self._timer_active

	def set_timer_active(self, active: bool) -> None:
		with self._timer_lock:
			self._timer_active = active

	def start_timer(self) -> None:
		if not self.selected_user.get():
			messagebox.showwarning("בחר משתמש", "בחר משתמש.")
			return
		minutes = int(self.selected_duration.get())
		seconds = minutes * 60
		user_id = self._ensure_user(self.selected_user.get())
		self._session_id = start_session(user_id, seconds)
		self._session_start_utc = datetime.utcnow()
		self._session_end_utc = self._session_start_utc + timedelta(seconds=seconds)
		self.set_timer_active(True)
		self.btn_start.config(state="disabled")
		self.btn_stop.config(state="normal")
		self._stop_countdown.clear()
		self._countdown_thread = threading.Thread(target=self._countdown_loop, name="CountdownThread", daemon=True)
		self._countdown_thread.start()
		# start sampler
		self._stop_sampler.clear()
		self._sampler_thread = threading.Thread(target=self._sampler_loop, name="SamplerThread", daemon=True)
		self._sampler_thread.start()

	def stop_timer(self) -> None:
		self._stop_countdown.set()
		self._finish_session()
		# Clear selection and require choosing player again
		self.selected_user.set("")
		self.btn_stop.config(state="disabled")
		self._update_start_button_state()

	def _countdown_loop(self) -> None:
		while not self._stop_countdown.is_set():
			now = datetime.utcnow()
			if not self._paused and self._session_end_utc and now >= self._session_end_utc:
				self.root.after(0, self._time_over)
				break
			if self._session_end_utc:
				remaining = int((self._session_end_utc - now).total_seconds())
			else:
				remaining = 0
			self.root.after(0, lambda r=remaining: self.remaining_label_var.set(f"נשאר: {self._fmt_seconds(max(0, r))}"))
			time.sleep(0.5)

	def _time_over(self) -> None:
		# Keep timer active until child confirms they saved, to avoid force-closing before save.
		if self._save_prompt_open:
			return
		self._save_prompt_open = True
		self._show_save_dialog()
		# Monitor will continue to allow whitelisted apps while timer remains active.

	def _finish_session(self) -> None:
		if self._session_id and self._session_start_utc:
			now = datetime.utcnow()
			paused_total = self._total_paused_seconds
			if self._paused and self._pause_started_utc:
				paused_total += max(0, int((now - self._pause_started_utc).total_seconds()))
			actual = int((now - self._session_start_utc).total_seconds()) - paused_total
			end_session(self._session_id, max(0, actual))
			self._session_id = None
			self._session_start_utc = None
			self._session_end_utc = None
			self._refresh_status()
		# stop sampler
		self._stop_sampler.set()
		self.remaining_label_var.set("נשאר: 00:00:00")
		# reset pause accounting
		self._paused = False
		self._pause_started_utc = None
		self._total_paused_seconds = 0

	def _on_process_blocked(self, proc_name: str) -> None:
		# Notify on UI thread
		self.root.after(0, lambda: messagebox.showwarning("הלו מה אתה עושה?", f"{proc_name} נסגר לך בפנים כי לא פתחת את המתזמן"))

	def _ensure_user(self, name: str) -> int:
		if name in self.user_name_to_id:
			return self.user_name_to_id[name]
		user_id = add_user(name)
		self.user_name_to_id[name] = user_id
		self.user_combo.config(values=list(self.user_name_to_id.keys()))
		return user_id

	def _prompt_add_user(self) -> None:
		from tkinter.simpledialog import askstring

		name = askstring("הוסף משתמש", "הקלד שם משתמש")
		if not name:
			return
		name = name.strip()
		if not name:
			return
		user_id = add_user(name)
		self.user_name_to_id[name] = user_id
		self.user_combo.config(values=list(self.user_name_to_id.keys()))
		self.selected_user.set(name)

	def _manage_whitelist(self) -> None:
		win = ttk.Frame(self.root)
		win_top = Toplevel(self.root)
		win_top.title("תהליכים לניטור")
		win_top.geometry("420x340")
		pad = {"padx": 8, "pady": 8}

		frame = ttk.Frame(win_top)
		frame.pack(fill="both", expand=True, **pad)

		lst = ttk.Treeview(frame, columns=("proc",), show="headings", height=10)
		lst.heading("proc", text="שם תהליך (לדוגמא: Minecraft.exe)")
		lst.pack(fill="both", expand=True)

		def refresh_list():
			lst.delete(*lst.get_children())
			for p in get_whitelist():
				lst.insert("", "end", values=(p,))
			self.whitelist_count_var.set(f"תהליכים לניטור: {len(get_whitelist())}")

		row = ttk.Frame(frame)
		row.pack(fill="x", **pad)
		entry_var = StringVar()
		entry = ttk.Entry(row, textvariable=entry_var)
		entry.pack(side="left", fill="x", expand=True)
		def add_item():
			val = entry_var.get().strip()
			if val:
				add_to_whitelist(val)
				entry_var.set("")
				refresh_list()
		btn_add = ttk.Button(row, text="הוסף תהליך", command=add_item)
		btn_add.pack(side="left", padx=8)

		def remove_selected():
			for sel in lst.selection():
				vals = lst.item(sel, "values")
				if vals:
					remove_from_whitelist(vals[0])
			refresh_list()
		btn_remove = ttk.Button(frame, text="בטל ניטור", command=remove_selected)
		btn_remove.pack(**pad)

		refresh_list()

	def _sampler_loop(self) -> None:
		"""While timer active, sample running whitelisted processes and increment usage."""
		SAMPLE_SECONDS = 5
		while not self._stop_sampler.is_set() and self.is_timer_active():
			try:
				# Do not record usage while paused
				if self._paused:
					time.sleep(SAMPLE_SECONDS)
					continue
				whitelist_lc = set(p.lower() for p in get_whitelist())
				if not whitelist_lc or not self.selected_user.get():
					time.sleep(SAMPLE_SECONDS)
					continue
				user_name = self.selected_user.get()
				user_id = self._ensure_user(user_name)
				seen: set[str] = set()
				for proc in psutil.process_iter(attrs=["name"]):
					name = (proc.info.get("name") or "").strip()
					if not name:
						continue
					if name.lower() in whitelist_lc:
						seen.add(name)
				for pname in seen:
					increment_usage(user_id, pname, SAMPLE_SECONDS)
			finally:
				time.sleep(SAMPLE_SECONDS)

	def _open_stats(self) -> None:
		win = Toplevel(self.root)
		win.title("סטיסטיקה")
		win.geometry("640x420")
		pad = {"padx": 8, "pady": 8}

		frame = ttk.Frame(win)
		frame.pack(fill="both", expand=True, **pad)

		cols = ("user", "game", "time")
		tree = ttk.Treeview(frame, columns=cols, show="headings")
		tree.heading("user", text="משתמש")
		tree.heading("game", text="משחק")
		tree.heading("time", text="זמן שבוזבז")
		tree.column("user", width=120)
		tree.column("game", width=320)
		tree.column("time", width=120)
		tree.pack(fill="both", expand=True)

		def fmt(s: int) -> str:
			h = s // 3600
			m = (s % 3600) // 60
			sec = s % 60
			return f"{h:02d}:{m:02d}:{sec:02d}"

		def refresh():
			tree.delete(*tree.get_children())
			for r in get_usage_per_user_game():
				user = r["user_name"]
				game = r["process_name"]
				secs = int(r["total_seconds"]) if r["total_seconds"] is not None else 0
				tree.insert("", "end", values=(user, game, fmt(secs)))

		refresh()

	def _manage_users(self) -> None:
		win = Toplevel(self.root)
		win.title("ניהול משתמשים")
		win.geometry("460x360")
		pad = {"padx": 8, "pady": 8}

		frame = ttk.Frame(win)
		frame.pack(fill="both", expand=True, **pad)

		cols = ("id", "name")
		tree = ttk.Treeview(frame, columns=cols, show="headings")
		tree.heading("id", text="ID")
		tree.heading("name", text="שם")
		tree.column("id", width=60, anchor="center")
		tree.column("name", width=320)
		tree.pack(fill="both", expand=True)

		def refresh():
			tree.delete(*tree.get_children())
			self.users = list_users()
			self.user_name_to_id = {row["name"]: row["id"] for row in self.users}
			for u in self.users:
				tree.insert("", "end", values=(u["id"], u["name"]))
			self.user_combo.config(values=[u["name"] for u in self.users])
			if self.selected_user.get() and self.selected_user.get() not in self.user_name_to_id:
				# Previously selected user deleted; clear selection
				self.selected_user.set("")
			self._update_start_button_state()

		row_add = ttk.Frame(frame)
		row_add.pack(fill="x", **pad)
		add_var = StringVar()
		add_entry = ttk.Entry(row_add, textvariable=add_var)
		add_entry.pack(side="left", fill="x", expand=True)
		def do_add():
			name = (add_var.get() or "").strip()
			if not name:
				return
			add_user(name)
			add_var.set("")
			refresh()
		btn_add = ttk.Button(row_add, text="הוסף", command=do_add)
		btn_add.pack(side="left", padx=8)

		row_edit = ttk.Frame(frame)
		row_edit.pack(fill="x", **pad)
		rename_var = StringVar()
		rename_entry = ttk.Entry(row_edit, textvariable=rename_var)
		rename_entry.pack(side="left", fill="x", expand=True)

		def on_select(evt=None):
			selections = tree.selection()
			if selections:
				vals = tree.item(selections[0], "values")
				if vals:
					rename_var.set(vals[1])
		tree.bind("<<TreeviewSelect>>", on_select)

		def do_rename():
			selections = tree.selection()
			if not selections:
				return
			vals = tree.item(selections[0], "values")
			if not vals:
				return
			uid = int(vals[0])
			new_name = (rename_var.get() or "").strip()
			if not new_name:
				return
			rename_user(uid, new_name)
			if self.selected_user.get() == vals[1]:
				self.selected_user.set(new_name)
			refresh()
			self._update_start_button_state()
		btn_rename = ttk.Button(row_edit, text="שנה שם", command=do_rename)
		btn_rename.pack(side="left", padx=8)

		def do_delete():
			selections = tree.selection()
			if not selections:
				return
			vals = tree.item(selections[0], "values")
			if not vals:
				return
			uid = int(vals[0])
			uname = vals[1]
			if messagebox.askyesno("מחיקה", f"למחוק את המשתמש '{uname}'? הפעולה תמחק גם נתוני זמן ומשחקים."):
				delete_user(uid)
				if self.selected_user.get() == uname:
					self.selected_user.set("")
				refresh()
				self._update_start_button_state()
		btn_delete = ttk.Button(frame, text="מחק נבחר", command=do_delete)
		btn_delete.pack(**pad)

	def _show_save_dialog(self) -> None:
		# Minimize other windows so the warning is visible
		self._minimize_all_windows()
		self._bring_app_to_front()

		win = Toplevel(self.root)
		win.title("יאללה לשחרר תמסך")
		win.geometry("360x160")
		win.resizable(False, False)
		win.grab_set()
		try:
			# Make the dialog itself topmost and focused
			win.transient(self.root)
			win.lift(self.root)
			win.attributes("-topmost", True)
			win.focus_force()
			win.update()
			# Force the dialog to foreground
			user32 = ctypes.windll.user32
			SetForegroundWindow = user32.SetForegroundWindow
			SetForegroundWindow.argtypes = [wintypes.HWND]
			SetForegroundWindow.restype = wintypes.BOOL
			SetForegroundWindow(wintypes.HWND(win.winfo_id()))
		except Exception:
			pass
		pad = {"padx": 12, "pady": 12}

		frame = ttk.Frame(win)
		frame.pack(fill="both", expand=True, **pad)
		msg = ttk.Label(frame, text="הזמן נגר אחשילי. יאללה תלחץ על שמור ושחרר לבא בתור")
		msg.pack(**pad)

		btn_row = ttk.Frame(frame)
		btn_row.pack()

		def on_saved():
			try:
				self.set_timer_active(False)
				self._finish_session()
				self.btn_start.config(state="normal")
				self.btn_stop.config(state="disabled")
			finally:
				self._save_prompt_open = False
				try:
					win.grab_release()
				except Exception:
					pass
				win.destroy()

		btn_saved = ttk.Button(btn_row, text="שמרתי אומר'ך", command=on_saved)
		btn_saved.pack(side="left", padx=8)

		def disable_close():
			pass
		win.protocol("WM_DELETE_WINDOW", disable_close)

	def _minimize_all_windows(self) -> None:
		try:
			user32 = ctypes.windll.user32
			EnumWindows = user32.EnumWindows
			IsWindowVisible = user32.IsWindowVisible
			ShowWindow = user32.ShowWindow
			GetWindowThreadProcessId = user32.GetWindowThreadProcessId

			EnumWindows.argtypes = [ctypes.WINFUNCTYPE(ctypes.c_bool, wintypes.HWND, wintypes.LPARAM), wintypes.LPARAM]
			EnumWindows.restype = wintypes.BOOL

			IsWindowVisible.argtypes = [wintypes.HWND]
			IsWindowVisible.restype = wintypes.BOOL

			ShowWindow.argtypes = [wintypes.HWND, ctypes.c_int]
			ShowWindow.restype = wintypes.BOOL

			GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
			GetWindowThreadProcessId.restype = wintypes.DWORD

			SW_MINIMIZE = 6

			this_pid = os.getpid()

			@ctypes.WINFUNCTYPE(ctypes.c_bool, wintypes.HWND, wintypes.LPARAM)
			def enum_proc(hWnd, lParam):
				if not IsWindowVisible(hWnd):
					return True
				pid = wintypes.DWORD()
				GetWindowThreadProcessId(hWnd, ctypes.byref(pid))
				# Skip our own app windows
				if int(pid.value) == this_pid:
					return True
				# Minimize other windows, including games; our app will be brought to front after
				ShowWindow(hWnd, SW_MINIMIZE)
				return True

			EnumWindows(enum_proc, 0)
		except Exception:
			pass

	def _bring_app_to_front(self) -> None:
		try:
			self.root.deiconify()
			self.root.lift()
			user32 = ctypes.windll.user32
			SetForegroundWindow = user32.SetForegroundWindow
			SetForegroundWindow.argtypes = [wintypes.HWND]
			SetForegroundWindow.restype = wintypes.BOOL
			hwnd = wintypes.HWND(self.root.winfo_id())
			SetForegroundWindow(hwnd)
		except Exception:
			pass

	def _on_close_requested(self) -> None:
		try:
			messagebox.showinfo("פעולה נחסמה", "סגירת האפליקציה חסומה. פנו להורה.")
		except Exception:
			pass

	def _open_shame(self) -> None:
		win = Toplevel(self.root)
		win.title("מי בזבז הכי הרבה זמן")
		win.geometry("420x360")
		pad = {"padx": 8, "pady": 8}

		frame = ttk.Frame(win)
		frame.pack(fill="both", expand=True, **pad)

		cols = ("user", "time")
		tree = ttk.Treeview(frame, columns=cols, show="headings")
		tree.heading("user", text="מי")
		tree.heading("time", text="זמן שבוזבז")
		tree.column("user", width=200)
		tree.column("time", width=180)
		tree.pack(fill="both", expand=True)

		def fmt(s: int) -> str:
			h = s // 3600
			m = (s % 3600) // 60
			sec = s % 60
			return f"{h:02d}:{m:02d}:{sec:02d}"

		def refresh():
			tree.delete(*tree.get_children())
			rows = get_usage_by_user_totals()
			rows = sorted(rows, key=lambda r: int(r["total_seconds"] or 0), reverse=True)
			for r in rows:
				user = r["user_name"]
				secs = int(r["total_seconds"]) if r["total_seconds"] is not None else 0
				tree.insert("", "end", values=(user, fmt(secs)))

		refresh()

	def _update_start_button_state(self) -> None:
		# Enable Start only if no session is active and a user is selected
		if self.is_timer_active():
			self.btn_start.config(state="disabled")
			return
		name = (self.selected_user.get() or "").strip()
		self.btn_start.config(state=("normal" if name else "disabled"))


def main() -> None:
    handle = _acquire_single_instance()
    if not handle:
        return
    try:
        root = Tk()
        app = ScreenTimerApp(root)
        root.mainloop()
    finally:
        try:
            ctypes.windll.kernel32.CloseHandle(handle)
        except Exception:
            pass


if __name__ == "__main__":
    main()



