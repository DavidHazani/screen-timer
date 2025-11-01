import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime


DB_FILE = "screen_timer.db"


_init_lock = threading.Lock()


def _get_connection() -> sqlite3.Connection:
	conn = sqlite3.connect(DB_FILE, check_same_thread=False)
	conn.row_factory = sqlite3.Row
	return conn


@contextmanager
def db_cursor():
	conn = _get_connection()
	try:
		yield conn.cursor()
		conn.commit()
	except Exception:
		conn.rollback()
		raise
	finally:
		conn.close()


def init_db() -> None:
	with _init_lock:
		with db_cursor() as cur:
			cur.execute(
				"""
				CREATE TABLE IF NOT EXISTS users (
					id INTEGER PRIMARY KEY AUTOINCREMENT,
					name TEXT NOT NULL UNIQUE
				);
				"""
			)
			cur.execute(
				"""
				CREATE TABLE IF NOT EXISTS sessions (
					id INTEGER PRIMARY KEY AUTOINCREMENT,
					user_id INTEGER NOT NULL,
					start_ts TEXT NOT NULL,
					end_ts TEXT,
					duration_seconds INTEGER NOT NULL,
					actual_seconds INTEGER,
					FOREIGN KEY (user_id) REFERENCES users(id)
				);
				"""
			)
			cur.execute(
				"""
				CREATE TABLE IF NOT EXISTS whitelist_processes (
					id INTEGER PRIMARY KEY AUTOINCREMENT,
					process_name TEXT NOT NULL UNIQUE
				);
				"""
			)
			# Usage totals per user per process (game)
			cur.execute(
				"""
				CREATE TABLE IF NOT EXISTS usage_totals (
					user_id INTEGER NOT NULL,
					process_name TEXT NOT NULL,
					total_seconds INTEGER NOT NULL DEFAULT 0,
					PRIMARY KEY (user_id, process_name),
					FOREIGN KEY (user_id) REFERENCES users(id)
				);
				"""
			)

			# Seed demo users and whitelist if empty
			cur.execute("SELECT COUNT(1) AS c FROM users")
			if cur.fetchone()["c"] == 0:
				cur.executemany(
					"INSERT INTO users(name) VALUES (?)",
					[("Alice",), ("Bob",), ("Charlie",)],
				)
			else:
				cur.execute(
					"DELETE FROM users where name in ('Alice','Bob','Charlie')",
				)

			cur.execute("SELECT COUNT(1) AS c FROM whitelist_processes")
			if cur.fetchone()["c"] == 0:
				default_list = [
					"RobloxPlayerBeta.exe",
					"MinecraftLauncher.exe",
					"Minecraft.Windows.exe",
					"FortniteClient-Win64-Shipping.exe",
					"Valorant.exe",
					"LeagueClientUx.exe",
					"Steam.exe",
					"EpicGamesLauncher.exe",
					"Chrome.exe",
					"Firefox.exe",
					"Edge.exe",
					"generals.exe",
					"rc2.exe",
					"rct3.exe",
					"heroes3/exe",
				]
				cur.executemany(
					"INSERT OR IGNORE INTO whitelist_processes(process_name) VALUES (?)",
					[(p,) for p in default_list],
				)


def list_users() -> list[sqlite3.Row]:
	with db_cursor() as cur:
		cur.execute("SELECT id, name FROM users ORDER BY name ASC")
		return cur.fetchall()


def add_user(name: str) -> int:
	with db_cursor() as cur:
		cur.execute("INSERT OR IGNORE INTO users(name) VALUES (?)", (name,))
		cur.execute("SELECT id FROM users WHERE name = ?", (name,))
		row = cur.fetchone()
		return int(row["id"]) if row else -1


def rename_user(user_id: int, new_name: str) -> None:
	with db_cursor() as cur:
		cur.execute("UPDATE users SET name = ? WHERE id = ?", (new_name, user_id))


def delete_user(user_id: int) -> None:
	"""Delete user and related data (sessions, usage)."""
	with db_cursor() as cur:
		cur.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
		cur.execute("DELETE FROM usage_totals WHERE user_id = ?", (user_id,))
		cur.execute("DELETE FROM users WHERE id = ?", (user_id,))


def get_last_session() -> sqlite3.Row | None:
	with db_cursor() as cur:
		cur.execute(
			"""
			SELECT s.*, u.name AS user_name
			FROM sessions s
			JOIN users u ON u.id = s.user_id
			WHERE s.end_ts IS NOT NULL
			ORDER BY s.end_ts DESC
			LIMIT 1
			"""
		)
		return cur.fetchone()


def get_hall_of_shame() -> sqlite3.Row | None:
	"""Return the user with the highest cumulative actual_seconds."""
	with db_cursor() as cur:
		cur.execute(
			"""
			SELECT u.id, u.name, COALESCE(SUM(COALESCE(s.actual_seconds, 0)), 0) AS total_seconds
			FROM users u
			LEFT JOIN sessions s ON s.user_id = u.id AND s.end_ts IS NOT NULL
			GROUP BY u.id, u.name
			ORDER BY total_seconds DESC, u.name ASC
			LIMIT 1
			"""
		)
		return cur.fetchone()


def start_session(user_id: int, duration_seconds: int) -> int:
	start_ts = datetime.utcnow().isoformat()
	with db_cursor() as cur:
		cur.execute(
			"""
			INSERT INTO sessions(user_id, start_ts, duration_seconds)
			VALUES (?, ?, ?)
			""",
			(user_id, start_ts, duration_seconds),
		)
		return int(cur.lastrowid)


def end_session(session_id: int, actual_seconds: int) -> None:
	end_ts = datetime.utcnow().isoformat()
	with db_cursor() as cur:
		cur.execute(
			"""
			UPDATE sessions
			SET end_ts = ?, actual_seconds = ?
			WHERE id = ?
			""",
			(end_ts, actual_seconds, session_id),
		)


def get_whitelist() -> list[str]:
	with db_cursor() as cur:
		cur.execute("SELECT process_name FROM whitelist_processes ORDER BY process_name ASC")
		return [r["process_name"] for r in cur.fetchall()]


def add_to_whitelist(process_name: str) -> None:
	with db_cursor() as cur:
		cur.execute(
			"INSERT OR IGNORE INTO whitelist_processes(process_name) VALUES (?)",
			(process_name,),
		)


def remove_from_whitelist(process_name: str) -> None:
	with db_cursor() as cur:
		cur.execute(
			"DELETE FROM whitelist_processes WHERE process_name = ?",
			(process_name,),
		)


def increment_usage(user_id: int, process_name: str, seconds: int) -> None:
	"""Accumulate usage seconds for a given user and process."""
	if seconds <= 0:
		return
	with db_cursor() as cur:
		cur.execute(
			"""
			INSERT INTO usage_totals(user_id, process_name, total_seconds)
			VALUES (?, ?, ?)
			ON CONFLICT(user_id, process_name) DO UPDATE SET total_seconds = total_seconds + excluded.total_seconds
			""",
			(user_id, process_name, seconds),
		)


def get_usage_per_user_game() -> list[sqlite3.Row]:
	with db_cursor() as cur:
		cur.execute(
			"""
			SELECT u.name AS user_name, t.process_name, t.total_seconds
			FROM usage_totals t
			JOIN users u ON u.id = t.user_id
			ORDER BY u.name ASC, t.process_name ASC
			"""
		)
		return cur.fetchall()


def get_usage_by_user_totals() -> list[sqlite3.Row]:
	with db_cursor() as cur:
		cur.execute(
			"""
			SELECT u.name AS user_name, COALESCE(SUM(t.total_seconds), 0) AS total_seconds
			FROM users u
			LEFT JOIN usage_totals t ON t.user_id = u.id
			GROUP BY u.name
			ORDER BY total_seconds DESC, u.name ASC
			"""
		)
		return cur.fetchall()


def get_usage_by_game_totals() -> list[sqlite3.Row]:
	with db_cursor() as cur:
		cur.execute(
			"""
			SELECT t.process_name, COALESCE(SUM(t.total_seconds), 0) AS total_seconds
			FROM usage_totals t
			GROUP BY t.process_name
			ORDER BY total_seconds DESC, t.process_name ASC
			"""
		)
		return cur.fetchall()



