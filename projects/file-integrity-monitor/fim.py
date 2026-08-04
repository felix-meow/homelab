#!/usr/bin/env python3
"""
File Integrity Monitor - Robert Mircea
Homelab Project

Monitors file system changes using SHA256 hashes.
Detects file creation, modification, and deletion in real-time.
"""

import os
import hashlib
import sqlite3
import time
import argparse
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


class FIMHandler(FileSystemEventHandler):
    """Handles file system events and updates the database."""

    def __init__(self, db_path):
        self.db_path = db_path
        self.init_db()

    def init_db(self):
        """Initialize the SQLite database with the required table."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS files (
                path TEXT PRIMARY KEY,
                hash TEXT,
                size INTEGER,
                mtime INTEGER,
                created_at TEXT,
                modified_at TEXT
            )
        """)
        conn.commit()
        conn.close()

    def calculate_hash(self, filepath):
        """Calculate SHA256 hash of a file."""
        sha256 = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except (IOError, OSError):
            return None

    def get_file_info(self, filepath):
        """Get file metadata including hash, size, and modification time."""
        try:
            stat = os.stat(filepath)
            return {
                "size": stat.st_size,
                "mtime": stat.st_mtime,
                "hash": self.calculate_hash(filepath)
            }
        except (IOError, OSError):
            return None

    def save_file_info(self, filepath, file_info, event_type):
        """Save or update file information in the database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        now = datetime.now().isoformat()

        if event_type == "created":
            cursor.execute("""
                INSERT OR REPLACE INTO files
                (path, hash, size, mtime, created_at, modified_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (filepath, file_info["hash"], file_info["size"],
                  file_info["mtime"], now, now))
            print(f"[CREATED] {filepath}")

        elif event_type == "modified":
            cursor.execute("""
                UPDATE files
                SET hash = ?, size = ?, mtime = ?, modified_at = ?
                WHERE path = ?
            """, (file_info["hash"], file_info["size"],
                  file_info["mtime"], now, filepath))
            print(f"[MODIFIED] {filepath}")

        elif event_type == "deleted":
            cursor.execute("DELETE FROM files WHERE path = ?", (filepath,))
            print(f"[DELETED] {filepath}")

        conn.commit()
        conn.close()

    def check_initial_integrity(self, directory):
        """Walk through the directory and hash all files."""
        print(f"[INIT] Checking integrity of {directory}...")
        count = 0

        for root, dirs, files in os.walk(directory):
            for file in files:
                filepath = os.path.join(root, file)
                file_info = self.get_file_info(filepath)
                if file_info:
                    self.save_file_info(filepath, file_info, "created")
                    count += 1

        print(f"[INIT] Initialized {count} files in database")

    def on_created(self, event):
        if not event.is_directory:
            file_info = self.get_file_info(event.src_path)
            if file_info:
                self.save_file_info(event.src_path, file_info, "created")

    def on_modified(self, event):
        if not event.is_directory:
            file_info = self.get_file_info(event.src_path)
            if file_info:
                self.save_file_info(event.src_path, file_info, "modified")

    def on_deleted(self, event):
        if not event.is_directory:
            self.save_file_info(event.src_path, None, "deleted")

    def on_moved(self, event):
        if not event.is_directory:
            print(f"[MOVED] {event.src_path} -> {event.dest_path}")


def main():
    parser = argparse.ArgumentParser(description="File Integrity Monitor")
    parser.add_argument(
        "-d", "--directory",
        required=True,
        help="Directory to monitor"
    )
    parser.add_argument(
        "--db",
        default="database/fim.db",
        help="Path to SQLite database"
    )
    parser.add_argument(
        "--init",
        action="store_true",
        help="Initialize database with current state"
    )

    args = parser.parse_args()

    if not os.path.exists(args.directory):
        print(f"[ERROR] Directory {args.directory} does not exist")
        return

    db_dir = os.path.dirname(args.db)
    if db_dir and not os.path.exists(db_dir):
        os.makedirs(db_dir)

    handler = FIMHandler(args.db)

    if args.init:
        handler.check_initial_integrity(args.directory)
        return

    print(f"[MONITOR] Watching {args.directory}...")
    observer = Observer()
    observer.schedule(handler, args.directory, recursive=True)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        print("\n[MONITOR] Stopped")

    observer.join()


if __name__ == "__main__":
    main()