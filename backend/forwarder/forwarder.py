import os
import sys
import threading
import time
from collections import deque
import traceback

current_dir = os.path.dirname(__file__)
parent_dir = os.path.abspath(os.path.join(current_dir, os.pardir))
sys.path.append(parent_dir)

from backend.detections.detections_runner import start_rule_scheduler
from backend.parser.log_parser import parser
from backend.utils.database.database_operations import get_db_connection

BUFFER_SIZE = 100
BUFFER_TIMEOUT = 5


log_queue = deque()
sender_thread = None
stop_event = threading.Event()
active_tail_threads = []
forwarder_running = False
forwarder_lock = threading.Lock()


def clean_invalid_paths():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT id, path FROM log_sources")
    rows = cursor.fetchall()
    
    removed = []

    for row in rows:
        log_path = row["path"]
        if not os.path.exists(log_path) and "Ingested Log" not in log_path:
            source_id = row["id"]
            cursor.execute("DELETE FROM log_sources WHERE id = ?", (source_id,))
            cursor.execute("DELETE FROM parsed_logs WHERE source_id = ?", (source_id,))
            removed.append(log_path)

    conn.commit()
    conn.close()

    if removed:
        print(f"✅ Removed {len(removed)} invalid paths from DB:")
        for p in removed:
            print(f"   - {p}")
    elif not rows:
        print("No log sources detected in the database.")
    else:
        print("✅ All log paths in DB are valid.")

def get_log_files_from_folder(folder, extensions=[".log"]):
    for root, dirs, files in os.walk(folder):
        for file in files:
            if any(file.endswith(ext) for ext in extensions):
                yield os.path.join(root, file)

def send_buffered_logs(log_queue: deque, stop_event: threading.Event):
    buffer = []
    last_sent_time = time.time()

    while not stop_event.is_set():
        try:
            while len(log_queue) > 0 and len(buffer) < BUFFER_SIZE and not stop_event.is_set():
                try:
                    log_entry = log_queue.popleft()
                    buffer.append(log_entry)
                except IndexError:
                    pass

            if len(buffer) >= BUFFER_SIZE or (len(buffer) > 0 and (time.time() - last_sent_time) >= BUFFER_TIMEOUT):
                payloads = []

                for file_path, line, log_type, source_id in buffer:
                    if line.strip() == '':
                        continue

                    payloads.append({
                        "source": file_path,
                        "log": line.strip(),
                        "type": log_type,
                        "source_id": source_id
                    })

                if payloads:
                    print(f"DEBUG: Sending {len(payloads)} logs to parser...")
                    try:
                        parser(payloads)
                        buffer.clear()
                        last_sent_time = time.time()
                        print("DEBUG: Logs sent and buffer cleared.")
                    except Exception as e:
                        print(f"[!] Failed to send log batch: {e}")
                        buffer.clear()
                        last_sent_time = time.time()
            else:
                time.sleep(0.1)

        except Exception as e:
            print(f"Error in sender thread: {e}")
            with open("error_sender.log", "a") as f:
                traceback.print_exc(file=f)
            time.sleep(1)
    print("Log sender thread stopped.")

def tail_file(file_path: str, log_queue: deque, source_id: int, last_position_str: str, log_type: str, stop_event: threading.Event):
    try:
        if not os.path.exists(file_path):
            print(f"File not found: {file_path}. Skipping tailing.")
            return

        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            print(f"🔄 Resuming tail for {file_path} (Type: {log_type}) from position {last_position_str}")
            
            try:
                initial_position = int(last_position_str)
            except ValueError:
                print(f"Warning: Invalid last_position '{last_position_str}' for {file_path}. Starting from 0.")
                initial_position = 0
            
            f.seek(initial_position)
            
            while not stop_event.is_set():
                line = f.readline()
                if not line:
                    time.sleep(0.5)
                    if stop_event.is_set():
                        break
                    continue

                log_queue.append((file_path, line, log_type, source_id))
                current_position_int = f.tell() # This returns an integer
                
                try:
                    conn = get_db_connection()
                    cursor = conn.cursor()
                    # CRITICAL FIX 2: Convert the integer current_position to a string for DB update
                    cursor.execute("UPDATE log_sources SET last_position = ? WHERE id = ?", (str(current_position_int), source_id))
                    conn.commit()
                    conn.close()
                except Exception as db_err:
                    print(f"❗ DB update error for {file_path}: {db_err}")
                    with open("error_db_update.log", "a") as f_err:
                        traceback.print_exc(file=f_err)

    except Exception as e:
        print(f"Error tailing file {file_path}: {e}")
        with open("error_tailing.log", "a") as f:
            traceback.print_exc(file=f)
    print(f"Tailing thread for {file_path} stopped.")

def start_forwarder():
    global sender_thread, active_tail_threads, forwarder_running, stop_event, log_queue

    with forwarder_lock:
        if forwarder_running:
            print("\n--- Forwarder Restart Initiated ---")
            stop_event.set()

            if sender_thread and sender_thread.is_alive():
                print("Waiting for sender thread to stop...")
                sender_thread.join(timeout=10)
                if sender_thread.is_alive():
                    print("Warning: Sender thread did not stop gracefully within timeout.")

            for t in active_tail_threads:
                if t.is_alive():
                    print(f"Waiting for tailing thread {t.name} to stop...")
                    t.join(timeout=5)
                    if t.is_alive():
                        print(f"Warning: Tailing thread {t.name} did not stop gracefully within timeout.")
            
            log_queue.clear() 
            active_tail_threads = []
            stop_event.clear()
            print("--- Existing forwarder threads stopped and reset. ---")

        print("\n--- Starting Forwarder ---")
        clean_invalid_paths()

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT id, path, last_position, log_type FROM log_sources")
        rows = cursor.fetchall()
        conn.close()

        if not rows:
            print("No log sources configured in DB. Forwarder will not start.")
            forwarder_running = False
            return

        all_log_files = []
        
        for row in rows:
            source_id = row["id"]
            log_path = row["path"]
            last_position_from_db = row["last_position"] or '0' 
            log_type = row["log_type"]

            abs_path = os.path.abspath(log_path)

            if not os.path.exists(abs_path) and "Ingested Log" not in log_path:
                print(f"❌ Invalid path detected in DB (will be cleaned on next run): {abs_path}")
                continue

            if os.path.isfile(abs_path):
                # Pass the string representation of last_position to tail_file
                all_log_files.append((abs_path, source_id, last_position_from_db, log_type))
            elif "Ingested Log" in log_path:
                pass
            else:
                print(f"Skipping non-file path from DB: {abs_path}")

        if not all_log_files and "Ingested Log" not in log_path:
            print("❌ No valid log files found to watch after checking database entries.")
            forwarder_running = False
            return

        sender_thread = threading.Thread(
            target=send_buffered_logs,
            args=(log_queue, stop_event),
            daemon=True,
            name="LogSenderThread"
        )
        sender_thread.start()
        print("🚀 Log sender thread started.")

        for log_file, source_id, last_position_for_tail, log_type_for_tail in all_log_files:
            print(f"📄 Watching: {log_file} (Type: {log_type_for_tail})")
            thread = threading.Thread(
                target=tail_file,
                # last_position_for_tail is already a string here
                args=(log_file, log_queue, source_id, last_position_for_tail, log_type_for_tail, stop_event),
                daemon=True,
                name=f"TailThread-{os.path.basename(log_file)}"
            )
            thread.start()
            active_tail_threads.append(thread)

        forwarder_running = True
        print("✅ Forwarder fully started with new configuration.")

