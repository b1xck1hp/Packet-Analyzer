import subprocess
import threading
import time
import os
import logging
from datetime import datetime
from wsl_manager import WSLManager

class CowrieManager:
    def __init__(self, wsl_manager):
        self.process = None
        self.log_monitor_thread = None
        self.running = False
        self.log_file = None
        self.wsl_manager = wsl_manager
        
    def start_cowrie(self):
        try:
            # First cleanup any existing instances
            self.wsl_manager.cleanup_cowrie()
            
            # Start Cowrie as cowrie user
            cmd = 'wsl -d kali-linux -u cowrie bash -ic "cd ~/cowrie && source cowrie-env/bin/activate && bin/cowrie start"'
            subprocess.run(cmd, shell=True, check=True)
            
            self.running = True
            # Start log monitoring
            self.monitor_logs()
            logging.info("Cowrie honeypot started successfully")
            return True
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to start Cowrie: {str(e)}")
            return False

    def stop_cowrie(self):
        if self.running:
            try:
                # Stop Cowrie and cleanup
                self.wsl_manager.stop_cowrie()
                self.running = False
                logging.info("Cowrie honeypot stopped successfully")
                return True
            except subprocess.CalledProcessError as e:
                logging.error(f"Failed to stop Cowrie: {str(e)}")
                return False

    def monitor_logs(self):
        def tail_log():
            cmd = 'wsl -d kali-linux -u cowrie bash -ic "cd ~/cowrie && tail -f var/log/cowrie/cowrie.log"'
            process = subprocess.Popen(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            while self.running:
                line = process.stdout.readline()
                if line:
                    self.process_log_line(line.strip())
                    
            process.terminate()

        self.log_monitor_thread = threading.Thread(target=tail_log)
        self.log_monitor_thread.daemon = True
        self.log_monitor_thread.start()

    def process_log_line(self, line):
        try:
            logging.info(f"Cowrie Log: {line}")
            # Add processing logic here
            pass
        except Exception as e:
            logging.error(f"Error processing Cowrie log line: {str(e)}")

    def is_running(self):
        try:
            cmd = 'wsl -d kali-linux -u cowrie bash -ic "cd ~/cowrie && bin/cowrie status"'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            return "cowrie is running" in result.stdout
        except Exception:
            return False
