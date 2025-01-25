import subprocess
import getpass
import logging
import os
from dotenv import load_dotenv

class WSLManager:
    def __init__(self):
        self.password = None
        load_dotenv()
        
    def initialize(self):
        """Get WSL password from user and verify it"""
        try:
            # First try to get password from environment variable
            self.password = os.getenv('WSL_PASSWORD')
            if not self.password:
                self.password = getpass.getpass("Enter WSL password for cowrie user: ")
            
            # Test the password
            test_cmd = f'wsl -d kali-linux -u root bash -ic "echo {self.password} | sudo -S echo test"'
            result = subprocess.run(test_cmd, shell=True, capture_output=True, text=True)
            if result.returncode != 0:
                logging.error("Invalid WSL password")
                return False
            return True
        except Exception as e:
            logging.error(f"WSL initialization error: {e}")
            return False
            
    def run_as_root(self, command):
        """Run a command as root in WSL"""
        if not self.password:
            return False
            
        full_cmd = f'wsl -d kali-linux -u root bash -ic "echo {self.password} | sudo -S {command}"'
        try:
            subprocess.run(full_cmd, shell=True, check=True)
            return True
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to run command as root: {e}")
            return False
            
    def stop_cowrie(self):
        """Stop any running Cowrie instances"""
        self.run_as_root("pkill -f cowrie")
        
    def cleanup_cowrie(self):
        """Clean up Cowrie processes and files"""
        commands = [
            "pkill -f cowrie",
            "rm -f /home/cowrie/cowrie/var/run/cowrie.pid",
            "rm -f /home/cowrie/cowrie/var/log/cowrie/cowrie.log.*"
        ]
        for cmd in commands:
            self.run_as_root(cmd)
