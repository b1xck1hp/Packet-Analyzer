import os
import sys
import subprocess
import platform
import random
import string
import shutil

def generate_password(length=12):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for _ in range(length))

def check_wsl_support():
    if platform.system() != 'Windows':
        return False
    
    try:
        result = subprocess.run(['wsl', '--status'], capture_output=True, text=True)
        return result.returncode == 0
    except FileNotFoundError:
        return False

def setup_project():
    print("🚀 Starting project setup...")
    
    # Step 1: Install npm dependencies
    print("\n📦 Installing npm dependencies...")
    subprocess.run(['npm', 'install'], check=True)
    
    # Step 2: Install Python dependencies
    print("\n📦 Installing Python dependencies...")
    subprocess.run([sys.executable, '-m', 'pip', 'install', '-r', 'backend/requirements.txt'], check=True)
    
    # Step 3: Check and setup WSL
    print("\n🐧 Checking WSL support...")
    if check_wsl_support():
        print("WSL is supported on your system!")
        try:
            # Check if Kali Linux is installed
            result = subprocess.run(['wsl', '-l', '-v'], capture_output=True, text=True)
            if 'kali-linux' not in result.stdout.lower():
                print("Installing Kali Linux...")
                subprocess.run(['wsl', '--install', '-d', 'kali-linux'], check=True)
            
            # Create honeypot user
            password = generate_password()
            print(f"\n🔑 Generated password for honeypot user: {password}")
            
            # Create .env file from example
            if os.path.exists('backend/.env.example'):
                shutil.copy('backend/.env.example', 'backend/.env')
                with open('backend/.env', 'a') as f:
                    f.write(f'\nWSL_PASSWORD={password}\n')
                print("\n📄 Created .env file with WSL password")
        except subprocess.CalledProcessError as e:
            print(f"Error setting up WSL: {e}")
    else:
        print("⚠️ WSL is not supported on your system. Some features may not work.")
    
    # Step 4: Instructions for API setup
    print("\n🔑 Important Setup Steps:")
    print("\n1. Please register for Google App Password at:")
    print("   https://support.google.com/accounts/answer/185833?hl=en")
    print("   After getting the password, add it to backend/.env as GMAIL_PASSWORD")
    
    print("\n2. Register for AbuseIPDB API at:")
    print("   https://www.abuseipdb.com/")
    print("   After getting the API key, add it to backend/.env as ABUSEIPDB_API_KEY")
    
    print("\n✅ Setup complete! You can now run the project using run.py")

if __name__ == "__main__":
    setup_project()
