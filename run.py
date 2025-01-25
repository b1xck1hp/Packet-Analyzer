import subprocess
import sys
import os
import webbrowser
from time import sleep

def run_project():
    try:
        # Start backend server
        print("🚀 Starting backend server...")
        backend_process = subprocess.Popen([sys.executable, 'backend/app.py'], 
                                         stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE)
        
        # Start frontend development server
        print("🌐 Starting frontend server...")
        frontend_process = subprocess.Popen(['npm', 'run', 'dev'],
                                          stdout=subprocess.PIPE,
                                          stderr=subprocess.PIPE)
        
        # Wait a bit for servers to start
        sleep(3)
        
        # Open the application in default browser
        webbrowser.open('http://localhost:5173')
        
        print("\n✨ Project is running!")
        print("Frontend: http://localhost:5173")
        print("Backend: http://localhost:5000")
        print("\nPress Ctrl+C to stop the servers...")
        
        # Keep the script running
        frontend_process.wait()
        
    except KeyboardInterrupt:
        print("\n🛑 Stopping servers...")
        frontend_process.terminate()
        backend_process.terminate()
        print("Servers stopped successfully!")
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    run_project()
