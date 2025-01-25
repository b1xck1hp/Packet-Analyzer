# Network Security Monitoring System

A real-time network security monitoring system with honeypot capabilities.

## Quick Start

### Prerequisites
- Docker Desktop ([Download here](https://www.docker.com/products/docker-desktop/))
  - Windows: Windows 10/11 Pro, Enterprise, or Education
  - Mac: macOS 10.15 or newer
  - Linux: Ubuntu, Debian, Fedora, or other major distributions

### Installation Steps

1. **Install Docker Desktop**
   - Download and install Docker Desktop for your operating system
   - Start Docker Desktop
   - Wait until Docker Desktop is running (check the whale icon in taskbar)

2. **Get the Project**
   ```bash
   git clone [your-repository-url]
   cd [repository-name]
   ```

3. **Set up Environment Variables**
   ```bash
   cd backend
   cp .env.example .env
   ```
   - Open `.env` in a text editor
   - Fill in your configuration values

4. **Start the Application**
   ```bash
   docker-compose up --build
   ```

5. **Access the Application**
   - Open your browser and go to: `http://localhost`
   - The application should be up and running!

### Stopping the Application
To stop the application, press `Ctrl+C` in the terminal or run:
```bash
docker-compose down
```

## Troubleshooting

If you encounter any issues:

1. Make sure Docker Desktop is running
2. Try restarting Docker Desktop
3. Run `docker-compose down` and then `docker-compose up --build`
4. Check if all required ports (80, 5000) are available

## Note

- The first build might take a few minutes as Docker downloads and builds all required components
- No other installations are needed - Docker handles everything!
- All your data and configurations are preserved between restarts
