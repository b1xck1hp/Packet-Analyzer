# Network Security Monitoring System

A comprehensive network security monitoring system that combines real-time packet analysis, honeypot capabilities, and threat intelligence integration.

## 👥 Team Members
1. Mohamed Saied
2. Ahmed Eldesouki 
3. Mohamed Wael 
4. Essameldin Amr
5. Ahmed Abdelmoniem
6. Marwan HossamEldin
7. Randa Emam
8. Monira Mahmoud
9. Ahmed Tarek

## 🚀 Features

### 🕷️ Honeypot System
- Integrated Cowrie honeypot for SSH and Telnet attack monitoring
- Automated attacker behavior analysis
- Real-time attack pattern detection
- Secure logging of all attack attempts

### 📊 Network Analysis
- Real-time packet capture and analysis
- Protocol-based filtering (TCP, UDP, ICMP)
- Deep packet inspection
- Traffic pattern visualization
- Customizable packet filtering

### 🛡️ Security Features
- Integration with AbuseIPDB for threat intelligence
- Automated IP reputation checking
- Real-time threat scoring
- Configurable blocking rules
- Port-based security monitoring

### 📧 Alert System
- SMTP-based email notifications
- Customizable alert thresholds
- Critical event notifications
- Detailed attack reports
- Automated incident reporting

### 💻 User Interface
- Modern React-based dashboard
- Real-time updates via WebSocket
- Interactive data visualization
- Advanced filtering capabilities
- Responsive design for all devices

## 🛠️ Technology Stack
- **Frontend**: React, TypeScript, Tailwind CSS, Socket.IO Client
- **Backend**: Python, Flask, Socket.IO
- **Security**: Cowrie Honeypot, Scapy, AbuseIPDB API
- **Monitoring**: Real-time packet capture, WSL integration
- **Notifications**: SMTP, Email integration

## 📋 Prerequisites
- Windows 10/11 with WSL support
- Python 3.8 or higher
- Node.js 16.x or higher
- WSL enabled (for Kali Linux integration)

## 🚀 Quick Start

1. **Clone the Repository**
   ```bash
   git clone https://github.com/b1xck1hp/Packet-Analyzer.git
   cd Packet-Analyzer
   ```

2. **Run Setup Script**
   ```bash
   python setup.py
   ```
   The setup script will:
   - Install all required dependencies
   - Set up WSL and Kali Linux if needed
   - Configure the honeypot environment
   - Set up necessary environment variables

3. **Configure APIs**
   - Register for [AbuseIPDB API](https://www.abuseipdb.com/)
   - Set up Gmail App Password for notifications
   - Update the `.env` file with your credentials

4. **Start the Application**
   ```bash
   python run.py
   ```

5. **Access the Dashboard**
   - Open your browser and navigate to: `http://localhost:5173`
   - The backend API will be available at: `http://localhost:5000`

## 📝 Configuration

### Environment Variables
Create a `.env` file in the backend directory with:
```env
ABUSEIPDB_API_KEY=your_api_key
GMAIL_ADDRESS=your_email@gmail.com
GMAIL_PASSWORD=your_app_password
WSL_PASSWORD=your_wsl_password
```

## 🔧 Troubleshooting

1. **WSL Issues**
   - Ensure WSL is enabled in Windows features
   - Check if Kali Linux is properly installed
   - Verify WSL password in .env file

2. **Network Capture Issues**
   - Run the application with administrator privileges
   - Check if Scapy is properly installed
   - Verify network interface settings

3. **Email Notification Issues**
   - Confirm Gmail App Password is correct
   - Check spam folder for notifications
   - Verify SMTP settings

## 📚 Contributing
Contributions are welcome! Please feel free to submit a Pull Request.

## 📄 License
This project is licensed under the MIT License - see the LICENSE file for details.
