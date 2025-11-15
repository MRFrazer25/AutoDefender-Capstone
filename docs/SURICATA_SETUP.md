# Suricata Setup for AutoDefender

This guide covers Suricata installation, configuration, and testing with AutoDefender.

## Table of Contents
- [Windows Setup](#windows-setup)
- [Linux/Mac Setup](#linuxmac-setup)
- [Starting Suricata](#starting-suricata)
- [Testing with AutoDefender](#testing-with-autodefender)
- [Troubleshooting](#troubleshooting)

---

## Windows Setup

### Installation Location

**Suricata Path:** `C:\Program Files\Suricata\`  
**Executable:** `C:\Program Files\Suricata\suricata.exe`  
**Log File:** `C:\Program Files\Suricata\log\eve.json`  
**Config File:** `C:\Program Files\Suricata\suricata.yaml`

### Adding Suricata to PATH (Optional)

To make `suricata` command available in all terminals:

**Option 1: PowerShell (Run as Administrator)**
```powershell
[Environment]::SetEnvironmentVariable("Path", $env:Path + ";C:\Program Files\Suricata", "Machine")
```

**Option 2: GUI Method**
1. Press `Win + X` then System then Advanced system settings
2. Click "Environment Variables"
3. Under "System variables", find "Path" and click "Edit"
4. Click "New" and add: `C:\Program Files\Suricata`
5. Click OK on all dialogs
6. **Restart your terminal/PowerShell**

### Finding Your Network Interface

```powershell
Get-NetAdapter | Where-Object {$_.Status -eq "Up"} | Select-Object Name, InterfaceDescription
```

You should see something like:
- `Wi-Fi`
- `Ethernet`
- `Ethernet 3`

---

## Linux/Mac Setup

### Finding Suricata Log File

```bash
# Check Suricata config for log path
sudo suricata -c /etc/suricata/suricata.yaml --dump-config | grep eve-log

# Common locations:
# Linux: /var/log/suricata/eve.json
# Mac: /usr/local/var/log/suricata/eve.json
```

### Check if Suricata is Running

```bash
# Linux
sudo systemctl status suricata
# or
ps aux | grep suricata

# Check if log file exists and is being written to
ls -lh /var/log/suricata/eve.json
tail -f /var/log/suricata/eve.json
```

---

## Starting Suricata

### Windows

Open a **new PowerShell window as Administrator** (keep it open) and run:

```powershell
cd "C:\Program Files\Suricata"
.\suricata.exe -c suricata.yaml -i "Wi-Fi"
```

Replace `"Wi-Fi"` with your actual network interface name.

### Linux

```bash
# Start Suricata service
sudo systemctl start suricata

# Or run manually
sudo suricata -c /etc/suricata/suricata.yaml -i eth0
```

### Mac

```bash
# Run manually (replace eth0 with your interface)
sudo suricata -c /usr/local/etc/suricata/suricata.yaml -i en0
```

### Verify Log File is Created

**Windows:**
```powershell
Test-Path "C:\Program Files\Suricata\log\eve.json"
Get-Item "C:\Program Files\Suricata\log\eve.json" | Select-Object Length, LastWriteTime
```

**Linux/Mac:**
```bash
ls -lh /var/log/suricata/eve.json
```

The file should exist and the `LastWriteTime` (or modification time) should be recent.

---

## Testing with AutoDefender

### Step 1: Configure Environment Variables

**Windows PowerShell:**
```powershell
cd "C:\Users\<your-username>\AutoDefender_Hackathon"

$env:SURICATA_ENABLED = "true"
$env:SURICATA_DRY_RUN = "true"  # Safe testing - won't write real rules
$env:AUTO_APPROVE_SURICATA = "false"  # Manual approval
$env:OLLAMA_MODEL = "phi4-mini"
```

**Linux/Mac:**
```bash
cd ~/AutoDefender_Hackathon

export SURICATA_ENABLED=true
export SURICATA_DRY_RUN=true
export AUTO_APPROVE_SURICATA=false
export OLLAMA_MODEL=phi4-mini
```

### Step 2: Start AutoDefender Monitoring

**Windows:**
```powershell
python main.py --monitor "C:\Program Files\Suricata\log\eve.json" --model phi4-mini
```

**Linux:**
```bash
python main.py --monitor /var/log/suricata/eve.json --model phi4-mini
```

**Mac:**
```bash
python main.py --monitor /usr/local/var/log/suricata/eve.json --model phi4-mini
```

### Step 3: Generate Test Traffic

**Windows:**
```powershell
# Port scan (creates alerts)
nmap -p 1-1000 localhost

# Or use PowerShell
Test-NetConnection -ComputerName localhost -Port 80
Test-NetConnection -ComputerName localhost -Port 443
Invoke-WebRequest -Uri "http://testphp.vulnweb.com/" -UseBasicParsing
```

**Linux/Mac:**
```bash
# Port scan
nmap -p 1-1000 localhost

# HTTP requests
curl http://testphp.vulnweb.com/
```

You should see threats being detected in real-time in the AutoDefender terminal!

---

## Troubleshooting

### Suricata won't start

**Windows:**
- Make sure you're running PowerShell as Administrator
- Check if another instance is already running: `Get-Process suricata -ErrorAction SilentlyContinue`
- Check Suricata config: `.\suricata.exe -c suricata.yaml -T`

**Linux:**
- Check service status: `sudo systemctl status suricata`
- View logs: `sudo journalctl -u suricata -f`
- Check config: `sudo suricata -c /etc/suricata/suricata.yaml -T`

### No log file created

- Verify Suricata is actually running
- Check Suricata output for errors
- Verify network interface name is correct
- Check Suricata config to ensure EVE logging is enabled

### No threats detected

- Check if log file is growing (size should increase)
- Generate test traffic (nmap, curl, etc.)
- Check Suricata rules are enabled
- Verify AutoDefender is monitoring the correct file path

### Permission errors

**Windows:**
- Run PowerShell as Administrator
- Check file permissions on log directory

**Linux/Mac:**
- Use `sudo` to run Suricata
- Check file permissions: `ls -l /var/log/suricata/eve.json`
- Add your user to the `suricata` group (if it exists)

### Suricata not found in PATH

**Windows:**
- Add to PATH using instructions above
- Or use full path: `C:\Program Files\Suricata\suricata.exe`

**Linux/Mac:**
- Check installation: `which suricata`
- Install Suricata if not found

---

## Running Suricata as a Service (Optional)

### Windows

```powershell
cd "C:\Program Files\Suricata"
.\suricata.exe --service-install
.\suricata.exe --service-start

# Check service status
Get-Service -Name "*suricata*"
```

### Linux

```bash
# Enable and start service
sudo systemctl enable suricata
sudo systemctl start suricata

# Check status
sudo systemctl status suricata
```


