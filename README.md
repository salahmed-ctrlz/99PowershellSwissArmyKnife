# 99Powershell SwissArmyKnife

A portable, all-in-one **PowerShell utility** for system administrators, network engineers, and technicians.  
Designed to work **offline**, without external libraries, and run **99 admin-ready commands** organized into categories.  

It’s your quick-response toolkit for diagnostics, cleanup, configuration, and troubleshooting — all in one script.  

---

## 📂 Features

- **99 Admin Commands** grouped into categories:  
  1. **System Management** – Cleanup, updates, performance tweaks, shutdown/reboot, BIOS access.  
  2. **Network Tools** – Reset adapters, DNS tweaks, ping sweeps, traceroutes, port scans.  
  3. **Security & Privacy** – Firewall control, Defender scans, BitLocker management, account settings.  
  4. **File & Storage Ops** – Disk cleanup, defrag, temp/cache purges, file searches, permissions fixes.  
  5. **Advanced Admin Tasks** – Service control, process killing, logging, system restore, backups.  

- **Pre-Execution System Restore Point** before any risky operation.  
- **Confirmation Prompts** for destructive actions (disable, restart, remove, format, etc.).  
- **Interactive Menu** – Navigate categories and run multiple commands before returning to main menu.  
- **Colored CLI** – Clear, organized interface for quick reading.  
- **Portable** – No install needed, works from USB stick.  
- **Runs as Administrator Automatically** (via included `.bat` launcher).  

---

## 📦 Contents

```

99PowershellSwissArmyKnife.ps1   → Main script
Run\_as\_Admin.bat                 → Double-click launcher (always runs as admin)
README.md                        → This file

```

---

## 🛠️ Requirements

- **OS**: Windows 7, 8, 10, 11  
- **Permissions**: Admin rights required  
- **PowerShell Version**: 5.1 or later (default in Windows 10+)  

---

## 🚀 Usage

### 1️⃣ Extract the ZIP
Unzip the package to a folder (e.g., Desktop or USB drive).

### 2️⃣ Run as Administrator
Double-click **Run_as_Admin.bat** to launch the tool with admin rights.

### 3️⃣ Navigate Menu
- Enter the **letter or number** of a category.  
- Choose commands to execute.  
- You can run multiple commands in a category before returning to main menu.

### 4️⃣ Exit
Type `X` or `Exit` to close the tool.

---

## ⚠️ Safety Notes

- This script **modifies system settings**.  
- Always run in a **controlled environment first** before production use.  
- Some commands may restart your PC or disrupt network connectivity.  

---

## 👨‍💻 Developer

**Medkour Salahuddin**  
🔗 [LinkedIn](https://www.linkedin.com/in/salah-eddine-medkour/)  
💻 [GitHub](https://github.com/salahmed-ctrlz)  

---

## 📜 License

Free for personal & educational use. Do not redistribute under a paid license.


