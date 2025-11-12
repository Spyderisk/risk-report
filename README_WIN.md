# README_WIN.md

## ⚙️ Compatibility

- The project has been tested on **Windows 10 (22H2)** with **WSL 1 + Ubuntu 22.04 LTS**.
- It *should also run* on **Windows 11** or **Windows 10 with WSL 2**, using the same commands.
- Users on WSL 2 do not need to change anything — the Makefile and Python environment are platform-independent.
- If you encounter virtualization-related errors on Windows 10, you can safely use WSL 1 as described below.

> 🧩 **Note for WSL 2 users**  
> This project *should* also work under **WSL 2** (for example, on Windows 11 or Windows 10 systems with virtualization enabled).  
> However, it has not yet been formally tested in that environment.  
> If you use WSL 2, the same setup commands and Makefile are expected to function without changes, but please report any differences or issues you observe.

---

## 🚀 Quick Start

### 1️⃣ Check or Set Your Default WSL Distro

Before running any commands, ensure that your default WSL distribution is set to **Ubuntu 22.04**.

In **PowerShell**:

```powershell
wsl -l -v             # list installed distros
wsl -s Ubuntu-22.04   # set Ubuntu 22.04 as default (if not already)
```

Then open Ubuntu with:
```powershell
wsl
```

---

### 2️⃣ Run the Project

Inside Ubuntu:

```bash
cd /mnt/c/Users/<wsl_username>/path/to/your/project
make report ARGS="-i system_model.nq.gz -o risk-report.csv -d domain-network/csv"
```

> 💡 **No need to run `make init` manually.** The first `make report` will create the virtual environment and install dependencies automatically. Subsequent runs will skip setup and execute immediately.

---

## 🧰 One-Time Ubuntu Setup (22.04 LTS)

Run these once in the new WSL environment:

```bash
sudo apt update
sudo apt upgrade -y            # optional but recommended
sudo apt install -y make python3-venv python3-pip build-essential
```

Optional quality-of-life:
```bash
touch ~/.hushlogin             # hide the daily login banner
alias ll='ls -alF'             # nicer directory listings
```

---

## 📌 Notes for Windows / WSL

- **Default distro:** Set once so `wsl` opens Ubuntu without `-d`:
  ```powershell
  wsl -s Ubuntu-22.04
  ```

- **File locations:** Your Windows home drive is mounted under `/mnt/c`.  
  Example project path:  
  `/mnt/c/Users/<wsl_username>/path/to/your/project`

- **Virtual environment:** The Makefile creates `env/` in the repo; it’s ignored by Git.
- **Reproducibility:** Use separate checkouts for different OSes (Linux VM vs WSL) to avoid venv conflicts.

---

## 🔧 First Aid (Troubleshooting)

**If Ubuntu doesn’t start** (run in *PowerShell*):
```powershell
wsl --shutdown
Get-Service LxssManager | Restart-Service
wsl
```

**If `make` / `pip` are missing** (run in *Ubuntu*):
```bash
sudo apt update
sudo apt install -y make python3-venv python3-pip
```

**If Python packages fail to build** (C extensions):
```bash
sudo apt install -y build-essential
rm -rf env && make report ARGS="..."
```

**If venv breaks:**
```bash
rm -rf env
make report ARGS="..."
```

**If permissions look odd (created as root):**
```bash
sudo chown -R "$USER:$USER" .
```

**If networking is flaky (apt/pip can’t reach):** *(run in PowerShell)*
```powershell
wsl --shutdown
netsh winsock reset
```

---

## 🧭 Verifications

Inside Ubuntu:
```bash
lsb_release -a          # Ubuntu version (e.g., 22.04.5 LTS)
python3 --version       # Python version
which python3           # /usr/bin/python3
```

From PowerShell:
```powershell
wsl -l -v               # list distros and WSL version
```

---

## 🆙 Optional: Upgrade to WSL 2 later

Once virtualization is available and stable on the host:
```powershell
wsl --set-version Ubuntu-22.04 2
```
This keeps your files and settings; only the backend changes.

---

## ✅ Daily Usage Summary

```bash
wsl                                  # open Ubuntu (default)
cd /mnt/c/Users/<wsl_username>/path/to/your/project
make report ARGS="-i system_model.nq.gz -o risk-report.csv -d domain-network/csv"
```

Happy building!
