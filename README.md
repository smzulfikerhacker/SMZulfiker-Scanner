# 🛡️ SMZulfiker-Scanner  
### Developer: **SM Zulfiker**  
Black Mafia Commander

---

## 🚀 What This Tool Can Do (Full Features)

✔ **Subdomain Scan** – টার্গেটের সব লুকানো সাবডোমেইন বের করে  
✔ **Port Scanner** – ওপেন পোর্ট চেক করে  
✔ **Admin Panel Finder** – লুকানো অ্যাডমিন পেজ খুঁজে বের করে  
✔ **SQL Injection Detector** – URL এ SQLi আছে কিনা চেক করে  
✔ **XSS Auto Scanner** – ইনপুট ফিল্ড এ XSS payload fire করে  
✔ **Directory Bruteforce** – হিডেন ডিরেক্টরি বের করে  
✔ **WAF Detector** – ওয়েবসাইটে কোন Web Application Firewall আছে চেক  
✔ **CMS Detector** – WordPress, Joomla, Drupal চেনার সিস্টেম  
✔ **Parameter Fuzzer** – Hidden parameters brute-force  
✔ **Live Output Mode** – টার্মিনালে লাইভ রেজাল্ট দেখায়  
✔ **Auto Save Mode** – চাইলে ফাইলেও save করে  
✔ **Fast Scan Mode** – দ্রুত স্ক্যান করার সিস্টেম  
✔ **Full Recon Automation** – একবার রান দিলে সব স্ক্যান অটো রান  
✔ **Colorful Animated Output** – চলার সময় animation + color  

---

# 📥 Installation  
কালী লিনাক্স এবং টার্মাক্সে একইভাবে কাজ করবে।

---

## 🐧 Kali Linux Install
```bash
sudo apt update
sudo apt install -y python3 python3-pip git
git clone https://github.com/smzulfikerhacker/SMZulfiker-Scanner.git
cd SMZulfiker-Scanner
pip install -r requirements.txt
```

---

## 📱 Termux Install
```bash
pkg update
pkg install -y python git
git clone https://github.com/smzulfikerhacker/SMZulfiker-Scanner.git
cd SMZulfiker-Scanner
pip install -r requirements.txt
```

---

# ▶️ How to Run

## 🔥 Basic Scan
```bash
python3 SMZulfiker.py --target example.com
```

---

## 😈 Full Recon (Everything Auto)
```bash
python3 SMZulfiker.py --target example.com --full
```

---

## 🎯 Subdomain Only
```bash
python3 SMZulfiker.py --target example.com --subs
```

---

## 🔑 Admin Panel Finder
```bash
python3 SMZulfiker.py --target example.com --admin
```

---

## 🧨 SQL Injection Check
```bash
python3 SMZulfiker.py --target example.com --sqli
```

---

## ⚔️ XSS Auto Attack
```bash
python3 SMZulfiker.py --target example.com --xss
```

---

## ⚡ Fast Scan
```bash
python3 SMZulfiker.py --target example.com --fast
```

---

## 🧾 Save Result to Files
```bash
python3 SMZulfiker.py --target example.com --save
```

---

# 👑 Developer  
**SM Zulfiker**  
Black Mafia Commander  
GitHub: https://github.com/smzulfikerhacker  

---

# ⚠️ Disclaimer  
Educational purpose only. Unauthorized testing is illegal.

---
