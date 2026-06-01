# CyberGuard

**CyberGuard** is a simple on-premises SOC threat intelligence repository for identifying Indicators of Compromise (IoCs). It runs on a local Windows machine or local LAN using **Node.js + Express + MongoDB Community Server**. No cloud database is required.

## Features

- Admin/Analyst login
- Dashboard with IoC statistics
- Add, list, edit, and delete IoCs
- Exact IoC search/identification
- CSV import for bulk IoC upload
- Threat report summary
- Audit logging for important actions
- Local MongoDB connection only

## Default Login

The app automatically creates these users on first run:

| Role | Username | Password |
|---|---|---|
| Admin | `admin` | `admin123` |
| Analyst | `analyst` | `analyst123` |

Change these passwords before using the project outside a classroom/demo environment.

## Requirements

1. Node.js installed
2. MongoDB Community Server installed and running locally
3. MongoDB Shell/Compass optional but helpful

## Setup in VS Code

Open the project folder in VS Code, then run these commands in the terminal:

```powershell
npm install
npm start
```

Open the browser:

```text
http://127.0.0.1:3000
```

## MongoDB Connection

The project uses this default local database connection:

```env
MONGO_URI=mongodb://127.0.0.1:27017/cyberguard
```

You can edit `.env` if your MongoDB runs on a different host or port.

## Load Demo IoC Data

After `npm install`, you can load sample IoCs by running:

```powershell
npm run seed:demo
```

You can also import the CSV file from the web dashboard:

```text
data/sample_iocs.csv
```

## LAN Usage Without Cloud

To access the app from another computer on the same LAN, change this line in `.env`:

```env
HOST=0.0.0.0
```

Then run:

```powershell
npm start
```

Find the server PC IP address, for example `192.168.1.10`, and open this on another LAN computer:

```text
http://192.168.1.10:3000
```

Make sure Windows Firewall allows Node.js on the local/private network.

## CSV Format

Use this format for importing IoCs:

```csv
value,type,threatType,severity,confidence,source,description,tags
203.0.113.10,IP,Malware C2,High,85,Internal SOC,Demo malicious IP,"malware,c2"
```

Allowed severity values:

```text
Low, Medium, High, Critical
```

Allowed IoC type values:

```text
IP, Domain, URL, MD5, SHA1, SHA256, Email, Unknown
```

## Project Structure

```text
CyberGuard/
├── config/
├── middleware/
├── models/
├── routes/
├── scripts/
├── utils/
├── views/
├── public/
├── uploads/
├── data/
├── server.js
├── package.json
└── README.md
```

## Notes

This project is intended for academic/demo use. For real SOC production use, add HTTPS, stronger password rules, CSRF protection, centralized logging, backups, and hardened server configuration.

## npm install troubleshooting

If `npm install` tries to download packages from an internal/non-public registry such as `packages.applied-caas-gateway1.internal.api.openai.org`, delete `package-lock.json` and `node_modules`, then force npm to use the public registry:

```powershell
cd D:\cyberguard\CyberGuard
npm config set registry https://registry.npmjs.org/
rmdir /s /q node_modules
del package-lock.json
npm cache clean --force
npm install --registry=https://registry.npmjs.org/
npm start
```

This ZIP does not include a `package-lock.json`, so npm should create a fresh lock file from the public npm registry on your computer.
