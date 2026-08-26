# Indicators of Compromise (IOCs)

### Network Indicators

| Type | Indicator | Description |
| :--- | :--- | :--- |
| Domain | `opsbridge.digital` | C2 Operator Panel |
| Subdomain | `api.opsbridge.digital` | Agent C2 Beacon Endpoint |
| Subdomain | `upload.opsbridge.digital` | Data Exfiltration Staging |
| IP (Origin) | `69.164.245.216` | Linode Backend VPS |
| IP (Exfiltration) | `163.245.221.212` | Staging Exfiltration Host |
| URL (Phishing) | `https://littletonpc.org/adbrdbckup/adobedocument.html` | Compromised Delivery Lure |

### File Hashes

| File | Hash (SHA256) | Role |
| :--- | :--- | :--- |
| `AdbRds_BckUp_SetUp.msi` | `44dc049de6284dd000bad1292967939951ff8a307a3efe0dc3b25c77350db13c` | Dropper Installer |
| `OpsBridgeAgent.exe` (`AgentExe`) | `72d68bc646680c746decf5f8aa48cd8a011f04c7a1be6c3f5d247f14131d6635` | Core RAT Binary |

### Configuration Artifacts

| Field | Extracted Value |
| :--- | :--- |
| Campaign ID | `e2b5d59c80f0a816b3d58728f9552898` |
| Digital Certificate | `SSLcom-SubCA-EV-CodeSigning-RSA-4096-R3` |
