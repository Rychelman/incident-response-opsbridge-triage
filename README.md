# Live Incident Response & Malware Triage: OpsBridge C2 Loader Campaign

An end-to-end DFIR case study detailing the containment of an enterprise business email compromise (BEC) and static malware triage of an EV-signed Windows installer delivering the OpsBridge C2 agent.

---

## Executive Summary

An unauthorized login occurred on an enterprise Microsoft 365 mailbox originating from an external IP address. The threat actor established persistence via malicious inbox rules and distributed a zero-hour phishing blast to approximately 450 contacts. 

Investigation of the payload revealed a multi-stage malware campaign deploying an EV-signed MSI installer delivering an evasive Command and Control (C2) agent linked to `opsbridge.digital`.

---

## Incident Timeline & Triage

1. **Unauthorized Access:** External login detected on the endpoint mailbox via session cookie theft or credential reuse.
2. **Mailbox Manipulation:** Threat actor created a hidden inbox rule forwarding replies and bounce notifications directly to Deleted Items to mask malicious activity.
3. **Phishing Blast:** 450 external vendors and contacts received a lure disguised as an urgent document update (`Grove Hill Doc2026.pdf`).
4. **Remediation Executed:**
   - Deleted malicious mailbox routing rules.
   - Performed tenant-wide credential resets.
   - Revoked all active session tokens (`Sign out everywhere`) to disconnect active sessions.
   - Dispatched a liability-neutral security advisory to all impacted recipients.

---

## Static Malware Analysis

Static triage was conducted in an isolated Kali Linux sandbox to analyze the payload without executing native Windows binaries.

### Stage 1: Delivery & Lure
- **Phishing URL:** Hosted on a compromised third-party WordPress installation (`littletonpc.org`).
- **Lure Technique:** Fake Adobe Acrobat Reader landing page prompting the victim to download `AdbRds_BckUp_SetUp.msi` (34.8 MB) to view a blurred background document.

### Stage 2: MSI & CAB Deconstruction
Using `7z` to unpack the compound archive structure without executing the installer:

```bash
# Unpack MSI container
7z x AdbRds_BckUp_SetUp.msi -o./extracted_msi/

# Extract internal cabinet file
cd extracted_msi
7z x cab1.cab -o./cab_contents/
