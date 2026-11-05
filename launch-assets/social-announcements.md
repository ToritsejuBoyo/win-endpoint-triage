# Launch Announcement Copy: `win-endpoint-triage`

Use these ready-to-publish posts across LinkedIn, Reddit, and X/Twitter to launch Day 1 of your 30-day initiative.

---

## 1. LinkedIn Post (Target: IT Managers, MSP Owners, SysAdmins)

```markdown
Every SysAdmin and MSP Lead knows the pain of this ticket:

"User says laptop is running slow. Rebooted. Issue persists. Please advise." 🤦‍♂️

L1 spent 40 minutes poking around Event Viewer.
L2 rejects the ticket because there are no logs or error codes.
The user waits 3 days while the ticket bounces back and forth.

Today, I’m open-sourcing Day 1 of our 30-Day IT Operations Agent Skills Library:
🔥 Windows Endpoint Triage & Escalation Packager (`win-endpoint-triage`)

Here’s how it works:
1️⃣ The technician runs a 15-second, 100% read-only PowerShell command on the troubled PC.
2️⃣ It captures 6 critical domains: Uptime & Fast Startup, Windows Reliability Score (1-10), SSD bad blocks / IO resets, memory hogs, Entra ID PRT token state, and thermal throttling.
3️⃣ The AI analyzes the sanitized ~18 KB JSON against senior sysadmin rules, determines if L1 can fix it in 5 minutes, and drafts an airtight ticket escalation note ready to paste into ServiceNow, Jira, HaloPSA, or ConnectWise.

🔒 Enterprise Safe:
- 100% Read-Only (0 system changes, 0 reboots, 0 service stops).
- Privilege-Adaptive (works for standard users without admin rights).
- Automated PII masking (-Sanitize).
- Works offline with local Ollama if logs can't touch the cloud.

Check out the open-source repo and run the one-liner on your machine:
👉 https://github.com/ToritsejuBoyo/win-endpoint-triage

What’s the most frustrating ticket escalation note you’ve ever received? Drop it in the comments below! 👇

#ITSupport #SysAdmin #MSP #HelpDesk #PowerShell #AIOps #Windows11 #ITSM
```

---

## 2. Reddit Post (Target: r/sysadmin & r/msp)

**Title:** `I built a 100% read-only PowerShell + AI triage tool to kill incomplete L1-to-L2 ticket escalations (open source)`

**Body:**
```markdown
Hey everyone,

If you've spent any time working L2/L3 or running an MSP service desk, you’ve probably wanted to pull your hair out over ticket notes like:
*"User says PC is freezing. Ran sfc /scannow. Rebooted. Still slow. Escalating to engineering."*

You open the ticket and have to re-do 45 minutes of basic discovery: What’s the uptime? Are there disk controller resets? Is Fast Startup causing a zombie session? Is the Entra PRT token broken?

I built and open-sourced **`win-endpoint-triage`** to solve this:

### How it works:
1. **The Collector:** A zero-dependency, 100% read-only PowerShell script. It doesn't need admin privileges (it adapts gracefully if run as a standard user) and modifies zero system state.
2. **What it pulls in ~15 seconds:**
   - Real uptime vs. Fast Startup hibernation state.
   - Built-in Windows Reliability Index (1-10 stability score from `Win32_ReliabilityStabilityMetrics`).
   - Disk capacity & Event ID 7/153 bad blocks or NVMe controller resets.
   - Modern Workplace identity (`dsregcmd /status` check for `AzureAdPrt: YES/NO`).
   - Event ID 37 CPU thermal throttling (finding laptops stuck at 0.79 GHz due to bad chargers or dust).
   - High-signal System/Application errors from the last 48 hours.
3. **The AI Skill:** You paste the sanitized JSON into Claude, ChatGPT, Cursor, or local Ollama. It evaluates the 6 domains, tells L1 plainly if they can fix it right now, and generates an airtight escalation block formatted for ServiceNow/Jira or ConnectWise/HaloPSA.

### Security / Trust:
- Zero writes, zero reboots, zero service restarts.
- Auto-sanitizes hostnames, usernames, internal domains, and IP octets with `-Sanitize`.
- Plaintext PowerShell only—no compiled binaries or external DLLs.
- 100% offline compatible with Ollama (`qwen2.5-coder`).

Code is open-source under MIT on GitHub: https://github.com/ToritsejuBoyo/win-endpoint-triage

Would love to hear your feedback on the schema and what edge-case event IDs you think should be added!
```

---

## 3. X / Twitter Thread

```text
1/5 Frontline IT support spends 30-45 minutes digging through Event Viewer on slow laptops, only to escalate vague tickets that L2 engineers reject.

Today, we're launching win-endpoint-triage — an open-source AI skill + 15s read-only PowerShell collector to kill ticket ping-pong. 🧵👇

2/5 🛠️ What it captures in 15 seconds:
• Real uptime vs Fast Startup zombie sessions
• Windows Reliability Index (1-10)
• NVMe/SSD bad blocks (Event 7/153)
• Entra ID PRT token loops (dsregcmd)
• CPU thermal throttling (Event 37)
• Top memory & crash stacks

3/5 🧠 What the AI does:
Instead of dumping raw logs, it correlates the true root cause, answers "Can L1 fix it in 5 mins?", and outputs a pre-formatted escalation brief for ServiceNow, Jira, HaloPSA, or ConnectWise.

4/5 🔒 Enterprise-Safe by Design:
• 100% Read-Only (0 writes, 0 reboots)
• Privilege-adaptive (runs without local admin)
• Automated PII masking
• Works 100% offline with local Ollama

5/5 Grab the open-source repo and test the one-liner on your machine today:
👉 https://github.com/ToritsejuBoyo/win-endpoint-triage

#SysAdmin #PowerShell #HelpDesk #AI
```

