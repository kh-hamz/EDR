# Response Runbook

General triage order for an alert or incident in this EDR:

1. **Read the timeline before acting.** An incident groups alerts by host
   and a 30-minute time window - the process tree and timeline together
   usually tell the whole story (initial access -> execution -> follow-on
   action) without needing to dig through raw events.
2. **Check severity against evidence.** Rule-tagged severity is a starting
   point, not the final word - a `critical` alert on a test host behaving
   as expected (e.g. a known Atomic Red Team run) may not warrant the same
   response as the same alert on a production host.
3. **Reverse shell (T1059/T1571) - kill first, ask questions after.** This
   is the one rule with an auto-response playbook: a matching alert
   auto-issues `kill_process` for the shell's pid. If you see the process
   is already gone by the time you triage, the playbook likely already
   handled it - check `/response/commands` for the issued command and its
   result before manually re-killing.
4. **Persistence (cron, systemd, backdoor user) requires manual cleanup.**
   Killing the running process does not remove a cron entry, systemd unit,
   or backdoor account - those must be removed by hand (or via a future
   scripted response action) or the attacker regains access on the next
   scheduled run or login.
5. **Credential access (T1003/T1552) escalates the response.** If
   `/etc/shadow` or an SSH key was read, assume credentials may be
   compromised - rotate the affected account's password/keys regardless of
   whether the rest of the incident looks contained.
6. **Isolate before investigating further only if containment is urgent.**
   `isolate_host` drops all network traffic except the backend connection -
   use it when active data exfiltration or lateral movement is suspected,
   not as a default first step, since it also cuts off legitimate access
   for whoever is using that host.
7. **Close the incident only after persistence is confirmed removed** and,
   for reverse-shell/webshell cases, after confirming the process (and any
   dropped files) are gone.
