from agents.endpoint_agent.linux_event_collector import AuditdProcessCollector


collector = AuditdProcessCollector()

syscall_line = (
    'type=SYSCALL msg=audit(17200000000.1:42): '
    'arch=c000003e syscall=59 success=yes exit=0 '
    'pid=1234 ppid=100 uid=100 comm="nc.traditional" '
    'exe="/bin/nc.traditional" ' 
)

execve_line = (
    'type=EXECVE msg=audit(17200000000.1:42): '
    'argc=4 a0="nc.traditional" a1="-vz" '
    'a2="10.0.0.50" a3="4444"'
)

event = collector._normalize(syscall_line, execve_line)
assert event["name"] == "nc.traditional"
assert event["path"] == "/bin/nc.traditional"
assert event["command_line"] == "nc.traditional -vz 10.0.0.50 4444"
assert event["event_source"] == "auditd"
print(event)