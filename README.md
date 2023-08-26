# Docker Detection Notes
##### Warning - Experimental / all done in lab environment, please test before using any of this in production

## Data Sources

- Sumo Logic Docker Driver - https://github.com/SumoLogic/sumologic-docker-logging-driver
- Laurel - https://github.com/threathunters-io/laurel
- Florian Roth's Auditd Configuration - https://github.com/Neo23x0/auditd
- Malcolm for PCAP - https://malcolm.fyi/

## References

- https://lobster1234.github.io/2019/04/05/docker-socket-file-for-ipc/
- https://github.com/cdk-team/CDK
- https://www.rapid7.com/db/modules/exploit/linux/http/docker_daemon_tcp/
- https://www.bordergate.co.uk/docker-penetration-testing/
- https://book.hacktricks.xyz/network-services-pentesting/2375-pentesting-docker
- https://github.com/stealthcopter/deepce

## TTPs

### Docker Enumeration 

![](20230826094147.png)

```sql
_source="Laurel" 
| where %"syscall.exe" = "/usr/bin/docker"
| where _raw matches /(docker|ps|info)/
| json field=_raw "PROCTITLE.ARGV[*]" as cmd_arg
| values(cmd_arg) as cmd_args by %"syscall.exe",%"syscall.ppid.comm"
```

![](20230826094119.png)

### Suspicious Container Start

![](20230826095126.png)

```sql
_source="Laurel" 
| where _raw matches /(chroot|mount)/
| where %"syscall.exe" = "/usr/bin/dockerd" OR %"syscall.exe"= "/usr/bin/docker"
| json field=_raw "PROCTITLE.ARGV[*]" as cmd_arg
| values(cmd_arg) as cmd_args by %"syscall.exe",%"syscall.ppid.comm"
```

![](20230826095147.png)

### Docker Filesystem Enumeration within Container

- Note this utilizes the Docker driver

![](20230826095731.png)

```sql
_source="Docker" and _collector="Docker"
| if(_raw matches /mount|fdisk/,1,0) as file_system_container_commands
| where file_system_container_commands = 1
```

![](20230826095750.png)

### Privileged Container Started

![](20230826100205.png)

```sql
_source="Laurel" 
| where _raw matches /(privileged)/
| where %"syscall.exe" = "/usr/bin/dockerd" OR %"syscall.exe"= "/usr/bin/docker"
| json field=_raw "PROCTITLE.ARGV[*]" as cmd_arg
| values(cmd_arg) as cmd_args by %"syscall.exe",%"syscall.ppid.comm"
```

![](20230826100223.png)

### Container Started with SYS_ADMIN privs

![](20230826100548.png)

```sql
_source="Laurel" 
| where _raw matches /(SYS_ADMIN)/
| where %"syscall.exe" = "/usr/bin/dockerd" OR %"syscall.exe"= "/usr/bin/docker"
| json field=_raw "PROCTITLE.ARGV[*]" as cmd_arg
| values(cmd_arg) as cmd_args by %"syscall.exe",%"syscall.ppid.comm"
```

![](20230826100614.png)

### Overly Permissive Mount

![](20230826101130.png)

```sql
_source="Laurel" 
| where _raw matches /(\-v\"\,"\/\:\/mnt)/
| where %"syscall.exe" = "/usr/bin/dockerd" OR %"syscall.exe"= "/usr/bin/docker"
| where %"syscall.ppid.comm" = "bash"
| json field=_raw "PROCTITLE.ARGV[*]" as cmd_arg
| values(cmd_arg) as cmd_args by %"syscall.exe",%"syscall.ppid.comm"
```

![](20230826102226.png)

```sql
_source="Docker" and _collector="Docker"
| where _raw matches /(cat.\/mnt\/etc\/)/
```

![](20230826102830.png)

### Docker Daemon - Unprotected TCP Socket Exploit

![](20230826103136.png)

```sql
_source="Laurel" 
| where %"syscall.key" = "network_socket_created"
| where %"syscall.exe" matches /(\/tmp\/\w\w\w\w\w\w\w\w)/
| values(%"proctitle.argv") as args by %"syscall.exe"
```

![](20230826103851.png)

```sql
_source="Laurel" 
| json field=_raw "PROCTITLE.ARGV[*]" as cmd_arg
| %"path[0].name" as path_name
| where %"syscall.ppid.exe" = "/usr/bin/containerd-shim-runc-v2"
| where path_name matches /(cron\.d)/
| values (path_name) by cmd_arg
```

![](20230826104442.png)

![](20230826104830.png)

![](20230826104950.png)

![](20230826105335.png)






