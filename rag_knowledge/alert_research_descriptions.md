# Splunk Research Alert Descriptions

## Alert: Linux Doas Tool Execution

Description: The following analytic detects the execution of the 'doas' tool on a Linux host. This tool allows standard users to perform tasks with root privileges, similar to 'sudo'. The detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and command-line executions. This activity is significant as 'doas' can be exploited by adversaries to gain elevated privileges on a compromised host. If confirmed malicious, this could lead to unauthorized administrative access, potentially compromising the entire system.

## Alert: Linux Docker Privilege Escalation

Description: The following analytic detects attempts to escalate privileges on a Linux system using Docker. It identifies processes where Docker commands are used to mount the root directory or execute shell commands within a container. This detection leverages Endpoint Detection and Response (EDR) telemetry, focusing on process names, command-line arguments, and parent processes. This activity is significant because it can allow an attacker with Docker privileges to modify critical system files, such as /etc/passwd, to create a superuser. If confirmed malicious, this could lead to full system compromise and persistent unauthorized access.

## Alert: Linux Edit Cron Table Parameter

Description: The following analytic detects the suspicious editing of cron jobs in Linux using the crontab command-line parameter (-e). It identifies this activity by monitoring command-line executions involving 'crontab' and the edit parameter. This behavior is significant for a SOC as cron job manipulations can indicate unauthorized persistence attempts or scheduled malicious actions. If confirmed malicious, this activity could lead to system compromise, unauthorized access, or broader network compromise.

## Alert: Linux Emacs Privilege Escalation

Description: The following analytic detects the execution of Emacs with elevated privileges using the sudo command and the --eval option. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process execution logs that include command-line arguments. This activity is significant because it indicates a potential privilege escalation attempt, where a user could gain root access by running Emacs with elevated permissions. If confirmed malicious, this could allow an attacker to execute arbitrary commands as root, leading to full system compromise and unauthorized access to sensitive information.

## Alert: Linux File Created In Kernel Driver Directory
	
Description: The following analytic detects the creation of files in the Linux kernel/driver directory. It leverages filesystem data to identify new files in this critical directory. This activity is significant because the kernel/driver directory is typically reserved for kernel modules, and unauthorized file creation here can indicate a rootkit installation. If confirmed malicious, this could allow an attacker to gain high-level privileges, potentially compromising the entire system by executing code at the kernel level.

## Alert: Linux File Creation In Init Boot Directory

Description: The following analytic detects the creation of files in Linux init boot directories, which are used for automatic execution upon system startup. It leverages file system logs to identify new files in directories such as /etc/init.d/ and /etc/rc.d/. This activity is significant as it is a common persistence technique used by adversaries, malware authors, and red teamers. If confirmed malicious, this could allow an attacker to maintain persistence on the compromised host, potentially leading to further exploitation and unauthorized control over the system.

## Alert: Linux File Creation In Profile Directory

Description: The following analytic detects the creation of files in the /etc/profile.d directory on Linux systems. It leverages filesystem data to identify new files in this directory, which is often used by adversaries for persistence by executing scripts upon system boot. This activity is significant as it may indicate an attempt to maintain long-term access to the compromised host. If confirmed malicious, this could allow attackers to execute arbitrary code with elevated privileges each time the system boots, potentially leading to further compromise and data exfiltration.

## Alert: Linux Find Privilege Escalation

Description: The following analytic detects the use of the 'find' command with 'sudo' and '-exec' options, which can indicate an attempt to escalate privileges on a Linux system. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process execution logs that include command-line arguments. This activity is significant because it can allow a user to execute system commands as root, potentially leading to a root shell. If confirmed malicious, this could enable an attacker to gain full control over the system, leading to severe security breaches and unauthorized access to sensitive data.

## Alert: Linux GDB Privilege Escalation

Description: The following analytic detects the execution of the GNU Debugger (GDB) with specific flags that indicate an attempt to escalate privileges on a Linux system. It leverages Endpoint Detection and Response (EDR) telemetry to identify processes where GDB is run with the -nx, -ex, and sudo flags. This activity is significant because it can allow a user to execute system commands as root, potentially leading to a root shell. If confirmed malicious, this could result in full system compromise, allowing an attacker to gain complete control over the affected endpoint.

## Alert: Linux Gem Privilege Escalation

Description: The following analytic detects the execution of the RubyGems utility with elevated privileges, specifically when it is used to run system commands as root. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on command-line executions that include "gem open -e" and "sudo". This activity is significant because it indicates a potential privilege escalation attempt, allowing a user to execute commands as the root user. If confirmed malicious, this could lead to full system compromise, enabling the attacker to gain root access and execute arbitrary commands with elevated privileges.

