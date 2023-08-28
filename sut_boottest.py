#!/usr/bin/env python3
# Reboots remote systems (SUTs) and captures boot timing results
# Writes JSON file in format ready for ingest in ElasticSearch
#
# Tested on CentOS Stream 8 - Python 3.6.8.
# DEPENDENCIES: # python3 -m pip install paramiko
#
# grep string that covers the known premutations for when first link is ready
net_str = '-Ei "link.*(ready|up)"'

#####################################
# DICTIONARY Format - dicts initialized in main()
#
# testrun_dict = {
#     "cluster_name": hostname,
#     "date": curtime,
#     "test_type": "boot-time",
#     "sample": 1,
#     "test_config": {
#         testcfg_dict{}
#     }, 
#     "test_results": {
#         "reboot":
#             reboot_dict{}
#         "satime":
#             sa_dict{}
#         "sablame":
#             sa_dict{}
#         "neptuneui":
#             neptuneui_dict{}
#     },
#     "system_config": {
#         syscfg_dict{}
#     } 
# }
#

import sys
import time
import paramiko
import re
import datetime
import json
import io
import argparse
from typing import Dict, List, Tuple



#####################################
# CLASSES
class TimerError(Exception):
    # A custom exception used to report errors in use of Timer class
    # use built-in class for error handling
    pass

class Timer: 
    def __init__(self, text="Elapsed time: {:0.2f} seconds", logger=print):
        self._start_time = None
        self.text = text
        self.logger = logger

    def start(self):
        # Start a new timer
        if self._start_time is not None:
            raise TimerError(f"Timer is running. Use .stop() to stop it")
        self._start_time = time.perf_counter()

    def stop(self):
        # Stop the timer, and report the elapsed time in seconds
        if self._start_time is None:
            raise TimerError(f"Timer is not running. Use .start() to start it")
        elapsed_time = time.perf_counter() - self._start_time
        self._start_time = None
        if self.logger:
            self.logger(self.text.format(elapsed_time))
        return elapsed_time

#####################################
# FUNCTIONS
def parse_args():
    parser = argparse.ArgumentParser(\
            description='Reboots remote systems (SUTs) and captures boot timing results')

    parser.add_argument(
            'hostname',
            help='Description of device to run boot time tests',
            )
    parser.add_argument(
            'ip',
            help='IP address of device to run boot time tests',
            )
    parser.add_argument(
            'username',
            nargs='?',
            default='root',
            help='Username to login to device',
            )
    parser.add_argument(
            'password',
            nargs='?',
            default='password',
            help='Password to login to device',
            )
    parser.add_argument(
            '-s',
            '--samples',
            type=int,
            default='1',
            help='Number of samples to collect',
            )
    parser.add_argument(
            '-b',
            '--blame-count',
            type=int,
            default='10',
            help='Number of services to collect for systemd-analzye blame',
            )

    return parser.parse_args()


def write_json(thedict, thefile):
    to_unicode = str
   # Write JSON file
    with io.open(thefile, 'w', encoding='utf8') as outfile:
        str_ = json.dumps(thedict,
                          indent=4, sort_keys=False,
                          separators=(',', ': '), ensure_ascii=False)
        outfile.write(to_unicode(str_))
        outfile.write(to_unicode("\n"))

    print(f"Wrote file: {thefile}")

def init_dict(hname, ip, reboot, ssh, boot_tgt, bl_cnt):
    # Initialize new dict{} for the test config for this workload
    the_dict = {}             # new empty dict

    the_dict["hostname"] = str(hname)
    the_dict["IPaddr"] = str(ip)
    the_dict["reboot_timeout"] = str(reboot_timeout)
    the_dict["ssh_timeout"] = str(ssh_timeout)
    the_dict["boot_tgt"] = str(boot_tgt)
    the_dict["blame_cnt"] = str(bl_cnt)

    return the_dict

##################################
# PARSER Functions
def parse_osrelease(cmd_out, the_dict):
    # PRETTY NAME value
    for line in cmd_out.split("\n"):
        if "PRETTY_NAME=" in line:
            raw_str = re.search('PRETTY_NAME=(.*)', cmd_out).group(1)
            pname = raw_str.replace('"', "")   # remove surrounding quotes
    the_dict['osrelease'] = verify_trim(pname)

    return the_dict

def parse_lscpu(cmd_out, the_dict):
    # cpu architecture
    for line in cmd_out.split("\n"):
        if "Architecture:" in line:
            arch = re.search('Architecture:(.*)', cmd_out).group(1)
    the_dict['architecture'] = verify_trim(arch)

    # cpu model
    for line in cmd_out.split("\n"):
        if "Model name:" in line:
            model = re.search('Model name.*:(.*)', cmd_out).group(1)
    the_dict['model'] = verify_trim(model)

    # Number of cores
    for line in cmd_out.split("\n"):
        if "CPU(s):" in line:
            numcores = re.search('CPU\(s\):(.*)', cmd_out).group(1)
    the_dict['numcores'] = verify_trim(numcores)

    # BogoMIPS
    for line in cmd_out.split("\n"):
        if "BogoMIPS:" in line:
            bogo = re.search('BogoMIPS:(.*)', cmd_out).group(1)
    the_dict['bogomips'] = verify_trim(bogo)

    return the_dict

def parse_satime(cmd_out, the_dict):
    # 'systemd-analyze time' key metrics and key names
    satime_list = ["kernel", "initrd", "userspace"]
    satotal = float(0.0) 

##    for i, regex in enumerate(satime_list):
# Results can in seconds or millisec, so search for both
    for regex in satime_list:
        match_sec = re.findall('(\d+\.\d+)s\s\('+regex+'\)', cmd_out)
        match_ms = re.findall('(\d+)ms\s\('+regex+'\)', cmd_out)
##        result = re.search('(\d+\.\d+)s\s\('+regex+'\)', cmd_out)
        if match_sec:
            the_dict[regex] = float(match_sec[0])
            satotal = satotal + float(match_sec[0])
        elif match_ms:
            ms = float(match_ms[0]) / 1000
            the_dict[regex] = float(ms)
            satotal = satotal + float(ms)
        else:
            the_dict[regex] = float(0.0)

    # add TOTAL time to the_dict[]
    the_dict['total'] = float(satotal) 

    return the_dict

def parse_sablame(cmd_out, the_dict, blame_cnt):
    # Parse cmd output, calc time in seconds and populate dict
    cntr = 1
    for line in cmd_out.split("\n"):
        if (cntr <= int(blame_cnt)):
            ##words = re.split(r'\s', line)
            words = line.split()
            service = words[-1]
            minutes = re.search('(\d+)min', line)
            seconds = re.search('(\d+\.\d+)s', line)
            millisec = re.search('(\d+)ms', line)
            if (minutes and seconds):
                min = minutes[0].strip("min")
                sec = seconds[0].strip("s")
                total_sec = str((int(min) * 60) + float(sec))
            elif (seconds and not minutes):
                total_sec = seconds[0].strip("s")
            elif millisec:
                ms = millisec[0].strip("ms")
                total_sec = str((int(ms)/1000)%60)

            if (service and total_sec):
                cntr += 1
                the_dict[service] = float(total_sec)
        else:
            break

    return the_dict

def parse_neptuneui(cmd_out, the_dict, km_list):
    # Parse neptune-ui timing stats and populate dict
    for line in cmd_out.split("\n"):
        for x, (km_label, search_str) in enumerate (km_list):
            if search_str in line:
                # key metric found, extract key/value
                rstrip1 = line.rstrip('#')
                rstrip2 = rstrip1.rstrip()
                splitted = rstrip2.split(':')
                result = splitted[3].lstrip()
##                keymsg = re.search(key_metric, result)
                raw_value = result.split(' ')
                # cleanup raw_value: 3'975.381  --> 3.975381
                tmp1 = raw_value[0].replace(".", "")
                tmp2 = tmp1.replace("'", ".") 
                the_dict[km_label] = float(tmp2) 

    return the_dict

def verify_trim(value):  # Extend to handle str(), float(), int()
    # Verify value. Return value or None if invalid
    if not value:
##        ret_val = str("")
        ret_val = None
    else:
        ret_val = str(value.strip())

    return ret_val

def openclient(ssh_ip, ssh_user, ssh_passwd, tout):
    # Initiate SSH connection
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    result = None       # returned when w/exception OR timeout exceeded

    # Start timeout timer and calc end timer
    timeout_exceeded = time.time() + tout

    while time.time() < timeout_exceeded:
        try:
            client.connect(ssh_ip, username=ssh_user, password=ssh_passwd,
                port=22, look_for_keys=False, allow_agent=False)

        except paramiko.ssh_exception.SSHException as e:
            # socket is open, but no SSH service responded
            if e.message == 'Error reading SSH protocol banner':
                print(e)
                continue
            print('SSH transport is available but exception occured')
            break

        except paramiko.ssh_exception.NoValidConnectionsError as e:
##            print('SSH transport is not ready...')
            continue

        else:
##            print('SSH responded!')
            result = client
            break

        time.sleep(retry_int)         # pause between retries (GLOBAL)

    return result

def testssh(ip, usr, pswd, retry_timeout):
    ssh_status = False         # return value

    # Verify SUT can be ssh'd to
    print(f'> testssh: verifying SSH to {ip}. Timeout: {retry_timeout}s')

    # STOPWATCH returns elapsed time in seconds
##    et_ssh = Timer(text="testssh: SUT ssh active in {:.2f} seconds",\
##                      logger=print)
    et_ssh = Timer(text="", logger=None)    # Be silent
    et_ssh.start()

    ssh = openclient(ip, usr, pswd, retry_timeout)
    if ssh == None:
        # Error condition - no connection to close
        print(f'testssh: Could not connect to {ip}. Timed out')
        ssh_status = False     # continue on to next SUT
    else: 
        # Stop the stopwatch and report on elapsed time
        et_ssh.stop()

        # Close SSH connection
        ssh.close()
        ssh_status = True     # connection success
    return ssh_status

########## per Phase functions
# Phase 1 - gather sysfacts and populate dict{}
def phase1(sship, sshuser, sshpasswd):
    ph1_dict = {}         # empty dict{} for us in this phase function
    #              KEY        COMMAND
    cmd_list = [("kernel", "uname -r"),
                ("osrelease", "cat /etc/os-release | grep PRETTY_NAME"),
                ("various", "lscpu")
    ]

    # Initiate SSH connection - ssh_timeout (GLOBAL)
    client = openclient(sship, sshuser, sshpasswd, ssh_timeout)

    for x, (key, cmd) in enumerate (cmd_list):
##        print(f'COMMAND: {cmd}')
        # redirect stderr to stdout
        cmd_str = cmd + " 2> \&1"
        stdin, stdout, stderr = client.exec_command(cmd_str, get_pty=True)
        # Block on completion of exec_command
        exit_status = stdout.channel.recv_exit_status()
        # Single string contains entire cmd result
        cmd_result = stdout.read().decode('utf8').rstrip('\n')

        # Populate dict{}, format varies with command type
        if "lscpu" in cmd:
            # Parse results from 'lscpu' command
            ph1_dict = parse_lscpu(cmd_result, ph1_dict)
        elif "os-release" in cmd:
            # Parse results from 'cat' command
            ph1_dict = parse_osrelease(cmd_result, ph1_dict)
        else:
            ph1_dict[key] = str(verify_trim(cmd_result))

    # Close SSH connection
    client.close()

    return ph1_dict

# Phase 2 - configure SUT for (consistent) reboot
def phase2(sship, sshuser, sshpasswd, boot_target):
    # Initiate SSH connection - ssh_timeout (GLOBAL)
    client = openclient(sship, sshuser, sshpasswd, ssh_timeout)

    # Set target boot mode

    # If neptune-ui running, then enable Neptune UI startup timings
    neptuneui_enabled = False
    # check for neptune pids

    # Verify target boot mode

    # Close SSH connection
    client.close()

    return neptuneui_enabled

# Phase 3 - reboot and wait for system readiness
def phase3(ip, usr, passwd):
    ph3_dict = {}         # empty dict{} for use in this phase function
    # Initiate SSH connection - ssh_timeout (GLOBAL)
    ssh_reboot = openclient(ip, usr, passwd, ssh_timeout)

    # Issue reboot cmd
    try:
##        ssh_reboot.exec_command("uptime >/dev/null 2>&1")  # DEBUG
##        ssh_reboot.close()                                 # DEBUG
        ssh_reboot.exec_command("reboot >/dev/null 2>&1")
    except:
        # Error, suggested to explictly close
        ssh_reboot.close()
        print('reboot issue failed')
        sys.exit(1)

    ######################
    # START the clock on total shutdown and reboot time
    et_reboot = Timer(
        text="phase3: SUT shutdown and reboot required {:.2f} seconds",
        logger=print)           ## SILENCE THIS 'logger=none'
    et_reboot.start()

    # Need to stall/pause while shutdown completes
    delay = 60           # just a guess, pause for reboot to complete
    time.sleep(delay)   # just a guess...

    # Start ssh timer
    ssh_start = time.time()

    # Verify SSH responds. Wait upto 'reboot_timeout' (GLOBAL) 
    ping_ssh = testssh(ip, usr, passwd, reboot_timeout)
    if ping_ssh is False:
        print('phase3: Aborting test run') 
        sys.exit(1)

    # Reboot closed existing SSH client, open new as SUT boots
    # Verify SSH responds. Wait upto 'ssh_timeout' (GLOBAL) 
    ssh_new = openclient(ip, usr, passwd, ssh_timeout)

    # Stop ssh timer and calc elapsed time
    ssh_et = time.time() - ssh_start

    # SSH is active, now wait for system up condition:
    #     'systemctl list-jobs == No jobs running'
    sysctl_start = time.time()
    rebooted = False
    pause = 1         # NOTE: timer granularity NEEDS WORK 

    print(f'phase3: SUT {ip}, ', 
          f'waiting {reboot_timeout}s for reboot to complete...''')
    while rebooted == False:
        # if cmd==True, then SUT has completed boot process
        cmd = "systemctl list-jobs | grep -q 'No jobs running'"
        cmd_str = cmd + " 2> \&1"
        stdin, stdout, stderr = ssh_new.exec_command(
                cmd_str, get_pty=True)
        # Block on completion of exec_command
        exit_status = stdout.channel.recv_exit_status()
        # Test for completed boot
        if exit_status == 0:
            rebooted = True          # Triggers break out of loop
        else:
            time.sleep(pause)

        # Test if exceeded time limit
        sysctl_et = time.time() - sysctl_start
        total_et = ssh_et + sysctl_et
        if total_et >= reboot_timeout:
            # Error, suggested to explictly close
            ssh_new.close()
            print(f'rebootsut: SUT {ip} reboot Timed out')
            sys.exit(1)

    # SUCCESS
    # Stop timer and Populate reboot_dict{} with results
    reboot_et = et_reboot.stop()
    ph3_dict['reboot_et'] = float(reboot_et)
    ph3_dict['ssh_et'] = float(ssh_et)
    ph3_dict['sysctl_et'] = float(sysctl_et)
    ph3_dict['total_et'] = float(total_et)

    # Record 'link_is_up' timestamp value from dmesg buffer
    # - search for 'net_str' as defined in SUT_VARS section
    # EXAMPLE messages:
    #[   15.744369] atlantic 0002:81:00.0 eth0: atlantic: link change...
    #[   15.746078] IPv6: ADDRCONF(NETDEV_CHANGE): eth0: link becomes ready
    # dmesg | grep -m 1 eth0 | cut -d "[" -f2 | cut -d "]" -f1
    cmd_linkup = "dmesg | grep -m 1 {}".format(net_str)

    stdin, stdout, stderr = ssh_new.exec_command(cmd_linkup, get_pty=True)
    # Block on completion of exec_command
    exit_status = stdout.channel.recv_exit_status()

    if exit_status:
        print("ERROR: Unable to find first link is up string. Check `net_str`.")
        sys.exit(1)
    cmdres_linkup = stdout.read().decode('utf8').rstrip('\n')
    pattern = r'\[([\d.]+)\]'
    linkup_timestamp = re.findall(r'\[\s*([\d.]+)\]', cmdres_linkup)
# Test for valid value
    ph3_dict['link_is_up'] = float(linkup_timestamp[0])
# Set to 0.0 if value is invalid
#    ph3_dict['link_is_up'] = float(0.0)
    
    # Record boot target
    cmd_bt = "systemctl get-default 2> \&1"
    stdin, stdout, stderr = ssh_new.exec_command(cmd_bt, get_pty=True)
    # Block on completion of exec_command
    exit_status = stdout.channel.recv_exit_status()
    cmdres_bt = stdout.read().decode('utf8').rstrip('\n')
    ph3_dict['boot_tgt'] = str(verify_trim(cmdres_bt))

    ssh_new.close()

    return ph3_dict

# Phase 4
# - executes instr_list cmds, builds dict from cmd result and returns dict
def phase4(ip, usr, passwd, num_blames):
    satime_dict = {}           # systemd-analyze time results
    sablame_dict = {}          # systemd-analyze blame results
    ph4_dict = {}              # systemd-analyze complete results
    #                 KEY        COMMAND
    instr_list = [("sa_time",  "systemd-analyze time"),
                  ("sa_blame", "systemd-analyze blame --no-pager | grep service")
    ]

    # Initiate SSH connection - ssh_timeout (GLOBAL)
    client = openclient(ip, usr, passwd, ssh_timeout)

    for x, (key, cmd) in enumerate (instr_list):
        # redirect stderr to stdout
        cmd_str = cmd + " 2> \&1"
        stdin, stdout, stderr = client.exec_command(cmd_str, get_pty=True)
        # Block on completion of exec_command
        exit_status = stdout.channel.recv_exit_status()

        # single string contains entire cmd result
        cmd_result = stdout.read().decode('utf8').rstrip('\n')

        # populate dictionaries, format varies with command type
        if "sa_time" in key:
            satime_dict = parse_satime(cmd_result, satime_dict)
            ph4_dict[key] = satime_dict

        if "sa_blame" in key:
            sablame_dict = parse_sablame(cmd_result, sablame_dict, num_blames)
            ph4_dict[key] = sablame_dict

    return ph4_dict

def phase5(ip, usr, passwd):
    # VARS
    ph5_dict = {}          # neptune-ui startup timings
    # List of key metric search strings and dict keys
    #                 KEY        SEARCH STRING
    km_list = [("logging", "after logging setup"),
               ("D-Bus",   "after starting session D-Bus"),
               ("first-frame", "after first frame drawn")
    ]

    # Initiate SSH connection - ssh_timeout (GLOBAL)
    client = openclient(ip, usr, passwd, ssh_timeout)

    cmd = "journalctl | grep -m1 -A20 'STARTUP TIMING REPORT: System UI'"

    # redirect stderr to stdout
    cmd_str = cmd + " 2> \&1"
    stdin, stdout, stderr = client.exec_command(cmd_str, get_pty=True)
    # Block on completion of exec_command
    exit_status = stdout.channel.recv_exit_status()

    # Check if CMD suceeded, perhaps neptune-ui isn't running
    if exit_status != 0:
        print("neptune_stats:"\
              " neptune-ui startup timing stats unavailable on SUT,"\
              " skipping")
        return ph5_dict           # return empty dict{}

    # single string contains entire cmd result
    cmd_result = stdout.read().decode('utf8').rstrip('\n')

    # Parse neptune stats from cmd_out and populate dict
    ph5_dict = parse_neptuneui(cmd_result, ph5_dict, km_list) 

    return ph5_dict


def run_ssh_cmd(cmd: str, ip: str, usr: str, passwd) -> Tuple[int, str, str]:
    """
    Run ssh command and returns a Tuple with return code,stdout and stderr
    """
    client = openclient(ip, usr, passwd, ssh_timeout)

    stdin, stdout, stderr = client.exec_command(cmd, get_pty=True)
    exit_status = stdout.channel.recv_exit_status()
    stdout_result = stdout.read().decode('utf8').rstrip('\n')
    stderr_result = stderr.read().decode('utf8').rstrip('\n')


    return (exit_status, stdout_result, stderr_result)


def sample_dmesg():

        return '''[    0.000000] Booting Linux on physical CPU 0x0000000000 [0x410fd4b2]
[    0.000000] Linux version 5.14.0-349.312.test.el9iv.aarch64 (mockbuild@aarch64-002.build.eng.bos.redhat.com) (gcc (GCC) 11.3.1 20221121 (Red Hat 11.3.1-4), GNU ld version 2.35.2-37.el9) #1 SMP PREEMPT_RT Thu Aug 3 12:07:44 EDT 2023
[    0.000000] The list of certified hardware and cloud instances for Red Hat Enterprise Linux 9 can be viewed at the Red Hat Ecosystem Catalog, https://catalog.redhat.com.
[    0.000000] Machine model: Qualcomm SA8775P Ride
[    0.000000] efi: UEFI not found.
[    0.000000] [Firmware Bug]: Kernel image misaligned at boot, please fix your bootloader!
[    0.000000] ACPI: Early table checksum verification disabled
[    0.000000] ACPI: Failed to init ACPI tables
[    0.000000] NUMA: No NUMA configuration found
[    0.000000] NUMA: Faking a node at [mem 0x0000000080000000-0x0000000f7fffffff]
[    0.000000] NUMA: NODE_DATA [mem 0xf7b997e00-0xf7b99cfff]
[    0.000000] Zone ranges:
[    0.000000]   DMA      [mem 0x0000000080000000-0x00000000ffffffff]
[    0.000000]   DMA32    empty
[    0.000000]   Normal   [mem 0x0000000100000000-0x0000000f7fffffff]
[    0.000000]   Device   empty
[    0.000000] Movable zone start for each node
[    0.000000] Early memory node ranges
[    0.000000]   node   0: [mem 0x0000000080000000-0x000000009087ffff]
[    0.000000]   node   0: [mem 0x0000000090880000-0x00000000908affff]
[    0.000000]   node   0: [mem 0x00000000908b0000-0x00000000908bffff]
[    0.000000]   node   0: [mem 0x00000000908c0000-0x00000000908effff]
[    0.000000]   node   0: [mem 0x00000000908f0000-0x0000000090bfffff]
[    0.000000]   node   0: [mem 0x0000000090c00000-0x0000000093afffff]
[    0.000000]   node   0: [mem 0x0000000093b00000-0x00000000956fffff]
[    0.000000]   node   0: [mem 0x0000000095700000-0x0000000095bfffff]
[    0.000000]   node   0: [mem 0x0000000095c00000-0x00000000979fffff]
[    0.000000]   node   0: [mem 0x0000000097a00000-0x0000000097afffff]
[    0.000000]   node   0: [mem 0x0000000097b00000-0x000000009b6fffff]
[    0.000000]   node   0: [mem 0x000000009b700000-0x000000009b7fffff]
[    0.000000]   node   0: [mem 0x000000009b800000-0x000000009d601fff]
[    0.000000]   node   0: [mem 0x000000009d602000-0x000000009d6fffff]
[    0.000000]   node   0: [mem 0x000000009d700000-0x00000000a02fffff]
[    0.000000]   node   0: [mem 0x00000000a0300000-0x00000000beafffff]
[    0.000000]   node   0: [mem 0x00000000beb00000-0x00000000bedfffff]
[    0.000000]   node   0: [mem 0x00000000c0000000-0x00000000d50fffff]
[    0.000000]   node   0: [mem 0x00000000d5100000-0x00000003ffffffff]
[    0.000000]   node   0: [mem 0x0000000900000000-0x00000009323fffff]
[    0.000000]   node   0: [mem 0x0000000940000000-0x0000000bffffffff]
[    0.000000]   node   0: [mem 0x0000000d00000000-0x0000000f7fffffff]
[    0.000000] Initmem setup node 0 [mem 0x0000000080000000-0x0000000f7fffffff]
[    0.000000] On node 0, zone DMA: 4608 pages in unavailable ranges
[    0.000000] On node 0, zone Normal: 23552 pages in unavailable ranges
[    0.000000] crashkernel reserved: 0x00000000e0000000 - 0x0000000100000000 (512 MB)
[    0.000000] psci: probing for conduit method from DT.
[    0.000000] psci: PSCIv1.1 detected in firmware.
[    0.000000] psci: Using standard PSCI v0.2 function IDs
[    0.000000] psci: MIGRATE_INFO_TYPE not supported.
[    0.000000] psci: SMC Calling Convention v1.3
[    0.000000] psci: OSI mode supported.
[    0.000000] percpu: Embedded 32 pages/cpu s94080 r8192 d28800 u131072
[    0.000000] pcpu-alloc: s94080 r8192 d28800 u131072 alloc=32*4096
[    0.000000] pcpu-alloc: [0] 0 [0] 1 [0] 2 [0] 3 [0] 4 [0] 5 [0] 6 [0] 7 
[    0.000000] Detected PIPT I-cache on CPU0
[    0.000000] CPU features: detected: GIC system register CPU interface
[    0.000000] CPU features: detected: Hardware dirty bit management
[    0.000000] CPU features: detected: Spectre-v4
[    0.000000] CPU features: detected: Spectre-BHB
[    0.000000] CPU features: kernel page table isolation forced ON by KASLR
[    0.000000] CPU features: detected: Kernel page table isolation (KPTI)
[    0.000000] alternatives: applying boot alternatives
[    0.000000] Fallback order for Node 0: 0 
[    0.000000] Built 1 zonelists, mobility grouping on.  Total pages: 9229680
[    0.000000] Policy zone: Normal
[    0.000000] Kernel command line: root=UUID=76a22bf4-f153-4541-b6c7-0332c0dfaeac root=PARTLABEL=system_a crashkernel=512M androidboot.bootdevice=1d84000.ufshc androidboot.fstab_suffix=default androidboot.serialno=c91cd446 androidboot.baseband=apq silent_boot.mode=nonsilent
[    0.000000] Dentry cache hash table entries: 8388608 (order: 14, 67108864 bytes, linear)
[    0.000000] Inode-cache hash table entries: 4194304 (order: 13, 33554432 bytes, linear)
[    0.000000] mem auto-init: stack:off, heap alloc:off, heap free:off
[    0.000000] software IO TLB: area num 8.
[    0.000000] software IO TLB: mapped [mem 0x00000000dc000000-0x00000000e0000000] (64MB)
[    0.000000] Memory: 35269964K/37505024K available (12928K kernel code, 5456K rwdata, 10312K rodata, 5504K init, 10877K bss, 2235060K reserved, 0K cma-reserved)
[    0.000000] random: get_random_u64 called from kmem_cache_open+0x2c/0x324 with crng_init=0
[    0.000000] SLUB: HWalign=64, Order=0-3, MinObjects=0, CPUs=8, Nodes=1
[    0.000000] ftrace: allocating 45601 entries in 179 pages
[    0.000000] ftrace: allocated 179 pages with 5 groups
[    0.000000] trace event string verifier disabled
[    0.000000] rcu: Preemptible hierarchical RCU implementation.
[    0.000000] rcu: 	RCU restricting CPUs from NR_CPUS=4096 to nr_cpu_ids=8.
[    0.000000] rcu: 	RCU priority boosting: priority 1 delay 500 ms.
[    0.000000] rcu: 	RCU_SOFTIRQ processing moved to rcuc kthreads.
[    0.000000] 	No expedited grace period (rcu_normal_after_boot).
[    0.000000] 	Trampoline variant of Tasks RCU enabled.
[    0.000000] 	Rude variant of Tasks RCU enabled.
[    0.000000] 	Tracing variant of Tasks RCU enabled.
[    0.000000] rcu: RCU calculated value of scheduler-enlistment delay is 10 jiffies.
[    0.000000] rcu: Adjusting geometry for rcu_fanout_leaf=16, nr_cpu_ids=8
[    0.000000] NR_IRQS: 64, nr_irqs: 64, preallocated irqs: 0
[    0.000000] GICv3: 988 SPIs implemented
[    0.000000] GICv3: 0 Extended SPIs implemented
[    0.000000] Root IRQ handler: gic_handle_irq
[    0.000000] GICv3: GICv3 features: 16 PPIs
[    0.000000] GICv3: CPU0: found redistributor 0 region 0:0x0000000017a60000
[    0.000000] rcu: srcu_init: Setting srcu_struct sizes based on contention.
[    0.000000] kfence: initialized - using 2097152 bytes for 255 objects at 0x(____ptrval____)-0x(____ptrval____)
[    0.000000] random: crng init done
[    0.000000] arch_timer: cp15 and mmio timer(s) running at 19.20MHz (virt/virt).
[    0.000000] clocksource: arch_sys_counter: mask: 0xffffffffffffff max_cycles: 0x46d987e47, max_idle_ns: 440795202767 ns
[    0.000000] sched_clock: 56 bits at 19MHz, resolution 52ns, wraps every 4398046511078ns
[    0.000023] arm-pv: using stolen time PV
[    0.000024] Timer rate: 19200000 Hz
[    0.000026] mark: primary_entry(): 83868579
[    0.000027] mark: start_kernel(): 83902901 (34322)
[    0.000028] mark: local_irq_disabled(): 83903230 (329)
[    0.000030] mark: boot_cpu_init(): 83903251 (21)
[    0.000031] mark: page_address_init(): 83903252 (1)
[    0.000032] mark: early_security_init(): 83903361 (109)
[    0.000033] mark: setup_arch(): 94882358 (10978997)
[    0.000034] mark: boot_cpu_hotplug_init(): 94886967 (4609)
[    0.000035] mark: page_alloc(): 94887306 (339)
[    0.000036] mark: trap_init(): 94963871 (76565)
[    0.000037] mark: mm_init(): 96657693 (1693822)
[    0.000038] mark: sched_init(): 97541451 (883758)
[    0.000039] mark: trace_init(): 97642954 (101503)
[    0.000039] mark: tick_init(): 97742678 (99724)
[    0.000040] mark: time_init(): 97753999 (11321)
[    0.000132] Console: colour dummy device 80x25
[    0.000292] printk: console [tty0] enabled
[    0.000324] Calibrating delay loop (skipped), value calculated using timer frequency.. 38.40 BogoMIPS (lpj=192000)
[    0.000328] pid_max: default: 32768 minimum: 301
[    0.000383] LSM: initializing lsm=lockdown,capability,yama,integrity,selinux,bpf
[    0.000403] Yama: becoming mindful.
[    0.000413] SELinux:  Initializing.
[    0.000461] LSM support for eBPF active
[    0.000548] Mount-cache hash table entries: 131072 (order: 8, 1048576 bytes, linear)
[    0.000603] Mountpoint-cache hash table entries: 131072 (order: 8, 1048576 bytes, linear)
[    0.001442] cblist_init_generic: Setting adjustable number of callback queues.
[    0.001446] cblist_init_generic: Setting shift to 3 and lim to 1.
[    0.001496] cblist_init_generic: Setting shift to 3 and lim to 1.
[    0.001524] cblist_init_generic: Setting shift to 3 and lim to 1.
[    0.001642] rcu: Hierarchical SRCU implementation.
[    0.001643] rcu: 	Max phase no-delay instances is 1000.
[    0.001659] printk: console [tty0] printing thread started
[    0.002432] EFI services will not be available.
[    0.002636] smp: Bringing up secondary CPUs ...
[    0.003764] Detected PIPT I-cache on CPU1
[    0.003834] GICv3: CPU1: found redistributor 100 region 0:0x0000000017a80000
[    0.003963] CPU1: Booted secondary processor 0x0000000100 [0x410fd4b2]
[    0.009980] Detected PIPT I-cache on CPU2
[    0.010017] GICv3: CPU2: found redistributor 200 region 0:0x0000000017aa0000
[    0.010121] CPU2: Booted secondary processor 0x0000000200 [0x410fd4b2]
[    0.016080] Detected PIPT I-cache on CPU3
[    0.016132] GICv3: CPU3: found redistributor 300 region 0:0x0000000017ac0000
[    0.016247] CPU3: Booted secondary processor 0x0000000300 [0x410fd4b2]
[    0.023513] Detected PIPT I-cache on CPU4
[    0.023570] GICv3: CPU4: found redistributor 10000 region 0:0x0000000017ae0000
[    0.023700] CPU4: Booted secondary processor 0x0000010000 [0x410fd4b2]
[    0.029810] Detected PIPT I-cache on CPU5
[    0.029866] GICv3: CPU5: found redistributor 10100 region 0:0x0000000017b00000
[    0.029987] CPU5: Booted secondary processor 0x0000010100 [0x410fd4b2]
[    0.036066] Detected PIPT I-cache on CPU6
[    0.036126] GICv3: CPU6: found redistributor 10200 region 0:0x0000000017b20000
[    0.036232] CPU6: Booted secondary processor 0x0000010200 [0x410fd4b2]
[    0.042345] Detected PIPT I-cache on CPU7
[    0.042404] GICv3: CPU7: found redistributor 10300 region 0:0x0000000017b40000
[    0.042499] CPU7: Booted secondary processor 0x0000010300 [0x410fd4b2]
[    0.042604] smp: Brought up 1 node, 8 CPUs
[    0.042608] SMP: Total of 8 processors activated.
[    0.042611] CPU features: detected: 32-bit EL0 Support
[    0.042612] CPU features: detected: Data cache clean to the PoU not required for I/D coherence
[    0.042614] CPU features: detected: Common not Private translations
[    0.042615] CPU features: detected: CRC32 instructions
[    0.042616] CPU features: detected: Data cache clean to Point of Persistence
[    0.042617] CPU features: detected: RCpc load-acquire (LDAPR)
[    0.042618] CPU features: detected: LSE atomic instructions
[    0.042619] CPU features: detected: Privileged Access Never
[    0.042620] CPU features: detected: RAS Extension Support
[    0.042622] CPU features: detected: Speculative Store Bypassing Safe (SSBS)
[    0.042718] CPU: All CPU(s) started at EL1
[    0.042723] alternatives: applying system-wide alternatives
[    0.045437] devtmpfs: initialized
[    0.056723] clocksource: jiffies: mask: 0xffffffff max_cycles: 0xffffffff, max_idle_ns: 19112604462750000 ns
[    0.056731] futex hash table entries: 2048 (order: 5, 131072 bytes, linear)
[    0.056880] pinctrl core: initialized pinctrl subsystem
[    0.057187] DMI not present or invalid.
[    0.057414] NET: Registered PF_NETLINK/PF_ROUTE protocol family
[    0.058219] DMA: preallocated 8192 KiB GFP_KERNEL pool for atomic allocations
[    0.058627] DMA: preallocated 8192 KiB GFP_KERNEL|GFP_DMA pool for atomic allocations
[    0.059032] DMA: preallocated 8192 KiB GFP_KERNEL|GFP_DMA32 pool for atomic allocations
[    0.059064] audit: initializing netlink subsys (disabled)
[    0.059172] audit: type=2000 audit(0.050:1): state=initialized audit_enabled=0 res=1
[    0.059427] thermal_sys: Registered thermal governor 'fair_share'
[    0.059430] thermal_sys: Registered thermal governor 'step_wise'
[    0.059431] thermal_sys: Registered thermal governor 'user_space'
[    0.059485] cpuidle: using governor menu
[    0.059552] hw-breakpoint: found 6 breakpoint and 4 watchpoint registers.
[    0.059684] ASID allocator initialised with 32768 entries
[    0.059840] Serial: AMBA PL011 UART driver
[    0.062895] platform 1d84000.ufs: Fixed dependency cycle(s) with /soc@0/phy@1d87000
[    0.065380] KASLR enabled
[    0.070307] HugeTLB: registered 1.00 GiB page size, pre-allocated 0 pages
[    0.070311] HugeTLB: 0 KiB vmemmap can be freed for a 1.00 GiB page
[    0.070312] HugeTLB: registered 32.0 MiB page size, pre-allocated 0 pages
[    0.070313] HugeTLB: 0 KiB vmemmap can be freed for a 32.0 MiB page
[    0.070315] HugeTLB: registered 2.00 MiB page size, pre-allocated 0 pages
[    0.070316] HugeTLB: 0 KiB vmemmap can be freed for a 2.00 MiB page
[    0.070317] HugeTLB: registered 64.0 KiB page size, pre-allocated 0 pages
[    0.070318] HugeTLB: 0 KiB vmemmap can be freed for a 64.0 KiB page
[    0.070718] cryptd: max_cpu_qlen set to 1000
[    0.071152] ACPI: Interpreter disabled.
[    0.071255] iommu: Default domain type: Translated 
[    0.071257] iommu: DMA domain TLB invalidation policy: lazy mode 
[    0.071473] SCSI subsystem initialized
[    0.071533] libata version 3.00 loaded.
[    0.071624] usbcore: registered new interface driver usbfs
[    0.071638] usbcore: registered new interface driver hub
[    0.071650] usbcore: registered new device driver usb
[    0.071707] pps_core: LinuxPPS API ver. 1 registered
[    0.071708] pps_core: Software ver. 5.3.6 - Copyright 2005-2007 Rodolfo Giometti <giometti@linux.it>
[    0.071712] PTP clock support registered
[    0.071785] EDAC MC: Ver: 3.0.0
[    0.071915] psci: failed to set PC mode: -3
[    0.072014] qcom_scm: convention: smc arm 64
[    0.072557] NetLabel: Initializing
[    0.072559] NetLabel:  domain hash size = 128
[    0.072560] NetLabel:  protocols = UNLABELED CIPSOv4 CALIPSO
[    0.072584] NetLabel:  unlabeled traffic allowed by default
[    0.072680] vgaarb: loaded
[    0.072876] clocksource: Switched to clocksource arch_sys_counter
[    0.104291] VFS: Disk quotas dquot_6.6.0
[    0.104312] VFS: Dquot-cache hash table entries: 512 (order 0, 4096 bytes)
[    0.104490] pnp: PnP ACPI: disabled
[    0.106883] NET: Registered PF_INET protocol family
[    0.107031] IP idents hash table entries: 262144 (order: 9, 2097152 bytes, linear)
[    0.109601] tcp_listen_portaddr_hash hash table entries: 32768 (order: 8, 1310720 bytes, linear)
[    0.109884] Table-perturb hash table entries: 65536 (order: 6, 262144 bytes, linear)
[    0.109908] TCP established hash table entries: 524288 (order: 10, 4194304 bytes, linear)
[    0.110439] TCP bind hash table entries: 65536 (order: 9, 2621440 bytes, linear)
[    0.110944] TCP: Hash tables configured (established 524288 bind 65536)
[    0.111262] MPTCP token hash table entries: 65536 (order: 9, 3670016 bytes, linear)
[    0.111970] UDP hash table entries: 32768 (order: 9, 3145728 bytes, linear)
[    0.112784] UDP-Lite hash table entries: 32768 (order: 9, 3145728 bytes, linear)
[    0.113787] NET: Registered PF_UNIX/PF_LOCAL protocol family
[    0.113802] NET: Registered PF_XDP protocol family
[    0.113813] PCI: CLS 0 bytes, default 64
[    0.113938] Trying to unpack rootfs image as initramfs...
[    0.114262] kvm [1]: HYP mode not available
[    0.115010] Initialise system trusted keyrings
[    0.115031] Key type blacklist registered
[    0.115108] workingset: timestamp_bits=40 max_order=24 bucket_order=0
[    0.119840] zbud: loaded
[    0.120703] integrity: Platform Keyring initialized
[    0.120707] integrity: Machine keyring initialized
[    0.134501] NET: Registered PF_ALG protocol family
[    0.134515] xor: measuring software checksum speed
[    0.135289]    8regs           : 12782 MB/sec
[    0.136064]    32regs          : 12728 MB/sec
[    0.136640]    arm64_neon      : 17255 MB/sec
[    0.136642] xor: using function: arm64_neon (17255 MB/sec)
[    0.136647] Key type asymmetric registered
[    0.136649] Asymmetric key parser 'x509' registered
[    0.136651] Running certificate verification selftests
[    0.137475] Loaded X.509 cert 'Certificate verification self-testing key: f58703bb33ce1b73ee02eccdee5b8817518fe3db'
[    0.138218] Block layer SCSI generic (bsg) driver version 0.4 loaded (major 244)
[    0.138295] io scheduler mq-deadline registered
[    0.138299] io scheduler kyber registered
[    0.138396] io scheduler bfq registered
[    0.138774] atomic64_test: passed
[    0.140909] Serial: 8250/16550 driver, 4 ports, IRQ sharing enabled
[    0.144113] arm-smmu 15000000.iommu: probing hardware configuration...
[    0.144116] arm-smmu 15000000.iommu: SMMUv2 with:
    [    0.144136] arm-smmu 15000000.iommu: 	stage 1 translation
[    0.144137] arm-smmu 15000000.iommu: 	non-coherent table walk
[    0.144139] arm-smmu 15000000.iommu: 	(IDR0.CTTW overridden by FW configuration)
[    0.144141] arm-smmu 15000000.iommu: 	stream matching with 172 register groups
[    0.144152] arm-smmu 15000000.iommu: 	112 context banks (0 stage-2 only)
[    0.144976] arm-smmu 15000000.iommu: 	Supported page sizes: 0x61311000
[    0.144978] arm-smmu 15000000.iommu: 	Stage-1: 36-bit VA -> 36-bit IPA
[    0.145226] arm-smmu 15000000.iommu: 	preserved 0 boot mappings
[    0.148176] rdac: device handler registered
[    0.148229] hp_sw: device handler registered
[    0.148230] emc: device handler registered
[    0.148273] alua: device handler registered
[    0.148627] libphy: Fixed MDIO Bus: probed
[    0.148915] usbcore: registered new interface driver usbserial_generic
[    0.148927] usbserial: USB Serial support registered for generic
[    0.149022] mousedev: PS/2 mouse device common for all mice
[    0.149337] ghes_edac: GHES probing device list is empty
[    0.149541] SMCCC: SOC_ID: ARCH_SOC_ID not implemented, skipping ....
[    0.149606] hid: raw HID events driver (C) Jiri Kosina
[    0.149673] usbcore: registered new interface driver usbhid
[    0.149674] usbhid: USB HID core driver
[    0.150124] drop_monitor: Initializing network drop monitor service
[    0.161449] Initializing XFRM netlink socket
[    0.161480] NET: Registered PF_PACKET protocol family
[    0.161575] mpls_gso: MPLS GSO support
[    0.161906] registered taskstats version 1
[    0.162413] Loading compiled-in X.509 certificates
[    0.162983] Loaded X.509 cert 'Red Hat Enterprise Linux kernel signing key: b9aa430de36d336f12c23c8fd7b3ebef251187c5'
[    0.163408] Loaded X.509 cert 'Red Hat Enterprise Linux Driver Update Program (key 3): bf57f3e87362bc7229d9f465321773dfd1f77a80'
[    0.163812] Loaded X.509 cert 'Red Hat Enterprise Linux kpatch signing key: 4d38fd864ebe18c5f0b72e3852e2014c3a676fc8'
[    0.164000] zswap: loaded using pool lzo/zbud
[    0.164125] page_owner is disabled
[    0.164217] Key type .fscrypt registered
[    0.164219] Key type fscrypt-provisioning registered
[    0.164298] Key type big_key registered
[    0.164304] Key type encrypted registered
[    0.164318] ima: No TPM chip found, activating TPM-bypass!
[    0.164320] Loading compiled-in module X.509 certificates
[    0.164734] Loaded X.509 cert 'Red Hat Enterprise Linux kernel signing key: b9aa430de36d336f12c23c8fd7b3ebef251187c5'
[    0.164736] ima: Allocated hash algorithm: sha256
[    0.164756] ima: No architecture policies found
[    0.164785] evm: Initialising EVM extended attributes:
    [    0.164786] evm: security.selinux
[    0.164787] evm: security.SMACK64 (disabled)
[    0.164788] evm: security.SMACK64EXEC (disabled)
[    0.164789] evm: security.SMACK64TRANSMUTE (disabled)
[    0.164790] evm: security.SMACK64MMAP (disabled)
[    0.164790] evm: security.apparmor (disabled)
[    0.164791] evm: security.ima
[    0.164791] evm: security.capability
[    0.164792] evm: HMAC attrs: 0x1
[    0.400157] Freeing initrd memory: 18944K
[    0.402665] Freeing unused kernel memory: 5504K
[    0.552537] Checked W+X mappings: passed, no W+X pages found
[    0.552570] Run /init as init process
[    0.552572]   with arguments:
    [    0.552574]     /init
[    0.552576]   with environment:
    [    0.552577]     HOME=/
[    0.552578]     TERM=linux
[    0.561910] systemd[1]: System time before build time, advancing clock.
[    0.614422] NET: Registered PF_INET6 protocol family
[    0.623337] Segment Routing with IPv6
[    0.628326] systemd[1]: systemd 252-17.el9 running in system mode (+PAM +AUDIT +SELINUX -APPARMOR +IMA +SMACK +SECCOMP +GCRYPT +GNUTLS +OPENSSL +ACL +BLKID +CURL +ELFUTILS -FIDO2 +IDN2 -IDN -IPTC +KMOD +LIBCRYPTSETUP +LIBFDISK +PCRE2 -PWQUALITY +P11KIT -QRENCODE +TPM2 +BZIP2 +LZ4 +XZ +ZLIB +ZSTD -BPF_FRAMEWORK +XKBCOMMON +UTMP +SYSVINIT default-hierarchy=unified)
[    0.628627] systemd[1]: Detected architecture arm64.
[    0.628631] systemd[1]: Running in initrd.
[    0.628934] systemd[1]: No hostname configured, using default hostname.
[    0.629027] systemd[1]: Hostname set to <localhost>.
[    0.629218] systemd[1]: Initializing machine ID from random generator.
[    0.775496] systemd[1]: Queued start job for default target Initrd Default Target.
[    0.775902] systemd[1]: Started Dispatch Password Requests to Console Directory Watch.
[    0.776168] systemd[1]: Reached target Initrd /usr File System.
[    0.776241] systemd[1]: Reached target Local File Systems.
[    0.776299] systemd[1]: Reached target Path Units.
[    0.776363] systemd[1]: Reached target Slice Units.
[    0.776424] systemd[1]: Reached target Swaps.
[    0.776479] systemd[1]: Reached target Timer Units.
[    0.776787] systemd[1]: Listening on Journal Socket (/dev/log).
[    0.777065] systemd[1]: Listening on Journal Socket.
[    0.777351] systemd[1]: Listening on udev Control Socket.
[    0.777555] systemd[1]: Listening on udev Kernel Socket.
[    0.777623] systemd[1]: Reached target Socket Units.
[    0.780447] systemd[1]: Starting Create List of Static Device Nodes...
[    0.784491] systemd[1]: Starting Journal Service...
[    0.786537] systemd[1]: Starting Load Kernel Modules...
[    0.788506] systemd[1]: Starting Setup Virtual Console...
[    0.789877] systemd[1]: Finished Create List of Static Device Nodes.
[    0.792071] systemd[1]: Starting Create Static Device Nodes in /dev...
[    0.797961] systemd[1]: Finished Setup Virtual Console.
[    0.798433] systemd[1]: dracut ask for additional cmdline parameters was skipped because no trigger condition checks were met.
[    0.800503] systemd[1]: Starting dracut cmdline hook...
[    0.806651] fuse: init (API version 7.36)
[    0.809033] systemd[1]: Finished Load Kernel Modules.
[    0.811444] systemd[1]: Starting Apply Kernel Variables...
[    0.814642] systemd[1]: Started Journal Service.
[    1.554003] vreg_s4a: Setting 1800000-1816000uV
[    1.554100] vreg_l1c: Setting 1140000-1260000uV
[    1.554109] vreg_s4e: Setting 970000-1520000uV
[    1.554267] vreg_s5a: Setting 1850000-1996000uV
[    1.555047] vreg_l2c: Setting 900000-1100000uV
[    1.555197] vreg_s7e: Setting 1010000-1170000uV
[    1.555425] vreg_s9a: Setting 535000-1120000uV
[    1.556315] vreg_l3c: Setting 1100000-1300000uV
[    1.556531] vreg_s9e: Setting 300000-570000uV
[    1.556795] vreg_l4a: Setting 788000-1050000uV
[    1.557290] vreg_l4c: Setting 1100000-1300000uV
[    1.557549] vreg_l6e: Setting 1280000-1450000uV
[    1.557868] gpio gpiochip0: (f000000.pinctrl): not an immutable chip, please consider fixing it!
[    1.558031] vreg_l5a: Setting 870000-950000uV
[    1.559011] vreg_l5c: Setting 1100000-1300000uV
[    1.559643] vreg_l8e: Setting 1800000-1950000uV
[    1.561468] vreg_l6a: Setting 870000-970000uV
[    1.562390] vreg_l6c: Setting 1620000-1980000uV
[    1.562832] vreg_l7a: Setting 720000-950000uV
[    1.562997] vreg_l7c: Setting 1620000-2000000uV
[    1.563115] vreg_l8a: Setting 2504000-3300000uV
[    1.563231] vreg_l8c: Setting 2400000-3300000uV
[    1.563352] vreg_l9a: Setting 2970000-3544000uV
[    1.563463] vreg_l9c: Setting 1650000-2700000uV
[    1.575115] geni_se_qup 8c0000.geniqup: Adding to iommu group 0
[    1.583545] ufshcd-qcom 1d84000.ufs: Adding to iommu group 1
[    1.583635] geni_se_qup ac0000.geniqup: Adding to iommu group 2
[    1.583902] 88c000.serial: ttyHS2 at MMIO 0x88c000 (irq = 152, base_baud = 0) is a MSM
[    1.586334] ufshcd-qcom 1d84000.ufs: ufshcd_populate_vreg: Unable to find vdd-hba-supply regulator, assuming enabled
[    1.586342] ufshcd-qcom 1d84000.ufs: ufshcd_populate_vreg: Unable to find vccq2-supply regulator, assuming enabled
[    1.586658] a8c000.serial: ttyMSM0 at MMIO 0xa8c000 (irq = 154, base_baud = 0) is a MSM
[    1.587071] printk: console [ttyMSM0] printing thread started
[    1.587072] printk: console [ttyMSM0] enabled
[    1.587989] scsi host0: ufshcd
[    1.592075] a94000.serial: ttyHS1 at MMIO 0xa94000 (irq = 156, base_baud = 0) is a MSM
[    1.599693] arm-smmu 3da0000.iommu: probing hardware configuration...
[    1.599698] arm-smmu 3da0000.iommu: SMMUv2 with:
    [    1.599718] arm-smmu 3da0000.iommu: 	stage 1 translation
[    1.599719] arm-smmu 3da0000.iommu: 	coherent table walk
[    1.599721] arm-smmu 3da0000.iommu: 	stream matching with 9 register groups
[    1.599734] arm-smmu 3da0000.iommu: 	7 context banks (0 stage-2 only)
[    1.599748] arm-smmu 3da0000.iommu: 	Supported page sizes: 0x61311000
[    1.599750] arm-smmu 3da0000.iommu: 	Stage-1: 48-bit VA -> 36-bit IPA
[    1.600047] arm-smmu 3da0000.iommu: 	preserved 0 boot mappings
[    1.685031] scsi 0:0:0:49488: Well-known LUN    KIOXIA   THGJFGT0T25BAZZA 0100 PQ: 0 ANSI: 6
[    1.685836] scsi 0:0:0:49476: Well-known LUN    KIOXIA   THGJFGT0T25BAZZA 0100 PQ: 0 ANSI: 6
[    1.686581] scsi 0:0:0:49456: Well-known LUN    KIOXIA   THGJFGT0T25BAZZA 0100 PQ: 0 ANSI: 6
[    1.687604] scsi 0:0:0:0: Direct-Access     KIOXIA   THGJFGT0T25BAZZA 0100 PQ: 0 ANSI: 6
[    1.688331] scsi 0:0:0:1: Direct-Access     KIOXIA   THGJFGT0T25BAZZA 0100 PQ: 0 ANSI: 6
[    1.688996] scsi 0:0:0:2: Direct-Access     KIOXIA   THGJFGT0T25BAZZA 0100 PQ: 0 ANSI: 6
[    1.689666] scsi 0:0:0:3: Direct-Access     KIOXIA   THGJFGT0T25BAZZA 0100 PQ: 0 ANSI: 6
[    1.690329] scsi 0:0:0:4: Direct-Access     KIOXIA   THGJFGT0T25BAZZA 0100 PQ: 0 ANSI: 6
[    1.690989] scsi 0:0:0:5: Direct-Access     KIOXIA   THGJFGT0T25BAZZA 0100 PQ: 0 ANSI: 6
[    1.691650] scsi 0:0:0:6: Direct-Access     KIOXIA   THGJFGT0T25BAZZA 0100 PQ: 0 ANSI: 6
[    1.692304] scsi 0:0:0:7: Direct-Access     KIOXIA   THGJFGT0T25BAZZA 0100 PQ: 0 ANSI: 6
[    1.694263] sd 0:0:0:0: [sda] 6750208 4096-byte logical blocks: (27.6 GB/25.8 GiB)
[    1.694317] sd 0:0:0:0: [sda] Write Protect is off
[    1.694320] sd 0:0:0:0: [sda] Mode Sense: 00 32 00 10
[    1.694420] sd 0:0:0:0: [sda] Write cache: enabled, read cache: enabled, supports DPO and FUA
[    1.694423] sd 0:0:0:0: [sda] Preferred minimum I/O size 4096 bytes
[    1.694425] sd 0:0:0:0: [sda] Optimal transfer size 524288 bytes
[    1.695322] sd 0:0:0:1: [sdb] 5120 4096-byte logical blocks: (21.0 MB/20.0 MiB)
[    1.695370] sd 0:0:0:1: [sdb] Write Protect is off
[    1.695374] sd 0:0:0:1: [sdb] Mode Sense: 00 32 00 10
[    1.695481] sd 0:0:0:1: [sdb] Write cache: disabled, read cache: enabled, supports DPO and FUA
[    1.695485] sd 0:0:0:1: [sdb] Preferred minimum I/O size 4096 bytes
[    1.695487] sd 0:0:0:1: [sdb] Optimal transfer size 524288 bytes
[    1.697862] sd 0:0:0:2: [sdc] 5120 4096-byte logical blocks: (21.0 MB/20.0 MiB)
[    1.697921] sd 0:0:0:2: [sdc] Write Protect is off
[    1.697924] sd 0:0:0:2: [sdc] Mode Sense: 00 32 00 10
[    1.698036] sd 0:0:0:2: [sdc] Write cache: disabled, read cache: enabled, supports DPO and FUA
[    1.698039] sd 0:0:0:2: [sdc] Preferred minimum I/O size 4096 bytes
[    1.698041] sd 0:0:0:2: [sdc] Optimal transfer size 524288 bytes
[    1.702923] sd 0:0:0:3: [sdd] 8192 4096-byte logical blocks: (33.6 MB/32.0 MiB)
[    1.703101]  sda: sda1 sda2 sda3 sda4 sda5 sda6 sda7 sda8 sda9 sda10 sda11 sda12 sda13 sda14
[    1.703133] sd 0:0:0:3: [sdd] Write Protect is off
[    1.703138] sd 0:0:0:3: [sdd] Mode Sense: 00 32 00 10
[    1.703283] sd 0:0:0:3: [sdd] Write cache: enabled, read cache: enabled, supports DPO and FUA
[    1.703290] sd 0:0:0:3: [sdd] Preferred minimum I/O size 4096 bytes
[    1.703292] sd 0:0:0:3: [sdd] Optimal transfer size 524288 bytes
[    1.704095]  sdb: sdb1 sdb2 sdb3
[    1.705397] sd 0:0:0:4: [sde] 8750080 4096-byte logical blocks: (35.8 GB/33.4 GiB)
[    1.705494] sd 0:0:0:4: [sde] Write Protect is off
[    1.705497] sd 0:0:0:4: [sde] Mode Sense: 00 32 00 10
[    1.705596] sd 0:0:0:4: [sde] Write cache: enabled, read cache: enabled, supports DPO and FUA
[    1.705599] sd 0:0:0:4: [sde] Preferred minimum I/O size 4096 bytes
[    1.705601] sd 0:0:0:4: [sde] Optimal transfer size 524288 bytes
[    1.705813]  sdc: sdc1 sdc2 sdc3
[    1.710509] sd 0:0:0:1: [sdb] Attached SCSI disk
[    1.710644] sd 0:0:0:5: [sdf] 5242880 4096-byte logical blocks: (21.5 GB/20.0 GiB)
[    1.710697] sd 0:0:0:5: [sdf] Write Protect is off
[    1.710699] sd 0:0:0:5: [sdf] Mode Sense: 00 32 00 10
[    1.710804] sd 0:0:0:5: [sdf] Write cache: enabled, read cache: enabled, supports DPO and FUA
[    1.710807] sd 0:0:0:5: [sdf] Preferred minimum I/O size 4096 bytes
[    1.710809] sd 0:0:0:5: [sdf] Optimal transfer size 524288 bytes
[    1.712400] sd 0:0:0:2: [sdc] Attached SCSI disk
[    1.714377]  sdd: sdd1 sdd2 sdd3
[    1.716984]  sde: sde1 sde2 sde3 sde4 sde5 sde6 sde7 sde8 sde9 sde10 sde11 sde12 sde13 sde14 sde15 sde16 sde17 sde18 sde19 sde20 sde21 sde22 sde23 sde24 sde25 sde26 sde27 sde28 sde29 sde30 sde31 sde32 sde33 sde34 sde35 sde36 sde37 sde38 sde39 sde40 sde41 sde42 sde43 sde44 sde45
[    1.718823] sd 0:0:0:6: [sdg] 100352 4096-byte logical blocks: (411 MB/392 MiB)
[    1.718877] sd 0:0:0:6: [sdg] Write Protect is off
[    1.718879] sd 0:0:0:6: [sdg] Mode Sense: 00 32 00 10
[    1.718976] sd 0:0:0:6: [sdg] Write cache: enabled, read cache: enabled, supports DPO and FUA
[    1.718980] sd 0:0:0:6: [sdg] Preferred minimum I/O size 4096 bytes
[    1.718981] sd 0:0:0:6: [sdg] Optimal transfer size 524288 bytes
[    1.721210] sd 0:0:0:3: [sdd] Attached SCSI disk
[    1.722354]  sdf: sdf1 sdf2 sdf3 sdf4 sdf5 sdf6 sdf7 sdf8 sdf9 sdf10 sdf11 sdf12 sdf13 sdf14 sdf15 sdf16 sdf17 sdf18 sdf19 sdf20 sdf21 sdf22 sdf23
[    1.727494] sd 0:0:0:7: [sdh] 10363904 4096-byte logical blocks: (42.5 GB/39.5 GiB)
[    1.727548] sd 0:0:0:7: [sdh] Write Protect is off
[    1.727551] sd 0:0:0:7: [sdh] Mode Sense: 00 32 00 10
[    1.727641] sd 0:0:0:7: [sdh] Write cache: enabled, read cache: enabled, supports DPO and FUA
[    1.727645] sd 0:0:0:7: [sdh] Preferred minimum I/O size 4096 bytes
[    1.727647] sd 0:0:0:7: [sdh] Optimal transfer size 524288 bytes
[    1.731398]  sdg: sdg1 sdg2 sdg3 sdg4 sdg5 sdg6 sdg7 sdg8 sdg9
[    1.732695] sd 0:0:0:0: [sda] Attached SCSI disk
[    1.737083]  sdh: sdh1 sdh2 sdh3 sdh4 sdh5 sdh6
[    1.744656] sd 0:0:0:6: [sdg] Attached SCSI disk
[    1.745522] sd 0:0:0:7: [sdh] Attached SCSI disk
[    1.749258] sd 0:0:0:5: [sdf] Attached SCSI disk
[    1.750535] sd 0:0:0:4: [sde] Attached SCSI disk
[    2.625387] EXT4-fs (sde38): mounted filesystem with ordered data mode. Quota mode: none.
[    5.158655] systemd-journald[173]: Received SIGTERM from PID 1 (systemd).
[    5.383051] audit: type=1404 audit(1691107204.819:2): enforcing=1 old_enforcing=0 auid=4294967295 ses=4294967295 enabled=1 old-enabled=1 lsm=selinux res=1
[    5.537164] SELinux:  policy capability network_peer_controls=1
[    5.537169] SELinux:  policy capability open_perms=1
[    5.537171] SELinux:  policy capability extended_socket_class=1
[    5.537172] SELinux:  policy capability always_check_network=0
[    5.537173] SELinux:  policy capability cgroup_seclabel=1
[    5.537173] SELinux:  policy capability nnp_nosuid_transition=1
[    5.537174] SELinux:  policy capability genfs_seclabel_symlinks=1
[    5.724345] audit: type=1403 audit(1691107205.159:3): auid=4294967295 ses=4294967295 lsm=selinux res=1
[    5.726779] systemd[1]: Successfully loaded SELinux policy in 442.002ms.
[    5.881392] systemd[1]: Relabelled /dev, /dev/shm, /run, /sys/fs/cgroup in 126.739ms.
[    5.891109] systemd[1]: systemd 252-17.el9 running in system mode (+PAM +AUDIT +SELINUX -APPARMOR +IMA +SMACK +SECCOMP +GCRYPT +GNUTLS +OPENSSL +ACL +BLKID +CURL +ELFUTILS -FIDO2 +IDN2 -IDN -IPTC +KMOD +LIBCRYPTSETUP +LIBFDISK +PCRE2 -PWQUALITY +P11KIT -QRENCODE +TPM2 +BZIP2 +LZ4 +XZ +ZLIB +ZSTD -BPF_FRAMEWORK +XKBCOMMON +UTMP +SYSVINIT default-hierarchy=unified)
[    5.891368] systemd[1]: Detected architecture arm64.
[    5.982407] systemd-rc-local-generator[397]: /etc/rc.d/rc.local is not marked executable, skipping.
[    6.070567] systemd[1]: /usr/lib/systemd/system/restraintd.service:8: Standard output type syslog+console is obsolete, automatically updating to journal+console. Please update your unit file, and consider removing the setting altogether.
[    6.420517] systemd[1]: initrd-switch-root.service: Deactivated successfully.
[    6.420771] systemd[1]: Stopped Switch Root.
[    6.443449] systemd[1]: systemd-journald.service: Scheduled restart job, restart counter is at 1.
[    6.444142] systemd[1]: Created slice Slice /system/getty.
[    6.483590] systemd[1]: Created slice Slice /system/modprobe.
[    6.513724] systemd[1]: Created slice Slice /system/serial-getty.
[    6.553589] systemd[1]: Created slice Slice /system/sshd-keygen.
[    6.583599] systemd[1]: Created slice User and Session Slice.
[    6.613217] systemd[1]: Started Dispatch Password Requests to Console Directory Watch.
[    6.643183] systemd[1]: Started Forward Password Requests to Wall Directory Watch.
[    6.673614] systemd[1]: Set up automount Arbitrary Executable File Formats File System Automount Point.
[    6.702968] systemd[1]: Reached target Local Encrypted Volumes.
[    6.742961] systemd[1]: Stopped target Switch Root.
[    6.772950] systemd[1]: Stopped target Initrd File Systems.
[    6.802958] systemd[1]: Stopped target Initrd Root File System.
[    6.842964] systemd[1]: Reached target Local Integrity Protected Volumes.
[    6.872979] systemd[1]: Reached target Path Units.
[    6.902972] systemd[1]: Reached target Slice Units.
[    6.932949] systemd[1]: Reached target Swaps.
[    6.962959] systemd[1]: Reached target Local Verity Protected Volumes.
[    7.012710] systemd[1]: Listening on RPCbind Server Activation Socket.
[    7.053010] systemd[1]: Reached target RPC Port Mapper.
[    7.086203] systemd[1]: Listening on Process Core Dump Socket.
[    7.123300] systemd[1]: Listening on initctl Compatibility Named Pipe.
[    7.154183] systemd[1]: Listening on udev Control Socket.
[    7.183516] systemd[1]: Listening on udev Kernel Socket.
[    7.225320] systemd[1]: Mounting Huge Pages File System...
[    7.255255] systemd[1]: Mounting POSIX Message Queue File System...
[    7.285220] systemd[1]: Mounting Kernel Debug File System...
[    7.325221] systemd[1]: Mounting Kernel Trace File System...
[    7.355479] systemd[1]: Mounting Temporary Directory /tmp...
[    7.383043] systemd[1]: Kernel Module supporting RPCSEC_GSS was skipped because of an unmet condition check (ConditionPathExists=/etc/krb5.keytab).
[    7.385213] systemd[1]: Starting Create List of Static Device Nodes...
[    7.424883] systemd[1]: Starting Load Kernel Module configfs...
[    7.454979] systemd[1]: Starting Load Kernel Module drm...
[    7.484789] systemd[1]: Starting Load Kernel Module fuse...
[    7.513297] systemd[1]: Read and set NIS domainname from /etc/sysconfig/network was skipped because of an unmet condition check (ConditionPathExists=/etc/sysconfig/network).
[    7.513482] systemd[1]: systemd-fsck-root.service: Deactivated successfully.
[    7.513629] systemd[1]: Stopped File System Check on Root Device.
[    7.583133] systemd[1]: Stopped Journal Service.
[    7.617043] systemd[1]: Starting Journal Service...
[    7.645709] systemd[1]: Starting Load Kernel Modules...
[    7.684854] systemd[1]: Starting Generate network units from Kernel command line...
[    7.715051] systemd[1]: Starting Remount Root and Kernel File Systems...
[    7.726337] EXT4-fs (sde38): re-mounted. Quota mode: none.
[    7.743132] systemd[1]: Repartition Root Disk was skipped because no trigger condition checks were met.
[    7.745358] systemd[1]: Starting Coldplug All udev Devices...
[    7.785592] systemd[1]: Started Journal Service.
[    8.363709] systemd-journald[422]: Received client request to flush runtime journal.
[    9.186343] RPC: Registered named UNIX socket transport module.
[    9.186347] RPC: Registered udp transport module.
[    9.186348] RPC: Registered tcp transport module.
[    9.186349] RPC: Registered tcp NFSv4.1 backchannel transport module.
[    9.526830] spmi spmi-0: PMIC arbiter version v5 (0x50020000)
[    9.529396] nvmem-reboot-mode reboot-mode: failed to get the nvmem cell reboot-mode
[    9.596231] nvmem-reboot-mode reboot-mode: failed to get the nvmem cell reboot-mode
[    9.596865] nvmem-reboot-mode reboot-mode: failed to get the nvmem cell reboot-mode
[    9.597299] nvmem-reboot-mode reboot-mode: failed to get the nvmem cell reboot-mode
[    9.597893] nvmem-reboot-mode reboot-mode: failed to get the nvmem cell reboot-mode
[    9.609064] nvmem-reboot-mode reboot-mode: failed to get the nvmem cell reboot-mode
[    9.610087] qcom-spmi-gpio c440000.spmi:pmic@2:gpio@8800: can't add gpio chip
[    9.628208] dwc3 a400000.usb: Adding to iommu group 3
[    9.630181] xhci-hcd xhci-hcd.0.auto: xHCI Host Controller
[    9.630407] xhci-hcd xhci-hcd.0.auto: new USB bus registered, assigned bus number 1
[    9.630545] xhci-hcd xhci-hcd.0.auto: USB3 root hub has no ports
[    9.630548] xhci-hcd xhci-hcd.0.auto: hcc params 0x0220fe65 hci version 0x110 quirks 0x0000000000010010
[    9.630707] xhci-hcd xhci-hcd.0.auto: irq 178, io mem 0x0a400000
[    9.630860] usb usb1: New USB device found, idVendor=1d6b, idProduct=0002, bcdDevice= 5.14
[    9.630863] usb usb1: New USB device strings: Mfr=3, Product=2, SerialNumber=1
[    9.630864] usb usb1: Product: xHCI Host Controller
[    9.630865] usb usb1: Manufacturer: Linux 5.14.0-349.312.test.el9iv.aarch64 xhci-hcd
[    9.630866] usb usb1: SerialNumber: xhci-hcd.0.auto
[    9.631122] hub 1-0:1.0: USB hub found
[    9.631130] hub 1-0:1.0: 1 port detected
[    9.631362] dwc3 a600000.usb: Adding to iommu group 4
[    9.674581] dwc3 a800000.usb: Adding to iommu group 5
[    9.713268] xhci-hcd xhci-hcd.1.auto: xHCI Host Controller
[    9.713384] xhci-hcd xhci-hcd.1.auto: new USB bus registered, assigned bus number 2
[    9.715836] xhci-hcd xhci-hcd.1.auto: hcc params 0x0110ffc5 hci version 0x110 quirks 0x0000000000010010
[    9.715939] xhci-hcd xhci-hcd.1.auto: irq 180, io mem 0x0a800000
[    9.716048] xhci-hcd xhci-hcd.1.auto: xHCI Host Controller
[    9.716117] xhci-hcd xhci-hcd.1.auto: new USB bus registered, assigned bus number 3
[    9.716120] xhci-hcd xhci-hcd.1.auto: Host supports USB 3.1 Enhanced SuperSpeed
[    9.716170] usb usb2: New USB device found, idVendor=1d6b, idProduct=0002, bcdDevice= 5.14
[    9.716172] usb usb2: New USB device strings: Mfr=3, Product=2, SerialNumber=1
[    9.716173] usb usb2: Product: xHCI Host Controller
[    9.716174] usb usb2: Manufacturer: Linux 5.14.0-349.312.test.el9iv.aarch64 xhci-hcd
[    9.716175] usb usb2: SerialNumber: xhci-hcd.1.auto
[    9.716332] hub 2-0:1.0: USB hub found
[    9.716339] hub 2-0:1.0: 1 port detected
[    9.716456] usb usb3: We don't know the algorithms for LPM for this host, disabling LPM.
[    9.716482] usb usb3: New USB device found, idVendor=1d6b, idProduct=0003, bcdDevice= 5.14
[    9.716484] usb usb3: New USB device strings: Mfr=3, Product=2, SerialNumber=1
[    9.716485] usb usb3: Product: xHCI Host Controller
[    9.716486] usb usb3: Manufacturer: Linux 5.14.0-349.312.test.el9iv.aarch64 xhci-hcd
[    9.716486] usb usb3: SerialNumber: xhci-hcd.1.auto
[    9.716626] hub 3-0:1.0: USB hub found
[    9.716632] hub 3-0:1.0: 1 port detected
[   10.102954] usb 3-1: new SuperSpeed USB device number 2 using xhci-hcd
[   10.133609] usb 3-1: New USB device found, idVendor=0bda, idProduct=8153, bcdDevice=30.00
[   10.133613] usb 3-1: New USB device strings: Mfr=1, Product=2, SerialNumber=6
[   10.133614] usb 3-1: Product: USB 10/100/1000 LAN
[   10.133615] usb 3-1: Manufacturer: Realtek
[   10.133616] usb 3-1: SerialNumber: 000001
[   10.180066] usbcore: registered new device driver r8152-cfgselector
[   10.452290] r8152-cfgselector 3-1: reset SuperSpeed USB device number 2 using xhci-hcd
[   10.514591] r8152 3-1:1.0: load rtl8153a-4 v2 02/07/20 successfully
[   10.612945] r8152 3-1:1.0 eth0: v1.12.13
[   10.612988] usbcore: registered new interface driver r8152
[   10.620082] usbcore: registered new interface driver cdc_ether
[   10.622517] usbcore: registered new interface driver r8153_ecm
[   11.373500]  sdf: sdf1 sdf2 sdf3 sdf4 sdf5 sdf6 sdf7 sdf8 sdf9 sdf10 sdf11 sdf12 sdf13 sdf14 sdf15 sdf16 sdf17 sdf18 sdf19 sdf20 sdf21 sdf22 sdf23
[   13.445073] IPv6: ADDRCONF(NETDEV_CHANGE): eth0: link becomes ready
[   13.445295] r8152 3-1:1.0 eth0: carrier on
[   20.963476] qcom-ethqos 23040000.ethernet: Adding to iommu group 6
[   20.964097] qcom-ethqos 23040000.ethernet: IRQ eth_wake_irq not found
[   20.964100] qcom-ethqos 23040000.ethernet: IRQ eth_lpi not found
[   20.964257] platform 23040000.ethernet: deferred probe pending''' 

def grab_dmesg(ip: str, usr: str, passwd) -> str:
    """
    Grab dmesg logs off the SUT
    """
    (rc, stdout, stderr) = run_ssh_cmd("dmesg", ip, usr, passwd)
    if rc:
        print("ERROR: cannot get dmesg", stderr)
        sys.exit(1)
    return stdout

def search_dmesg(queries: List [ Dict[str, str | Tuple[str, str]] ], dmesg: str):
    """
    Expects a list of dictionaries with the following format:
    { name_of_entry, regex_text_to_match }
    or if the same text has mulitple matches, the match occurence is specified 
    { name_of_entry, (regex_text_to_match, number_to_match) }
    """
    matches = []

    for query in queries:
        name = next(iter(query))
        value = next(iter(query.values()))
        # Optional value to specify which match to use in a tuple, otherwise use 0
        if isinstance(value, tuple):
          entry = value[0]
          index = value[1]
        else:
          entry = value
          index = 0

        # Match the timestamp as a group and entry specified by the input as another
        regex_query = rf'^\[\s*([\d.]+)\]\s+({entry})'
        result = re.findall(regex_query, dmesg, re.MULTILINE)

        if not result:
          raise ValueError(f'"ERROR: {entry}" was not found in dmesg.')

        matches.append((name,) + result[index])
    return matches

def calc_duration(msgs):
   previous_msg = None
   output = {}
   for msg in msgs: 
       # Create timestamp entries
       (name, timestamp, *_) = msg
       field_name = name + '_ts'
       output[field_name] = float(timestamp)

       # Create duration entries
       if previous_msg:
           (prev_name, prev_timestamp, *_) = previous_msg
           duration = float(timestamp) - float(prev_timestamp)
           field_name = f'{prev_name}_{name}_int'
           output[field_name] = duration

       previous_msg = msg
   return output

def initramfs(dmesg: str):
    queries = [
        {'unpack': 'Trying to unpack rootfs image as initramfs'},
        {'init': 'Run /init as init process'},
        {'systemd': 'systemd\[1\]: .* running in system mode'},
        ]

    initramfs_msgs = search_dmesg(queries, dmesg)
    return calc_duration(initramfs_msgs)

def dklm(dmesg: str):
    queries = [
            { 'systemd': ('systemd\[1\]: .* running in system mode',1)},
            { 'udev': ('systemd\[1\]: Listening on udev Control Socket',1)},
            { 'start_kmod_load': ('systemd\[1\]: Starting Load Kernel Modules',1)},
            ]

    dklm_msgs = search_dmesg(queries, dmesg)
    return calc_duration(dklm_msgs)


#####################################
# GLOBAL VARS 
target = "multi-user.target"  # graphical.target
reboot_timeout = 300          # max. number of seconds: rebootsut()
ssh_timeout = 20              # max. number of seconds: testssh()
retry_int = 2                 # client.connect retry interval (in sec)

##############################################################
# MAIN

def main():

    
    # Parse CLI args and assign them to their respective variables
    args = parse_args()
    (sut_host, sut_ip, sut_usr, sut_pswd) = (
            args.hostname, args.ip, args.username, args.password 
            )
    run_count = args.samples
    blame_cnt = args.blame_count

    ##########################
    # OUTER LOOP - For each SUT
    # initialize vars and print msg for this SUT being tested
    print(f'\n***SUT: {sut_ip}  {sut_host}  Number of Runs: {run_count}***')
    results_list = []          # comprehensive results - list of dicts
    outfilename = str(sut_host + "_" +\
                  datetime.datetime.now().strftime('%m_%d_%Y_%H_%M_%S') +\
                  ".json")
    run_number = 1          # initialize
    while run_number <= run_count:
        print(f'\n** Run: {run_number} **')
        
        # Dictionaries
        testrun_dict = {}        # complete testrun results (per SUT)
        testcfg_dict = {}        # test configuration
        syscfg_dict = {}         # system configuration
        data_dict = {}           # testdata results (nested)

        # Verify connectivity to SUT
        ping_ssh1 = testssh(sut_ip, sut_usr, sut_pswd, ssh_timeout)
        if ping_ssh1 is False:
            continue            # skip this SUT

        # Add to dict{} for this SUT
        testrun_dict["cluster_name"] = str(sut_host)
        curtime = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        testrun_dict["date"] = str(curtime.strip())
        testrun_dict["test_type"] = "boot-time"   # hardcoded
        testrun_dict["sample"] = int(run_number)

        # Initialize testcfg dict{} for this SUT
        testcfg_dict = init_dict(
            sut_host, sut_ip, reboot_timeout, ssh_timeout, target, blame_cnt)
        testrun_dict["test_config"] = testcfg_dict

        ############
        # INNER LOOP
        # Proceed through testing phases
        #----------
        # Phase 1: gather system facts
        print(f'*Phase 1 - gather facts')
        syscfg_dict = phase1(sut_ip, sut_usr, sut_pswd)

        #----------
        # Phase 2: configure SUT for reboot
        # returns if neptuneui (boolean) is running
        print(f'*Phase 2 - configure SUT for reboot')
        neptuneui = phase2(sut_ip, sut_usr, sut_pswd, target)

        #----------
        # Phase 3: initiate reboot, wait for system readiness
        #          and record timing results into reboot_dict{}
        print(f'*Phase 3 - initiate reboot and wait for system readiness')
        reboot_dict = phase3(sut_ip, sut_usr, sut_pswd)
        # Verify connectivity to freshly rebooted SUT
        ping_ssh2 = testssh(sut_ip, sut_usr, sut_pswd, ssh_timeout)
        if ping_ssh2 is False:
            continue           # reboot failed, abort this SUT test

        #----------
        # Phase 4: instrument SUT reboot w/systemd-analyze commands
        # NOTE: sa_dict is nested with "sa_time" and "sa_blame" keys
        print(f'*Phase 4 - record systemd-analyze reboot stats')
        sa_dict = phase4(sut_ip, sut_usr, sut_pswd, blame_cnt)

        #----------
        # Phase 5: neptune UI startup timings
        print(f'*Phase 5 - neptune timing stats (if available)')
        neptuneui_dict = phase5(sut_ip, sut_usr, sut_pswd)


        dmesg = grab_dmesg(sut_ip, sut_usr, sut_pswd)

        #------------
        # Phase 6: initramfs timings
        print(f'*Phase 6 - initramfs timing stats')
        data_dict["initramfs"] = initramfs(dmesg)

        #------------
        # Phase 7: initramfs timings
        print(f'*Phase 7 - dklm timing stats')
        data_dict["dklm"] = dklm(dmesg)




        ######################
        # All PHASEs for this SUT completed
        # Insert existing test results into 'test_results' section
        data_dict["reboot"] = reboot_dict
        data_dict["satime"] = sa_dict["sa_time"]
        data_dict["sablame"] = sa_dict["sa_blame"]
        data_dict["neptuneui"] = neptuneui_dict

        # Insert complete data_dict{} into testrun_dict (final dictionary)
        testrun_dict["test_results"] = data_dict

        # Insert syscfg_dict{} into testrun_dict{}
        testrun_dict["system_config"] = syscfg_dict

        # Insert test results for this SUT into results_list[]
        results_list.append(testrun_dict)

        run_number += 1          # incr run cntr

    print(f'+++TESTING for {sut_host} COMPLETED+++')

    write_json(results_list, outfilename)
        
    print(f'+++TESTING for all systems COMPLETED+++')
# END MAIN

if __name__ == "__main__":
    main()

##############################################################
