#-..TESTING/DESIGNing a CLI main inteface

import sys
import os
import time
import argparse
import subprocess
import logging
import json

from networking.ip_monitoring import monitor_public_ip, analyze_traffic
from networking.ddos_protection import rate_limit_traffic, redirect_traffic
from networking.panic_button import activate_panic_mode, send_remote_alert
from networking.connection_discriminator import log_connections, analyze_connection_patterns
from networking.firewall_manual import configure_iptables, load_rule_set, backup_firewall, restore_firewall

from system.bios import check_bios_settings, detect_bios_changes
from system.cpu import check_cpu_status, detect_cpu_vulnerabilities
from system.ram import check_ram_security
from system.kernel import check_kernel_integrity, monitor_kernel_logs
from system.os import secure_os, manage_patches, audit_user_privileges, harden_services, monitor_file_integrity

from audits.regular_audits import perform_security_assessment, check_compliance
from audits.incident_response import define_incident_roles, establish_communication_channels, review_incident

from external_tools import configure_nessus

#--- CONFIGs
CONFIG_FILE = "beltz_config.yaml"
LOG_FILE = "beltz.log"

def load_config():
  try:
        with open(CONFIG_FILE, 'r') as f:
            config = json.load(f)
        return config
    except FileNotFoundError:
        logging.error(f"NO CONFIG ERROR 0xDDDDDD {CONFIG_FILE}")
        sys.exit(1)
    except json.JSONDecodeError:
        logging.error(f"ERROR, YAML FILE CORRUPTED 0xEEEEEE {CONFIG_FILE}")
        sys.exit(1)

def save_config(config):
  try:
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=4)
    except Exception as e:
        logging.error(f"ERROR SAVING YAML 0xFFFFFF {e}")

  def initialize_logging():
    """Initializes logging to file.""    logging.basicConfig(filename=LOG_FILE, level=logging.INFO,
                        format='%(asctime)s - %(levelname)s - %(message)s')
def parse_arguments():
    """Parses command-line arguments."""
    parser = argparse.ArgumentParser(description="Boundary Enhanced Linux Threat Zeroday-ing (BELT)")
    subparsers = parser.add_subparsers(dest='command')

    #----NETs-1
    net_parser = subparsers.add_parser('net', help='Networking commands')
    net_subparsers = net_parser.add_subparsers(dest='net_command')
    net_subparsers.add_parser('ip_monitor', help='Monitor public IP address')
    net_subparsers.add_parser('traffic_analyze', help='Analyze network traffic')
    net_subparsers.add_parser('rate_limit', help='Enable rate limiting')
    net_subparsers.add_parser('redirect_traffic', help='Redirect traffic')
    net_subparsers.add_parser('panic_button', help='Activate panic mode')
    net_subparsers.add_parser('send_alert', help='Send remote alert')
    net_subparsers.add_parser('log_connections', help='Log network connections')
    net_subparsers.add_parser('analyze_patterns', help='Analyze connection patterns')
    net_subparsers.add_parser('config_firewall', help='Configure iptables firewall')
    net_subparsers.add_parser('load_rules', help='Load predefined firewall rules')
    net_subparsers.add_parser('backup_firewall', help='Backup firewall configuration')
    net_subparsers.add_parser('restore_firewall', help='Restore firewall configuration')

    # System commands
    sys_parser = subparsers.add_parser('sys', help='System commands')
    sys_subparsers = sys_parser.add_subparsers(dest='sys_command')
    sys_subparsers.add_parser('check_bios', help='Check BIOS settings')
    sys_subparsers.add_parser('detect_bios_changes', help='Detect BIOS changes')
    sys_subparsers.add_parser('check_cpu', help='Check CPU status')
    sys_subparsers.add_parser('detect_cpu_vuln', help='Detect CPU vulnerabilities')
    sys_subparsers.add_parser('check_ram', help='Check RAM security')
    sys_subparsers.add_parser('check_kernel', help='Check kernel integrity')
    sys_subparsers.add_parser('monitor_kernel_logs', help='Monitor kernel logs')
    sys_subparsers.add_parser('secure_os', help='Secure OS settings')
    sys_subparsers.add_parser('manage_patches', help='Manage OS patches')
    sys_subparsers.add_parser('audit_users', help='Audit user privileges')
    sys_subparsers.add_parser('harden_services', help='Harden system services')
    sys_subparsers.add_parser('monitor_files', help='Monitor file integrity')

    #--AUDITs-functions:
    audit_parser = subparsers.add_parser('audit', help='Audit commands')
    audit_subparsers = audit_parser.add_subparsers(dest='audit_command')
    audit_subparsers.add_parser('security_assessment', help='Perform security assessment')
    audit_subparsers.add_parser('check_compliance', help='Check compliance with security policies')
    audit_subparsers.add_parser('define_incident_roles', help='Define incident response roles')
    audit_subparsers.add_parser('establish_communication', help='Establish communication channels')
    audit_subparsers.add_parser('review_incident', help='Review incident response')

    #--Nessus/NMAP/etab.
    tools_parser = subparsers.add_parser('tools', help='External tools commands')
    tools_subparsers = tools_parser.add_parser('configure_nessus', help='Configure Nessus')

    return parser.parse_args()

    # --- MAIN
def main():
    """Main function."""
    initialize_logging()
    config = load_config()
    args = parse_arguments()

    # --NETs
    if args.command == 'net':
        if args.net_command == 'ip_monitor':
            monitor_public_ip(config)
        elif args.net_command == 'traffic_analyze':
            analyze_traffic(config)
        elif args.net_command == 'rate_limit':
            rate_limit_traffic(config)
        elif args.net_command == 'redirect_traffic':
            redirect_traffic(config)
        elif args.net_command == 'panic_button':
            activate_panic_mode(config)
        elif args.net_command == 'send_alert':
            send_remote_alert(config)
        elif args.net_command == 'log_connections':
            log_connections(config)
        elif args.net_command == 'analyze_patterns':
            analyze_connection_patterns(config)
        elif args.net_command == 'config_firewall':
            configure_iptables(config)
        elif args.net_command == 'load_rules':
            load_rule_set(config)
        elif args.net_command == 'backup_firewall':
            backup_firewall(config)
        elif args.net_command == 'restore_firewall':
            restore_firewall(config)

    #--SYS
    elif args.command == 'sys':
        if args.sys_command == 'check_bios':
            check_bios_settings(config)
        elif args.sys_command == 'detect_bios_changes':
            detect_bios_changes(config)
        elif args.sys_command == 'check_cpu':
            check_cpu_status(config)
        elif args.sys_command == 'detect_cpu_vuln':
            detect_cpu_vulnerabilities(config)
        elif args.sys_command == 'check_ram':
            check_ram_security(config)
        elif args.sys_command == 'check_kernel':
            check_kernel_integrity(config)
        elif args.sys_command == 'monitor_kernel_logs':
            monitor_kernel_logs(config)
        elif args.sys_command == 'secure_os':
            secure_os(config)
        elif args.sys_command == 'manage_patches':
            manage_patches(config)
        elif args.
