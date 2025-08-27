#!/usr/bin/env python3
"""
Vertiv PDU Firmware Upgrade Script

This script automates the firmware upgrade process for Vertiv PDUs using Nornir
and the PDU's REST API. It includes pre-upgrade checks, firmware upload, and
post-upgrade verification.

Usage:
    python upgradePDU.py --firmware /path/to/firmware.bin
    python upgradePDU.py --firmware /path/to/firmware.bin --check-only
    python upgradePDU.py --firmware /path/to/firmware.bin --target-host PDU_NAME

Author: Network Automation Team
"""

import json
import os
import sys
import argparse
import time
from pathlib import Path
from nornir import InitNornir
from nornir.core.filter import F
from nornir.core.task import Task, Result
from nornir_utils.plugins.functions import print_result
from dotenv import load_dotenv

# Import our custom functions from vertiv.py
from Vertiv import (
    nr_transfer_firmware,
    nr_get_firmware_version,
    nr_firmware_upgrade_workflow,
    post_url
)

# Load environment variables
load_dotenv()

# Configuration
api_token = os.getenv("VERTIV_API_TOKEN")
if not api_token:
    print("ERROR: VERTIV_API_TOKEN environment variable not set!")
    sys.exit(1)

headers = {
    'Authorization': f'Basic {api_token}',
    'Accept': 'application/json',
    'Content-Type': 'application/json'
}

# Global settings
FIRMWARE_BACKUP_DIR = "./firmware_backups"
UPGRADE_LOG_DIR = "./upgrade_logs"


def ensure_directories():
    """Ensure required directories exist"""
    Path(FIRMWARE_BACKUP_DIR).mkdir(parents=True, exist_ok=True)
    Path(UPGRADE_LOG_DIR).mkdir(parents=True, exist_ok=True)


def nr_backup_config(task: Task) -> Result:
    """
    Backup PDU configuration before firmware upgrade
    """
    try:
        backup_url = f"http://{task.host.hostname}/transfer/backup"
        
        import requests
        response = requests.get(backup_url, verify=False, timeout=60)
        response.raise_for_status()
        
        # Generate backup filename based on MAC address format specified in API
        mac_addr = getattr(task.host, 'mac_address', task.host.name)
        clean_mac = mac_addr.replace(':', '').replace('-', '')
        backup_filename = f"{FIRMWARE_BACKUP_DIR}/backup_{clean_mac}_{int(time.time())}.bin"
        
        with open(backup_filename, 'wb') as f:
            f.write(response.content)
        
        return Result(
            host=task.host,
            result={
                'status': 'success',
                'backup_file': backup_filename,
                'message': f"Configuration backup saved to {backup_filename}"
            }
        )
        
    except Exception as e:
        return Result(
            host=task.host,
            failed=True,
            result=f"Configuration backup failed: {str(e)}"
        )


def nr_validate_firmware_file(task: Task, firmware_path: str) -> Result:
    """
    Validate firmware file before upload
    """
    try:
        if not os.path.exists(firmware_path):
            return Result(
                host=task.host,
                failed=True,
                result=f"Firmware file not found: {firmware_path}"
            )
        
        file_size = os.path.getsize(firmware_path)
        if file_size < 1024:  # Less than 1KB
            return Result(
                host=task.host,
                failed=True,
                result=f"Firmware file appears too small: {file_size} bytes"
            )
        
        # Check file extension (common firmware extensions)
        valid_extensions = ['.bin', '.img', '.fw', '.hex']
        file_ext = Path(firmware_path).suffix.lower()
        
        if file_ext not in valid_extensions:
            print(f"WARNING: Firmware file extension '{file_ext}' is not typical. Continue anyway.")
        
        return Result(
            host=task.host,
            result={
                'status': 'valid',
                'file_size': file_size,
                'file_path': firmware_path,
                'message': f"Firmware file validated: {file_size:,} bytes"
            }
        )
        
    except Exception as e:
        return Result(
            host=task.host,
            failed=True,
            result=f"Firmware validation failed: {str(e)}"
        )


def nr_check_pdu_compatibility(task: Task) -> Result:
    """
    Check PDU model and current version for compatibility
    """
    try:
        # Get model information
        model_url = f"http://{task.host.hostname}/api/sys/modelNumber"
        model_payload = {'token': '', 'cmd': 'get', 'data': {}}
        model_response = post_url(model_url, headers, model_payload)
        
        # Get current firmware version
        version_result = task.run(
            task=nr_get_firmware_version,
            headers=headers
        )
        
        if version_result.failed:
            return Result(
                host=task.host,
                failed=True,
                result="Failed to get current firmware version for compatibility check"
            )
        
        compatibility_info = {
            'model': model_response.get('data', 'Unknown'),
            'current_version': version_result.result.get('firmware_version', {}),
            'compatible': True,  # Assume compatible unless specific issues found
            'warnings': []
        }
        
        # Add version-specific warnings
        current_fw = version_result.result.get('firmware_version', {}).get('data', '')
        if '5.9.0' in str(current_fw) or '5.10' in str(current_fw):
            compatibility_info['warnings'].append(
                "WARNING: Systems running 5.9.0 or later may not support downgrading"
            )
        
        return Result(
            host=task.host,
            result=compatibility_info
        )
        
    except Exception as e:
        return Result(
            host=task.host,
            failed=True,
            result=f"Compatibility check failed: {str(e)}"
        )


def nr_post_upgrade_verification(task: Task, expected_reboot_time: int = 300) -> Result:
    """
    Verify PDU comes back online after firmware upgrade and check new version
    """
    import requests
    
    print(f"Waiting {expected_reboot_time} seconds for {task.host} to reboot...")
    time.sleep(expected_reboot_time)
    
    # Try to reconnect and verify new firmware
    max_attempts = 10
    retry_interval = 30
    
    for attempt in range(max_attempts):
        try:
            print(f"Verification attempt {attempt + 1}/{max_attempts} for {task.host}")
            
            # Try to get firmware version
            version_result = task.run(
                task=nr_get_firmware_version,
                headers=headers
            )
            
            if not version_result.failed:
                return Result(
                    host=task.host,
                    result={
                        'status': 'online',
                        'new_firmware_version': version_result.result,
                        'attempts': attempt + 1,
                        'message': f"PDU came back online after {attempt + 1} attempts"
                    }
                )
                
        except Exception as e:
            print(f"Attempt {attempt + 1} failed: {str(e)}")
        
        if attempt < max_attempts - 1:
            print(f"Retrying in {retry_interval} seconds...")
            time.sleep(retry_interval)
    
    return Result(
        host=task.host,
        failed=True,
        result=f"PDU did not come back online after {max_attempts} attempts"
    )


def firmware_upgrade_with_checks(task: Task, firmware_path: str, check_only: bool = False) -> Result:
    """
    Complete firmware upgrade process with pre/post checks
    """
    results = []
    
    try:
        print(f"\n{'='*60}")
        print(f"Starting firmware upgrade process for {task.host}")
        print(f"Firmware file: {firmware_path}")
        print(f"{'='*60}")
        
        # Step 1: Validate firmware file
        validation = task.run(
            name="Validate firmware file",
            task=nr_validate_firmware_file,
            firmware_path=firmware_path
        )
        results.append(f"Firmware validation: {validation.result}")
        
        if validation.failed:
            return Result(host=task.host, failed=True, result={'steps': results})
        
        # Step 2: Check compatibility
        compatibility = task.run(
            name="Check PDU compatibility",
            task=nr_check_pdu_compatibility
        )
        results.append(f"Compatibility check: {compatibility.result}")
        
        if compatibility.failed:
            return Result(host=task.host, failed=True, result={'steps': results})
        
        # Display warnings
        warnings = compatibility.result.get('warnings', [])
        for warning in warnings:
            print(f"⚠️  {warning}")
        
        # Step 3: Backup current configuration
        if not check_only:
            backup = task.run(
                name="Backup configuration",
                task=nr_backup_config
            )
            results.append(f"Configuration backup: {backup.result}")
            
            if backup.failed:
                print("WARNING: Configuration backup failed, but continuing...")
        
        if check_only:
            return Result(
                host=task.host,
                result={
                    'check_only': True,
                    'ready_for_upgrade': True,
                    'steps': results
                }
            )
        
        # Step 4: Perform firmware upgrade
        print(f"\n🚀 Starting firmware upload for {task.host}...")
        upgrade = task.run(
            name="Firmware upgrade",
            task=nr_transfer_firmware,
            headers=headers,
            firmware_file_path=firmware_path
        )
        results.append(f"Firmware upgrade: {upgrade.result}")
        
        if upgrade.failed:
            return Result(host=task.host, failed=True, result={'steps': results})
        
        print(f"✅ Firmware upload successful for {task.host}")
        print("📱 PDU will now reboot automatically...")
        
        # Step 5: Post-upgrade verification
        verification = task.run(
            name="Post-upgrade verification",
            task=nr_post_upgrade_verification
        )
        results.append(f"Post-upgrade verification: {verification.result}")
        
        if verification.failed:
            print(f"⚠️  Post-upgrade verification failed for {task.host}")
        else:
            print(f"✅ {task.host} successfully upgraded and verified!")
        
        return Result(
            host=task.host,
            failed=verification.failed,
            result={
                'upgrade_completed': True,
                'verification_passed': not verification.failed,
                'steps': results
            }
        )
        
    except Exception as e:
        error_msg = f"Unexpected error in firmware upgrade process: {str(e)}"
        results.append(error_msg)
        return Result(
            host=task.host,
            failed=True,
            result={'error': error_msg, 'steps': results}
        )


def main():
    """Main execution function"""
    parser = argparse.ArgumentParser(description='Vertiv PDU Firmware Upgrade Tool')
    parser.add_argument('--firmware', '-f', required=True, 
                       help='Path to firmware file')
    parser.add_argument('--check-only', '-c', action='store_true',
                       help='Only perform pre-upgrade checks without upgrading')
    parser.add_argument('--target-host', '-t', 
                       help='Target specific host (use Netbox device name)')
    parser.add_argument('--config', default="config.yaml",
                       help='Nornir configuration file (default: config.yaml)')
    
    args = parser.parse_args()
    
    # Ensure required directories exist
    ensure_directories()
    
    # Validate firmware file
    if not os.path.exists(args.firmware):
        print(f"ERROR: Firmware file not found: {args.firmware}")
        sys.exit(1)
    
    # Initialize Nornir
    try:
        nr = InitNornir(
                            inventory={
                                "plugin": "NetBoxInventory2",
                                "options": {
                                    "nb_url": os.getenv("NETBOX_URL"),
                                    "nb_token": os.getenv("NETBOX_API_TOKEN"),
                                    "ssl_verify": os.getenv("NB_SSL_VERIFY", "true").lower() == 'true',
                                    "group_file": "../inventory/groups.yaml",
                                    "defaults_file": "../inventory/defaults.yaml"
                                }
                            })
    except Exception as e:
        print(f"ERROR: Failed to initialize Nornir: {e}")
        sys.exit(1)
    
    # Filter hosts if specific target provided
    if args.target_host:
        nr = nr.filter(F(name__contains=args.target_host))
        if len(nr.inventory.hosts) == 0:
            print(f"ERROR: No hosts found matching '{args.target_host}'")
            sys.exit(1)
    
    # Apply environment filter if set
    description_filter = os.getenv("NORNIR_FILTER_DESCRIPTION")
    if description_filter:
        nr = nr.filter(F(description__contains=description_filter))
    
    print(f"\nTarget PDUs ({len(nr.inventory.hosts)}):")
    for host in nr.inventory.hosts:
        print(f"  - {host}")
    
    if not args.check_only:
        print(f"\n⚠️  FIRMWARE UPGRADE MODE")
        print(f"Firmware file: {args.firmware}")
        response = input("\nDo you want to proceed with the firmware upgrade? (yes/no): ")
        if response.lower() != 'yes':
            print("Upgrade cancelled by user.")
            sys.exit(0)
    else:
        print(f"\n🔍 CHECK-ONLY MODE")
    
    # Run the firmware upgrade process
    results = nr.run(
        task=firmware_upgrade_with_checks,
        firmware_path=args.firmware,
        check_only=args.check_only
    )
    
    # Print results
    print(f"\n{'='*80}")
    print("FIRMWARE UPGRADE RESULTS")
    print(f"{'='*80}")
    
    print_result(results)
    
    # Summary
    failed_hosts = [host for host, result in results.items() if result.failed]
    successful_hosts = [host for host, result in results.items() if not result.failed]
    
    print(f"\n{'='*80}")
    print("SUMMARY")
    print(f"{'='*80}")
    print(f"✅ Successful: {len(successful_hosts)}")
    print(f"❌ Failed: {len(failed_hosts)}")
    
    if failed_hosts:
        print(f"\nFailed hosts:")
        for host in failed_hosts:
            print(f"  - {host}")
        sys.exit(1)
    else:
        print(f"\n🎉 All PDUs processed successfully!")


if __name__ == "__main__":
    main()