#!/usr/bin/env python3
"""
Simple rPDU Configuration Script

A streamlined version for basic rPDU configuration:
- Admin user creation
- Basic system configuration
- Network services setup
"""

import json
import os
import logging
from dotenv import load_dotenv
from nornir import InitNornir
from nornir.core.filter import F
from nornir.core.task import Task, Result
from nornir_utils.plugins.functions import print_result

from Vertiv import (
    nr_add_user_admin,
    nr_post_system,
    nr_post_contact,
    nr_post_syslog,
    nr_post_ntp,
    nr_post_dns,
    nr_disable_ipv6,
    nr_enable_modbus,
    create_vertiv_auth_headers
)

# Load environment variables
load_dotenv()

# Configuration
VERTIV_API_TOKEN = os.getenv("VERTIV_API_TOKEN")
VERTIV_USERNAME = os.getenv("VERTIV_USERNAME", "admin")
VERTIV_PASSWORD = os.getenv("VERTIV_PASSWORD")
DESCRIPTION_FILTER = os.getenv("NORNIR_FILTER_DESCRIPTION")
NETBOX_API_URL = os.getenv("NETBOX_API_URL")
NETBOX_URL = os.getenv("NETBOX_URL") 
NETBOX_TOKEN = os.getenv("NETBOX_API_TOKEN")
NB_SSL_VERIFY = os.getenv("NB_SSL_VERIFY", "true").lower() == 'true'
TIMEZONE = os.getenv("TIMEZONE", "Europe/Tallinn")


# Validate required environment variables
if not VERTIV_API_TOKEN:
    raise ValueError("VERTIV_API_TOKEN environment variable is required")
if not VERTIV_PASSWORD:
    raise ValueError("VERTIV_PASSWORD environment variable is required")

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Create headers for API requests
HEADERS = create_vertiv_auth_headers(VERTIV_API_TOKEN)


def rpdu_create_admin_user(task: Task) -> Result:
    """Create admin user on rPDU device."""
    logger.info(f"Creating admin user '{VERTIV_USERNAME}' on {task.host.name}")
    
    try:
        result = task.run(
            name="Create Admin User",
            task=nr_add_user_admin,
            #headers=HEADERS,
            username=VERTIV_USERNAME,
            password=VERTIV_PASSWORD
        )
        
        if not result.failed:
            logger.info(f"✅ Admin user created successfully on {task.host.name}")
            return Result(
                host=task.host,
                result=f"Admin user '{VERTIV_USERNAME}' created successfully"
            )
        else:
            logger.error(f"❌ Failed to create admin user on {task.host.name}")
            return Result(
                host=task.host,
                failed=True,
                result=f"Failed to create admin user: {result.result}"
            )
            
    except Exception as e:
        logger.error(f"Exception creating admin user on {task.host.name}: {e}")
        return Result(
            host=task.host,
            failed=True,
            result=f"Exception: {str(e)}"
        )


def rpdu_configure_basic_settings(task: Task) -> Result:
    """Configure basic system settings."""
    logger.info(f"Configuring basic settings for {task.host.name}")
    
    basic_tasks = [
        ("Configure System Settings", nr_post_system),
        ("Configure Contact Information", nr_post_contact),
    ]
    
    results = {}
    failed_count = 0
    
    for task_name, task_func in basic_tasks:
        try:
            logger.info(f"Executing: {task_name} for {task.host.name}")
            result = task.run(name=task_name, task=task_func, headers=HEADERS)
            
            if result.failed:
                results[task_name] = "FAILED"
                failed_count += 1
                logger.error(f"❌ {task_name} failed for {task.host.name}")
            else:
                results[task_name] = "SUCCESS"
                logger.info(f"✅ {task_name} completed for {task.host.name}")
                
        except Exception as e:
            results[task_name] = f"ERROR: {str(e)}"
            failed_count += 1
            logger.error(f"❌ Exception in {task_name} for {task.host.name}: {e}")
    
    return Result(
        host=task.host,
        result={
            'task_results': results,
            'success_count': len(basic_tasks) - failed_count,
            'failed_count': failed_count
        },
        failed=failed_count > 0
    )


def rpdu_configure_network_services(task: Task) -> Result:
    """Configure network services (NTP, DNS, Syslog)."""
    logger.info(f"Configuring network services for {task.host.name}")
    
    network_tasks = [
        ("Configure NTP Servers", nr_post_ntp),
        ("Configure DNS Servers", nr_post_dns),
        ("Configure Syslog Server", nr_post_syslog),
    ]
    
    results = {}
    failed_count = 0
    
    for task_name, task_func in network_tasks:
        try:
            logger.info(f"Executing: {task_name} for {task.host.name}")
            result = task.run(name=task_name, task=task_func, headers=HEADERS)
            
            if result.failed:
                results[task_name] = "FAILED"
                failed_count += 1
                logger.error(f"❌ {task_name} failed for {task.host.name}")
            else:
                results[task_name] = "SUCCESS"
                logger.info(f"✅ {task_name} completed for {task.host.name}")
                
        except Exception as e:
            results[task_name] = f"ERROR: {str(e)}"
            failed_count += 1
            logger.error(f"❌ Exception in {task_name} for {task.host.name}: {e}")
    
    return Result(
        host=task.host,
        result={
            'task_results': results,
            'success_count': len(network_tasks) - failed_count,
            'failed_count': failed_count
        },
        failed=failed_count > 0
    )


def rpdu_configure_security(task: Task) -> Result:
    """Configure security settings."""
    logger.info(f"Configuring security settings for {task.host.name}")
    
    security_tasks = [
        ("Disable IPv6", nr_disable_ipv6),
        ("Enable Modbus", nr_enable_modbus),
    ]
    
    results = {}
    failed_count = 0
    
    for task_name, task_func in security_tasks:
        try:
            logger.info(f"Executing: {task_name} for {task.host.name}")
            result = task.run(name=task_name, task=task_func, headers=HEADERS)
            
            if result.failed:
                results[task_name] = "FAILED"
                failed_count += 1
                logger.error(f"❌ {task_name} failed for {task.host.name}")
            else:
                results[task_name] = "SUCCESS"
                logger.info(f"✅ {task_name} completed for {task.host.name}")
                
        except Exception as e:
            results[task_name] = f"ERROR: {str(e)}"
            failed_count += 1
            logger.error(f"❌ Exception in {task_name} for {task.host.name}: {e}")
    
    return Result(
        host=task.host,
        result={
            'task_results': results,
            'success_count': len(security_tasks) - failed_count,
            'failed_count': failed_count
        },
        failed=failed_count > 0
    )


def rpdu_complete_configuration(task: Task) -> Result:
    """Complete rPDU configuration workflow."""
    logger.info(f"🚀 Starting configuration for {task.host.name}")
    
    # Configuration phases
    config_phases = [
        ("Admin User Creation", rpdu_create_admin_user),
        ("Basic Settings Configuration", rpdu_configure_basic_settings),
        ("Network Services Configuration", rpdu_configure_network_services),
        ("Security Configuration", rpdu_configure_security),
    ]
    
    phase_results = {}
    total_failed = 0
    critical_failure = False
    
    for phase_name, phase_func in config_phases:
        try:
            logger.info(f"📋 {task.host.name}: Starting {phase_name}")
            
            phase_result = task.run(name=phase_name, task=phase_func)
            
            if phase_result.failed:
                phase_results[phase_name] = "FAILED"
                total_failed += 1
                
                # Admin user creation is critical
                if phase_name == "Admin User Creation":
                    critical_failure = True
                    logger.error(f"💥 Critical failure: {phase_name} failed for {task.host.name}")
                    break
                else:
                    logger.warning(f"⚠️ {phase_name} failed for {task.host.name}")
            else:
                phase_results[phase_name] = "SUCCESS"
                logger.info(f"✅ {phase_name} completed successfully for {task.host.name}")
                
        except Exception as e:
            phase_results[phase_name] = f"ERROR: {str(e)}"
            total_failed += 1
            logger.error(f"💥 Exception in {phase_name} for {task.host.name}: {e}")
            
            if phase_name == "Admin User Creation":
                critical_failure = True
                break
    
    # Generate summary
    total_phases = len([p for p in phase_results])
    success_phases = len([r for r in phase_results.values() if r == "SUCCESS"])
    
    if critical_failure:
        overall_status = "CRITICAL_FAILURE"
    elif total_failed == 0:
        overall_status = "SUCCESS"
    else:
        overall_status = "PARTIAL_SUCCESS"
    
    summary = {
        'host': task.host.name,
        'overall_status': overall_status,
        'total_phases': total_phases,
        'successful_phases': success_phases,
        'failed_phases': total_failed,
        'success_rate': (success_phases / total_phases * 100) if total_phases > 0 else 0,
        'phase_results': phase_results
    }
    
    # Log final status
    if overall_status == "SUCCESS":
        logger.info(f"🎉 {task.host.name}: Configuration completed successfully!")
    elif overall_status == "PARTIAL_SUCCESS":
        logger.warning(f"⚠️ {task.host.name}: Partial success ({success_phases}/{total_phases} phases)")
    else:
        logger.error(f"💥 {task.host.name}: Configuration failed critically")
    
    return Result(
        host=task.host,
        result=summary,
        failed=critical_failure
    )


def main():
    """Main execution function."""
    try:
        print("🚀 rPDU Configuration Script Starting...")
        
        # Initialize Nornir
        logger.info(f"Initializing Nornir to load inventory from NetBox at {NETBOX_URL}")
        nr = InitNornir(
                        inventory={
                            "plugin": "NetBoxInventory2",
                            "options": {
                                "nb_url": NETBOX_URL,
                                "nb_token": NETBOX_TOKEN,
                                "ssl_verify": NB_SSL_VERIFY,
                                "group_file": "../inventory/groups.yaml",
                                "defaults_file": "../inventory/defaults.yaml"
                            }
                        })
        
        # Apply filter if specified
        if DESCRIPTION_FILTER:
            logger.info(f"Applying filter: description contains '{DESCRIPTION_FILTER}'")
            nr = nr.filter(F(description__contains=DESCRIPTION_FILTER))
        
        # Check hosts
        if not nr.inventory.hosts:
            logger.warning("No hosts found matching criteria")
            return
        
        print(f"📊 Found {len(nr.inventory.hosts)} hosts to configure:")
        for hostname in nr.inventory.hosts:
            print(f"  📌 {hostname}")
        
        print("\n" + "="*60)
        print("🔧 STARTING rPDU CONFIGURATION")
        print("="*60)
        
        # Run configuration
        results = nr.run(
            name="rPDU Complete Configuration",
            task=rpdu_complete_configuration
        )
        
        # Print results
        print("\n" + "="*60)
        print("📋 CONFIGURATION RESULTS")
        print("="*60)
        print_result(results)
        
        # Summary report
        total_hosts = len(nr.inventory.hosts)
        successful = len([r for r in results if not results[r].failed])
        failed = total_hosts - successful
        
        print("\n" + "="*60)
        print("📊 FINAL SUMMARY")
        print("="*60)
        print(f"Total Hosts: {total_hosts}")
        print(f"Successful: {successful}")
        print(f"Failed: {failed}")
        print(f"Success Rate: {(successful/total_hosts*100):.1f}%" if total_hosts > 0 else "0%")
        
        if failed > 0:
            print(f"\n❌ Failed hosts:")
            for hostname, result in results.items():
                if result.failed:
                    print(f"  - {hostname}: {result.result.get('overall_status', 'FAILED')}")
        
        if successful == total_hosts:
            print("\n🎉 All configurations completed successfully!")
        elif successful > 0:
            print("\n⚠️ Some configurations completed with issues")
        else:
            print("\n💥 All configurations failed")
            
    except KeyboardInterrupt:
        logger.warning("Script interrupted by user")
    except Exception as e:
        logger.error(f"Script execution failed: {e}")
        raise


if __name__ == "__main__":
    main()