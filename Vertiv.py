"""
Vertiv PDU API Module - Complete improved version with robust networking and error handling.

This module provides functions to interact with Vertiv PDU devices through their REST API,
including configuration, monitoring, and management operations.
"""

import json
import logging
import os
import re
import time
from typing import Dict, Any, Optional, Tuple, Union, List
from urllib.parse import urljoin, urlparse

import httpx
import pandas as pd
import requests
from dotenv import load_dotenv
from nornir.core.exceptions import NornirExecutionError
from nornir.core.task import Task, Result
from requests.auth import HTTPBasicAuth
from requests.exceptions import RequestException, Timeout, ConnectionError, HTTPError
from httpx import HTTPError as HttpxHTTPError, TimeoutException, ConnectError

# Load environment variables
load_dotenv()

# Environment variables
VERTIV_USERNAME = os.getenv("VERTIV_USERNAME", "admin")
VERTIV_PASSWORD = os.getenv("VERTIV_PASSWORD")
VERTIV_API_KEY = os.getenv("VERTIV_API_KEY")
DC1_SERVER = os.getenv("DC1_SERVER")
DC2_SERVER = os.getenv("DC2_SERVER")
SYSLOG_SERVER = os.getenv("SYSLOG_SERVER")

# Configuration constants
DEFAULT_TIMEOUT = 30
MAX_RETRIES = 3
RETRY_DELAY = 1  # seconds
DEFAULT_VERIFY_SSL = False
DEFAULT_PORT_HTTP = 80
DEFAULT_PORT_HTTPS = 443

# Set up logger
logger = logging.getLogger(__name__)


class VertivAPIError(Exception):
    """Custom exception for Vertiv API errors."""
    
    def __init__(self, message: str, status_code: Optional[int] = None, 
                 response_text: Optional[str] = None, host: Optional[str] = None):
        super().__init__(message)
        self.status_code = status_code
        self.response_text = response_text
        self.host = host


class VertivDevice:
    """Represents a Vertiv device with connection management."""
    
    def __init__(self, host: str, api_key: str, use_https: bool = False, 
                 timeout: int = DEFAULT_TIMEOUT):
        self.host = host
        self.api_key = api_key
        self.use_https = use_https
        self.timeout = timeout
        self.protocol = "https" if use_https else "http"
        self.base_url = f"{self.protocol}://{host}"
        
        # Connection state
        self._session = None
        self._last_response_time = None
        
    def get_headers(self, additional_headers: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        """Get standardized headers for API requests."""
        headers = {
            'Authorization': f'Basic {self.api_key}',
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'User-Agent': 'VertivAPI/2.0'
        }
        
        if additional_headers:
            headers.update(additional_headers)
            
        return headers
    
    def build_url(self, endpoint: str) -> str:
        """Build complete URL for API endpoint."""
        if not endpoint.startswith('/'):
            endpoint = f'/{endpoint}'
        return urljoin(self.base_url, endpoint)


def _validate_url(url: str) -> str:
    """Validate and normalize URL."""
    if not url or not isinstance(url, str):
        raise ValueError("URL must be a non-empty string")
    
    if not url.startswith(('http://', 'https://')):
        url = f"http://{url}"
    
    parsed = urlparse(url)
    if not parsed.netloc:
        raise ValueError(f"Invalid URL format: {url}")
    
    return url


def _validate_headers(headers: Optional[Dict[str, str]]) -> Dict[str, str]:
    """Validate and normalize headers."""
    if headers is None:
        headers = {}
    
    if not isinstance(headers, dict):
        raise ValueError("Headers must be a dictionary")
    
    default_headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'User-Agent': 'VertivAPI/2.0'
    }
    
    return {**default_headers, **headers}


def _validate_json_response(response_text: str, url: str) -> Dict[str, Any]:
    """Validate and parse JSON response."""
    if not response_text.strip():
        logger.warning(f"Empty response from {url}")
        return {}
    
    try:
        return json.loads(response_text)
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON response from {url}: {e}")
        logger.debug(f"Response text: {response_text[:500]}...")
        raise VertivAPIError(f"Invalid JSON response from {url}: {str(e)}", response_text=response_text)


def _check_vertiv_api_error(data: Dict[str, Any], url: str) -> None:
    """Check for Vertiv API specific errors in response."""
    if not isinstance(data, dict):
        return
    
    # Check for common Vertiv API error patterns
    error_indicators = [
        ('error', lambda x: x != 0 and x is not None),
        ('status', lambda x: x not in ['ok', 'success', 0, '0']),
        ('result', lambda x: x in ['error', 'failed']),
    ]
    
    for field, check_func in error_indicators:
        if field in data and check_func(data[field]):
            error_msg = data.get('message', data.get('description', f"API returned {field}: {data[field]}"))
            raise VertivAPIError(f"Vertiv API error from {url}: {error_msg}", response_text=str(data))


def _retry_request(func, *args, **kwargs) -> Any:
    """Retry mechanism for network requests with exponential backoff."""
    last_exception = None
    
    for attempt in range(MAX_RETRIES):
        try:
            return func(*args, **kwargs)
        except (ConnectionError, ConnectError, Timeout, TimeoutException) as e:
            last_exception = e
            if attempt < MAX_RETRIES - 1:
                wait_time = RETRY_DELAY * (2 ** attempt)
                logger.warning(f"Request failed (attempt {attempt + 1}/{MAX_RETRIES}), "
                             f"retrying in {wait_time}s: {str(e)}")
                time.sleep(wait_time)
            else:
                logger.error(f"All retry attempts failed: {str(e)}")
        except Exception as e:
            logger.error(f"Non-retryable error: {str(e)}")
            raise
    
    raise last_exception


def geturl(url: str, headers: Optional[Dict[str, str]] = None, 
          timeout: int = DEFAULT_TIMEOUT, verify: bool = DEFAULT_VERIFY_SSL) -> Dict[str, Any]:
    """
    Make a GET request using httpx with robust error handling and retries.
    
    Args:
        url: Target URL
        headers: HTTP headers (optional)
        timeout: Request timeout in seconds
        verify: SSL certificate verification
        
    Returns:
        JSON response as dictionary
        
    Raises:
        VertivAPIError: For API-related errors
    """
    url = _validate_url(url)
    headers = _validate_headers(headers)
    
    logger.debug(f"Making GET request to: {url}")
    
    def _make_request():
        with httpx.Client(verify=verify, timeout=timeout) as client:
            response = client.get(url, headers=headers)
            response.raise_for_status()
            return response
    
    try:
        response = _retry_request(_make_request)
        logger.info(f"GET request successful: {url} (Status: {response.status_code})")
        
        data = _validate_json_response(response.text, url)
        _check_vertiv_api_error(data, url)
        
        return data
        
    except HttpxHTTPError as e:
        logger.error(f"HTTP error for GET {url}: {e}")
        raise VertivAPIError(f"HTTP error for GET {url}: {str(e)}", 
                           status_code=getattr(e.response, 'status_code', None),
                           response_text=getattr(e.response, 'text', None))
    except Exception as e:
        logger.error(f"GET request failed for {url}: {e}")
        raise VertivAPIError(f"GET request failed for {url}: {str(e)}")


def post_url(url: str, headers: Optional[Dict[str, str]] = None, 
            payload: Optional[Dict[str, Any]] = None,
            timeout: int = DEFAULT_TIMEOUT, verify: bool = DEFAULT_VERIFY_SSL) -> Dict[str, Any]:
    """
    Make a POST request using requests library with robust error handling and retries.
    
    Args:
        url: Target URL
        headers: HTTP headers (optional)
        payload: JSON payload for POST request (optional)
        timeout: Request timeout in seconds
        verify: SSL certificate verification
        
    Returns:
        JSON response as dictionary
        
    Raises:
        VertivAPIError: For API-related errors
    """
    url = _validate_url(url)
    headers = _validate_headers(headers)
    
    if payload is None:
        payload = {}
    
    logger.debug(f"Making POST request to: {url}")
    
    def _make_request():
        response = requests.post(url, headers=headers, json=payload, 
                               timeout=timeout, verify=verify)
        response.raise_for_status()
        return response
    
    try:
        response = _retry_request(_make_request)
        logger.info(f"POST request successful: {url} (Status: {response.status_code})")
        
        data = _validate_json_response(response.text, url)
        _check_vertiv_api_error(data, url)
        
        return data
        
    except HTTPError as e:
        logger.error(f"HTTP error for POST {url}: {e}")
        raise VertivAPIError(f"HTTP error for POST {url}: {str(e)}", 
                           status_code=e.response.status_code if e.response else None,
                           response_text=e.response.text if e.response else None)
    except RequestException as e:
        logger.error(f"Request error for POST {url}: {e}")
        raise VertivAPIError(f"Request error for POST {url}: {str(e)}")


def posturl(url: str, headers: Optional[Dict[str, str]] = None, 
           payload: Optional[Dict[str, Any]] = None,
           timeout: int = DEFAULT_TIMEOUT, verify: bool = DEFAULT_VERIFY_SSL) -> Dict[str, Any]:
    """
    Make a POST request using httpx with robust error handling and retries.
    
    Args:
        url: Target URL
        headers: HTTP headers (optional)
        payload: JSON payload for POST request (optional)
        timeout: Request timeout in seconds
        verify: SSL certificate verification
        
    Returns:
        JSON response as dictionary
        
    Raises:
        VertivAPIError: For API-related errors
    """
    url = _validate_url(url)
    headers = _validate_headers(headers)
    
    if payload is None:
        payload = {}
    
    logger.debug(f"Making POST request (httpx) to: {url}")
    
    def _make_request():
        with httpx.Client(verify=verify, timeout=timeout) as client:
            response = client.post(url, headers=headers, json=payload)
            response.raise_for_status()
            return response
    
    try:
        response = _retry_request(_make_request)
        logger.info(f"POST request (httpx) successful: {url} (Status: {response.status_code})")
        
        data = _validate_json_response(response.text, url)
        _check_vertiv_api_error(data, url)
        
        return data
        
    except HttpxHTTPError as e:
        logger.error(f"HTTP error for POST {url}: {e}")
        raise VertivAPIError(f"HTTP error for POST {url}: {str(e)}", 
                           status_code=getattr(e.response, 'status_code', None),
                           response_text=getattr(e.response, 'text', None))


def nr_get_url(task: Task, cmd: str, headers: Optional[Dict[str, str]] = None,
               use_https: bool = False, timeout: int = DEFAULT_TIMEOUT) -> Result:
    """
    Make a GET request to device URL using Nornir task context.
    
    Args:
        task: Nornir task object
        cmd: Command/path to append to base URL
        headers: HTTP headers (optional)
        use_https: Whether to use HTTPS
        timeout: Request timeout in seconds
        
    Returns:
        Nornir Result object
    """
    try:
        if not cmd.startswith('/'):
            cmd = f'/{cmd}'
        
        protocol = 'https' if use_https else 'http'
        url = f"{protocol}://{task.host.name}{cmd}"
        
        logger.info(f"Making GET request for {task.host.name} to: {cmd}")
        
        response_data = geturl(url, headers=headers, timeout=timeout)
        
        # Store response for potential later use
        if not hasattr(task.host, 'data'):
            task.host.data = {}
        task.host.data['last_get_response'] = response_data
        
        return Result(
            host=task.host,
            result={
                'url': url,
                'method': 'GET',
                'status': 'success',
                'data': response_data
            }
        )
        
    except VertivAPIError as e:
        logger.error(f"Vertiv API error for {task.host.name}: {e}")
        return Result(
            host=task.host,
            failed=True,
            result={
                'url': url if 'url' in locals() else 'unknown',
                'method': 'GET',
                'status': 'api_error',
                'error': str(e),
                'status_code': e.status_code,
                'response_text': e.response_text
            }
        )
    except Exception as e:
        logger.error(f"Unexpected error for GET request to {task.host.name}: {e}")
        return Result(
            host=task.host,
            failed=True,
            result={
                'url': url if 'url' in locals() else 'unknown',
                'method': 'GET',
                'status': 'error',
                'error': str(e)
            }
        )


def nr_post_url(task: Task, cmd: str, headers: Optional[Dict[str, str]] = None,
                payload: Optional[Dict[str, Any]] = None, use_https: bool = True,
                timeout: int = DEFAULT_TIMEOUT) -> Result:
    """
    Make a POST request to device URL using Nornir task context.
    
    Args:
        task: Nornir task object
        cmd: Command/path to append to base URL
        headers: HTTP headers (optional)
        payload: JSON payload for POST request (optional)
        use_https: Whether to use HTTPS
        timeout: Request timeout in seconds
        
    Returns:
        Nornir Result object
    """
    try:
        if not cmd.startswith('/'):
            cmd = f'/{cmd}'
        
        protocol = 'https' if use_https else 'http'
        url = f"{protocol}://{task.host.hostname}{cmd}"
        
        if payload is None:
            payload = {'token': '', 'cmd': 'get', 'data': {}}
        
        logger.info(f"Making POST request for {task.host.name} to: {cmd}")
        
        response_data = post_url(url, headers=headers, payload=payload, timeout=timeout)
        
        # Store response for potential later use
        if not hasattr(task.host, 'data'):
            task.host.data = {}
        task.host.data['last_post_response'] = response_data
        
        return Result(
            host=task.host,
            result={
                'url': url,
                'method': 'POST',
                'status': 'success',
                'data': response_data,
                'payload_sent': payload
            }
        )
        
    except VertivAPIError as e:
        logger.error(f"Vertiv API error for {task.host.name}: {e}")
        return Result(
            host=task.host,
            failed=True,
            result={
                'url': url if 'url' in locals() else 'unknown',
                'method': 'POST',
                'status': 'api_error',
                'error': str(e),
                'status_code': e.status_code,
                'response_text': e.response_text,
                'payload_sent': payload
            }
        )


def create_vertiv_auth_headers(api_token: str, additional_headers: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """Create standardized headers for Vertiv API requests."""
    headers = {
        'Authorization': f'Basic {api_token}',
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'User-Agent': 'VertivAPI/2.0'
    }
    
    if additional_headers:
        headers.update(additional_headers)
    
    return headers


def test_connectivity(host: str, timeout: int = 10) -> Tuple[bool, str, Optional[str]]:
    """
    Test basic connectivity to a Vertiv device.
    
    Returns:
        Tuple of (success, message, working_protocol)
    """
    try:
        for protocol in ['https', 'http']:
            try:
                url = f"{protocol}://{host}/api/sys/version"
                response = requests.get(url, timeout=timeout, verify=False)
                if response.status_code in [200, 401, 403]:
                    return True, f"Device responding on {protocol.upper()}", protocol
            except Exception:
                continue
        
        return False, "Device not responding on HTTP or HTTPS", None
        
    except Exception as e:
        return False, f"Connectivity test failed: {str(e)}", None


# Nornir Task Functions for Device Configuration

def nr_get_macAddr(task: Task, headers: Dict[str, str]) -> Result:
    """Get MAC address from device."""
    endpoint = "/api/conf/network/ethernet/macAddr"
    payload = {'token': '', 'cmd': 'get', 'data': {}}
    
    try:
        logger.info(f"Getting MAC address for {task.host.name}")
        result = nr_post_url(task, endpoint, headers=headers, payload=payload, use_https=True)
        
        if not result.failed and 'data' in result.result:
            mac_addr = result.result['data'].get('data', '')
            task.host['macAddress'] = mac_addr
            logger.info(f"MAC address for {task.host.name}: {mac_addr}")
            
        return result
        
    except Exception as e:
        logger.error(f"Failed to get MAC address for {task.host.name}: {e}")
        return Result(host=task.host, failed=True, result=f"MAC address retrieval failed: {str(e)}")


def nr_get_model(task: Task, headers: Dict[str, str]) -> Result:
    """Get model number from device."""
    endpoint = "/api/sys/modelNumber"
    payload = {'token': '', 'cmd': 'get', 'data': {}}
    
    try:
        logger.info(f"Getting model number for {task.host.name}")
        result = nr_post_url(task, endpoint, headers=headers, payload=payload, use_https=True)
        
        if not result.failed and 'data' in result.result:
            model = result.result['data'].get('data', '')
            task.host['model'] = model
            logger.info(f"Model for {task.host.name}: {model}")
            
        return result
        
    except Exception as e:
        logger.error(f"Failed to get model for {task.host.name}: {e}")
        return Result(host=task.host, failed=True, result=f"Model retrieval failed: {str(e)}")


def nr_get_serial(task: Task, headers: Dict[str, str]) -> Result:
    """Get serial number from device."""
    endpoint = "/api/sys/serialNumber"
    payload = {'token': '', 'cmd': 'get', 'data': {}}
    
    try:
        logger.info(f"Getting serial number for {task.host.name}")
        result = nr_post_url(task, endpoint, headers=headers, payload=payload, use_https=True)
        
        if not result.failed and 'data' in result.result:
            serial = result.result['data'].get('data', '')
            task.host['serial'] = serial
            logger.info(f"Serial number for {task.host.name}: {serial}")
            
        return result
        
    except Exception as e:
        logger.error(f"Failed to get serial number for {task.host.name}: {e}")
        return Result(host=task.host, failed=True, result=f"Serial number retrieval failed: {str(e)}")


def nr_get_hostname(task: Task, headers: Dict[str, str]) -> Result:
    """Get hostname from device."""
    endpoint = "/api/conf/system/hostname"
    payload = {'token': '', 'cmd': 'get', 'data': {}}
    
    try:
        logger.info(f"Getting hostname for {task.host.name}")
        result = nr_post_url(task, endpoint, headers=headers, payload=payload, use_https=True)
        
        if not result.failed and 'data' in result.result:
            hostname = result.result['data'].get('data', '')
            task.host['hostname'] = hostname
            logger.info(f"Hostname for {task.host.name}: {hostname}")
            
        return result
        
    except Exception as e:
        logger.error(f"Failed to get hostname for {task.host.name}: {e}")
        return Result(host=task.host, failed=True, result=f"Hostname retrieval failed: {str(e)}")


def nr_get_dev_id(task: Task, headers: Dict[str, str]) -> Result:
    """Get device ID from the device."""
    endpoint = "/api/dev"
    payload = {'token': '', 'cmd': 'get', 'data': {}}
    
    # Use API key for authentication
    auth_headers = create_vertiv_auth_headers(VERTIV_API_KEY or '', headers)
    
    try:
        logger.info(f"Getting device ID for {task.host.name}")
        result = nr_post_url(task, endpoint, headers=auth_headers, payload=payload, use_https=True)
        
        if not result.failed and 'data' in result.result:
            dev_data = result.result['data'].get('data', {})
            if dev_data:
                dev_id = list(dev_data.keys())[0]
                task.host['devID'] = dev_id
                logger.info(f"Device ID for {task.host.name}: {dev_id}")
            
        return result
        
    except Exception as e:
        logger.error(f"Failed to get device ID for {task.host.name}: {e}")
        return Result(host=task.host, failed=True, result=f"Device ID retrieval failed: {str(e)}")


def nr_post_system(task: Task, headers: Dict[str, str]) -> Result:
    """Configure system settings (hostname and label)."""
    endpoint = "/api/conf/system"
    
    try:
        logger.info(f"Configuring system settings for {task.host.name}")
        
        # Clean hostname - remove 'C' and leading zeros
        description = task.host.get('description', '')
        hostname = re.sub(r"C", "", description)
        hostname = re.sub(r'(?<!\d)0+(?=\d)', '', hostname)
        
        label = task.host.get('custom_fields', {}).get('label', '')
        if not label:
            label = task.host['tenant']['description']
        
        payload = {
            'token': '',
            'cmd': 'set',
            'data': {
                'label': label,
                'hostname': hostname
            }
        }
        
        result = nr_post_url(task, endpoint, headers=headers, payload=payload, use_https=False)
        
        if not result.failed:
            logger.info(f"System configuration successful for {task.host.name}")
        
        return result
        
    except Exception as e:
        logger.error(f"Failed to configure system for {task.host.name}: {e}")
        return Result(host=task.host, failed=True, result=f"System configuration failed: {str(e)}")


def nr_post_contact(task: Task, headers: Dict[str, str]) -> Result:
    """Configure contact information (location and description)."""
    endpoint = "/api/conf/contact"
    
    try:
        logger.info(f"Configuring contact information for {task.host.name}")
        
        location = task.host.get('rack', {}).get('description', '')
        description = task.host.get('custom_fields', {}).get('label', '')
        
        if not location:
            location = task.host['rack'],
        if not description:
            description = task.host['description']
        payload = {
            'token': '',
            'cmd': 'set',
            'data': {
                'location': location,
                'description': description
            }
        }
        
        result = nr_post_url(task, endpoint, headers=headers, payload=payload, use_https=False)
        
        if not result.failed:
            logger.info(f"Contact configuration successful for {task.host.name}")
        
        return result
        
    except Exception as e:
        logger.error(f"Failed to configure contact for {task.host.name}: {e}")
        return Result(host=task.host, failed=True, result=f"Contact configuration failed: {str(e)}")


def nr_post_syslog(task: Task, headers: Dict[str, str]) -> Result:
    """Configure syslog server settings."""
    endpoint = "/api/conf/syslog"
    
    try:
        logger.info(f"Configuring syslog server for {task.host.name}")
    
        
        payload = {
            'token': '',
            'cmd': 'set',
            'data': {
                'enabled': True,
                'target': task.host.get('syslogServer', SYSLOG_SERVER),
                'port': 514
            }
        }
        
        result = nr_post_url(task, endpoint, headers=headers, payload=payload, use_https=False)
        
        if not result.failed:
            logger.info(f"Syslog configuration successful for {task.host.name}")
        
        return result
        
    except Exception as e:
        logger.error(f"Failed to configure syslog for {task.host.name}: {e}")
        return Result(host=task.host, failed=True, result=f"Syslog configuration failed: {str(e)}")


def nr_post_ntp(task: Task, headers: Dict[str, str]) -> Result:
    """Configure NTP server settings."""
    endpoint = "/api/conf/time"
 
    try:
        logger.info(f"Configuring NTP servers for {task.host.name}")
        
        payload = {
            'ntpServer1': task.host.get('ntpServer1', DC1_SERVER),
            'ntpServer2': task.host.get('ntpServer2', DC2_SERVER),
            'zone': task.host.get('timezone', 'Europe/Tallinn'),
            'mode': 'ntp'
        }
        
        result = nr_post_url(task, endpoint, headers=headers, payload=payload, use_https=False)
        
        if not result.failed:
            logger.info(f"NTP configuration successful for {task.host.name}")
        
        return result
        
    except Exception as e:
        logger.error(f"Failed to configure NTP for {task.host.name}: {e}")
        return Result(host=task.host, failed=True, result=f"NTP configuration failed: {str(e)}")


def nr_post_dns(task: Task, headers: Dict[str, str]) -> Result:
    """Configure DNS server settings."""
    endpoint = "/api/conf/network/ethernet/dns"
    
    try:
        logger.info(f"Configuring DNS servers for {task.host.name}")
        
        payload = {
            '0': {
                'address': task.host.get('dnsServer1', DC1_SERVER),
            },
            '1': {
                'address': task.host.get('dnsServer2', DC2_SERVER),
            }
        }
        
        result = nr_post_url(task, endpoint, headers=headers, payload=payload, use_https=False)
        
        if not result.failed:
            logger.info(f"DNS configuration successful for {task.host.name}")
        
        return result
        
    except Exception as e:
        logger.error(f"Failed to configure DNS for {task.host.name}: {e}")
        return Result(host=task.host, failed=True, result=f"DNS configuration failed: {str(e)}")


def nr_disable_ipv6(task: Task, headers: Dict[str, str]) -> Result:
    """Disable IPv6 support on the device."""
    endpoint = "/api/conf/system"
    
    try:
        logger.info(f"Disabling IPv6 support for {task.host.name}")
        
        payload = {'ip6Enabled': False}
        
        result = nr_post_url(task, endpoint, headers=headers, payload=payload, use_https=False)
        
        if not result.failed:
            logger.info(f"IPv6 disable successful for {task.host.name}")
        
        return result
        
    except Exception as e:
        logger.error(f"Failed to disable IPv6 for {task.host.name}: {e}")
        return Result(host=task.host, failed=True, result=f"IPv6 disable failed: {str(e)}")


def nr_enable_modbus(task: Task, headers: Dict[str, str]) -> Result:
    """Enable Modbus on the device."""
    endpoint = "/api/conf/modbus"
    
    try:
        logger.info(f"Enabling Modbus for {task.host.name}")
        
        payload = {
            'tcp': {'enabled': True},
            'access': "readOnly"
        }
        
        result = nr_post_url(task, endpoint, headers=headers, payload=payload, use_https=False)
        
        if not result.failed:
            logger.info(f"Modbus enable successful for {task.host.name}")
        
        return result
        
    except Exception as e:
        logger.error(f"Failed to enable Modbus for {task.host.name}: {e}")
        return Result(host=task.host, failed=True, result=f"Modbus enable failed: {str(e)}")


def nr_add_user_admin(task: Task, username: str, password: str) -> Result:
    """Add an admin user to a Vertiv PDU using the REST API."""
    endpoint = "/api/auth/"
    
    try:
        logger.info(f"Creating admin user '{username}' on {task.host.name}")
        
        payload = {
            'token': '',
            'cmd': 'add',
            'data': {
                'username': username,
                'password': password,
                'language': 'en',
                'enabled': True,
                'control': True,
                'admin': True,
            }
        }
        
        result = nr_post_url(task, endpoint, payload=payload, use_https=False)
        
        if not result.failed:
            logger.info(f"User '{username}' created successfully on {task.host.name}")
        
        return result
        
    except Exception as e:
        logger.error(f"Failed to create user '{username}' on {task.host.name}: {e}")
        return Result(host=task.host, failed=True, result=f"User creation failed: {str(e)}")

def nr_transfer_firmware(task: Task, headers: Dict[str, str], firmware_file_path: str, session_token: str = '') -> Result:
    """
    Upgrades the firmware of a Vertiv PDU using the REST API.
    
    This function uploads a firmware file to the PDU. The file is signed and verified 
    before deployment. Upon successful upload, the unit will automatically reboot 
    with the new firmware version.
    
    Args:
        task (Task): Nornir task object containing the host.
        headers (Dict[str, str]): Base headers for authentication (should contain Authorization).
        firmware_file_path (str): Path to the firmware file to upload.
        session_token (str): Session token for authentication (optional, can be empty string).
    
    Returns:
        Result: Nornir Result object with host and operation output.
        
    Note:
        - Firmware files must match the platform and OEM currently running
        - Downgrading past certain versions is not supported
        - Systems running 5.9.0 or later may not be downgraded
        - User must have administrator privileges
    """
    
    # Construct the URL with token as query parameter (as required by API spec)
    base_url = f"http://{task.host.hostname}/transfer/firmware"
    if session_token:
        url = f"{base_url}?token={session_token}"
    else:
        url = base_url
    
    logger.debug(f"Uploading firmware to {url} for host {task.host}")
    
    # Validate firmware file exists
    if not os.path.exists(firmware_file_path):
        error_msg = f"Firmware file not found: {firmware_file_path}"
        logger.error(error_msg)
        return Result(
            host=task.host,
            failed=True,
            result=error_msg
        )
    
    try:
        # Open and prepare the firmware file for upload
        with open(firmware_file_path, 'rb') as firmware_file:
            # Prepare the multipart/form-data payload
            # The API expects a single component called "file"
            files = {
                'file': (
                    os.path.basename(firmware_file_path),  # filename (ignored by API)
                    firmware_file,                         # file content
                    'application/octet-stream'             # content type
                )
            }
            
            # Prepare headers - DO NOT set Content-Type manually for multipart uploads
            # requests library will set it automatically with proper boundary
            upload_headers = {}
            if 'Authorization' in headers:
                upload_headers['Authorization'] = headers['Authorization']
            
            logger.debug(f"Sending firmware upload request to {url}")
            
            # Make the POST request with file upload
            # Note: Using requests instead of httpx for better multipart handling
            response = requests.post(
                url, 
                headers=upload_headers,
                files=files,
                verify=False,  # Disable SSL verification as per existing code pattern
                timeout=180    # Extended timeout for firmware upload
            )
            
            # Check if request was successful
            response.raise_for_status()
            
            # Parse JSON response
            response_data = response.json()
            
            # Check API return code (Vertiv API uses retCode: 0 for success)
            ret_code = response_data.get('retCode', -1)
            ret_msg = response_data.get('retMsg', 'Unknown error')
            
            if ret_code == 0:
                success_msg = f"Firmware upload successful for {task.host}. Device will reboot with new firmware."
                logger.info(success_msg)
                return Result(
                    host=task.host,
                    result={
                        'status': 'success',
                        'message': success_msg,
                        'response': response_data,
                        'firmware_file': firmware_file_path,
                        'ret_code': ret_code,
                        'ret_msg': ret_msg
                    }
                )
            else:
                error_msg = f"Firmware upload failed with return code {ret_code}: {ret_msg}"
                logger.error(f"Firmware upload failed for {task.host}: {error_msg}")
                return Result(
                    host=task.host,
                    failed=True,
                    result={
                        'status': 'failed',
                        'ret_code': ret_code,
                        'message': error_msg,
                        'response': response_data
                    }
                )
                
    except requests.exceptions.Timeout:
        error_msg = f"Firmware upload timed out for {task.host}"
        logger.error(error_msg)
        return Result(
            host=task.host,
            failed=True,
            result=f"Upload timeout: {error_msg}"
        )
        
    except requests.exceptions.RequestException as e:
        error_msg = f"HTTP request failed for {task.host}: {str(e)}"
        logger.error(error_msg)
        return Result(
            host=task.host,
            failed=True,
            result=f"Request failed: {error_msg}"
        )
        
    except FileNotFoundError:
        error_msg = f"Firmware file not found: {firmware_file_path}"
        logger.error(error_msg)
        return Result(
            host=task.host,
            failed=True,
            result=f"File not found: {error_msg}"
        )
        
    except json.JSONDecodeError as e:
        error_msg = f"Invalid JSON response from {task.host}: {str(e)}"
        logger.error(error_msg)
        return Result(
            host=task.host,
            failed=True,
            result=f"JSON decode error: {error_msg}"
        )
        
    except Exception as e:
        error_msg = f"Unexpected error during firmware upload to {task.host}: {str(e)}"
        logger.error(error_msg)
        return Result(
            host=task.host,
            failed=True,
            result=f"Unexpected error: {error_msg}"
        )


def nr_get_firmware_version(task: Task, headers: Dict[str, str]) -> Result:
    """
    Gets the current firmware version of the Vertiv PDU.
    
    Args:
        task (Task): Nornir task object containing the host.
        headers (Dict[str, str]): Headers required for the HTTP POST (with authentication).
    
    Returns:
        Result: Nornir Result object with firmware version information.
    """
    url = f"http://{task.host.hostname}/api/sys/version/"
    
    payload = {
        'token': '',
        'cmd': 'get',
        'data': {}
    }
    
    try:
        response = post_url(url, headers, payload)
        logger.info(f"Firmware version retrieved for {task.host}: {response}")
        return Result(
            host=task.host,
            result={
                'firmware_version': response,
                'host': str(task.host)
            }
        )
    except Exception as e:
        logger.error(f"Failed to get firmware version from {task.host}: {e}")
        return Result(
            host=task.host,
            failed=True,
            result=f"Failed to get firmware version: {str(e)}"
        )


# Example usage function for firmware upgrade workflow
def nr_firmware_upgrade_workflow(task: Task, headers: Dict[str, str], firmware_file_path: str) -> Result:
    """
    Complete firmware upgrade workflow that includes version checking and upgrade.
    
    Args:
        task (Task): Nornir task object containing the host.
        headers (Dict[str, str]): Headers for authentication.
        firmware_file_path (str): Path to firmware file.
    
    Returns:
        Result: Workflow result with all steps.
    """
    results = []
    
    # Step 1: Get current firmware version
    logger.info(f"Starting firmware upgrade workflow for {task.host}")
    
    current_version = task.run(
        name="Get current firmware version",
        task=nr_get_firmware_version,
        headers=headers
    )
    results.append(f"Current version check: {current_version.result}")
    
    # Step 2: Upload new firmware
    if not current_version.failed:
        upgrade_result = task.run(
            name="Upload firmware",
            task=nr_transfer_firmware,
            headers=headers,
            firmware_file_path=firmware_file_path
        )
        results.append(f"Firmware upgrade: {upgrade_result.result}")
        
        if not upgrade_result.failed:
            results.append("Note: Device will reboot automatically with new firmware")
        
        return Result(
            host=task.host,
            failed=upgrade_result.failed,
            result={
                'workflow_steps': results,
                'upgrade_successful': not upgrade_result.failed
            }
        )
    else:
        return Result(
            host=task.host,
            failed=True,
            result={
                'workflow_steps': results,
                'error': 'Failed to get current firmware version'
            }
        )

def nr_connectivity_check(task: Task, headers: Dict[str, str]) -> Result:
    # Try basic connectivity first
    basic_url = f"http://{task.host.hostname}/"
    
    try:
        response = requests.get(basic_url, timeout=10, verify=False)
        if response.status_code == 200:
            return Result(host=task.host, result="PDU is online and responding")
    except:
        pass
    
    # If basic check fails, try API endpoint that exists in older firmware
    # Use a simpler API endpoint for verification
    return Result(host=task.host, failed=True, result="PDU not responding")


def nr_get_system_info(task: Task, headers: Dict[str, str]) -> Result:
    """
    Get comprehensive system information from PDU
    
    Args:
        task (Task): Nornir task object containing the host.
        headers (Dict[str, str]): Headers for authentication.
    
    Returns:
        Result: Dictionary with firmware, model, serial, and hostname info.
    """
    try:
        system_info = {}
        
        # Get firmware version (reuse existing function)
        version_result = task.run(task=nr_get_firmware_version, headers=headers)
        if not version_result.failed:
            system_info['firmware'] = version_result.result.get('firmware_version', {})
        
        # Get model number
        try:
            model_url = f"http://{task.host.hostname}/api/sys/modelNumber"
            model_payload = {'token': '', 'cmd': 'get', 'data': {}}
            model_response = post_url(model_url, headers, model_payload)
            if model_response.get('retCode') == 0:
                system_info['model'] = model_response.get('data', 'Unknown')
        except Exception as e:
            system_info['model'] = f"Error: {str(e)}"
        
        # Get serial number
        try:
            serial_url = f"http://{task.host.hostname}/api/sys/serialNumber"
            serial_payload = {'token': '', 'cmd': 'get', 'data': {}}
            serial_response = post_url(serial_url, headers, serial_payload)
            if serial_response.get('retCode') == 0:
                system_info['serial'] = serial_response.get('data', 'Unknown')
        except Exception as e:
            system_info['serial'] = f"Error: {str(e)}"
        
        # Get configured hostname
        try:
            hostname_url = f"http://{task.host.hostname}/api/conf/system/hostname"
            hostname_payload = {'token': '', 'cmd': 'get', 'data': {}}
            hostname_response = post_url(hostname_url, headers, hostname_payload)
            if hostname_response.get('retCode') == 0:
                system_info['configured_hostname'] = hostname_response.get('data', 'Unknown')
        except Exception as e:
            system_info['configured_hostname'] = f"Error: {str(e)}"
        
        logger.info(f"System info retrieved for {task.host}")
        return Result(
            host=task.host,
            result=system_info
        )
        
    except Exception as e:
        error_msg = f"Failed to get system info: {str(e)}"
        logger.error(f"System info retrieval failed for {task.host}: {error_msg}")
        return Result(
            host=task.host,
            failed=True,
            result=error_msg
        )


def nr_check_upgrade_success(task: Task, headers: Dict[str, str], expected_version: str = None) -> Result:
    """
    Check if firmware upgrade was successful by comparing versions
    
    Args:
        task (Task): Nornir task object containing the host.
        headers (Dict[str, str]): Headers for authentication.
        expected_version (str, optional): Expected firmware version after upgrade.
    
    Returns:
        Result: Upgrade verification status with version information.
    """
    try:
        from datetime import datetime
        
        # Get current firmware version
        version_result = task.run(task=nr_get_firmware_version, headers=headers)
        
        if version_result.failed:
            return Result(
                host=task.host,
                failed=True,
                result="Could not retrieve firmware version to verify upgrade"
            )
        
        current_version = version_result.result.get('firmware_version', {}).get('data', 'Unknown')
        
        result_data = {
            'current_version': current_version,
            'check_timestamp': datetime.now().isoformat()
        }
        
        if expected_version:
            result_data['expected_version'] = expected_version
            # Check if expected version is in current version string
            if expected_version in current_version:
                result_data['upgrade_success'] = True
                result_data['message'] = f"Firmware upgrade successful! Current version: {current_version}"
                logger.info(f"Upgrade verification successful for {task.host}: {current_version}")
            else:
                result_data['upgrade_success'] = False
                result_data['message'] = f"Version mismatch. Expected: {expected_version}, Current: {current_version}"
                logger.warning(f"Version mismatch for {task.host}: expected {expected_version}, got {current_version}")
        else:
            result_data['message'] = f"Current firmware version: {current_version}"
            logger.info(f"Current firmware version for {task.host}: {current_version}")
        
        return Result(
            host=task.host,
            result=result_data
        )
        
    except Exception as e:
        error_msg = f"Upgrade verification failed: {str(e)}"
        logger.error(f"Upgrade verification failed for {task.host}: {error_msg}")
        return Result(
            host=task.host,
            failed=True,
            result=error_msg
        )


def nr_wait_for_reboot(task: Task, headers: Dict[str, str], expected_reboot_time: int = 120, max_attempts: int = 10, retry_interval: int = 30) -> Result:
    """
    Wait for PDU to come back online after firmware upgrade reboot
    
    Args:
        task (Task): Nornir task object containing the host.
        headers (Dict[str, str]): Headers for authentication.
        expected_reboot_time (int): Initial wait time before checking (seconds).
        max_attempts (int): Maximum number of connectivity check attempts.
        retry_interval (int): Time between retry attempts (seconds).
    
    Returns:
        Result: Reboot recovery status with timing information.
    """
    import time
    
    try:
        logger.info(f"Waiting {expected_reboot_time} seconds for {task.host} to reboot...")
        time.sleep(expected_reboot_time)
        
        # Try to reconnect with retry logic
        for attempt in range(max_attempts):
            logger.debug(f"Reboot verification attempt {attempt + 1}/{max_attempts} for {task.host}")
            
            try:
                # Use connectivity check to verify PDU is back online
                connectivity_result = task.run(
                    task=nr_connectivity_check,
                    headers=headers
                )
                
                if not connectivity_result.failed:
                    success_msg = f"PDU came back online after {attempt + 1} attempts"
                    logger.info(f"Reboot recovery successful for {task.host}: {success_msg}")
                    return Result(
                        host=task.host,
                        result={
                            'status': 'online',
                            'attempts': attempt + 1,
                            'total_wait_time': expected_reboot_time + (attempt * retry_interval),
                            'connectivity_info': connectivity_result.result,
                            'message': success_msg
                        }
                    )
                    
            except Exception as e:
                logger.debug(f"Attempt {attempt + 1} failed for {task.host}: {str(e)}")
            
            if attempt < max_attempts - 1:
                logger.debug(f"Retrying in {retry_interval} seconds...")
                time.sleep(retry_interval)
        
        error_msg = f"PDU did not come back online after {max_attempts} attempts"
        logger.error(f"Reboot recovery failed for {task.host}: {error_msg}")
        return Result(
            host=task.host,
            failed=True,
            result={
                'status': 'offline',
                'attempts': max_attempts,
                'total_wait_time': expected_reboot_time + (max_attempts * retry_interval),
                'message': error_msg
            }
        )
        
    except Exception as e:
        error_msg = f"Reboot verification failed: {str(e)}"
        logger.error(f"Reboot verification failed for {task.host}: {error_msg}")
        return Result(
            host=task.host,
            failed=True,
            result=error_msg
        )


def nr_comprehensive_status_check(task: Task, headers: Dict[str, str], expected_version: str = None) -> Result:
    """
    Comprehensive status check combining connectivity, system info, and upgrade verification
    
    Args:
        task (Task): Nornir task object containing the host.
        headers (Dict[str, str]): Headers for authentication.
        expected_version (str, optional): Expected firmware version to verify against.
    
    Returns:
        Result: Complete status report with all check results.
    """
    try:
        from datetime import datetime
        
        results = {}
        logger.info(f"Running comprehensive status check for {task.host}")
        
        # Step 1: Connectivity check
        connectivity = task.run(
            name="Connectivity check",
            task=nr_connectivity_check,
            headers=headers
        )
        results['connectivity'] = connectivity.result
        
        if connectivity.failed:
            return Result(
                host=task.host,
                failed=True,
                result={
                    'status': 'offline',
                    'checks': results,
                    'timestamp': datetime.now().isoformat()
                }
            )
        
        # Step 2: System information
        system_info = task.run(
            name="Get system information",
            task=nr_get_system_info,
            headers=headers
        )
        results['system_info'] = system_info.result if not system_info.failed else {'error': str(system_info.result)}
        
        # Step 3: Upgrade verification (if expected version provided)
        if expected_version:
            upgrade_check = task.run(
                name="Verify firmware upgrade",
                task=nr_check_upgrade_success,
                headers=headers,
                expected_version=expected_version
            )
            results['upgrade_verification'] = upgrade_check.result if not upgrade_check.failed else {'error': str(upgrade_check.result)}
        
        logger.info(f"Comprehensive status check completed for {task.host}")
        return Result(
            host=task.host,
            result={
                'status': 'online',
                'checks': results,
                'timestamp': datetime.now().isoformat()
            }
        )
        
    except Exception as e:
        error_msg = f"Comprehensive status check failed: {str(e)}"
        logger.error(f"Comprehensive status check failed for {task.host}: {error_msg}")
        return Result(
            host=task.host,
            failed=True,
            result=error_msg
        )

def nr_get_measurement_from_url(task: Task, url: str, label: str) -> Result:
    """
    Get measurement value from a specific URL.
    
    Args:
        task: Nornir task object
        url: Complete URL to query
        label: Label for the measurement
        
    Returns:
        Nornir Result object with measurement data
    """
    headers = create_vertiv_auth_headers(VERTIV_API_KEY or '')
    payload = {'token': '', 'cmd': 'get', 'data': {}}

    try:
        logger.info(f"Getting measurement '{label}' for {task.host.name}")
        
        response_data = post_url(url, headers=headers, payload=payload)
        
        data = response_data.get("data")
        task.host[f"{label}_measurement"] = data
        
        logger.info(f"Measurement '{label}' retrieved for {task.host.name}")
        
        return Result(host=task.host, result={label: data})
        
    except VertivAPIError as e:
        logger.error(f"Vertiv API error getting measurement from {url}: {e}")
        return Result(host=task.host, failed=True, result=f"API error: {e}")
    except Exception as e:
        logger.error(f"Failed to get measurement from {url}: {e}")
        return Result(host=task.host, failed=True, result=f"Measurement retrieval failed: {str(e)}")


def parse_rpdu_summary(json_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Parse RPDU summary data into a structured format.
    
    Args:
        json_data: Raw JSON data from the device
        
    Returns:
        Parsed and structured data dictionary
    """
    if not isinstance(json_data, dict) or 'data' not in json_data:
        raise ValueError("Invalid JSON data structure")
    
    entities = json_data["data"].get("entity", {})
    
    result = {
        "Phases": {},
        "Total Measurements": {},
        "Circuit Breakers": {},
        "Neutral Line": {},
        "Load Balance": {},
        "Power Quality Indicators": {}
    }

    # Mapping for clarity
    phase_map = {
        "phase0": "Phase A",
        "phase1": "Phase B", 
        "phase2": "Phase C"
    }
    breaker_map = {
        "breaker0": "Circuit 1",
        "breaker1": "Circuit 2",
        "breaker2": "Circuit 3"
    }

    # Parse phase data
    for key, label in phase_map.items():
        if key in entities and "measurement" in entities[key]:
            try:
                m = entities[key]["measurement"]
                result["Phases"][label] = {
                    "Voltage": float(m.get("0", {}).get("value", 0)),
                    "Current": float(m.get("4", {}).get("value", 0)),
                    "Real Power": float(m.get("8", {}).get("value", 0)),
                    "Apparent Power": float(m.get("9", {}).get("value", 0)),
                    "Power Factor": int(m.get("10", {}).get("value", 0)),
                    "Energy": float(m.get("11", {}).get("value", 0)),
                }
                result["Load Balance"][label] = int(m.get("12", {}).get("value", 0))
                result["Power Quality Indicators"][label[-1]] = float(m.get("14", {}).get("value", 0))
            except (ValueError, TypeError, KeyError) as e:
                logger.warning(f"Error parsing phase {key} data: {e}")

    # Parse total measurements
    if "total0" in entities and "measurement" in entities["total0"]:
        try:
            total = entities["total0"]["measurement"]
            result["Total Measurements"] = {
                "Real Power": float(total.get("0", {}).get("value", 0)),
                "Apparent Power": float(total.get("1", {}).get("value", 0)),
                "Power Factor": int(total.get("2", {}).get("value", 0)),
                "Energy": float(total.get("3", {}).get("value", 0)),
            }
        except (ValueError, TypeError, KeyError) as e:
            logger.warning(f"Error parsing total measurements: {e}")

    # Parse circuit breaker data
    for key, label in breaker_map.items():
        if key in entities:
            try:
                entity = entities[key]
                if "measurement" in entity:
                    m = entity["measurement"]
                    loss = entity.get("point", {}).get("lossOfLoadDetected", {}).get("value", False)
                    result["Circuit Breakers"][label] = {
                        "Current": float(m.get("4", {}).get("value", 0)),
                        "Loss of Load Detected": bool(loss)
                    }
            except (ValueError, TypeError, KeyError) as e:
                logger.warning(f"Error parsing breaker {key} data: {e}")

    # Parse neutral line data
    if "line3" in entities and "measurement" in entities["line3"]:
        try:
            neutral = entities["line3"]["measurement"]
            result["Neutral Line"]["Current"] = float(neutral.get("0", {}).get("value", 0))
        except (ValueError, TypeError, KeyError) as e:
            logger.warning(f"Error parsing neutral line data: {e}")

    return result


def nr_get_rpdu_summary(task: Task) -> Result:
    """
    Get comprehensive RPDU summary data.
    
    Args:
        task: Nornir task object
        
    Returns:
        Nornir Result object with parsed RPDU summary
    """
    try:
        # Get device ID from host's custom fields
        dev_id = task.host.get('custom_fields', {}).get("devID")
        if not dev_id:
            return Result(host=task.host, failed=True, result="Device ID not found in custom fields")
        
        logger.info(f"Getting RPDU summary for {task.host.name}")
        
        # Get raw data
        url = f"https://{task.host.hostname}/api/dev/{dev_id}"
        data_result = task.run(
            name="Get PDU data",
            task=nr_get_measurement_from_url,
            url=url,
            label="summary"
        )
        
        if data_result.failed:
            return Result(host=task.host, failed=True, result="Failed to retrieve PDU data")
        
        # Parse the JSON response
        parsed_data = parse_rpdu_summary(data_result.result)
        
        # Add the parsed data to the host
        task.host['rpdu_summary'] = parsed_data
        
        logger.info(f"RPDU summary retrieved and parsed for {task.host.name}")
        return Result(host=task.host, result=parsed_data)
        
    except Exception as e:
        logger.error(f"Failed to get RPDU summary for {task.host.name}: {e}")
        return Result(host=task.host, failed=True, result=f"RPDU summary retrieval failed: {str(e)}")


def nr_get_measurements(task: Task) -> Result:
    """
    Get comprehensive measurements from the device with metadata.
    
    Args:
        task: Nornir task object
        
    Returns:
        Nornir Result object with enriched measurement data
    """
    try:
        hostname = getattr(task.host, 'hostname', task.host.name)
        dev_id = task.host.get('custom_fields', {}).get("devID")
        jira_key = task.host.get('custom_fields', {}).get("jiraObjectKey", "unknown")
        
        if not dev_id:
            return Result(host=task.host, failed=True, result="Device ID not found")
        
        logger.info(f"Getting comprehensive measurements for {task.host.name}")
        
        url = f"http://{hostname}/api/dev/{dev_id}"
        headers = create_vertiv_auth_headers(VERTIV_API_KEY or '')
        payload = {'token': '', 'cmd': 'get', 'data': {}}
        
        raw_data = post_url(url, headers=headers, payload=payload)
        
        # Parse and enrich with metadata
        json_data = parse_rpdu_summary(raw_data)
        json_data["jiraObjectKey"] = jira_key
        json_data['hostname'] = task.host.get('description', '')
        json_data["ipv4"] = hostname
        
        # Add data to the host
        task.host['rpdu_summary'] = json_data
        
        logger.info(f"Measurements retrieved successfully for {task.host.name}")
        return Result(host=task.host, result=json_data)
        
    except VertivAPIError as e:
        logger.error(f"Vertiv API error getting measurements for {task.host.name}: {e}")
        return Result(host=task.host, failed=True, result=f"API error: {e}")
    except Exception as e:
        logger.error(f"Failed to get measurements for {task.host.name}: {e}")
        return Result(host=task.host, failed=True, result=f"Measurements retrieval failed: {str(e)}")


def nr_get_line3_measurement(task: Task, headers: Dict[str, str]) -> Result:
    """Get neutral line (line3) measurement from device."""
    try:
        dev_id = task.host.get('custom_fields', {}).get("devID")
        if not dev_id:
            return Result(host=task.host, failed=True, result="Device ID not found")
        
        endpoint = f"/api/dev/{dev_id}/entity/line3/measurement/0/value"
        payload = {'token': '', 'cmd': 'get', 'data': {}}
        
        logger.info(f"Getting Line3 measurement for {task.host.name}")
        
        result = nr_post_url(task, endpoint, headers=headers, payload=payload, use_https=True)
        
        if not result.failed and 'data' in result.result:
            neutral_line = result.result['data'].get('data', 0)
            task.host['neutralLine'] = neutral_line
            logger.info(f"Neutral line current for {task.host.name}: {neutral_line}")
            
        return result
        
    except Exception as e:
        logger.error(f"Failed to get Line3 measurement for {task.host.name}: {e}")
        return Result(host=task.host, failed=True, result=f"Line3 measurement failed: {str(e)}")


# Utility Functions

def validate_device_config(task: Task) -> Tuple[bool, List[str]]:
    """
    Validate device configuration requirements.
    
    Returns:
        Tuple of (is_valid, list_of_missing_items)
    """
    required_fields = [
        ('hostname', 'Device hostname'),
        ('custom_fields.label', 'Device label'),
        ('syslogServer', 'Syslog server'),
        ('ntpServer1', 'Primary NTP server'),
        ('dnsServer1', 'Primary DNS server'),
        ('timezone', 'Timezone')
    ]
    
    missing = []
    
    for field_path, description in required_fields:
        try:
            value = task.host
            for key in field_path.split('.'):
                if isinstance(value, dict):
                    value = value.get(key)
                else:
                    value = getattr(value, key, None)
            
            if not value:
                missing.append(description)
        except (AttributeError, KeyError):
            missing.append(description)
    
    return len(missing) == 0, missing


def create_device_backup(task: Task, backup_path: str = "./backups") -> Result:
    """
    Create a configuration backup of the device.
    
    Args:
        task: Nornir task object
        backup_path: Directory to store backups
        
    Returns:
        Nornir Result object with backup status
    """
    try:
        import os
        from datetime import datetime
        
        # Create backup directory if it doesn't exist
        os.makedirs(backup_path, exist_ok=True)
        
        # Generate backup filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{task.host.name}_{timestamp}.json"
        filepath = os.path.join(backup_path, filename)
        
        # Collect device information
        device_info = {
            'timestamp': timestamp,
            'hostname': task.host.name,
            'host_data': dict(task.host.data) if hasattr(task.host, 'data') else {},
            'custom_fields': task.host.get('custom_fields', {}),
            'configuration': {}
        }
        
        # Add any stored measurement data
        if hasattr(task.host, 'rpdu_summary'):
            device_info['measurements'] = task.host['rpdu_summary']
        
        # Save to file
        with open(filepath, 'w') as f:
            json.dump(device_info, f, indent=2, default=str)
        
        logger.info(f"Device backup created: {filepath}")
        return Result(host=task.host, result=f"Backup created: {filename}")
        
    except Exception as e:
        logger.error(f"Failed to create backup for {task.host.name}: {e}")
        return Result(host=task.host, failed=True, result=f"Backup failed: {str(e)}")


def batch_configure_devices(nr, config_functions: List[tuple], headers: Dict[str, str]) -> Dict[str, Any]:
    """
    Execute multiple configuration functions on all devices.
    
    Args:
        nr: Nornir object
        config_functions: List of (function, description) tuples
        headers: HTTP headers for API calls
        
    Returns:
        Summary report dictionary
    """
    summary = {
        'total_hosts': len(nr.inventory.hosts),
        'functions_executed': len(config_functions),
        'results': {},
        'overall_success': True
    }
    
    for func, description in config_functions:
        logger.info(f"Executing batch operation: {description}")
        
        try:
            results = nr.run(name=description, task=func, headers=headers)
            
            # Analyze results
            success_count = len([r for r in results if not results[r].failed])
            failed_count = len([r for r in results if results[r].failed])
            
            summary['results'][description] = {
                'success_count': success_count,
                'failed_count': failed_count,
                'success_rate': (success_count / len(results)) * 100 if results else 0
            }
            
            if failed_count > 0:
                summary['overall_success'] = False
                
        except Exception as e:
            logger.error(f"Batch operation failed: {description} - {e}")
            summary['results'][description] = {
                'success_count': 0,
                'failed_count': len(nr.inventory.hosts),
                'success_rate': 0,
                'error': str(e)
            }
            summary['overall_success'] = False
    
    return summary


# Export commonly used functions
__all__ = [
    # Core networking functions
    'geturl', 'post_url', 'posturl', 'nr_get_url', 'nr_post_url',
    
    # Device information functions
    'nr_get_macAddr', 'nr_get_model', 'nr_get_serial', 'nr_get_hostname', 'nr_get_dev_id',
    
    # Configuration functions
    'nr_post_system', 'nr_post_contact', 'nr_post_syslog', 'nr_post_ntp', 
    'nr_post_dns', 'nr_disable_ipv6', 'nr_enable_modbus',
    
    # User management
    'nr_add_user_admin',
    
    # Monitoring and measurements
    'nr_get_measurements', 'nr_get_rpdu_summary', 'nr_get_line3_measurement',
    'parse_rpdu_summary',
    
    # Utility functions
    'create_vertiv_auth_headers', 'test_connectivity', 'validate_device_config',
    'create_device_backup', 'batch_configure_devices',
    
    # Classes and exceptions
    'VertivDevice', 'VertivAPIError'
]