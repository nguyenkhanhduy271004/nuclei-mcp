"""
Scanning Tools for MCP Server.

This module provides MCP tools for running Nuclei scans and retrieving information.
"""

import os
import json
import subprocess
import uuid
import datetime
from typing import Dict, Any, List, Optional, Callable
import logging

logger = logging.getLogger("nuclei-mcp")

# Base path for vulnerability data
DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "data")


def get_tool_handlers() -> Dict[str, Callable[[Dict[str, Any]], Dict[str, Any]]]:
    """Return a mapping of tool names to handler functions."""
    return {
        "scan_target": handle_scan_target,
        "get_templates": handle_get_templates,
        "get_vulnerability_info": handle_get_vulnerability_info,
    }


def handle_scan_target(message: Dict[str, Any]) -> Dict[str, Any]:
    """Handle scan_target tool requests."""
    params = message.get("params", {})
    target = params.get("target")
    templates = params.get("templates", [])
    
    if not target:
        return {
            "type": "error",
            "error": {
                "message": "Missing required parameter: target"
            }
        }
    
    try:
        # Generate a unique ID for this scan
        scan_id = str(uuid.uuid4())
        
        # For simulation, we'll just create a mock scan result
        # In a real implementation, this would call the Nuclei CLI
        scan_result = _mock_scan(scan_id, target, templates)
        
        # Save the scan result
        _save_scan_data(scan_id, scan_result)
        
        # Return the result with a URI to access the full scan data
        return {
            "type": "tool_response",
            "name": "scan_target",
            "result": {
                "scan_id": scan_id,
                "target": target,
                "timestamp": scan_result["timestamp"],
                "summary": {
                    "total_vulnerabilities": len(scan_result["vulnerabilities"]),
                    "by_severity": _count_by_severity(scan_result["vulnerabilities"]),
                },
                "resources": [
                    {
                        "uri": f"nuclei://scans/{scan_id}",
                        "description": f"Scan results for {target}"
                    }
                ]
            }
        }
    except Exception as e:
        logger.exception(f"Error scanning target {target}")
        return {
            "type": "error",
            "error": {
                "message": f"Error scanning target: {str(e)}"
            }
        }


def handle_get_templates(message: Dict[str, Any]) -> Dict[str, Any]:
    """Handle get_templates tool requests."""
    params = message.get("params", {})
    tags = params.get("tags", [])
    severity = params.get("severity", [])
    
    try:
        # Get available templates based on filters
        templates = _get_available_templates(tags, severity)
        
        # Return the list of templates
        return {
            "type": "tool_response",
            "name": "get_templates",
            "result": {
                "templates": templates,
                "count": len(templates),
                "resources": [
                    {
                        "uri": "nuclei://templates/",
                        "description": "List of all available templates"
                    }
                ]
            }
        }
    except Exception as e:
        logger.exception("Error retrieving templates")
        return {
            "type": "error",
            "error": {
                "message": f"Error retrieving templates: {str(e)}"
            }
        }


def handle_get_vulnerability_info(message: Dict[str, Any]) -> Dict[str, Any]:
    """Handle get_vulnerability_info tool requests."""
    params = message.get("params", {})
    vuln_id = params.get("vulnerability_id")
    
    if not vuln_id:
        return {
            "type": "error",
            "error": {
                "message": "Missing required parameter: vulnerability_id"
            }
        }
    
    try:
        # Load vulnerability data
        vuln_data = _load_vuln_data(vuln_id)
        if not vuln_data:
            return {
                "type": "error",
                "error": {
                    "message": f"Vulnerability not found: {vuln_id}"
                }
            }
        
        # Return the vulnerability information
        return {
            "type": "tool_response",
            "name": "get_vulnerability_info",
            "result": {
                "vulnerability": vuln_data,
                "resources": [
                    {
                        "uri": f"nuclei://vulnerabilities/{vuln_id}",
                        "description": f"Vulnerability details for {vuln_data.get('name', vuln_id)}"
                    }
                ]
            }
        }
    except Exception as e:
        logger.exception(f"Error retrieving vulnerability info for {vuln_id}")
        return {
            "type": "error",
            "error": {
                "message": f"Error retrieving vulnerability info: {str(e)}"
            }
        }


# Helper functions

def _mock_scan(scan_id: str, target: str, templates: List[str]) -> Dict[str, Any]:
    """Create a mock scan result for simulation purposes."""
    # Create mock vulnerabilities
    vulnerabilities = []
    
    # Create some random mock vulnerabilities
    mock_vulns = [
        {
            "id": str(uuid.uuid4()),
            "name": "SQL Injection Vulnerability",
            "severity": "high",
            "type": "sql-injection",
            "template": "sqli-detection",
            "location": f"{target}/login.php",
            "details": "SQL injection vulnerability in login form that could allow authentication bypass.",
            "cvss_score": 7.5,
            "remediation": "Use prepared statements or parameterized queries."
        },
        {
            "id": str(uuid.uuid4()),
            "name": "Cross-Site Scripting (XSS)",
            "severity": "medium",
            "type": "xss",
            "template": "xss-detection",
            "location": f"{target}/search.php",
            "details": "Reflected XSS vulnerability in search parameter.",
            "cvss_score": 6.1,
            "remediation": "Implement proper output encoding and input validation."
        },
        {
            "id": str(uuid.uuid4()),
            "name": "Information Disclosure",
            "severity": "low",
            "type": "info-disclosure",
            "template": "version-disclosure",
            "location": f"{target}/header",
            "details": "Server version information disclosed in HTTP headers.",
            "cvss_score": 3.5,
            "remediation": "Configure server to not disclose version information."
        }
    ]
    
    # Add some of the mock vulnerabilities to simulate scan results
    import random
    num_vulns = random.randint(0, len(mock_vulns))
    
    for i in range(num_vulns):
        vuln = mock_vulns[i].copy()
        # Save this vulnerability to the data directory
        _save_vuln_data(vuln["id"], vuln)
        # Add to scan results
        vulnerabilities.append(vuln)
    
    return {
        "id": scan_id,
        "target": target,
        "templates_used": templates,
        "timestamp": datetime.datetime.now().isoformat(),
        "vulnerabilities": vulnerabilities
    }


def _count_by_severity(vulnerabilities: List[Dict[str, Any]]) -> Dict[str, int]:
    """Count vulnerabilities by severity level."""
    counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0
    }
    
    for vuln in vulnerabilities:
        severity = vuln.get("severity", "").lower()
        if severity in counts:
            counts[severity] += 1
    
    return counts


def _get_available_templates(tags: List[str] = None, severity: List[str] = None) -> List[Dict[str, Any]]:
    """Get available templates based on filters."""
    # In a real implementation, this would query Nuclei's template directory
    # For simulation, we'll return mock templates
    
    mock_templates = [
        {
            "id": "sqli-detection",
            "name": "SQL Injection Detection",
            "author": "nuclei-team",
            "severity": "high",
            "description": "Detects SQL injection vulnerabilities in web applications",
            "tags": ["sqli", "injection", "vulnerability"]
        },
        {
            "id": "xss-detection",
            "name": "Cross-Site Scripting Detection",
            "author": "nuclei-team",
            "severity": "medium",
            "description": "Detects XSS vulnerabilities in web applications",
            "tags": ["xss", "injection", "vulnerability"]
        },
        {
            "id": "version-disclosure",
            "name": "Version Information Disclosure",
            "author": "nuclei-team",
            "severity": "low",
            "description": "Detects version information disclosure in HTTP headers and responses",
            "tags": ["info-disclosure", "recon"]
        },
        {
            "id": "cve-2023-1234",
            "name": "CVE-2023-1234 Apache Struts Vulnerability",
            "author": "nuclei-team",
            "severity": "critical",
            "description": "Detects a critical vulnerability in Apache Struts",
            "tags": ["cve", "apache", "struts", "rce"]
        }
    ]
    
    # Save mock templates to data directory
    for template in mock_templates:
        _save_template_data(template["id"], {
            "info": template,
            "requests": [
                {
                    "method": "GET",
                    "path": "/"
                }
            ]
        })
    
    # Apply filters
    if tags:
        # Filter templates that have any of the specified tags
        mock_templates = [
            t for t in mock_templates if any(tag in t.get("tags", []) for tag in tags)
        ]
    
    if severity:
        # Filter templates by severity
        mock_templates = [
            t for t in mock_templates if t.get("severity", "").lower() in [s.lower() for s in severity]
        ]
    
    return mock_templates


def _save_scan_data(scan_id: str, scan_data: Dict[str, Any]) -> None:
    """Save scan data to file."""
    scan_dir = os.path.join(DATA_DIR, "scans")
    os.makedirs(scan_dir, exist_ok=True)
    
    scan_file = os.path.join(scan_dir, f"{scan_id}.json")
    
    with open(scan_file, "w") as f:
        json.dump(scan_data, f, indent=2)


def _save_vuln_data(vuln_id: str, vuln_data: Dict[str, Any]) -> None:
    """Save vulnerability data to file."""
    vuln_dir = os.path.join(DATA_DIR, "vulnerabilities")
    os.makedirs(vuln_dir, exist_ok=True)
    
    vuln_file = os.path.join(vuln_dir, f"{vuln_id}.json")
    
    with open(vuln_file, "w") as f:
        json.dump(vuln_data, f, indent=2)


def _save_template_data(template_id: str, template_data: Dict[str, Any]) -> None:
    """Save template data to file."""
    template_dir = os.path.join(DATA_DIR, "templates")
    os.makedirs(template_dir, exist_ok=True)
    
    template_file = os.path.join(template_dir, f"{template_id}.json")
    
    with open(template_file, "w") as f:
        json.dump(template_data, f, indent=2)


def _load_vuln_data(vuln_id: str) -> Optional[Dict[str, Any]]:
    """Load vulnerability data from file."""
    vuln_file = os.path.join(DATA_DIR, "vulnerabilities", f"{vuln_id}.json")
    
    if not os.path.exists(vuln_file):
        logger.warning(f"Vulnerability file not found: {vuln_file}")
        return None
    
    with open(vuln_file, "r") as f:
        return json.load(f) 