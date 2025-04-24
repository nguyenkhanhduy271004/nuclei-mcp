"""
Vulnerability Resource Handlers for MCP Server.

This module provides handlers for vulnerability-related URIs in the format:
nuclei://vulnerabilities/{id}
nuclei://templates/{id}
nuclei://scans/{id}
"""

import re
import json
import os
from typing import Dict, Any, Callable, Pattern, List, Optional
import logging

logger = logging.getLogger("nuclei-mcp")

# Define URI patterns
VULN_PATTERN = re.compile(r"nuclei://vulnerabilities/(?P<vuln_id>.+)")
TEMPLATE_PATTERN = re.compile(r"nuclei://templates/(?P<template_id>.+)")
SCAN_PATTERN = re.compile(r"nuclei://scans/(?P<scan_id>.+)")
LIST_VULNS_PATTERN = re.compile(r"nuclei://vulnerabilities/?$")
LIST_TEMPLATES_PATTERN = re.compile(r"nuclei://templates/?$")
LIST_SCANS_PATTERN = re.compile(r"nuclei://scans/?$")

# Base path for vulnerability data
DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "data")


def get_resource_handlers() -> Dict[Pattern, Callable[[Dict[str, Any]], Dict[str, Any]]]:
    """Return a mapping of URI patterns to handler functions."""
    return {
        VULN_PATTERN: handle_vulnerability,
        TEMPLATE_PATTERN: handle_template,
        SCAN_PATTERN: handle_scan,
        LIST_VULNS_PATTERN: handle_list_vulnerabilities,
        LIST_TEMPLATES_PATTERN: handle_list_templates,
        LIST_SCANS_PATTERN: handle_list_scans,
    }


def handle_vulnerability(message: Dict[str, Any]) -> Dict[str, Any]:
    """Handle vulnerability resource requests."""
    uri = message.get("uri", "")
    match = VULN_PATTERN.match(uri)
    
    if not match:
        return {
            "type": "error",
            "error": {
                "message": f"Invalid vulnerability URI format: {uri}"
            }
        }
    
    vuln_id = match.group("vuln_id")
    
    # Try to load the vulnerability data
    try:
        vuln_data = _load_vuln_data(vuln_id)
        if not vuln_data:
            return {
                "type": "error",
                "error": {
                    "message": f"Vulnerability not found: {vuln_id}"
                }
            }
        
        # Return the vulnerability data
        return {
            "type": "resource",
            "uri": uri,
            "mime_type": "application/json",
            "metadata": {
                "id": vuln_id,
                "name": vuln_data.get("name", "Unnamed vulnerability"),
                "severity": vuln_data.get("severity", "unknown"),
                "type": vuln_data.get("type", "unknown"),
                "template": vuln_data.get("template", "unknown"),
            },
            "data": json.dumps(vuln_data)
        }
    except Exception as e:
        logger.exception(f"Error loading vulnerability data for {vuln_id}")
        return {
            "type": "error",
            "error": {
                "message": f"Error loading vulnerability data: {str(e)}"
            }
        }


def handle_template(message: Dict[str, Any]) -> Dict[str, Any]:
    """Handle template resource requests."""
    uri = message.get("uri", "")
    match = TEMPLATE_PATTERN.match(uri)
    
    if not match:
        return {
            "type": "error",
            "error": {
                "message": f"Invalid template URI format: {uri}"
            }
        }
    
    template_id = match.group("template_id")
    
    # Try to load the template data
    try:
        template_data = _load_template_data(template_id)
        if not template_data:
            return {
                "type": "error",
                "error": {
                    "message": f"Template not found: {template_id}"
                }
            }
        
        # Return the template data
        return {
            "type": "resource",
            "uri": uri,
            "mime_type": "application/yaml",
            "metadata": {
                "id": template_id,
                "name": template_data.get("info", {}).get("name", "Unnamed template"),
                "author": template_data.get("info", {}).get("author", "Unknown"),
                "severity": template_data.get("info", {}).get("severity", "unknown"),
                "description": template_data.get("info", {}).get("description", "No description"),
            },
            "data": json.dumps(template_data)
        }
    except Exception as e:
        logger.exception(f"Error loading template data for {template_id}")
        return {
            "type": "error",
            "error": {
                "message": f"Error loading template data: {str(e)}"
            }
        }


def handle_scan(message: Dict[str, Any]) -> Dict[str, Any]:
    """Handle scan resource requests."""
    uri = message.get("uri", "")
    match = SCAN_PATTERN.match(uri)
    
    if not match:
        return {
            "type": "error",
            "error": {
                "message": f"Invalid scan URI format: {uri}"
            }
        }
    
    scan_id = match.group("scan_id")
    
    # Try to load the scan data
    try:
        scan_data = _load_scan_data(scan_id)
        if not scan_data:
            return {
                "type": "error",
                "error": {
                    "message": f"Scan not found: {scan_id}"
                }
            }
        
        # Return the scan data
        return {
            "type": "resource",
            "uri": uri,
            "mime_type": "application/json",
            "metadata": {
                "id": scan_id,
                "target": scan_data.get("target", "Unknown target"),
                "timestamp": scan_data.get("timestamp", "Unknown"),
                "total_vulnerabilities": len(scan_data.get("vulnerabilities", [])),
            },
            "data": json.dumps(scan_data)
        }
    except Exception as e:
        logger.exception(f"Error loading scan data for {scan_id}")
        return {
            "type": "error",
            "error": {
                "message": f"Error loading scan data: {str(e)}"
            }
        }


def handle_list_vulnerabilities(message: Dict[str, Any]) -> Dict[str, Any]:
    """Handle request to list all vulnerabilities."""
    try:
        vulnerabilities = _list_vulnerabilities()
        
        # Return the list of vulnerabilities
        return {
            "type": "resource",
            "uri": "nuclei://vulnerabilities/",
            "mime_type": "application/json",
            "metadata": {
                "count": len(vulnerabilities)
            },
            "data": json.dumps({
                "vulnerabilities": vulnerabilities
            })
        }
    except Exception as e:
        logger.exception("Error listing vulnerabilities")
        return {
            "type": "error",
            "error": {
                "message": f"Error listing vulnerabilities: {str(e)}"
            }
        }


def handle_list_templates(message: Dict[str, Any]) -> Dict[str, Any]:
    """Handle request to list all templates."""
    try:
        templates = _list_templates()
        
        # Return the list of templates
        return {
            "type": "resource",
            "uri": "nuclei://templates/",
            "mime_type": "application/json",
            "metadata": {
                "count": len(templates)
            },
            "data": json.dumps({
                "templates": templates
            })
        }
    except Exception as e:
        logger.exception("Error listing templates")
        return {
            "type": "error",
            "error": {
                "message": f"Error listing templates: {str(e)}"
            }
        }


def handle_list_scans(message: Dict[str, Any]) -> Dict[str, Any]:
    """Handle request to list all scans."""
    try:
        scans = _list_scans()
        
        # Return the list of scans
        return {
            "type": "resource",
            "uri": "nuclei://scans/",
            "mime_type": "application/json",
            "metadata": {
                "count": len(scans)
            },
            "data": json.dumps({
                "scans": scans
            })
        }
    except Exception as e:
        logger.exception("Error listing scans")
        return {
            "type": "error",
            "error": {
                "message": f"Error listing scans: {str(e)}"
            }
        }


# Helper functions for data access

def _load_vuln_data(vuln_id: str) -> Optional[Dict[str, Any]]:
    """Load vulnerability data from file."""
    vuln_file = os.path.join(DATA_DIR, "vulnerabilities", f"{vuln_id}.json")
    
    if not os.path.exists(vuln_file):
        logger.warning(f"Vulnerability file not found: {vuln_file}")
        return None
    
    with open(vuln_file, "r") as f:
        return json.load(f)


def _load_template_data(template_id: str) -> Optional[Dict[str, Any]]:
    """Load template data from file."""
    template_file = os.path.join(DATA_DIR, "templates", f"{template_id}.json")
    
    if not os.path.exists(template_file):
        logger.warning(f"Template file not found: {template_file}")
        return None
    
    with open(template_file, "r") as f:
        return json.load(f)


def _load_scan_data(scan_id: str) -> Optional[Dict[str, Any]]:
    """Load scan data from file."""
    scan_file = os.path.join(DATA_DIR, "scans", f"{scan_id}.json")
    
    if not os.path.exists(scan_file):
        logger.warning(f"Scan file not found: {scan_file}")
        return None
    
    with open(scan_file, "r") as f:
        return json.load(f)


def _list_vulnerabilities() -> List[Dict[str, Any]]:
    """List all available vulnerabilities with basic metadata."""
    vuln_dir = os.path.join(DATA_DIR, "vulnerabilities")
    
    if not os.path.exists(vuln_dir):
        os.makedirs(vuln_dir, exist_ok=True)
        return []
    
    vulnerabilities = []
    
    for filename in os.listdir(vuln_dir):
        if filename.endswith(".json"):
            vuln_id = filename[:-5]  # Remove .json extension
            try:
                vuln_data = _load_vuln_data(vuln_id)
                if vuln_data:
                    vulnerabilities.append({
                        "id": vuln_id,
                        "name": vuln_data.get("name", "Unnamed vulnerability"),
                        "severity": vuln_data.get("severity", "unknown"),
                        "uri": f"nuclei://vulnerabilities/{vuln_id}"
                    })
            except Exception as e:
                logger.warning(f"Error loading vulnerability {vuln_id}: {str(e)}")
    
    return vulnerabilities


def _list_templates() -> List[Dict[str, Any]]:
    """List all available templates with basic metadata."""
    template_dir = os.path.join(DATA_DIR, "templates")
    
    if not os.path.exists(template_dir):
        os.makedirs(template_dir, exist_ok=True)
        return []
    
    templates = []
    
    for filename in os.listdir(template_dir):
        if filename.endswith(".json"):
            template_id = filename[:-5]  # Remove .json extension
            try:
                template_data = _load_template_data(template_id)
                if template_data:
                    templates.append({
                        "id": template_id,
                        "name": template_data.get("info", {}).get("name", "Unnamed template"),
                        "author": template_data.get("info", {}).get("author", "Unknown"),
                        "severity": template_data.get("info", {}).get("severity", "unknown"),
                        "uri": f"nuclei://templates/{template_id}"
                    })
            except Exception as e:
                logger.warning(f"Error loading template {template_id}: {str(e)}")
    
    return templates


def _list_scans() -> List[Dict[str, Any]]:
    """List all available scans with basic metadata."""
    scan_dir = os.path.join(DATA_DIR, "scans")
    
    if not os.path.exists(scan_dir):
        os.makedirs(scan_dir, exist_ok=True)
        return []
    
    scans = []
    
    for filename in os.listdir(scan_dir):
        if filename.endswith(".json"):
            scan_id = filename[:-5]  # Remove .json extension
            try:
                scan_data = _load_scan_data(scan_id)
                if scan_data:
                    scans.append({
                        "id": scan_id,
                        "target": scan_data.get("target", "Unknown target"),
                        "timestamp": scan_data.get("timestamp", "Unknown"),
                        "total_vulnerabilities": len(scan_data.get("vulnerabilities", [])),
                        "uri": f"nuclei://scans/{scan_id}"
                    })
            except Exception as e:
                logger.warning(f"Error loading scan {scan_id}: {str(e)}")
    
    return scans 