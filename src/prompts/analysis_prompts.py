"""
Analysis Prompts for MCP Server.

This module provides MCP prompts for analyzing vulnerabilities and suggesting remediation.
"""

import os
import json
from typing import Dict, Any, List, Optional, Callable
import logging

logger = logging.getLogger("nuclei-mcp")

# Base path for vulnerability data
DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "data")


def get_prompt_handlers() -> Dict[str, Callable[[Dict[str, Any]], Dict[str, Any]]]:
    """Return a mapping of prompt names to handler functions."""
    return {
        "analyze_vulnerabilities": handle_analyze_vulnerabilities,
        "suggest_remediation": handle_suggest_remediation,
    }


def handle_analyze_vulnerabilities(message: Dict[str, Any]) -> Dict[str, Any]:
    """Handle analyze_vulnerabilities prompt requests."""
    params = message.get("params", {})
    scan_id = params.get("scan_id")
    
    if not scan_id:
        return {
            "type": "error",
            "error": {
                "message": "Missing required parameter: scan_id"
            }
        }
    
    try:
        # Load scan data
        scan_data = _load_scan_data(scan_id)
        if not scan_data:
            return {
                "type": "error",
                "error": {
                    "message": f"Scan not found: {scan_id}"
                }
            }
        
        vulnerabilities = scan_data.get("vulnerabilities", [])
        
        # Create a prompt for analyzing the vulnerabilities
        prompt = {
            "type": "prompt_response",
            "name": "analyze_vulnerabilities",
            "prompt": {
                "role": "system",
                "content": "You are a cybersecurity expert analyzing the results of a Nuclei vulnerability scan. Provide an analysis of the vulnerabilities found, including their severity, potential business impact, and an overall risk assessment.",
                "embedded_resources": [
                    {
                        "uri": f"nuclei://scans/{scan_id}",
                        "mime_type": "application/json",
                        "description": f"Scan results for {scan_data.get('target', 'unknown target')}"
                    }
                ]
            }
        }
        
        # Add vulnerabilities as embedded resources
        for vuln in vulnerabilities:
            vuln_id = vuln.get("id")
            if vuln_id:
                prompt["prompt"]["embedded_resources"].append({
                    "uri": f"nuclei://vulnerabilities/{vuln_id}",
                    "mime_type": "application/json",
                    "description": f"Vulnerability: {vuln.get('name', 'Unnamed vulnerability')}"
                })
        
        return prompt
    except Exception as e:
        logger.exception(f"Error creating analysis prompt for scan {scan_id}")
        return {
            "type": "error",
            "error": {
                "message": f"Error creating analysis prompt: {str(e)}"
            }
        }


def handle_suggest_remediation(message: Dict[str, Any]) -> Dict[str, Any]:
    """Handle suggest_remediation prompt requests."""
    params = message.get("params", {})
    vulnerability_id = params.get("vulnerability_id")
    
    if not vulnerability_id:
        return {
            "type": "error",
            "error": {
                "message": "Missing required parameter: vulnerability_id"
            }
        }
    
    try:
        # Load vulnerability data
        vuln_data = _load_vuln_data(vulnerability_id)
        if not vuln_data:
            return {
                "type": "error",
                "error": {
                    "message": f"Vulnerability not found: {vulnerability_id}"
                }
            }
        
        # Create a prompt for suggesting remediation
        prompt = {
            "type": "prompt_response",
            "name": "suggest_remediation",
            "prompt": {
                "role": "system",
                "content": f"""You are a cybersecurity expert providing remediation advice for a vulnerability.
The vulnerability is: {vuln_data.get('name', 'Unknown vulnerability')}
Severity: {vuln_data.get('severity', 'unknown')}
Type: {vuln_data.get('type', 'unknown')}

Provide detailed remediation steps to fix this vulnerability, best practices to prevent similar issues, and any additional security measures that should be taken.""",
                "embedded_resources": [
                    {
                        "uri": f"nuclei://vulnerabilities/{vulnerability_id}",
                        "mime_type": "application/json",
                        "description": f"Vulnerability: {vuln_data.get('name', 'Unnamed vulnerability')}"
                    }
                ]
            }
        }
        
        # If this vulnerability is from a specific template, include that as well
        template_id = vuln_data.get("template")
        if template_id:
            template_data = _load_template_data(template_id)
            if template_data:
                prompt["prompt"]["embedded_resources"].append({
                    "uri": f"nuclei://templates/{template_id}",
                    "mime_type": "application/json",
                    "description": f"Template: {template_data.get('info', {}).get('name', template_id)}"
                })
        
        return prompt
    except Exception as e:
        logger.exception(f"Error creating remediation prompt for vulnerability {vulnerability_id}")
        return {
            "type": "error",
            "error": {
                "message": f"Error creating remediation prompt: {str(e)}"
            }
        }


# Helper functions

def _load_scan_data(scan_id: str) -> Optional[Dict[str, Any]]:
    """Load scan data from file."""
    scan_file = os.path.join(DATA_DIR, "scans", f"{scan_id}.json")
    
    if not os.path.exists(scan_file):
        logger.warning(f"Scan file not found: {scan_file}")
        return None
    
    with open(scan_file, "r") as f:
        return json.load(f)


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