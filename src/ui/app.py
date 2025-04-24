"""
Nuclei MCP Web UI

A simple web interface for interacting with the Nuclei MCP server.
"""

import os
import json
import uuid
import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from werkzeug.utils import secure_filename

# Import MCP modules
from src.tools import scan_tools
from src.resources import vuln_resource
from src.utils.helpers import ensure_directories_exist

# Create Flask app
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev_key_please_change_in_production')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload size

# Ensure data directories exist
ensure_directories_exist()

@app.route('/')
def index():
    """Render the home page."""
    return render_template('index.html')

@app.route('/scan', methods=['GET', 'POST'])
def scan():
    """Handle scan form and results."""
    if request.method == 'POST':
        target = request.form.get('target')
        templates = request.form.getlist('templates')
        
        if not target:
            flash('Target URL is required', 'error')
            return redirect(url_for('scan'))
        
        # Call the scan_target tool function with our parameters
        message = {
            "type": "tool",
            "name": "scan_target",
            "params": {
                "target": target,
                "templates": templates
            }
        }
        
        response = scan_tools.handle_scan_target(message)
        
        if response.get("type") == "error":
            flash(f"Error: {response.get('error', {}).get('message', 'Unknown error')}", 'error')
            return redirect(url_for('scan'))
        
        scan_id = response.get("result", {}).get("scan_id")
        if scan_id:
            return redirect(url_for('scan_results', scan_id=scan_id))
        else:
            flash('Scan completed but no scan ID was returned', 'warning')
            return redirect(url_for('scans'))
    
    # GET request - show the scan form
    templates = _get_templates()
    return render_template('scan.html', templates=templates)

@app.route('/scan_results/<scan_id>')
def scan_results(scan_id):
    """Show the results of a specific scan."""
    # Create a message to retrieve scan data
    message = {
        "type": "resource",
        "uri": f"nuclei://scans/{scan_id}"
    }
    
    response = vuln_resource.handle_scan(message)
    
    if response.get("type") == "error":
        flash(f"Error: {response.get('error', {}).get('message', 'Unknown error')}", 'error')
        return redirect(url_for('scans'))
    
    # Parse the JSON data from the response
    scan_data = json.loads(response.get("data", "{}"))
    
    # Get vulnerability details for each vulnerability in the scan
    vulnerabilities = []
    for vuln in scan_data.get("vulnerabilities", []):
        vuln_id = vuln.get("id")
        if vuln_id:
            vuln_message = {
                "type": "resource",
                "uri": f"nuclei://vulnerabilities/{vuln_id}"
            }
            vuln_response = vuln_resource.handle_vulnerability(vuln_message)
            if vuln_response.get("type") != "error":
                vulnerabilities.append(json.loads(vuln_response.get("data", "{}")))
    
    return render_template('scan_results.html', scan=scan_data, vulnerabilities=vulnerabilities)

@app.route('/vulnerability/<vuln_id>')
def vulnerability_details(vuln_id):
    """Show details for a specific vulnerability."""
    # Create a message to retrieve vulnerability data
    message = {
        "type": "resource",
        "uri": f"nuclei://vulnerabilities/{vuln_id}"
    }
    
    response = vuln_resource.handle_vulnerability(message)
    
    if response.get("type") == "error":
        flash(f"Error: {response.get('error', {}).get('message', 'Unknown error')}", 'error')
        return redirect(url_for('scans'))
    
    # Parse the JSON data from the response
    vuln_data = json.loads(response.get("data", "{}"))
    
    # Get template details if available
    template_data = None
    template_id = vuln_data.get("template")
    if template_id:
        template_message = {
            "type": "resource",
            "uri": f"nuclei://templates/{template_id}"
        }
        template_response = vuln_resource.handle_template(template_message)
        if template_response.get("type") != "error":
            template_data = json.loads(template_response.get("data", "{}"))
    
    return render_template('vulnerability.html', vulnerability=vuln_data, template=template_data)

@app.route('/templates')
def templates():
    """List all available templates."""
    templates = _get_templates()
    return render_template('templates.html', templates=templates)

@app.route('/scans')
def scans():
    """List all previous scans."""
    # Create a message to list all scans
    message = {
        "type": "resource",
        "uri": "nuclei://scans/"
    }
    
    response = vuln_resource.handle_list_scans(message)
    
    if response.get("type") == "error":
        flash(f"Error: {response.get('error', {}).get('message', 'Unknown error')}", 'error')
        return render_template('scans.html', scans=[])
    
    # Parse the JSON data from the response
    scan_data = json.loads(response.get("data", "{}"))
    scans_list = scan_data.get("scans", [])
    
    return render_template('scans.html', scans=scans_list)

@app.route('/vulnerabilities')
def vulnerabilities():
    """List all discovered vulnerabilities."""
    # Create a message to list all vulnerabilities
    message = {
        "type": "resource",
        "uri": "nuclei://vulnerabilities/"
    }
    
    response = vuln_resource.handle_list_vulnerabilities(message)
    
    if response.get("type") == "error":
        flash(f"Error: {response.get('error', {}).get('message', 'Unknown error')}", 'error')
        return render_template('vulnerabilities.html', vulnerabilities=[])
    
    # Parse the JSON data from the response
    vuln_data = json.loads(response.get("data", "{}"))
    vuln_list = vuln_data.get("vulnerabilities", [])
    
    return render_template('vulnerabilities.html', vulnerabilities=vuln_list)

@app.route('/api/scan', methods=['POST'])
def api_scan():
    """API endpoint for starting a scan."""
    data = request.json
    if not data:
        return jsonify({"error": "No JSON data provided"}), 400
    
    target = data.get('target')
    templates = data.get('templates', [])
    
    if not target:
        return jsonify({"error": "Target URL is required"}), 400
    
    # Call the scan_target tool function with our parameters
    message = {
        "type": "tool",
        "name": "scan_target",
        "params": {
            "target": target,
            "templates": templates
        }
    }
    
    response = scan_tools.handle_scan_target(message)
    
    if response.get("type") == "error":
        return jsonify({"error": response.get('error', {}).get('message', 'Unknown error')}), 500
    
    return jsonify(response.get("result", {}))

# Helper functions

def _get_templates():
    """Get all available templates."""
    # Create a message to retrieve templates
    message = {
        "type": "tool",
        "name": "get_templates",
        "params": {}
    }
    
    response = scan_tools.handle_get_templates(message)
    
    if response.get("type") == "error":
        return []
    
    return response.get("result", {}).get("templates", [])

def run_app(host='0.0.0.0', port=5000, debug=True):
    """Run the Flask application."""
    app.run(host=host, port=port, debug=debug)

if __name__ == '__main__':
    run_app() 