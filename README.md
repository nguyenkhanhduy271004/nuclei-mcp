# Nuclei MCP Server

A Model Context Protocol server for Nuclei vulnerability scanner integration using Python.

## Features

### Resources

* Access vulnerability data via `nuclei://` URIs
* Each vulnerability has detailed information and metadata
* Support for various MIME types for rich content access

### Tools

* `scan_target` - Run Nuclei scans against specified targets
* `get_templates` - Retrieve available templates for scanning
* `get_vulnerability_info` - Get detailed info about specific vulnerabilities

### Prompts

* `analyze_vulnerabilities` - Generate analysis of discovered vulnerabilities
* `suggest_remediation` - Get AI-generated remediation suggestions

## Web Interface

The project includes a responsive web interface that allows you to:

* Run vulnerability scans against targets
* View scan results with detailed vulnerability information
* Browse all templates and vulnerabilities
* Filter and sort results by severity and type

![Nuclei MCP Scanner UI](docs/ui-screenshot.png)

### Running the Web UI

To start the web interface:

```bash
python run_ui.py
```

You can configure the following environment variables:
- `NUCLEI_MCP_UI_HOST`: Host to bind to (default: 0.0.0.0)
- `NUCLEI_MCP_UI_PORT`: Port to listen on (default: 5000)
- `NUCLEI_MCP_UI_DEBUG`: Enable debug mode (default: true)

Then access the UI in your browser at: http://localhost:5000

## Development

Create a virtual environment:

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Run the MCP server:

```bash
python -m src.main
```

## Installation

To use with Claude Desktop, add the server config:

On MacOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
On Windows: `%APPDATA%/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "nuclei-server": {
      "command": "python -m /path/to/nuclei-mcp/src/main.py"
    }
  }
}
```

## Project Structure

```
nuclei-mcp/
├── data/                  # Sample vulnerability data
├── src/                   # Source code
│   ├── __init__.py        
│   ├── main.py            # MCP server entry point
│   ├── resources/         # MCP resources (URIs)
│   ├── tools/             # MCP tools 
│   ├── prompts/           # MCP prompts
│   ├── utils/             # Utility functions
│   └── ui/                # Web UI
│       ├── app.py         # Flask application
│       ├── templates/     # HTML templates
│       └── static/        # Static assets
├── tests/                 # Test cases
├── run_ui.py              # Script to run the web UI
├── README.md              # This file
└── requirements.txt       # Python dependencies
```

## About

This project integrates the Nuclei vulnerability scanner with AI assistants through the Model Context Protocol (MCP), allowing AI to access vulnerability data and perform security analysis tasks. 