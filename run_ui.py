#!/usr/bin/env python3
"""
Nuclei MCP Scanner - UI Server

This script launches the web interface for the Nuclei MCP Scanner.
"""

import os
import logging
from src.ui.app import run_app
from src.utils.helpers import ensure_directories_exist

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("nuclei-mcp-ui")

if __name__ == "__main__":
    # Ensure all data directories exist
    ensure_directories_exist()
    
    # Get host and port from environment variables or use defaults
    host = os.environ.get("NUCLEI_MCP_UI_HOST", "0.0.0.0")
    port = int(os.environ.get("NUCLEI_MCP_UI_PORT", "5000"))
    debug = os.environ.get("NUCLEI_MCP_UI_DEBUG", "true").lower() == "true"
    
    logger.info(f"Starting Nuclei MCP Scanner UI on {host}:{port}")
    run_app(host=host, port=port, debug=debug) 