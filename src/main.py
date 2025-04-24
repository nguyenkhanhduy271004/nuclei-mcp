#!/usr/bin/env python3
"""
Nuclei MCP Server - Main Entry Point

This module implements a Model Context Protocol (MCP) server for accessing
Nuclei vulnerability scanning data and functionality from AI assistants.
"""

import sys
import json
import logging
from typing import Dict, Any, List, Optional, Union

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stderr)]
)
logger = logging.getLogger("nuclei-mcp")

# Import MCP modules
from src.resources import vuln_resource
from src.tools import scan_tools
from src.prompts import analysis_prompts

class NucleiMcpServer:
    """Main MCP server implementation for Nuclei integration."""
    
    def __init__(self):
        """Initialize the MCP server."""
        self.resources = vuln_resource.get_resource_handlers()
        self.tools = scan_tools.get_tool_handlers()
        self.prompts = analysis_prompts.get_prompt_handlers()
    
    def handle_message(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Handle an incoming MCP message."""
        logger.debug(f"Received message: {message}")
        
        message_type = message.get("type")
        if message_type == "ping":
            return self._handle_ping(message)
        elif message_type == "resource":
            return self._handle_resource(message)
        elif message_type == "tool":
            return self._handle_tool(message)
        elif message_type == "prompt":
            return self._handle_prompt(message)
        else:
            logger.warning(f"Unknown message type: {message_type}")
            return {
                "type": "error",
                "error": {
                    "message": f"Unsupported message type: {message_type}"
                }
            }
    
    def _handle_ping(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Handle ping message with server capabilities."""
        logger.info("Handling ping message")
        return {
            "type": "pong",
            "capabilities": {
                "protocol_version": "0.1",
                "server_info": {
                    "name": "nuclei-mcp",
                    "version": "1.0.0",
                    "description": "A Model Context Protocol server for Nuclei vulnerability scanner"
                },
                "resource_patterns": [
                    "nuclei://*"
                ],
                "tools": list(self.tools.keys()),
                "prompts": list(self.prompts.keys())
            }
        }
    
    def _handle_resource(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Handle resource request."""
        uri = message.get("uri", "")
        logger.info(f"Handling resource request for {uri}")
        
        # Find the appropriate handler based on the URI
        for pattern, handler in self.resources.items():
            if pattern.match(uri):
                return handler(message)
        
        return {
            "type": "error",
            "error": {
                "message": f"No handler found for URI: {uri}"
            }
        }
    
    def _handle_tool(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Handle tool request."""
        tool_name = message.get("name", "")
        logger.info(f"Handling tool request for {tool_name}")
        
        # Find the appropriate tool handler
        if tool_name in self.tools:
            return self.tools[tool_name](message)
        
        return {
            "type": "error",
            "error": {
                "message": f"Unknown tool: {tool_name}"
            }
        }
    
    def _handle_prompt(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Handle prompt request."""
        prompt_name = message.get("name", "")
        logger.info(f"Handling prompt request for {prompt_name}")
        
        # Find the appropriate prompt handler
        if prompt_name in self.prompts:
            return self.prompts[prompt_name](message)
        
        return {
            "type": "error",
            "error": {
                "message": f"Unknown prompt: {prompt_name}"
            }
        }

def main():
    """Main entry point for the MCP server."""
    server = NucleiMcpServer()
    
    logger.info("Starting Nuclei MCP server")
    
    # MCP communication happens over stdin/stdout
    for line in sys.stdin:
        try:
            message = json.loads(line)
            response = server.handle_message(message)
            json_response = json.dumps(response)
            print(json_response, flush=True)
        except json.JSONDecodeError:
            logger.error(f"Failed to parse input as JSON: {line}")
            error_response = {
                "type": "error",
                "error": {
                    "message": "Failed to parse input as JSON"
                }
            }
            print(json.dumps(error_response), flush=True)
        except Exception as e:
            logger.exception("Error processing message")
            error_response = {
                "type": "error",
                "error": {
                    "message": f"Error processing message: {str(e)}"
                }
            }
            print(json.dumps(error_response), flush=True)

if __name__ == "__main__":
    main() 