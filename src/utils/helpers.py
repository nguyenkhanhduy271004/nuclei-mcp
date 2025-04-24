"""
Helper utilities for the Nuclei MCP server.

This module provides common utility functions used across the server.
"""

import os
import json
from typing import Dict, Any, List, Optional
import logging

logger = logging.getLogger("nuclei-mcp")

# Base path for data storage
DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "data")


def ensure_directories_exist() -> None:
    """Ensure that all necessary data directories exist."""
    directories = [
        os.path.join(DATA_DIR, "vulnerabilities"),
        os.path.join(DATA_DIR, "templates"),
        os.path.join(DATA_DIR, "scans")
    ]
    
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
        logger.info(f"Ensured directory exists: {directory}")


def save_json_to_file(data: Dict[str, Any], directory: str, filename: str) -> str:
    """
    Save JSON data to a file.
    
    Args:
        data: The data to save
        directory: The directory to save to
        filename: The filename to use
        
    Returns:
        The full path to the saved file
    """
    os.makedirs(directory, exist_ok=True)
    
    filepath = os.path.join(directory, filename)
    
    with open(filepath, "w") as f:
        json.dump(data, f, indent=2)
    
    logger.debug(f"Saved data to file: {filepath}")
    return filepath


def load_json_from_file(filepath: str) -> Optional[Dict[str, Any]]:
    """
    Load JSON data from a file.
    
    Args:
        filepath: The path to the file to load
        
    Returns:
        The loaded data, or None if the file doesn't exist
    """
    if not os.path.exists(filepath):
        logger.warning(f"File not found: {filepath}")
        return None
    
    try:
        with open(filepath, "r") as f:
            data = json.load(f)
        
        logger.debug(f"Loaded data from file: {filepath}")
        return data
    except json.JSONDecodeError:
        logger.error(f"Failed to parse JSON from file: {filepath}")
        return None
    except Exception as e:
        logger.exception(f"Error loading file: {filepath}")
        return None


def list_json_files(directory: str) -> List[str]:
    """
    List all JSON files in a directory.
    
    Args:
        directory: The directory to list
        
    Returns:
        A list of filenames (without extension)
    """
    if not os.path.exists(directory):
        logger.warning(f"Directory not found: {directory}")
        return []
    
    filenames = []
    
    for filename in os.listdir(directory):
        if filename.endswith(".json"):
            # Remove the .json extension
            filenames.append(filename[:-5])
    
    return filenames 