#!/usr/bin/env python3
"""
VLESS Key Parser

This script parses VLESS keys from the vpnkeys.org website and creates a subscription file.
"""

import re
import os
import sys
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse

def parse_vless_keys(html_content):
    """
    Parse VLESS keys from HTML content.
    
    Args:
        html_content (str): HTML content to parse
        
    Returns:
        list: List of valid VLESS keys
    """
    # Regular expression to find VLESS URLs
    vless_pattern = r'vless://[^"\s<>]+'
    
    # Find all matches
    all_matches = re.findall(vless_pattern, html_content)
    
    # Filter out invalid matches (like explanatory text containing "vless://")
    valid_keys = []
    for match in all_matches:
        # Valid VLESS keys typically have a UUID after the vless:// prefix
        # and contain @ symbol for the server address
        if '@' in match and not 'для импорта' in match:
            # Basic validation: check if it has the structure of a VLESS URL
            try:
                # The part after vless:// should be a valid UUID
                uuid_part = match.split('://')[1].split('@')[0]
                # UUID should be 36 characters (including hyphens)
                if len(uuid_part) == 36 and uuid_part.count('-') == 4:
                    valid_keys.append(match)
            except:
                # Skip invalid entries
                pass
    
    return valid_keys

def fetch_website(url):
    """
    Fetch website content.
    
    Args:
        url (str): URL to fetch
        
    Returns:
        str: HTML content
    """
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.text
    except Exception as e:
        print(f"Error fetching website: {e}")
        return None

def save_subscription_file(keys, output_file="vpnkeys_subscription.txt"):
    """
    Save VLESS keys to a subscription file.
    
    Args:
        keys (list): List of VLESS keys
        output_file (str): Output file path
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            for key in keys:
                f.write(f"{key}\n")
        return True
    except Exception as e:
        print(f"Error saving subscription file: {e}")
        return False

def main():
    """Main function."""
    # Get the directory where the script is located
    script_dir = os.path.dirname(os.path.abspath(__file__))
    output_file = os.path.join(script_dir, "vpnkeys_subscription.txt")
    
    # Check if HTML file is provided as argument
    if len(sys.argv) > 1 and os.path.exists(sys.argv[1]):
        # Read from local HTML file
        with open(sys.argv[1], 'r', encoding='utf-8') as f:
            html_content = f.read()
        print(f"Reading from local file: {sys.argv[1]}")
    else:
        # Fetch from website
        url = "https://vpnkeys.org/"
        print(f"Fetching from website: {url}")
        html_content = fetch_website(url)
        if not html_content:
            print("Failed to fetch website content. Exiting.")
            return
    
    # Parse VLESS keys
    vless_keys = parse_vless_keys(html_content)
    
    # Print statistics
    print(f"Found {len(vless_keys)} valid VLESS keys")
    
    # Save to subscription file
    if save_subscription_file(vless_keys, output_file):
        print(f"Subscription file saved to: {output_file}")
        print(f"output_filename={os.path.basename(output_file)}")
    else:
        print("Failed to save subscription file")

if __name__ == "__main__":
    main()
