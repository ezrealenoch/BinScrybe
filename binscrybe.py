#!/usr/bin/env python3
"""
BinScrybe - Binary Analysis Tool

Analyzes binaries using various security tools and formats the output for LLM ingestion.
"""

import argparse
import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
import traceback
import math
import struct
import binascii
import io
import re


class BinScrybe:
    def __init__(self, target_file, output_file=None, tools_dir="tools", die_dir=None, skip_capa=False, 
                 skip_die=False, skip_pesieve=False, verbose=False):
        """Initialize BinScrybe.
        
        Args:
            target_file (str): Path to the binary file to analyze.
            output_file (str, optional): Path to the output file. Defaults to None.
            tools_dir (str, optional): Path to the directory containing analysis tools. Defaults to "tools".
            die_dir (str, optional): Path to the DIE directory. Defaults to None (will try to auto-detect).
            skip_capa (bool, optional): Skip CAPA analysis. Defaults to False.
            skip_die (bool, optional): Skip DIE analysis. Defaults to False.
            skip_pesieve (bool, optional): Skip PE-sieve analysis. Defaults to False.
            verbose (bool, optional): Enable verbose output. Defaults to False.
        """
        self.target_file = os.path.abspath(target_file)
        if not os.path.exists(self.target_file):
            raise FileNotFoundError(f"Target file not found: {self.target_file}")
        
        self.filename = os.path.basename(self.target_file)
        self.output_file = output_file or f"{os.path.splitext(self.filename)[0]}_summary.md"
        
        # Store directory paths - keep these relative when possible for portability
        script_dir = os.path.dirname(os.path.abspath(__file__))
        if os.path.isabs(tools_dir):
            self.tools_dir = tools_dir
        else:
            # Make relative to script location for consistency
            self.tools_dir = os.path.normpath(os.path.join(script_dir, tools_dir))
        
        # Handle die_dir parameter
        if die_dir:
            if os.path.isabs(die_dir):
                self.die_dir = die_dir
            else:
                # Make relative to script location for consistency
                self.die_dir = os.path.normpath(os.path.join(script_dir, die_dir))
        else:
            self.die_dir = None
        
        self.skip_capa = skip_capa
        self.skip_die = skip_die
        self.skip_pesieve = skip_pesieve
        self.verbose = verbose
        
        # Analysis results
        self.capa_results = {}
        self.die_results = {}
        self.pesieve_results = {}
        
        # Create tools directory if it doesn't exist
        os.makedirs(self.tools_dir, exist_ok=True)
        
        # Initialize results dictionary
        self.results = {
            "file": self.filename,
            "analysis_time": datetime.now().isoformat(),
            "hashes": self._calculate_hashes(),
            "file_size": os.path.getsize(self.target_file),
            "capa": {},
            "die": {},
            "pesieve": {}
        }
    
    def _calculate_hashes(self) -> Dict[str, str]:
        """Calculate various hashes for the binary."""
        hashes = {}
        
        with open(self.target_file, 'rb') as f:
            content = f.read()
            hashes["md5"] = hashlib.md5(content).hexdigest()
            hashes["sha1"] = hashlib.sha1(content).hexdigest()
            hashes["sha256"] = hashlib.sha256(content).hexdigest()
        
        return hashes
    
    def _run_command(self, cmd: List[str], timeout: int = 300) -> Dict[str, Any]:
        """Run a command and return its output and error information."""
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False
            )
            return {
                "stdout": result.stdout,
                "stderr": result.stderr,
                "exit_code": result.returncode,
                "success": result.returncode == 0
            }
        except subprocess.TimeoutExpired:
            return {
                "stdout": "",
                "stderr": f"Command timed out after {timeout} seconds: {' '.join(cmd)}",
                "exit_code": -1,
                "success": False
            }
        except Exception as e:
            return {
                "stdout": "",
                "stderr": f"Error running command {' '.join(cmd)}: {str(e)}",
                "exit_code": -1,
                "success": False
            }
    
    def run_capa(self) -> Dict[str, Any]:
        """Run CAPA and parse the results."""
        if self.skip_capa:
            return {
                "error": "CAPA analysis skipped",
                "capabilities": [],
                "rules_triggered": []
            }
        
        # Look in tools directory first, then try PATH
        capa_path = os.path.join(self.tools_dir, "capa.exe")
        if not os.path.exists(capa_path):
            print(f"CAPA not found in tools directory, checking PATH...")
            capa_path = "capa.exe"  # Try using from PATH
        
        if not os.path.exists(capa_path) and not self._command_exists("capa.exe"):
            print("Warning: CAPA not found in tools directory or in PATH")
            return {
                "error": "CAPA executable not found",
                "capabilities": [],
                "rules_triggered": []
            }
            
        output_file = os.path.join(self.tools_dir, "capa_output.json")
        
        # First run CAPA with -vv to get detailed output with addresses
        print("Running CAPA...")
        cmd = [capa_path, self.target_file, "-vv"]
        result = self._run_command(cmd)
        
        if not result["success"]:
            error_msg = result["stderr"] or f"CAPA exited with code {result['exit_code']}"
            print(f"Error running CAPA: {error_msg}")
            return {
                "error": error_msg,
                "capabilities": [],
                "rules_triggered": []
            }
        
        # Parse the text-based verbose output to extract capabilities with addresses
        capabilities = []
        rules_triggered = []
        
        capa_output = result["stdout"].split("\n")
        
        # Process text output line by line
        i = 0
        current_capability = None
        current_addresses = []
        namespace = None
        skip_info_lines = True  # Skip metadata lines at the beginning
        
        while i < len(capa_output):
            line = capa_output[i].strip()
            
            # Skip empty lines and metadata lines at the beginning
            if not line or (skip_info_lines and (line.startswith("md5") or 
                                                line.startswith("sha1") or 
                                                line.startswith("path") or
                                                line.startswith("timestamp") or
                                                line.startswith("capa version") or
                                                line.startswith("os") or
                                                line.startswith("format") or
                                                line.startswith("arch") or
                                                line.startswith("analysis") or
                                                line.startswith("extractor") or
                                                line.startswith("base address") or
                                                line.startswith("rules") or
                                                line.startswith("function count") or
                                                line.startswith("library function count") or
                                                line.startswith("total feature count"))):
                i += 1
                continue
            
            # Stop skipping info lines once we get past the header
            skip_info_lines = False
            
            # If we find a capability name (it will be followed by details)
            if (not line.startswith(" ") and 
                not line.startswith("function @") and 
                not line.startswith("basic block @") and
                not line.startswith("instruction @") and 
                not line.startswith("scope") and
                not line.startswith("mbc") and
                not line.startswith("references") and
                not line.startswith("-") and
                not line.startswith("=") and
                ":" not in line[:5]):
                
                # Save previous capability if exists
                if current_capability and current_addresses:
                    # Create capability name with namespace if available
                    capability_name = current_capability
                    if namespace and not namespace.startswith("author") and "matches" not in namespace:
                        capability_name = f"{namespace}: {current_capability}"
                    
                    # Format address string
                    addr_str = ", ".join(current_addresses[:5])
                    if len(current_addresses) > 5:
                        addr_str += f" (+ {len(current_addresses) - 5} more)"
                    
                    capabilities.append(f"{capability_name} @ {addr_str}")
                    rule_info = {
                        "name": capability_name,
                        "addresses": current_addresses
                    }
                    rules_triggered.append(rule_info)
                
                # Start a new capability
                current_capability = line
                current_addresses = []
                namespace = None
                
                # Look for namespace in the next line
                if i+1 < len(capa_output) and capa_output[i+1].strip().startswith("namespace"):
                    namespace = capa_output[i+1].strip().replace("namespace", "").strip()
                
                # Skip metadata lines
                j = i + 1
                while j < len(capa_output) and (capa_output[j].strip().startswith("author") or 
                                               capa_output[j].strip().startswith("scope") or
                                               capa_output[j].strip().startswith("namespace") or
                                               capa_output[j].strip().startswith("att&ck") or
                                               capa_output[j].strip().startswith("mbc") or
                                               capa_output[j].strip().startswith("references")):
                    j += 1
                
                i = j
            
            # Look for addresses (indicated by @ symbol followed by hex)
            elif "@" in line and "0x" in line:
                # Extract all addresses from the line
                address_matches = re.findall(r'@ (0x[0-9a-fA-F]+)', line)
                if address_matches:
                    current_addresses.extend(address_matches)
                
                # Also check for comma-separated addresses
                comma_addr_matches = re.findall(r'(0x[0-9a-fA-F]+)(?:, )?(0x[0-9a-fA-F]+)?(?:, )?(0x[0-9a-fA-F]+)?', line)
                for match in comma_addr_matches:
                    for addr in match:
                        if addr and addr not in current_addresses:
                            current_addresses.append(addr)
                
                i += 1
            else:
                i += 1
        
        # Add the last capability if any
        if current_capability and current_addresses:
            # Create capability name with namespace if available
            capability_name = current_capability
            if namespace and not namespace.startswith("author") and "matches" not in namespace:
                capability_name = f"{namespace}: {current_capability}"
            
            # Format address string
            addr_str = ", ".join(current_addresses[:5])
            if len(current_addresses) > 5:
                addr_str += f" (+ {len(current_addresses) - 5} more)"
            
            capabilities.append(f"{capability_name} @ {addr_str}")
            rule_info = {
                "name": capability_name,
                "addresses": current_addresses
            }
            rules_triggered.append(rule_info)
        
        # If no capabilities found using text method, try the JSON method as fallback
        if not capabilities:
            print("No capabilities found using text parsing, trying JSON method...")
            cmd = [capa_path, self.target_file, "-j"]
            result = self._run_command(cmd)
            
            if result["success"]:
                try:
                    capa_results = json.loads(result["stdout"])
                    
                    if "rules" in capa_results:
                        for namespace, rules in capa_results["rules"].items():
                            # Skip meta/source/matches
                            if namespace in ["meta", "source", "matches"]:
                                continue
                            
                            for rule_name, details in rules.items():
                                capabilities.append(f"{namespace}: {rule_name}")
                                rule_info = {
                                    "name": f"{namespace}: {rule_name}",
                                    "addresses": []
                                }
                                rules_triggered.append(rule_info)
                except json.JSONDecodeError:
                    pass
        
        # Clean up and filter capabilities
        filtered_capabilities = []
        for capability in capabilities:
            # Skip capabilities that start with author or have author names
            if capability.startswith("author") or "@mandiant.com" in capability or "@google.com" in capability:
                continue
                
            # Skip capabilities that are just addresses or have "match:" prefix with no clear description
            if " @ 0x" in capability and (
                capability.startswith("basic block:") or
                capability.startswith("number:") or
                capability.startswith("optional:") or
                capability.startswith("operand[") or
                capability.startswith("mnemonic:") or
                "scope" in capability or
                "instruction:" in capability or
                "references" in capability or
                capability.startswith("match:")):
                continue
                
            # Skip URLs and email addresses
            if ("http" in capability and "://" in capability) or "@" in capability and "." in capability:
                continue
                
            # Skip cryptic entries that are likely just internal references
            if capability.startswith("[") and "]" in capability and len(capability.split("]")[0]) < 15:
                continue
                
            # Skip "match" entries - these are usually noise
            if capability.startswith("match"):
                continue
                
            # Keep the capability
            filtered_capabilities.append(capability)
        
        # Save output for reference
        with open(output_file, 'w') as f:
            f.write("\n".join(filtered_capabilities))
        
        return {
            "capabilities": filtered_capabilities,
            "rules_triggered": rules_triggered
        }
    
    def run_die(self) -> Dict[str, Any]:
        """Run Detect-It-Easy and parse the results."""
        if self.skip_die:
            return {
                "error": "DIE analysis skipped",
                "packer": None,
                "compiler": None,
                "linker": None,
                "entropy": None
            }
        
        # Define locations to check for DIE, starting with the most likely location
        possible_die_paths = [
            os.path.join(self.tools_dir, "die_winxp_portable_3.10_x86"),  # In tools dir
            self.die_dir if self.die_dir else None,  # User-specified dir
            "die_winxp_portable_3.10_x86",  # In current dir
            os.path.join(os.path.dirname(self.tools_dir), "die_winxp_portable_3.10_x86")  # Next to tools dir
        ]
        
        # Filter out None values
        possible_die_paths = [p for p in possible_die_paths if p]
        
        # Try each location until we find one that exists
        die_dir = None
        for path in possible_die_paths:
            if os.path.exists(path):
                if os.path.exists(os.path.join(path, "diec.exe")) or os.path.exists(os.path.join(path, "die.exe")):
                    die_dir = path
                    print(f"Using DIE from: {die_dir}")
                    break
        
        if not die_dir:
            print("DIE not found in any of the expected locations")
            return {
                "error": "DIE directory not found",
                "packer": None,
                "compiler": None,
                "linker": None,
                "entropy": None
            }
        
        die_cli_path = os.path.join(die_dir, "diec.exe")
        die_gui_path = os.path.join(die_dir, "die.exe")
        die_light_path = os.path.join(die_dir, "diel.exe")
        
        if not os.path.exists(die_cli_path) and not os.path.exists(die_gui_path) and not os.path.exists(die_light_path):
            print(f"DIE not found in {die_dir}")
            return {
                "error": f"DIE not found in {die_dir}",
                "packer": None,
                "compiler": None,
                "linker": None,
                "entropy": None
            }
        
        output_file = os.path.join(self.tools_dir, "die_output.json")
        
        # First try the CLI version (diec.exe)
        if os.path.exists(die_cli_path):
            print(f"Using DIE CLI: {die_cli_path}")
            # Use enhanced options for better results
            # -d: Deep scan
            # -e: Show heuristic scan
            # -j: Output as JSON for easier parsing
            # -i: Show file info
            cmd = [die_cli_path, "-d", "-e", "-i", "-j", self.target_file]
            print(f"Running DIE command: {' '.join(cmd)}")
            
            result = self._run_command(cmd)
            
            # If the first command fails, try different parameter combinations
            if not result["success"] or not result["stdout"]:
                print("First DIE command failed, trying alternative...")
                # Try just the basic scan with JSON output
                cmd = [die_cli_path, "-j", self.target_file]
                result = self._run_command(cmd)
                
                # If that still fails, try without JSON
                if not result["success"] or not result["stdout"]:
                    print("Second DIE command failed, trying plain text...")
                    cmd = [die_cli_path, self.target_file]
                    result = self._run_command(cmd)
        
        # If CLI version fails or doesn't exist, try the GUI version
        if not os.path.exists(die_cli_path) or not result["success"] or not result["stdout"]:
            if os.path.exists(die_gui_path):
                print(f"CLI version failed or not found, trying GUI version: {die_gui_path}")
                # Try GUI version with console output option
                cmd = [die_gui_path, self.target_file, "-console"]
                result = self._run_command(cmd)
                
                # If that fails, try with no special options
                if not result["success"] or not result["stdout"]:
                    print("GUI with console option failed, trying basic GUI command...")
                    cmd = [die_gui_path, self.target_file]
                    result = self._run_command(cmd)
            
            # If GUI version fails or doesn't exist, try the light version
            if (not os.path.exists(die_gui_path) or not result["success"] or not result["stdout"]) and os.path.exists(die_light_path):
                print(f"GUI version failed or not found, trying light version: {die_light_path}")
                cmd = [die_light_path, self.target_file]
                result = self._run_command(cmd)
        
        # If all DIE versions fail, try to analyze basic file info
        if not result["success"] or not result["stdout"]:
            print("All DIE commands failed, parsing file manually...")
            return self._fallback_file_info()
        
        die_output = result["stdout"]
        
        # Try to parse output as JSON first
        try:
            if result["stdout"].strip().startswith("{") or result["stdout"].strip().startswith("["):
                die_json = json.loads(result["stdout"])
                
                # Extract information from JSON output
                # DIE CLI JSON schema may vary, we'll try to handle multiple formats
                compiler = None
                packer = None
                entropy = None
                linker = None
                file_format = None
                suspicious_indicators = []
                
                # Parse JSON structure (format depends on DIE version)
                if isinstance(die_json, dict):
                    # Newer format
                    if "detects" in die_json:
                        for detect in die_json["detects"]:
                            if detect.get("type", "").lower() == "compiler":
                                compiler = detect.get("name", "Unknown")
                            elif detect.get("type", "").lower() == "packer":
                                packer = detect.get("name", "Unknown")
                            elif detect.get("type", "").lower() == "linker":
                                linker = detect.get("name", "Unknown")
                            elif detect.get("type", "").lower() == "format":
                                file_format = detect.get("name", "Unknown")
                
                    if "entropy" in die_json:
                        entropy = die_json["entropy"]
                elif isinstance(die_json, list):
                    # Older format with array of detections
                    for item in die_json:
                        if item.get("type", "").lower() == "compiler":
                            compiler = item.get("name", "Unknown")
                        elif item.get("type", "").lower() == "packer":
                            packer = item.get("name", "Unknown")
                        elif item.get("type", "").lower() == "linker":
                            linker = item.get("name", "Unknown")
                        elif item.get("type", "").lower() == "format":
                            file_format = item.get("name", "Unknown")
                
                # Determine if there are suspicious indicators
                if packer and "UPX" not in packer:
                    suspicious_indicators.append(f"Packed with {packer} (potential obfuscation)")
                
                if entropy and entropy > 7.0:
                    suspicious_indicators.append(f"High entropy ({entropy}) suggests encryption or compression")
                
                return {
                    "compiler": compiler,
                    "packer": packer,
                    "linker": linker,
                    "entropy": entropy,
                    "file_format": file_format,
                    "suspicious_indicators": suspicious_indicators
                }
        except json.JSONDecodeError:
            print("Failed to parse DIE output as JSON, parsing text output...")
            pass
        
        # If JSON parsing fails, parse as text
        output_lines = die_output.strip().split("\n")
        compiler = None
        packer = None
        entropy = None
        linker = None
        file_format = None
        suspicious_indicators = []
        
        # Parse text output (format varies depending on DIE version and arguments)
        for line in output_lines:
            line = line.strip()
            
            # Try to identify different parts of output
            if "Entropy:" in line:
                try:
                    entropy = float(line.split("Entropy:")[1].strip().split()[0])
                except (IndexError, ValueError):
                    pass
            
            if "Format:" in line or "filetype:" in line.lower():
                try:
                    file_format = line.split(":", 1)[1].strip()
                except IndexError:
                    pass
            
            if "Compiler:" in line:
                try:
                    compiler = line.split("Compiler:")[1].strip()
                except IndexError:
                    pass
            
            if "Packer:" in line:
                try:
                    packer = line.split("Packer:")[1].strip()
                except IndexError:
                    pass
            
            if "Linker:" in line:
                try:
                    linker = line.split("Linker:")[1].strip()
                except IndexError:
                    pass
            
            # Look for suspicious indicators
            if "suspicious" in line.lower() or "obfuscated" in line.lower():
                suspicious_indicators.append(line.strip())
        
        # Add common suspicious indicators
        if packer and "UPX" not in packer.upper():
            suspicious_indicators.append(f"Packed with {packer} (potential obfuscation)")
        
        if entropy and entropy > 7.0:
            suspicious_indicators.append(f"High entropy ({entropy}) suggests encryption or compression")
        
        # If no data found from output, try fallback analysis
        if not compiler and not packer and not entropy and not file_format:
            print("No useful data from DIE output, using fallback analysis...")
            return self._fallback_file_info()
        
        return {
            "compiler": compiler,
            "packer": packer,
            "linker": linker,
            "entropy": entropy,
            "file_format": file_format,
            "suspicious_indicators": suspicious_indicators
        }
    
    def _fallback_file_info(self) -> Dict[str, Any]:
        """Basic file analysis when DIE tools fail."""
        result = {
            "packer": None,
            "compiler": None,
            "linker": None,
            "entropy": None,
            "file_format": None,
            "suspicious_indicators": []
        }
        
        try:
            with open(self.target_file, "rb") as f:
                data = f.read()
                
            # Calculate file entropy
            if data:
                file_size = len(data)
                byte_counts = {}
                for byte in data:
                    if isinstance(byte, int):  # Python 3
                        byte_counts[byte] = byte_counts.get(byte, 0) + 1
                    else:  # Python 2
                        byte_counts[ord(byte)] = byte_counts.get(ord(byte), 0) + 1
                
                entropy = 0
                for count in byte_counts.values():
                    probability = count / file_size
                    entropy -= probability * math.log2(probability)
                
                result["entropy"] = entropy
                
                if entropy > 7.0:
                    result["suspicious_indicators"].append(f"High entropy ({entropy:.2f}) suggests encryption or compression")
            
            # Check file type based on magic bytes
            if data[:2] == b'MZ':  # Windows PE
                result["file_format"] = "PE32"
                
                # Check for PE header
                e_lfanew = struct.unpack("<I", data[0x3c:0x40])[0]
                if e_lfanew < len(data) - 4:
                    pe_signature = data[e_lfanew:e_lfanew+4]
                    if pe_signature == b'PE\0\0':
                        # Check architecture
                        machine_offset = e_lfanew + 4
                        if machine_offset + 2 <= len(data):
                            machine = struct.unpack("<H", data[machine_offset:machine_offset+2])[0]
                            if machine == 0x014c:
                                result["file_format"] = "PE32 (32-bit)"
                            elif machine == 0x8664:
                                result["file_format"] = "PE32+ (64-bit)"
                        
                        # Look for common section names
                        has_unusual_sections = False
                        section_offset = e_lfanew + 0xF8  # Typical location for first section header
                        
                        if section_offset + 40 < len(data):  # Section header is 40 bytes
                            num_sections_offset = e_lfanew + 6
                            if num_sections_offset + 2 <= len(data):
                                num_sections = struct.unpack("<H", data[num_sections_offset:num_sections_offset+2])[0]
                                
                                # Check if number of sections is reasonable
                                if num_sections > 20:
                                    result["suspicious_indicators"].append(f"Unusually high number of sections: {num_sections}")
                                
                                standard_sections = {b'.text', b'.data', b'.rdata', b'.idata', b'.rsrc', b'.reloc', b'.pdata'}
                                unusual_sections = []
                                
                                for i in range(min(num_sections, 20)):  # Cap at 20 sections to prevent hang
                                    curr_section_offset = section_offset + (40 * i)
                                    if curr_section_offset + 8 <= len(data):
                                        section_name = data[curr_section_offset:curr_section_offset+8].rstrip(b'\0')
                                        if section_name and section_name not in standard_sections:
                                            unusual_sections.append(section_name.decode('utf-8', errors='replace'))
                                
                                if unusual_sections:
                                    result["suspicious_indicators"].append(f"Unusual section names: {', '.join(unusual_sections)}")
                        
                        # Check for overlay data
                        opt_header_size_offset = e_lfanew + 20
                        if opt_header_size_offset + 2 <= len(data):
                            opt_header_size = struct.unpack("<H", data[opt_header_size_offset:opt_header_size_offset+2])[0]
                            sections_offset = e_lfanew + 24 + opt_header_size
                            
                            if sections_offset + 40 <= len(data):
                                # Find the last section to check for overlay
                                num_sections_offset = e_lfanew + 6
                                if num_sections_offset + 2 <= len(data):
                                    num_sections = struct.unpack("<H", data[num_sections_offset:num_sections_offset+2])[0]
                                    
                                    if num_sections > 0:
                                        last_section_offset = sections_offset + (40 * (num_sections - 1))
                                        if last_section_offset + 40 <= len(data):
                                            raw_size_offset = last_section_offset + 16
                                            raw_offset = last_section_offset + 20
                                            
                                            if raw_size_offset + 4 <= len(data) and raw_offset + 4 <= len(data):
                                                raw_size = struct.unpack("<I", data[raw_size_offset:raw_size_offset+4])[0]
                                                raw_ptr = struct.unpack("<I", data[raw_offset:raw_offset+4])[0]
                                                
                                                expected_end = raw_ptr + raw_size
                                                if file_size > expected_end + 1024:  # Allow for padding
                                                    overlay_size = file_size - expected_end
                                                    result["suspicious_indicators"].append(f"Found {overlay_size} bytes of overlay data beyond the last section")
            
            elif data[:4] == b'\x7fELF':  # ELF (Linux)
                result["file_format"] = "ELF"
                if len(data) > 4:
                    if data[4] == 1:  # 32-bit
                        result["file_format"] = "ELF (32-bit)"
                    elif data[4] == 2:  # 64-bit
                        result["file_format"] = "ELF (64-bit)"
            
            elif data[:4] in (b'\xCA\xFE\xBA\xBE', b'\xCE\xFA\xED\xFE', b'\xCF\xFA\xED\xFE'):  # Mach-O
                result["file_format"] = "Mach-O"
            
            elif data[:2] == b'PK':  # ZIP-based (could be JAR, APK, etc.)
                result["file_format"] = "ZIP Archive"
                
                # Try to detect specific file types within the ZIP
                try:
                    import zipfile
                    with zipfile.ZipFile(io.BytesIO(data)) as zip_file:
                        file_list = zip_file.namelist()
                        
                        if any(name.endswith('.dex') for name in file_list):
                            result["file_format"] = "APK (Android Package)"
                        elif 'META-INF/MANIFEST.MF' in file_list:
                            result["file_format"] = "JAR (Java Archive)"
                        elif any(name.endswith('.docx') for name in file_list) or 'word/document.xml' in file_list:
                            result["file_format"] = "DOCX (Word Document)"
                        elif any(name.endswith('.xlsx') for name in file_list) or 'xl/workbook.xml' in file_list:
                            result["file_format"] = "XLSX (Excel Spreadsheet)"
                except:
                    pass
            
            # Calculate file hash
            md5_hash = hashlib.md5(data).hexdigest()
            sha1_hash = hashlib.sha1(data).hexdigest()
            sha256_hash = hashlib.sha256(data).hexdigest()
            
            result["md5"] = md5_hash
            result["sha1"] = sha1_hash
            result["sha256"] = sha256_hash
            
            # Add basic file statistics
            result["file_size"] = file_size
            
        except Exception as e:
            result["error"] = f"Error in fallback analysis: {str(e)}"
        
        return result
    
    def run_pesieve(self) -> Dict[str, Any]:
        """Run PE-sieve and parse the results."""
        if self.skip_pesieve:
            return {
                "error": "PE-sieve analysis skipped",
                "hollowing_detected": False,
                "anomalies": [],
                "injected_sections": [],
                "basic_pe_analysis": {}
            }
        
        # Look in tools directory first, then try PATH
        pesieve_path = os.path.join(self.tools_dir, "pe-sieve64.exe")
        if not os.path.exists(pesieve_path):
            print(f"PE-sieve not found in tools directory, checking PATH...")
            pesieve_path = "pe-sieve64.exe"  # Try using from PATH
            
        if not os.path.exists(pesieve_path) and not self._command_exists("pe-sieve64.exe"):
            print("Warning: PE-sieve not found in tools directory or in PATH")
            
            # Try to do basic PE analysis ourselves
            pe_analysis = self._analyze_pe_file()
            return {
                "error": "PE-sieve executable not found - basic analysis performed",
                "hollowing_detected": False,
                "anomalies": [],
                "injected_sections": [],
                "basic_pe_analysis": pe_analysis
            }
        
        output_file = os.path.join(self.tools_dir, "pesieve_output.txt")
        
        # First check PE-sieve version using help to determine supported parameters
        help_cmd = [pesieve_path, "/help"]
        help_result = self._run_command(help_cmd)
        help_output = help_result["stdout"] or ""
        
        # Try different command formats for PE-sieve with added parameters for better detection
        result = None
        tried_commands = []
        
        # Format 1: Direct file parameter with /file 
        cmd1 = [pesieve_path, "/file", self.target_file, "/shellc", "/data", "3"]
        tried_commands.append(" ".join(cmd1))
        result1 = self._run_command(cmd1)
        
        # Format 2: With /scan_file parameter (newer versions)
        cmd2 = [pesieve_path, "/scan_file", self.target_file, "/shellc", "/data", "3"]
        tried_commands.append(" ".join(cmd2))
        result2 = self._run_command(cmd2)
        
        # Format 3: Direct file parameter (some versions)
        cmd3 = [pesieve_path, self.target_file, "/shellc", "/data", "3"]
        tried_commands.append(" ".join(cmd3))
        result3 = self._run_command(cmd3)
        
        # Format 4: With /data parameter only
        cmd4 = [pesieve_path, "/data", "3", self.target_file]
        tried_commands.append(" ".join(cmd4))
        result4 = self._run_command(cmd4)
        
        # Check which command gave the best output
        if result1["success"] and result1["stdout"]:
            result = result1
        elif result2["success"] and result2["stdout"]:
            result = result2
        elif result3["success"] and result3["stdout"]:
            result = result3
        elif result4["success"] and result4["stdout"]:
            result = result4
        else:
            # If all formats fail, try a basic error check
            candidates = [result1, result2, result3, result4]
            # Check if any contained a useful error message
            for r in candidates:
                if "is not a valid PE file" in r["stderr"]:
                    # This is a valid error for non-PE files
                    with open(output_file, 'w') as f:
                        f.write(f"PE-sieve error: {r['stderr']}\n")
                        f.write("This indicates the file is not a valid PE format executable.")
                    
                    return {
                        "error": "Not a valid PE file",
                        "hollowing_detected": False,
                        "anomalies": [],
                        "injected_sections": [],
                        "basic_pe_analysis": self._analyze_pe_file()
                    }
                    
            # If no useful error found, return generic message with detailed logs
            with open(output_file, 'w') as f:
                f.write("PE-sieve failed to analyze the file with all attempted command formats:\n\n")
                for i, cmd in enumerate(tried_commands):
                    candidates = [result1, result2, result3, result4]
                    f.write(f"Command {i+1}: {cmd}\n")
                    f.write(f"Exit code: {candidates[i]['exit_code']}\n")
                    f.write(f"Stdout: {candidates[i]['stdout']}\n")
                    f.write(f"Stderr: {candidates[i]['stderr']}\n")
                    f.write("\n")
                    
            return {
                "error": "PE-sieve command failed with all attempted formats",
                "hollowing_detected": False,
                "anomalies": [],
                "injected_sections": [],
                "basic_pe_analysis": self._analyze_pe_file()
            }
        
        # Save raw output
        with open(output_file, 'w') as f:
            f.write(result["stdout"])
        
        # Parse the output for malicious indicators
        hollowing_detected = False
        anomalies = []
        injected_sections = []
        
        # Common strings indicating malicious activity
        malicious_indicators = [
            "process hollowing",
            "hollow process",
            "injected section",
            "suspicious section",
            "modified section",
            "shellcode detected",
            "hook detected",
            "implant",
            "patched code",
            "replaced function",
            "IAT hook",
            "memory patch",
            "dumped payload",
            "reflective injection",
            "thread injection",
            "stolen code",
            "code cave"
        ]
        
        # Process line by line
        lines = result["stdout"].splitlines()
        for line in lines:
            line_lower = line.lower()
            
            # Check for process hollowing
            if "hollow" in line_lower or "hollowing" in line_lower:
                hollowing_detected = True
                anomalies.append("Process hollowing detected")
            
            # Check for other malicious indicators
            for indicator in malicious_indicators:
                if indicator in line_lower:
                    # Avoid duplicates
                    if line.strip() not in anomalies:
                        anomalies.append(line.strip())
            
            # Check for section information
            if "section" in line_lower and any(x in line_lower for x in ["inject", "suspicious", "modified", "shellcode"]):
                # Try to extract section name - different format possibilities
                if ":" in line:
                    parts = line.split(":")
                    section_name = parts[0].strip()
                    if section_name and section_name not in injected_sections:
                        injected_sections.append(section_name)
                elif "[" in line and "]" in line:
                    # Try to extract section name from format like "Section[.text]"
                    start = line.find("[")
                    end = line.find("]", start)
                    if start > 0 and end > start:
                        section_name = line[start+1:end].strip()
                        if section_name and section_name not in injected_sections:
                            injected_sections.append(section_name)
        
        # Look for JSON output format (modern PE-sieve versions)
        json_data = None
        json_start = result["stdout"].find("{")
        json_end = result["stdout"].rfind("}")
        if json_start >= 0 and json_end > json_start:
            try:
                json_text = result["stdout"][json_start:json_end+1]
                json_data = json.loads(json_text)
                
                # Extract information from JSON
                if "scan_report" in json_data:
                    report = json_data["scan_report"]
                    
                    # Check for hollowing
                    if "replaced" in report and report["replaced"] > 0:
                        hollowing_detected = True
                        anomalies.append(f"Process hollowing detected (replaced: {report['replaced']})")
                    
                    # Check for hooks
                    if "hooked" in report and report["hooked"] > 0:
                        anomalies.append(f"API hooking detected (hooked: {report['hooked']})")
                    
                    # Check for patches
                    if "patched" in report and report["patched"] > 0:
                        anomalies.append(f"Memory patching detected (patched: {report['patched']})")
                    
                    # Check for implants
                    if "implanted" in report and report["implanted"] > 0:
                        anomalies.append(f"Code implants detected (implanted: {report['implanted']})")
                    
                    # Check for shellcode
                    if "unreachable_file" in report and report["unreachable_file"] > 0:
                        anomalies.append(f"Detached code/shellcode detected (unreachable: {report['unreachable_file']})")
                    
                    # Get all suspicious modules
                    if "modules" in report:
                        for module in report["modules"]:
                            if "suspicious" in module and module["suspicious"]:
                                if "module" in module:
                                    mod_name = module["module"]
                                    anomalies.append(f"Suspicious module: {mod_name}")
                                    if "shellcode" in module and module["shellcode"]:
                                        anomalies.append(f"Shellcode detected in module: {mod_name}")
            except json.JSONDecodeError:
                pass
        
        # Check if PE-sieve is reporting it's not a PE file
        if "is not a valid PE file" in result["stdout"] or "is not a valid PE file" in result["stderr"]:
            return {
                "error": "Not a valid PE file",
                "hollowing_detected": False,
                "anomalies": [],
                "injected_sections": [],
                "basic_pe_analysis": self._analyze_pe_file()
            }
        
        # Return consolidated results
        return {
            "hollowing_detected": hollowing_detected,
            "anomalies": anomalies,
            "injected_sections": injected_sections,
            "raw_output": result["stdout"]
        }
    
    def _analyze_pe_file(self) -> Dict[str, Any]:
        """Perform basic PE file analysis without external tools."""
        pe_info = {
            "is_pe": False,
            "sections": [],
            "imports": [],
            "suspicious_imports": []
        }
        
        try:
            with open(self.target_file, 'rb') as f:
                # Check for MZ header
                magic = f.read(2)
                if magic != b'MZ':
                    return pe_info
                
                pe_info["is_pe"] = True
                
                # Read more for basic analysis
                header = f.read(4094)  # Read up to 4KB total
                
                # Check for PE header
                if b'PE\0\0' not in header:
                    pe_info["error"] = "MZ header found but PE header missing"
                    return pe_info
                
                # Look for common suspicious strings in the binary
                # This is a very basic heuristic approach
                common_suspicious_imports = [
                    b"VirtualAlloc",
                    b"WriteProcessMemory",
                    b"CreateRemoteThread",
                    b"LoadLibrary",
                    b"GetProcAddress",
                    b"WSASocket",
                    b"connect",
                    b"URLDownload",
                    b"ShellExecute",
                    b"CreateProcess"
                ]
                
                # Check the whole file for these strings
                f.seek(0)
                content = f.read()
                for sus_import in common_suspicious_imports:
                    if sus_import in content:
                        pe_info["suspicious_imports"].append(sus_import.decode('ascii', errors='ignore'))
                
        except Exception as e:
            pe_info["error"] = str(e)
        
        return pe_info
    
    def _command_exists(self, cmd):
        """Check if a command exists in the PATH."""
        for path in os.environ.get("PATH", "").split(os.pathsep):
            cmd_path = os.path.join(path, cmd)
            if os.path.exists(cmd_path) and os.access(cmd_path, os.X_OK):
                return True
        return False
    
    def analyze(self) -> Dict[str, Any]:
        """Run all analysis tools and gather results."""
        print(f"Analyzing {self.target_file}...")
        
        # Run each tool and store results
        if not self.skip_capa:
            print("Running CAPA...")
            self.capa_results = self.run_capa()
        
        if not self.skip_die:
            print("Running DIE...")
            self.die_results = self.run_die()
        
        if not self.skip_pesieve:
            print("Running PE-sieve...")
            self.pesieve_results = self.run_pesieve()
        
        # Save full report
        report_path = os.path.join(self.tools_dir, "full_report.json")
        with open(report_path, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        # Generate summary
        self._generate_summary()
        
        return self.results
    
    def _generate_summary(self) -> None:
        """Generate a detailed verbose summary report with all information from analysis tools."""
        summary_path = self.output_file
        
        summary = []
        summary.append("# BinScrybe Analysis Summary\n")
        
        # Basic Info - More detailed
        summary.append("## Basic Info")
        summary.append(f"File: {self.results['file']}")
        summary.append(f"Path: {self.target_file}")
        summary.append(f"Size: {self._format_size(self.results['file_size'])} ({self.results['file_size']} bytes)")
        summary.append(f"MD5: {self.results['hashes']['md5']}")
        summary.append(f"SHA1: {self.results['hashes']['sha1']}")
        summary.append(f"SHA256: {self.results['hashes']['sha256']}")
        summary.append(f"Analysis Time: {self.results['analysis_time']}")
        summary.append("")
        
        # CAPA Capabilities - Detailed listing
        if "capabilities" in self.capa_results and self.capa_results["capabilities"]:
            summary.append("## CAPA Capabilities Detected")
            summary.append(f"Total capabilities found: {len(self.capa_results['capabilities'])}")
            summary.append("")
            
            # Group capabilities by category
            categories = {}
            
            for capability in self.capa_results["capabilities"]:
                # Find the category
                category = "Uncategorized"
                if ":" in capability:
                    parts = capability.split(":", 1)
                    if "/" in parts[0]:
                        # Handle namespaced capabilities like "host-interaction/file-system"
                        category = parts[0].strip().split("/")[0]
                    else:
                        category = parts[0].strip()
                
                # Add to category list
                if category not in categories:
                    categories[category] = []
                categories[category].append(capability)
            
            # Define category order for more logical presentation
            category_order = [
                "anti-analysis",
                "host-interaction",
                "data-manipulation",
                "collection",
                "targeting",
                "communication",
                "executable",
                "crypto",
                "persistence",
                "process",
                "load-code",
                "linking",
                "Defense Evasion",
                "Discovery",
                "Execution",
                "General",
                "Uncategorized"
            ]
            
            # Custom sorting function
            def category_sort_key(cat):
                try:
                    return category_order.index(cat)
                except ValueError:
                    return len(category_order)
            
            # Output capabilities grouped by category
            for category in sorted(categories.keys(), key=category_sort_key):
                summary.append(f"\n### {category.title()}")
                summary.append(f"Total capabilities in this category: {len(categories[category])}")
                cap_list = categories[category]
                for cap in sorted(cap_list):
                    summary.append(f"- {cap}")
            
            # Include the raw rules triggered
            if "rules_triggered" in self.capa_results and self.capa_results["rules_triggered"]:
                summary.append("\n### Detailed Rule Triggers")
                for rule in self.capa_results["rules_triggered"]:
                    rule_name = rule.get('name', 'Unknown rule')
                    addresses = rule.get('addresses', [])
                    summary.append(f"- **{rule_name}**")
                    if addresses:
                        summary.append(f"  - Found at {len(addresses)} locations:")
                        for addr in addresses[:20]:  # Limit to first 20 to avoid extreme verbosity
                            summary.append(f"    - {addr}")
                        if len(addresses) > 20:
                            summary.append(f"    - (+ {len(addresses) - 20} more addresses)")
            
            summary.append("")
        elif "error" in self.capa_results:
            summary.append("## CAPA Analysis")
            summary.append(f"- Error: {self.capa_results['error']}")
            summary.append("")
        
        # DIE Info - Detailed
        summary.append("## Detect It Easy (DIE) Analysis")
        if "error" in self.die_results:
            summary.append(f"- Error: {self.die_results['error']}")
        else:
            summary.append("### File Information")
            if self.die_results.get("file_format"):
                summary.append(f"- File format: {self.die_results['file_format']}")
            else:
                summary.append("- File format: Not detected")
                
            if self.die_results.get("compiler"):
                summary.append(f"- Compiler: {self.die_results['compiler']}")
            else:
                summary.append("- Compiler: Not detected")
                
            if self.die_results.get("packer"):
                summary.append(f"- Packer: {self.die_results['packer']}")
            else:
                summary.append("- Packer: Not detected")
                
            if self.die_results.get("linker"):
                summary.append(f"- Linker: {self.die_results['linker']}")
            else:
                summary.append("- Linker: Not detected")
                
            if self.die_results.get("entropy") is not None:
                entropy = self.die_results["entropy"]
                entropy_desc = "High" if entropy > 7.0 else "Medium" if entropy > 5.0 else "Low"
                summary.append(f"- Entropy: {entropy} ({entropy_desc})")
                
                # Add more context about entropy values
                if entropy > 7.0:
                    summary.append("  - Note: Very high entropy (>7.0) often indicates encryption, compression, or obfuscation")
                elif entropy > 6.5:
                    summary.append("  - Note: High entropy (>6.5) may indicate some form of compression or encoding")
                elif entropy < 5.0:
                    summary.append("  - Note: Low entropy (<5.0) is typical for uncompressed executables with plain text")
            else:
                summary.append("- Entropy: Not calculated")
            
            # Add any suspicious indicators found by DIE
            if "suspicious_indicators" in self.die_results and self.die_results["suspicious_indicators"]:
                summary.append("\n### Suspicious Indicators from DIE")
                summary.append(f"Total suspicious indicators found: {len(self.die_results['suspicious_indicators'])}")
                for indicator in self.die_results["suspicious_indicators"]:
                    summary.append(f"- {indicator}")
            else:
                summary.append("\n### Suspicious Indicators")
                summary.append("- No suspicious indicators detected by DIE")
            
            # Include additional data if available
            if "md5" in self.die_results:
                summary.append("\n### File Hashes (from DIE)")
                summary.append(f"- MD5: {self.die_results['md5']}")
                summary.append(f"- SHA1: {self.die_results.get('sha1', 'Not calculated')}")
                summary.append(f"- SHA256: {self.die_results.get('sha256', 'Not calculated')}")
            
            if "file_size" in self.die_results:
                summary.append(f"\n- File size (reported by DIE): {self.die_results['file_size']} bytes")
                
        summary.append("")
        
        # PE-sieve Anomalies - Detailed
        summary.append("## PE-sieve Analysis")
        
        if "error" in self.pesieve_results:
            summary.append(f"- Note: {self.pesieve_results['error']}")
        else:
            # Report process hollowing status explicitly
            summary.append(f"### Process Hollowing Detection")
            if self.pesieve_results.get("hollowing_detected", False):
                summary.append("- **WARNING**: Process hollowing detected")
            else:
                summary.append("- No process hollowing detected")
            
            # Report all anomalies
            if self.pesieve_results.get("anomalies"):
                summary.append(f"\n### Anomalies Detected ({len(self.pesieve_results['anomalies'])} total)")
                for anomaly in self.pesieve_results["anomalies"]:
                    summary.append(f"- {anomaly}")
            else:
                summary.append("\n### Anomalies")
                summary.append("- No anomalies detected")
            
            # Report injected sections
            if self.pesieve_results.get("injected_sections"):
                summary.append(f"\n### Injected Sections ({len(self.pesieve_results['injected_sections'])} total)")
                for section in self.pesieve_results["injected_sections"]:
                    summary.append(f"- Suspicious injected code in section: {section}")
            else:
                summary.append("\n### Injected Sections")
                summary.append("- No injected sections detected")
            
            # Include basic PE analysis
            if "basic_pe_analysis" in self.pesieve_results and self.pesieve_results["basic_pe_analysis"]:
                pe_analysis = self.pesieve_results["basic_pe_analysis"]
                summary.append("\n### Basic PE Analysis")
                summary.append(f"- Is valid PE: {pe_analysis.get('is_pe', False)}")
                
                if pe_analysis.get("suspicious_imports"):
                    summary.append(f"\n#### Suspicious Imports Detected ({len(pe_analysis['suspicious_imports'])} total)")
                    for imp in pe_analysis["suspicious_imports"]:
                        summary.append(f"- {imp}")
                        
                        # Add context for common suspicious imports
                        if "VirtualAlloc" in imp:
                            summary.append("  - Often used for memory allocation in shellcode execution")
                        elif "WriteProcessMemory" in imp:
                            summary.append("  - Often used in process injection techniques")
                        elif "CreateRemoteThread" in imp:
                            summary.append("  - Common in process injection attacks")
                        elif "LoadLibrary" in imp:
                            summary.append("  - Used for dynamic loading of DLLs")
                        elif "GetProcAddress" in imp:
                            summary.append("  - Used to locate exported functions in DLLs")
                else:
                    summary.append("- No suspicious imports detected")
                
                # Include any PE analysis errors
                if "error" in pe_analysis:
                    summary.append(f"\n- PE Analysis Error: {pe_analysis['error']}")
            
            # Include raw output if available and verbose
            if "raw_output" in self.pesieve_results and self.pesieve_results["raw_output"] and self.verbose:
                summary.append("\n### Raw PE-sieve Output")
                raw_lines = self.pesieve_results["raw_output"].split('\n')
                if len(raw_lines) > 50:
                    # Truncate if too verbose
                    summary.append("```")
                    summary.append('\n'.join(raw_lines[:50]))
                    summary.append(f"... (truncated, {len(raw_lines) - 50} more lines)")
                    summary.append("```")
                else:
                    summary.append("```")
                    summary.append(self.pesieve_results["raw_output"])
                    summary.append("```")
                
        summary.append("\n---\n")
        
        # Add a detailed conclusion
        indicators = []
        threat_level = "Low"
        
        if self.die_results.get("packer") and "UPX" not in self.die_results.get("packer", ""):
            indicators.append("packed with an uncommon packer")
            threat_level = "Medium"
            
        if self.die_results.get("suspicious_indicators") and len(self.die_results["suspicious_indicators"]) > 0:
            indicators.append("suspicious indicators")
            threat_level = "Medium"
            
        if self.pesieve_results.get("hollowing_detected"):
            indicators.append("process hollowing detected")
            threat_level = "High"
            
        if self.pesieve_results.get("anomalies") and len(self.pesieve_results.get("anomalies", [])) > 3:
            indicators.append("multiple anomalies")
            threat_level = "High"
            
        if self.pesieve_results.get("injected_sections"):
            indicators.append("injected code sections")
            threat_level = "High"
            
        # Check for anti-analysis capabilities
        anti_analysis_found = False
        for cap in self.capa_results.get("capabilities", []):
            if "anti-analysis" in cap or "anti-debug" in cap:
                anti_analysis_found = True
                break
                
        if anti_analysis_found:
            indicators.append("anti-analysis techniques")
            if threat_level == "Low":
                threat_level = "Medium"
        
        summary.append("## Conclusion")
        
        if indicators:
            summary.append(f"This binary appears to be a {', '.join(indicators[:-1])}{' and ' if len(indicators) > 1 else ''}{indicators[-1] if indicators else ''} executable.")
            summary.append(f"\nThreat assessment: **{threat_level}** risk")
            
            # Add more specific description of concerns
            summary.append("\n### Security Concerns:")
            
            if self.die_results.get("suspicious_indicators"):
                for indicator in self.die_results["suspicious_indicators"]:
                    summary.append(f"- {indicator}")
                    
            if self.pesieve_results.get("anomalies"):
                for anomaly in self.pesieve_results["anomalies"]:
                    summary.append(f"- {anomaly}")
                    
            if anti_analysis_found:
                summary.append("- Contains anti-analysis techniques that may hinder debugging or analysis")
        else:
            summary.append("No significant security indicators were detected in this binary. Threat assessment: **Low** risk.")
        
        # Add tool versions if available
        summary.append("\n---\n")
        summary.append("## Analysis Tools Used")
        summary.append("- BinScrybe: Binary analysis and summary generation")
        summary.append("- CAPA: Capability detection")
        summary.append("- DIE (Detect It Easy): Format and compiler detection")
        summary.append("- PE-sieve: PE file anomaly detection")
        
        # Write summary to file
        with open(summary_path, 'w') as f:
            f.write("\n".join(summary))
    
    @staticmethod
    def _format_size(size_bytes: int) -> str:
        """Format file size in a human-readable format."""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024 or unit == 'GB':
                if unit == 'B':
                    return f"{size_bytes} {unit}"
                return f"{size_bytes/1024:.1f} {unit}"
            size_bytes /= 1024


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="BinScrybe: A tool for generating summaries of binaries.")
    parser.add_argument("target", help="Path to the binary file to analyze")
    parser.add_argument("-o", "--output", help="Output file path. Default is [binary_name]_summary.md", default=None)
    parser.add_argument("--skip-capa", action="store_true", help="Skip CAPA analysis")
    parser.add_argument("--skip-die", action="store_true", help="Skip DIE analysis")
    parser.add_argument("--skip-pesieve", action="store_true", help="Skip PE-sieve analysis")
    parser.add_argument("--tools-dir", help="Path to the directory containing analysis tools. Default is 'tools/'", default="tools")
    parser.add_argument("--die-dir", help="Path to the Detect-It-Easy directory. Default is 'tools/die_winxp_portable_3.10_x86/'", default="tools/die_winxp_portable_3.10_x86")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    
    # Ghidra integration options
    ghidra_group = parser.add_argument_group('Ghidra Integration')
    ghidra_group.add_argument("--ghidra", action="store_true", help="Import results into Ghidra after analysis")
    ghidra_group.add_argument("--ghidra-path", help="Path to the Ghidra installation directory")
    ghidra_group.add_argument("--ghidra-project", help="Path to the Ghidra project directory")
    ghidra_group.add_argument("--no-headless", action="store_true", help="Run Ghidra in GUI mode instead of headless mode")
    
    return parser.parse_args()


def main():
    """Main function."""
    args = parse_args()
    
    try:
        bs = BinScrybe(
            args.target,
            args.output,
            args.tools_dir,
            args.die_dir,
            args.skip_capa,
            args.skip_die,
            args.skip_pesieve,
            args.verbose
        )
        
        summary = bs.analyze()
        
        print(f"\nAnalysis complete. Summary saved to: {bs.output_file}")
        
        # If Ghidra integration is enabled
        if args.ghidra:
            try:
                from ghidra_integration import GhidraIntegrator
                
                print("\nImporting results into Ghidra...")
                integrator = GhidraIntegrator(
                    ghidra_path=args.ghidra_path,
                    project_path=args.ghidra_project,
                    headless=not args.no_headless
                )
                
                # Get the full report JSON file
                report_path = os.path.join(args.tools_dir, "full_report.json")
                if not os.path.exists(report_path):
                    print(f"Error: Could not find full report JSON at {report_path}")
                else:
                    success = integrator.import_binscrybe_results(report_path, args.target)
                    if success:
                        print("Results successfully imported into Ghidra.")
                    else:
                        print("Failed to import results into Ghidra.")
            except ImportError:
                print("Warning: ghidra_integration module not found. Skipping Ghidra integration.")
                print("To enable Ghidra integration, make sure ghidra_integration.py is in the same directory.")
        
    except Exception as e:
        print(f"Error: {e}")
        if args.verbose:
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    sys.exit(main()) 