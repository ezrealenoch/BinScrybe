#!/usr/bin/env python3
"""
BinScrybe - Ghidra Integration Module

This module provides integration between BinScrybe analysis results and Ghidra.
It allows importing findings from BinScrybe into Ghidra as bookmarks, comments,
and function metadata.
"""

import os
import json
import argparse
import subprocess
from pathlib import Path
from typing import Dict, List, Any, Optional


class GhidraIntegrator:
    def __init__(self, ghidra_path: str = None, project_path: str = None, headless: bool = True):
        """Initialize the Ghidra integration.
        
        Args:
            ghidra_path (str, optional): Path to the Ghidra installation. Defaults to None (will try to auto-detect).
            project_path (str, optional): Path to the Ghidra project. Defaults to None (will create a new one).
            headless (bool, optional): Whether to run Ghidra in headless mode. Defaults to True.
        """
        self.ghidra_path = ghidra_path or self._find_ghidra_installation()
        self.project_path = project_path
        self.headless = headless
        
        if not self.ghidra_path:
            print("Warning: Ghidra installation not found. Please specify path manually.")
    
    def _find_ghidra_installation(self) -> Optional[str]:
        """Attempt to locate Ghidra installation automatically."""
        # Common installation paths
        common_paths = [
            os.path.expanduser("~/ghidra"),
            os.path.expanduser("~/tools/ghidra"),
            "C:/Program Files/Ghidra",
            "/opt/ghidra",
            "/usr/local/bin/ghidra",
        ]
        
        # Also check environment variables
        if "GHIDRA_INSTALL_DIR" in os.environ:
            common_paths.insert(0, os.environ["GHIDRA_INSTALL_DIR"])
        
        for path in common_paths:
            if os.path.exists(path):
                # Check for ghidraRun or ghidraRun.bat
                if os.path.exists(os.path.join(path, "ghidraRun")) or \
                   os.path.exists(os.path.join(path, "ghidraRun.bat")):
                    return path
        
        return None
    
    def import_binscrybe_results(self, results_file: str, binary_file: str) -> bool:
        """Import BinScrybe results into Ghidra.
        
        Args:
            results_file (str): Path to the BinScrybe full_report.json file.
            binary_file (str): Path to the binary file that was analyzed.
            
        Returns:
            bool: Whether the import was successful.
        """
        if not os.path.exists(results_file):
            print(f"Error: Results file not found: {results_file}")
            return False
        
        if not os.path.exists(binary_file):
            print(f"Error: Binary file not found: {binary_file}")
            return False
        
        # Load the results
        try:
            with open(results_file, 'r') as f:
                results = json.load(f)
        except json.JSONDecodeError:
            print(f"Error: Failed to parse results file: {results_file}")
            return False
        
        # Create a Ghidra script that will handle the actual integration
        script_path = self._create_integration_script(results)
        
        # Run Ghidra with the script
        return self._run_ghidra_script(script_path, binary_file)
    
    def _create_integration_script(self, results: Dict[str, Any]) -> str:
        """Create a Ghidra script to import the BinScrybe results.
        
        Args:
            results (Dict[str, Any]): The BinScrybe results.
            
        Returns:
            str: Path to the created script.
        """
        # Create a directory for the script if it doesn't exist
        script_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ghidra_scripts")
        os.makedirs(script_dir, exist_ok=True)
        
        # Path to the script
        script_path = os.path.join(script_dir, "BinScrybeImporter.java")
        
        # Extract relevant information from the results
        capa_findings = results.get("capa", {}).get("capabilities", [])
        addresses = []
        
        # Extract addresses and capabilities from CAPA results
        for capability in capa_findings:
            if "@" in capability:
                name, addr_str = capability.split(" @ ", 1)
                addr_list = addr_str.split(", ")
                for addr in addr_list:
                    if addr.startswith("0x"):
                        addresses.append((addr, name))
        
        # Create the Ghidra script
        with open(script_path, 'w') as f:
            f.write(self._generate_ghidra_script(addresses))
        
        return script_path
    
    def _generate_ghidra_script(self, addresses: List[tuple]) -> str:
        """Generate the content of the Ghidra script.
        
        Args:
            addresses (List[tuple]): List of (address, capability) tuples.
            
        Returns:
            str: The content of the Ghidra script.
        """
        script = """// BinScrybe Importer for Ghidra
// Automatically imports BinScrybe findings into the current Ghidra project

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;

public class BinScrybeImporter extends GhidraScript {

    @Override
    public void run() throws Exception {
        println("BinScrybe Importer - Starting import...");
        
        BookmarkManager bookmarkManager = currentProgram.getBookmarkManager();
        int importCount = 0;
        
        // Import BinScrybe findings as bookmarks and comments
"""
        
        # Add code to create bookmarks for each address
        for addr, capability in addresses:
            script += f"""
        try {{
            Address addr = toAddr({addr});
            bookmarkManager.setBookmark(addr, BookmarkType.INFO, "BinScrybe", "{capability}");
            setPreComment(addr, "BinScrybe: {capability}");
            importCount++;
        }} catch (Exception e) {{
            println("Failed to import {addr}: " + e.getMessage());
        }}
"""
        
        script += """
        
        println("BinScrybe Importer - Completed: " + importCount + " findings imported.");
    }
}
"""
        return script
    
    def _run_ghidra_script(self, script_path: str, binary_file: str) -> bool:
        """Run the Ghidra script to import the results.
        
        Args:
            script_path (str): Path to the Ghidra script.
            binary_file (str): Path to the binary file to analyze.
            
        Returns:
            bool: Whether the script execution was successful.
        """
        if not self.ghidra_path:
            print("Error: Ghidra installation not found.")
            return False
        
        # Create a project if one doesn't exist
        if not self.project_path:
            self.project_path = os.path.join(os.path.dirname(binary_file), "ghidra_projects")
            os.makedirs(self.project_path, exist_ok=True)
        
        # Determine the project name from the binary file
        project_name = os.path.basename(binary_file).split('.')[0]
        
        # Determine the path to the headless analyzer
        analyzer_path = os.path.join(self.ghidra_path, "support", "analyzeHeadless")
        if os.name == 'nt' and not os.path.exists(analyzer_path):
            analyzer_path += ".bat"
        
        if not os.path.exists(analyzer_path):
            print(f"Error: Could not find Ghidra headless analyzer at {analyzer_path}")
            return False
        
        # Build the command
        cmd = [
            analyzer_path,
            self.project_path,
            project_name,
            "-import", binary_file,
            "-postScript", script_path,
            "-scriptPath", os.path.dirname(script_path),
            "-deleteProject"  # Delete the project if it already exists
        ]
        
        print(f"Running Ghidra with command: {' '.join(cmd)}")
        
        try:
            # Run the command
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            stdout, stderr = process.communicate()
            
            # Check if the command was successful
            if process.returncode != 0:
                print(f"Error running Ghidra: {stderr}")
                return False
            
            print("Ghidra import completed successfully.")
            return True
        except Exception as e:
            print(f"Error running Ghidra: {str(e)}")
            return False


def main():
    """Main function for running the Ghidra integration directly."""
    parser = argparse.ArgumentParser(description="BinScrybe Ghidra Integration")
    parser.add_argument("results", help="Path to the BinScrybe full_report.json file")
    parser.add_argument("binary", help="Path to the binary file that was analyzed")
    parser.add_argument("--ghidra-path", help="Path to the Ghidra installation", default=None)
    parser.add_argument("--project-path", help="Path to the Ghidra project", default=None)
    parser.add_argument("--no-headless", help="Run Ghidra in GUI mode", action="store_true")
    args = parser.parse_args()
    
    integrator = GhidraIntegrator(
        ghidra_path=args.ghidra_path,
        project_path=args.project_path,
        headless=not args.no_headless
    )
    
    success = integrator.import_binscrybe_results(args.results, args.binary)
    
    if success:
        print("BinScrybe results successfully imported into Ghidra.")
    else:
        print("Failed to import BinScrybe results into Ghidra.")
        return 1
    
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main()) 