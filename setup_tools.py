#!/usr/bin/env python3
"""
BinScrybe Tools Setup Helper

This script helps set up the tools directory for BinScrybe by:
1. Creating a 'tools' directory if it doesn't exist
2. Locating the required tools on the system or in the current directory
3. Creating symlinks or copying the tools to the tools directory
"""

import os
import shutil
import sys
import subprocess
from pathlib import Path


def find_executable(name, search_paths=None, current_dir=True):
    """Find an executable in the PATH or specified directories."""
    # Start with search paths
    if search_paths is None:
        search_paths = []
    
    # Add current directory if requested
    if current_dir:
        search_paths.append(".")
    
    # Try the search paths first
    for path in search_paths:
        exe_path = os.path.join(path, name)
        if os.path.isfile(exe_path) and os.access(exe_path, os.X_OK):
            return os.path.abspath(exe_path)
    
    # Try PATH
    for path in os.environ.get("PATH", "").split(os.pathsep):
        if not path:
            continue
        exe_path = os.path.join(path, name)
        if os.path.isfile(exe_path) and os.access(exe_path, os.X_OK):
            return os.path.abspath(exe_path)
    
    return None


def test_tool(exe_path, test_args=None, version_args=None):
    """
    Test if the tool runs properly and get its version.
    Returns a tuple (success, version, error_message)
    """
    if not os.path.exists(exe_path):
        return False, None, "Executable not found"
    
    # Try to get version info
    version = None
    if version_args:
        try:
            result = subprocess.run(
                [exe_path] + version_args,
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                version = result.stdout.strip()
            else:
                version = f"Unknown (exit code {result.returncode})"
        except Exception as e:
            version = f"Error getting version: {str(e)}"
    
    # Test basic functionality
    if test_args:
        try:
            result = subprocess.run(
                [exe_path] + test_args,
                capture_output=True,
                text=True,
                timeout=10
            )
            success = result.returncode == 0
            if not success:
                error = result.stderr if result.stderr else f"Exit code: {result.returncode}"
                return success, version, error
        except Exception as e:
            return False, version, str(e)
    
    return True, version, None


def setup_die(tools_dir, search_paths):
    """Special handling for DIE which has multiple components."""
    # Look for DIE in tools directory first
    tools_die_dir = os.path.join(tools_dir, "die_winxp_portable_3.10_x86")
    
    # Check if DIE exists in tools directory
    if os.path.exists(tools_die_dir):
        die_path = os.path.join(tools_die_dir, "diec.exe")
        die_main_exe = os.path.join(tools_die_dir, "die.exe")
        if os.path.exists(die_path):
            print(f"  Found DIE CLI in tools directory: {die_path}")
            
            # Check if DIE works
            success, version, error = test_tool(die_path, ["-h"])
            if success:
                print(f"  DIE appears to be working correctly!")
            else:
                print(f"  Warning: DIE CLI may not be working correctly: {error}")
                print(f"  This may be because diec.exe requires other files from the DIE directory.")
            
            # Create a batch file to run DIE from its own directory
            batch_path = os.path.join(tools_dir, "die.bat")
            if not os.path.exists(batch_path):
                try:
                    with open(batch_path, 'w') as f:
                        f.write('@echo off\n"%~dp0die_winxp_portable_3.10_x86\\die.exe" %*\n')
                    print(f"  Created batch file to run DIE from its directory in tools: {batch_path}")
                except Exception as e:
                    print(f"  Error creating DIE batch file: {str(e)}")
            
            return True
    
    # If not in tools, check for the original die directory
    die_dir = "die_winxp_portable_3.10_x86"
    if os.path.exists(die_dir):
        die_path = os.path.join(die_dir, "diec.exe")
        die_main_exe = os.path.join(die_dir, "die.exe")
        
        if os.path.exists(die_path):
            print(f"  Found DIE CLI in the DIE directory: {die_path}")
            
            # Check if DIE works
            success, version, error = test_tool(die_path, ["-h"])
            if success:
                print(f"  DIE appears to be working correctly!")
            else:
                print(f"  Warning: DIE CLI may not be working correctly: {error}")
                print(f"  This may be because diec.exe requires other files from the DIE directory.")
                print(f"  Recommend using DIE directly from the portable directory.")
            
            # Copy to tools directory
            target_path = os.path.join(tools_dir, "diec.exe")
            if os.path.exists(target_path):
                print(f"  Already exists in tools directory")
            else:
                try:
                    shutil.copy2(die_path, target_path)
                    print(f"  Copied diec.exe to: {target_path}")
                except Exception as e:
                    print(f"  Error setting up DIE CLI: {str(e)}")
                    print(f"  Please manually copy {die_path} to {target_path}")
            
            # Create a batch file to run DIE from its own directory
            batch_path = os.path.join(tools_dir, "die.bat")
            if not os.path.exists(batch_path):
                try:
                    with open(batch_path, 'w') as f:
                        f.write('@echo off\n"%~dp0die_winxp_portable_3.10_x86\\die.exe" %*\n')
                    print(f"  Created batch file to run DIE from its original directory: {batch_path}")
                except Exception as e:
                    print(f"  Error creating DIE batch file: {str(e)}")
            
            return True
        else:
            print(f"  DIE CLI (diec.exe) not found in {die_dir} directory.")
    
    # Try to find diec.exe elsewhere
    die_path = find_executable("diec.exe", search_paths)
    if die_path:
        print(f"  Found DIE CLI at: {die_path}")
        
        # Check if DIE works
        success, version, error = test_tool(die_path, ["-h"])
        if success:
            print(f"  DIE appears to be working correctly!")
        else:
            print(f"  Warning: DIE may not be working correctly: {error}")
        
        # Copy to tools directory
        target_path = os.path.join(tools_dir, "diec.exe")
        if os.path.exists(target_path):
            print(f"  Already exists in tools directory")
        else:
            try:
                shutil.copy2(die_path, target_path)
                print(f"  Copied to: {target_path}")
            except Exception as e:
                print(f"  Error setting up DIE: {str(e)}")
                print(f"  Please manually copy {die_path} to {target_path}")
        
        return True
    
    print("  NOT FOUND! Please download and install Detect-It-Easy (DIE)")
    print("  Download from: https://github.com/horsicq/DIE-engine/releases")
    return False


def setup_pesieve(tools_dir, search_paths):
    """Special handling for PE-sieve which has version-specific parameters."""
    pesieve_path = find_executable("pe-sieve64.exe", search_paths)
    if pesieve_path:
        print(f"  Found PE-sieve at: {pesieve_path}")
        
        # Check PE-sieve version and capabilities
        success, version, error = test_tool(pesieve_path, ["/help"])
        
        if success:
            # Check which commands are supported by examining help output
            result = subprocess.run(
                [pesieve_path, "/help"],
                capture_output=True,
                text=True,
                timeout=10
            )
            help_output = result.stdout
            
            if "/scan_file" in help_output:
                print("  PE-sieve supports /scan_file parameter (modern version)")
            elif "/data" in help_output:
                print("  PE-sieve supports /data parameter (older version)")
            else:
                print("  Warning: Could not determine PE-sieve command format")
        else:
            print(f"  Warning: PE-sieve may not be working correctly: {error}")
        
        # Copy to tools directory
        target_path = os.path.join(tools_dir, "pe-sieve64.exe")
        if os.path.exists(target_path):
            print(f"  Already exists in tools directory")
        else:
            try:
                shutil.copy2(pesieve_path, target_path)
                print(f"  Copied to: {target_path}")
            except Exception as e:
                print(f"  Error setting up PE-sieve: {str(e)}")
                print(f"  Please manually copy {pesieve_path} to {target_path}")
        
        return True
    
    print("  NOT FOUND! Please download and install PE-sieve")
    print("  Download from: https://github.com/hasherezade/pe-sieve/releases")
    return False


def setup_capa(tools_dir, search_paths):
    """Handle CAPA setup."""
    capa_path = find_executable("capa.exe", search_paths)
    if capa_path:
        print(f"  Found CAPA at: {capa_path}")
        
        # Check if CAPA works
        success, version, error = test_tool(capa_path, ["-h"])
        if success:
            print(f"  CAPA appears to be working correctly!")
            # Try to get CAPA version
            try:
                version_result = subprocess.run(
                    [capa_path, "-V"],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                if version_result.returncode == 0:
                    print(f"  CAPA version: {version_result.stdout.strip()}")
            except Exception:
                pass
        else:
            print(f"  Warning: CAPA may not be working correctly: {error}")
        
        # Copy to tools directory
        target_path = os.path.join(tools_dir, "capa.exe")
        if os.path.exists(target_path):
            print(f"  Already exists in tools directory")
        else:
            try:
                shutil.copy2(capa_path, target_path)
                print(f"  Copied to: {target_path}")
            except Exception as e:
                print(f"  Error setting up CAPA: {str(e)}")
                print(f"  Please manually copy {capa_path} to {target_path}")
        
        return True
    
    print("  NOT FOUND! Please download and install CAPA")
    print("  Download from: https://github.com/mandiant/capa/releases")
    return False


def main():
    # Get the script directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Create tools directory - use relative path for better portability
    tools_dir = os.path.join(script_dir, "tools")
    os.makedirs(tools_dir, exist_ok=True)
    
    # Alternate locations to check
    search_paths = [
        os.path.join(tools_dir, "die_winxp_portable_3.10_x86"),  # In tools dir
        os.path.join(script_dir, "die_winxp_portable_3.10_x86"),  # In script dir
        "."  # Current directory
    ]
    
    # Set up CAPA
    print("\nSetting up CAPA...")
    capa_installed = setup_capa(tools_dir, search_paths)
    
    # Set up DIE
    print("\nSetting up Detect-It-Easy (DIE)...")
    die_installed = setup_die(tools_dir, search_paths)
    
    # Set up PE-sieve
    print("\nSetting up PE-sieve...")
    pesieve_installed = setup_pesieve(tools_dir, search_paths)
    
    # Final instructions
    print("\n" + "="*60)
    print(" BinScrybe Setup Summary ".center(60, "="))
    print("="*60)
    
    print(f"\nTools directory: {os.path.abspath(tools_dir)}")
    
    print("\nTool Status:")
    print(f"- CAPA: {'Installed ✓' if capa_installed else 'Not installed ✗'}")
    print(f"- DIE: {'Installed ✓' if die_installed else 'Not installed ✗'}")
    print(f"- PE-sieve: {'Installed ✓' if pesieve_installed else 'Not installed ✗'}")
    
    # Add special note for DIE if it's installed
    if die_installed and os.path.exists(os.path.join(tools_dir, "die_winxp_portable_3.10_x86")):
        print(f"\nNOTE: DIE is configured to use the portable version at: {os.path.abspath(os.path.join(tools_dir, 'die_winxp_portable_3.10_x86'))}")
        print(f"This is recommended for best results as the DIE CLI may require access to files in its own directory.")
    
    print("\nMissing tools must be downloaded and placed in the tools directory:")
    if not capa_installed:
        print("- CAPA: https://github.com/mandiant/capa/releases")
    if not die_installed:
        print("- Detect-It-Easy: https://github.com/horsicq/DIE-engine/releases")
    if not pesieve_installed:
        print("- PE-sieve: https://github.com/hasherezade/pe-sieve/releases")
    
    if all([capa_installed, die_installed, pesieve_installed]):
        print("\nAll tools are installed! 🎉")
    
    print("\nTo use BinScrybe with these tools:")
    print(f"python binscrybe.py path/to/binary.exe --tools-dir {os.path.abspath(tools_dir)}")
    
    print("\nFor best results:")
    print("1. Ensure all tools are installed and properly configured")
    print("2. Use absolute paths when analyzing binaries outside the current directory")


if __name__ == "__main__":
    main() 