#!/usr/bin/env python3
"""
BinScrybe Tool Tester

This script tests each of the tools used by BinScrybe to ensure they can be located,
executed, and produce the expected output.
"""

import os
import subprocess
import sys
import json
from pathlib import Path

# Define root directory
ROOT_DIR = os.path.abspath(os.path.dirname(__file__))

# Define tool paths
TOOLS = {
    "capa": {
        "path": os.path.join(ROOT_DIR, "tools", "capa.exe"),
        "direct_path": os.path.join(ROOT_DIR, "capa.exe"),
        "test_args": ["-h"],
        "success_marker": "capa detects capabilities in executable files",
    },
    "die": {
        "path": os.path.join(ROOT_DIR, "tools", "diec.exe"),
        "direct_path": os.path.join(ROOT_DIR, "die_winxp_portable_3.10_x86", "diec.exe"),
        "test_args": ["-h"],
        "success_marker": "Detect It Easy",
    },
    "pe-sieve": {
        "path": os.path.join(ROOT_DIR, "tools", "pe-sieve64.exe"),
        "direct_path": os.path.join(ROOT_DIR, "pe-sieve64.exe"),
        "test_args": ["/help"],
        "success_marker": "PE-sieve",
    }
}

def run_command(cmd, timeout=60):
    """Run a command and return its output and status."""
    try:
        result = subprocess.run(
            cmd, 
            capture_output=True, 
            text=True, 
            timeout=timeout
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

def test_tool(tool_name):
    """Test a specific tool and report its status."""
    print(f"\n{'='*50}")
    print(f"Testing {tool_name.upper()}")
    print(f"{'='*50}")
    
    tool_info = TOOLS[tool_name]
    
    # Check tool in tools directory
    if os.path.exists(tool_info["path"]):
        tool_path = tool_info["path"]
        print(f"Found {tool_name} in tools directory: {tool_path}")
    # Check tool in direct path
    elif os.path.exists(tool_info["direct_path"]):
        tool_path = tool_info["direct_path"]
        print(f"Found {tool_name} in direct path: {tool_path}")
    else:
        print(f"❌ ERROR: {tool_name} not found in tools or direct path")
        return False
    
    # Check if it's a file
    if not os.path.isfile(tool_path):
        print(f"❌ ERROR: {tool_path} is not a file")
        return False
    
    # Test tool execution
    print(f"Testing {tool_name} execution...")
    cmd = [tool_path] + tool_info["test_args"]
    result = run_command(cmd)
    
    if result["success"]:
        print(f"✓ {tool_name} executed successfully (exit code: {result['exit_code']})")
        
        # Check for success marker in output
        if tool_info["success_marker"] in result["stdout"] or tool_info["success_marker"] in result["stderr"]:
            print(f"✓ Success marker found in output")
        else:
            print(f"⚠️ WARNING: Success marker '{tool_info['success_marker']}' not found in output")
            print("First 5 lines of output:")
            output_lines = (result["stdout"] or result["stderr"]).splitlines()
            for i, line in enumerate(output_lines[:5]):
                print(f"  {i+1}: {line}")
    else:
        print(f"❌ ERROR: {tool_name} failed to execute (exit code: {result['exit_code']})")
        print(f"Error: {result['stderr']}")
        return False
    
    # For DIE, test different command formats
    if tool_name == "die":
        print("\nTesting DIE with different command formats...")
        test_formats = [
            {"args": ["-h"], "desc": "Help flag"},
            {"args": ["-v"], "desc": "Version flag"},
            {"args": ["-l", __file__], "desc": "List format with this script"},
            {"args": ["-json", __file__], "desc": "JSON format with this script"},
            {"args": [__file__], "desc": "Default format with this script"}
        ]
        
        for test in test_formats:
            cmd = [tool_path] + test["args"]
            result = run_command(cmd)
            status = "✓" if result["success"] else "❌"
            print(f"{status} {test['desc']} format: {result['success']} (exit code: {result['exit_code']})")
    
    # For PE-sieve, test different parameter formats
    if tool_name == "pe-sieve":
        print("\nTesting PE-sieve with different parameter formats...")
        # Find a test executable
        test_exe = os.path.join(os.environ.get("WINDIR", "C:\\Windows"), "notepad.exe")
        if not os.path.exists(test_exe):
            test_exe = __file__  # Fallback to this script
        
        test_formats = [
            {"args": ["/help"], "desc": "Help parameter"},
            {"args": ["/version"], "desc": "Version parameter"},
            {"args": [test_exe], "desc": "Direct file parameter"},
            {"args": ["/file", test_exe], "desc": "File parameter"},
            {"args": ["/data", "3", test_exe], "desc": "Data parameter"}
        ]
        
        for test in test_formats:
            cmd = [tool_path] + test["args"]
            result = run_command(cmd)
            status = "✓" if result["success"] else "❌"
            print(f"{status} {test['desc']} format: {result['success']} (exit code: {result['exit_code']})")
            # If the test is successful, check if we can detect static analysis capability
            if result["success"] and test["desc"] not in ["Help parameter", "Version parameter"]:
                print(f"  Output indicates PE-sieve {test['desc']} can be used for static analysis")
                print(f"  First line of output: {result['stdout'].splitlines()[0] if result['stdout'] else 'No output'}")
    
    return True

def test_file_analysis(sample_file=None):
    """Test the analysis of a sample file with each tool."""
    print("\n" + "="*50)
    print("TESTING FILE ANALYSIS CAPABILITY")
    print("="*50)
    
    # Use this script as a sample file if none provided
    if not sample_file:
        sample_file = __file__
    
    print(f"Using sample file: {sample_file}")
    
    # Test CAPA analysis
    if os.path.exists(TOOLS["capa"]["path"]):
        print("\nTesting CAPA file analysis...")
        cmd = [TOOLS["capa"]["path"], sample_file, "-j"]
        result = run_command(cmd)
        if result["success"]:
            print("✓ CAPA successfully analyzed the file")
            try:
                capa_json = json.loads(result["stdout"])
                print(f"✓ CAPA JSON output parsed successfully ({len(result['stdout'])} bytes)")
            except json.JSONDecodeError:
                print("❌ ERROR: CAPA output is not valid JSON")
        else:
            print(f"❌ ERROR: CAPA analysis failed: {result['stderr']}")
    
    # Test DIE analysis
    if os.path.exists(TOOLS["die"]["path"]):
        print("\nTesting DIE file analysis...")
        cmd = [TOOLS["die"]["path"], sample_file]
        result = run_command(cmd)
        if result["success"]:
            print("✓ DIE successfully analyzed the file")
            print(f"Output: {result['stdout'][:100]}...")
        else:
            print(f"❌ ERROR: DIE analysis failed: {result['stderr']}")
            # Try alternate command format
            cmd = [TOOLS["die"]["path"], "-l", sample_file]
            result = run_command(cmd)
            if result["success"]:
                print("✓ DIE (-l format) successfully analyzed the file")
                print(f"Output: {result['stdout'][:100]}...")
    
    # Test PE-sieve analysis
    if os.path.exists(TOOLS["pe-sieve"]["path"]):
        print("\nTesting PE-sieve file analysis...")
        
        # Try different formats
        formats = [
            [TOOLS["pe-sieve"]["path"], sample_file],
            [TOOLS["pe-sieve"]["path"], "/file", sample_file],
            [TOOLS["pe-sieve"]["path"], "/scan_file", sample_file],
            [TOOLS["pe-sieve"]["path"], "/data", "3", sample_file]
        ]
        
        success = False
        for cmd in formats:
            print(f"Trying format: {' '.join(cmd)}")
            result = run_command(cmd)
            if result["success"]:
                print(f"✓ PE-sieve successfully analyzed the file with format: {' '.join(cmd)}")
                print(f"Output: {result['stdout'][:100]}...")
                success = True
                break
        
        if not success:
            print("❌ ERROR: All PE-sieve formats failed")
            print("PE-sieve may only support analyzing running processes.")

def main():
    """Main function to run all tests."""
    print("\nBINSCRYBE TOOL TESTER")
    print("====================")
    print(f"Working directory: {os.getcwd()}")
    print(f"Root directory: {ROOT_DIR}")
    
    # Test each tool
    test_results = {}
    for tool in TOOLS:
        test_results[tool] = test_tool(tool)
    
    # Test file analysis
    if any(test_results.values()):
        test_file_analysis()
    
    # Summary
    print("\n" + "="*50)
    print("TEST SUMMARY")
    print("="*50)
    
    for tool, result in test_results.items():
        status = "✓ PASS" if result else "❌ FAIL"
        print(f"{tool}: {status}")
    
    # Overall result
    if all(test_results.values()):
        print("\n✅ All tools passed basic tests!")
    else:
        print("\n⚠️ Some tools failed tests. BinScrybe may not work correctly.")
        print("Please check the individual test results above for details.")

if __name__ == "__main__":
    main() 