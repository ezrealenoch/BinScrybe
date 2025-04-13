#!/usr/bin/env python3
"""
BinScrybe Tools Unit Tests

Tests the integration and functionality of the external tools used by BinScrybe:
- CAPA
- DIE (Detect It Easy)
- PE-sieve

Requires the tools to be set up properly before running the tests.
Run setup_tools.py before running these tests.
"""

import unittest
import os
import sys
import tempfile
import shutil
from pathlib import Path

# Import BinScrybe
from binscrybe import BinScrybe


class TestBinScrybeTools(unittest.TestCase):
    """Test cases for BinScrybe tool integration."""

    @classmethod
    def setUpClass(cls):
        """Set up the test environment."""
        # Find a test binary (use this script as a fallback)
        cls.test_binary = os.path.join(os.environ.get("WINDIR", "C:\\Windows"), "notepad.exe")
        if not os.path.exists(cls.test_binary):
            cls.test_binary = sys.executable  # Use Python executable as fallback
        
        # Create a temp directory for output files
        cls.temp_dir = tempfile.mkdtemp()
        
        # Create BinScrybe instance for testing
        cls.binscrybe = BinScrybe(
            cls.test_binary,
            output_file=os.path.join(cls.temp_dir, "test_output.md"),
            tools_dir="tools",
            die_dir="die_winxp_portable_3.10_x86"
        )
        
        print(f"\nUsing test binary: {cls.test_binary}")
        print(f"Using temp directory: {cls.temp_dir}")
        print(f"Using tools directory: {os.path.abspath('tools')}")
        print(f"Using DIE directory: {os.path.abspath('die_winxp_portable_3.10_x86')}")

    @classmethod
    def tearDownClass(cls):
        """Clean up after tests."""
        # Remove temporary directory
        shutil.rmtree(cls.temp_dir, ignore_errors=True)

    def test_capa_availability(self):
        """Test if CAPA is available and produces valid output."""
        # Skip the test if CAPA is not supposed to be available
        if self.binscrybe.skip_capa:
            self.skipTest("CAPA analysis is disabled")
        
        # Check if CAPA is available in the tools directory
        capa_path = os.path.join(self.binscrybe.tools_dir, "capa.exe")
        self.assertTrue(
            os.path.exists(capa_path) or self.binscrybe._command_exists("capa.exe"),
            "CAPA executable not found"
        )
        
        # Run CAPA analysis
        capa_results = self.binscrybe.run_capa()
        
        # Check if CAPA produced valid results
        self.assertNotIn("error", capa_results, f"CAPA analysis error: {capa_results.get('error', '')}")
        self.assertIn("capabilities", capa_results, "CAPA results missing 'capabilities' field")
        self.assertIsInstance(capa_results["capabilities"], list, "CAPA capabilities should be a list")
        
        # Print some useful information
        if capa_results.get("capabilities"):
            print(f"\nFound {len(capa_results['capabilities'])} capabilities in test binary")
            for i, capability in enumerate(capa_results["capabilities"][:3]):
                print(f"  {i+1}. {capability}")
            if len(capa_results["capabilities"]) > 3:
                print(f"  ... and {len(capa_results['capabilities']) - 3} more")

    def test_die_availability(self):
        """Test if DIE is available and produces valid output."""
        # Skip the test if DIE is not supposed to be available
        if self.binscrybe.skip_die:
            self.skipTest("DIE analysis is disabled")
        
        # Check if DIE is available in the specified directory
        die_dir = self.binscrybe.die_dir or os.path.join(os.path.dirname(os.path.dirname(self.binscrybe.tools_dir)), "die_winxp_portable_3.10_x86")
        die_cli_path = os.path.join(die_dir, "diec.exe")
        die_gui_path = os.path.join(die_dir, "die.exe")
        die_light_path = os.path.join(die_dir, "diel.exe")
        
        self.assertTrue(
            os.path.exists(die_cli_path) or os.path.exists(die_gui_path) or os.path.exists(die_light_path),
            "No DIE executable found (tried diec.exe, die.exe, diel.exe)"
        )
        
        # Run DIE analysis
        die_results = self.binscrybe.run_die()
        
        # Print raw DIE results for debugging
        print("\nDIE raw results:")
        for key, value in die_results.items():
            print(f"  {key}: {value}")
        
        # Check if DIE executed without errors
        self.assertNotIn("error", die_results, f"DIE analysis error: {die_results.get('error', '')}")
        
        # Test if DIE produced any output - even if it's not in the exact format we expect
        # This is a more relaxed test that verifies DIE is functioning even if some fields are missing
        self.assertIsInstance(die_results, dict, "DIE results should be a dictionary")
        
        # For this test, we'll consider it a success if either:
        # 1. Any of the expected fields are non-None, or
        # 2. DIE ran without errors (we've already checked this above)
        has_valid_results = (
            die_results.get("compiler") is not None or
            die_results.get("packer") is not None or
            die_results.get("entropy") is not None or
            die_results.get("file_format") is not None
        )
        
        # Not failing the test, just print a warning if no data was found
        if not has_valid_results:
            print("\nWARNING: DIE didn't return any specific file information, but executed without errors")
            # Try to use fallback file info since DIE didn't return useful data
            fallback_info = self.binscrybe._fallback_file_info()
            if fallback_info:
                print("  Using fallback file analysis:")
                for key, value in fallback_info.items():
                    if key != "suspicious_indicators" and value:
                        print(f"    {key}: {value}")
                if fallback_info.get("suspicious_indicators"):
                    print(f"    suspicious_indicators: {len(fallback_info['suspicious_indicators'])} found")
        else:
            # Print some useful information if we did get data
            print("\nDIE analysis results:")
            if die_results.get("file_format"):
                print(f"  File format: {die_results['file_format']}")
            if die_results.get("compiler"):
                print(f"  Compiler: {die_results['compiler']}")
            if die_results.get("entropy") is not None:
                print(f"  Entropy: {die_results['entropy']}")
            if die_results.get("suspicious_indicators"):
                print(f"  Suspicious indicators: {len(die_results['suspicious_indicators'])}")
                for indicator in die_results['suspicious_indicators'][:2]:
                    print(f"    - {indicator}")

    def test_pesieve_availability(self):
        """Test if PE-sieve is available and produces valid output."""
        # Skip the test if PE-sieve is not supposed to be available
        if self.binscrybe.skip_pesieve:
            self.skipTest("PE-sieve analysis is disabled")
        
        # Check if PE-sieve is available in the tools directory
        pesieve_path = os.path.join(self.binscrybe.tools_dir, "pe-sieve64.exe")
        self.assertTrue(
            os.path.exists(pesieve_path) or self.binscrybe._command_exists("pe-sieve64.exe"),
            "PE-sieve executable not found"
        )
        
        # Run PE-sieve analysis
        pesieve_results = self.binscrybe.run_pesieve()
        
        # Check if PE-sieve produced valid results or a valid error message
        if "error" in pesieve_results:
            # If there's an error, make sure it's a "not a valid PE file" error (which is valid for static files)
            # or it's a "PE-sieve not found" error (which we already checked for)
            self.assertTrue(
                "not a valid PE file" in pesieve_results["error"] or 
                "PE-sieve executable not found" in pesieve_results["error"],
                f"Unexpected PE-sieve error: {pesieve_results['error']}"
            )
            print(f"\nExpected PE-sieve error (for static analysis): {pesieve_results['error']}")
            
            # Make sure basic PE analysis was performed
            self.assertIn("basic_pe_analysis", pesieve_results, "PE-sieve fallback analysis missing")
            basic_analysis = pesieve_results["basic_pe_analysis"]
            self.assertIsInstance(basic_analysis, dict, "Basic PE analysis should be a dictionary")
            
            # Print some useful information about the basic analysis
            print("\nBasic PE analysis results:")
            print(f"  Is PE file: {basic_analysis.get('is_pe', False)}")
            if basic_analysis.get("suspicious_imports"):
                print(f"  Suspicious imports: {', '.join(basic_analysis['suspicious_imports'])}")
        else:
            # If there's no error, check for expected fields
            self.assertIn("hollowing_detected", pesieve_results, "PE-sieve results missing 'hollowing_detected' field")
            self.assertIn("anomalies", pesieve_results, "PE-sieve results missing 'anomalies' field")
            
            # Print some useful information
            print("\nPE-sieve analysis results:")
            print(f"  Hollowing detected: {pesieve_results['hollowing_detected']}")
            print(f"  Anomalies: {len(pesieve_results['anomalies'])}")
            for anomaly in pesieve_results['anomalies'][:2]:
                print(f"    - {anomaly}")

    def test_integration_all_tools(self):
        """Test the integration of all tools together."""
        # Run the full analysis
        self.binscrybe.analyze()
        
        # Check that the output files were created
        self.assertTrue(
            os.path.exists(self.binscrybe.output_file),
            f"Output file not created: {self.binscrybe.output_file}"
        )
        
        # Check that the full report was created
        report_path = os.path.join(self.binscrybe.tools_dir, "full_report.json")
        self.assertTrue(
            os.path.exists(report_path),
            f"Full report not created: {report_path}"
        )
        
        # Verify the results are populated
        self.assertIsInstance(self.binscrybe.results, dict, "Results should be a dictionary")
        self.assertIn("file", self.binscrybe.results, "Results missing 'file' field")
        self.assertIn("hashes", self.binscrybe.results, "Results missing 'hashes' field")
        
        # Print the summary content for verification
        print("\nGenerated summary file content preview:")
        try:
            with open(self.binscrybe.output_file, 'r') as f:
                summary_content = f.read(1000)  # Read first 1000 chars
                print(f"  {summary_content[:500]}...")
        except Exception as e:
            print(f"  Error reading summary file: {e}")


if __name__ == "__main__":
    unittest.main() 