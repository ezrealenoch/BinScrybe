#!/usr/bin/env python3
"""
BinScrybe LLM Integration Example

This script demonstrates how to take the BinScrybe summary output and
generate a security report using an LLM API (in this case OpenAI's API).
"""

import argparse
import json
import os
import sys

# You would need to install the OpenAI Python package:
# pip install openai
try:
    import openai
except ImportError:
    print("This example requires the openai package. Install with: pip install openai")
    print("Note: This is just an example and can be adapted to use any LLM API")
    sys.exit(1)


def read_summary(summary_path):
    """Read the BinScrybe summary file."""
    try:
        with open(summary_path, 'r') as f:
            return f.read()
    except Exception as e:
        print(f"Error reading summary file: {e}")
        sys.exit(1)


def generate_report(summary_text, api_key=None):
    """Generate a security report using OpenAI's API."""
    # Set the API key if provided
    if api_key:
        openai.api_key = api_key
    elif "OPENAI_API_KEY" not in os.environ:
        print("Error: OpenAI API key not provided.")
        print("Either set the OPENAI_API_KEY environment variable or use the --api-key flag.")
        sys.exit(1)
    
    # Example prompt for the LLM
    prompt = f"""
You are a malware analyst tasked with interpreting binary analysis results.
Analyze the following output from BinScrybe, which contains findings from CAPA, DIE, sigtool, and PE-sieve.
Generate a comprehensive security report that includes:

1. A brief executive summary of the findings
2. Technical details about the binary's behavior and capabilities
3. Threat assessment (severity level and potential impact)
4. Recommendations for handling this binary
5. Potential attribution or similarities to known malware families (if applicable)

Here is the BinScrybe output:

{summary_text}
"""

    try:
        # Make the API call
        response = openai.ChatCompletion.create(
            model="gpt-4",  # or another appropriate model
            messages=[
                {"role": "system", "content": "You are a malware analysis expert."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.3,  # Lower temperature for more focused, analytical responses
            max_tokens=2000
        )
        
        # Return the generated report
        return response.choices[0].message.content
    
    except Exception as e:
        print(f"Error generating report: {e}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="Generate a security report from BinScrybe output using an LLM")
    parser.add_argument("summary", help="Path to the BinScrybe summary.txt file")
    parser.add_argument("--api-key", help="OpenAI API Key (if not using environment variable)")
    parser.add_argument("--output", help="Output file for the report (default: stdout)")
    
    args = parser.parse_args()
    
    # Read the summary
    summary_text = read_summary(args.summary)
    
    # Generate the report
    print("Generating security report using LLM...")
    report = generate_report(summary_text, args.api_key)
    
    # Output the report
    if args.output:
        with open(args.output, 'w') as f:
            f.write(report)
        print(f"Report saved to {args.output}")
    else:
        print("\n" + "="*80)
        print("SECURITY REPORT")
        print("="*80 + "\n")
        print(report)


if __name__ == "__main__":
    main() 