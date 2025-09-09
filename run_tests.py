#!/usr/bin/env python3
"""
Test runner for the security logging module.
Runs both the demo tests and the unit tests.
"""

import subprocess
import sys
import os

def run_command(command, description):
    """Run a command and print the result."""
    print(f"\n{'='*60}")
    print(f"🧪 {description}")
    print(f"{'='*60}")
    
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        
        if result.returncode == 0:
            print(f"✅ {description} - PASSED")
            if result.stdout:
                print("\n📋 Output:")
                print(result.stdout)
        else:
            print(f"❌ {description} - FAILED")
            if result.stderr:
                print("\n🚨 Error:")
                print(result.stderr)
            if result.stdout:
                print("\n📋 Output:")
                print(result.stdout)
        
        return result.returncode == 0
    except Exception as e:
        print(f"❌ {description} - ERROR: {str(e)}")
        return False

def main():
    """Run all tests."""
    print("🚀 Security Logging Module - Test Suite")
    print("=" * 60)
    
    # Change to the script's directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(script_dir)
    
    all_passed = True
    
    # Run unit tests
    unit_test_passed = run_command(
        "python3 -m unittest test_security_logging -v",
        "Unit Tests (Comprehensive)"
    )
    all_passed = all_passed and unit_test_passed
    
    # Run demo tests
    demo_test_passed = run_command(
        "python3 test_logging.py | tail -20",
        "Demo Tests (Integration Examples)"
    )
    all_passed = all_passed and demo_test_passed
    
    # Final result
    print(f"\n{'='*60}")
    if all_passed:
        print("🎉 ALL TESTS PASSED!")
        print("✅ Unit tests: Comprehensive validation and error handling")
        print("✅ Demo tests: Integration examples and standardized values")
    else:
        print("❌ SOME TESTS FAILED!")
        print("Please check the output above for details.")
    print(f"{'='*60}")
    
    return 0 if all_passed else 1

if __name__ == "__main__":
    sys.exit(main())
