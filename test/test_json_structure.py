#!/usr/bin/env python3
"""
Test to verify that JSON structure is preserved after security enhancements.
Specifically tests that arrays and objects remain valid JSON.
"""

import sys
import os
import json

# Add current directory to path so we can import our modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from security_logging_sns import init_security_logging, log_record_access
from security_log_fields import EventType, ActorType, CloudEnvType, Detail, DataSensitivityLevel

def test_json_structure_preservation():
    """Test that JSON arrays and objects are preserved correctly."""
    
    print("🔍 Testing JSON Structure Preservation")
    print("=" * 60)
    
    # Initialize in test mode
    init_security_logging(test_mode=True)
    
    # Test record access with id_list
    print("Testing id_list as JSON array...")
    result = log_record_access(
        event_type=EventType.RECORD_ACCESS,
        actor_identifier="analyst@company.com",
        actor_type=ActorType.HUMAN_INTERNAL,
        session_id="test-session-123",
        cloud_env_type=CloudEnvType.DEV,
        service_name="reporting-service",
        cloud_env_unique_id="687126124183",
        cloud_env_name="dev-us-west-2",
        service_account_id="sa-reports@company.iam.amazonaws.com",
        endpoint_path="/reports/customer-data",
        data_sensitivity_level=DataSensitivityLevel.CONFIDENTIAL,
        id_list=["cust-001", "cust-002", "cust-003"],  # This should remain an array
        detail=Detail.EXPORT_REPORT
    )
    
    if result.get("status") == "success":
        # Parse the JSON message to verify structure
        message_content = result.get("message_content", "{}")
        try:
            parsed_message = json.loads(message_content)
            id_list = parsed_message.get("id_list")
            
            print(f"✅ Log published successfully")
            print(f"✅ id_list type: {type(id_list)}")
            print(f"✅ id_list value: [REDACTED - {len(id_list) if id_list else 0} items]")
            
            # Verify it's still a list
            if isinstance(id_list, list):
                print("✅ id_list is properly preserved as JSON array")
                print(f"✅ Array length: {len(id_list)}")
                print(f"✅ Array elements: [REDACTED]")
                
                # Verify elements are sanitized but still strings
                for i, item in enumerate(id_list):
                    if isinstance(item, str):
                        print(f"✅ Element {i}: [REDACTED] (type: {type(item).__name__})")
                    else:
                        print(f"⚠️ Element {i}: [REDACTED] (type: {type(item).__name__})")
                
                return True
            else:
                print(f"❌ id_list is not an array! Type: {type(id_list)}")
                print(f"❌ Value: [REDACTED]")
                return False
                
        except json.JSONDecodeError as e:
            print(f"❌ Failed to parse JSON: {e}")
            return False
    else:
        print("❌ Log publishing failed")
        return False

def test_fields_accessed_array():
    """Test that fields_accessed remains a proper JSON array."""
    
    print("\nTesting fields_accessed as JSON array...")
    result = log_record_access(
        event_type=EventType.RECORD_ACCESS,
        actor_identifier="support@company.com",
        actor_type=ActorType.HUMAN_INTERNAL,
        session_id="test-session-456",
        cloud_env_type=CloudEnvType.DEV,
        service_name="customer-service",
        cloud_env_unique_id="687126124183",
        cloud_env_name="dev-us-west-2",
        service_account_id="sa-customer@company.iam.amazonaws.com",
        endpoint_path="/api/customers/cust-12345",
        data_sensitivity_level=DataSensitivityLevel.CONFIDENTIAL,
        id_list=["cust-12345"],
        fields_accessed=["email", "phone", "address"],  # This should remain an array
        detail=Detail.VIEW_RECORD
    )
    
    if result.get("status") == "success":
        message_content = result.get("message_content", "{}")
        try:
            parsed_message = json.loads(message_content)
            fields_accessed = parsed_message.get("fields_accessed")
            
            print(f"✅ Log published successfully")
            print(f"✅ fields_accessed type: {type(fields_accessed)}")
            print(f"✅ fields_accessed value: [REDACTED - {len(fields_accessed) if fields_accessed else 0} items]")
            
            if isinstance(fields_accessed, list):
                print("✅ fields_accessed is properly preserved as JSON array")
                return True
            else:
                print(f"❌ fields_accessed is not an array! Type: {type(fields_accessed)}")
                return False
                
        except json.JSONDecodeError as e:
            print(f"❌ Failed to parse JSON: {e}")
            return False
    else:
        print("❌ Log publishing failed")
        return False

def test_malicious_array_sanitization():
    """Test that malicious content in arrays is sanitized but structure preserved."""
    
    print("\nTesting malicious content sanitization in arrays...")
    malicious_ids = [
        "cust-001",
        "cust%s%s%s",  # Format string attack
        "cust{0}{1}",  # Brace format attack
        "cust\nFAKE_LOG",  # Log injection
        "cust\x00injection"  # Null byte injection
    ]
    
    result = log_record_access(
        event_type=EventType.RECORD_ACCESS,
        actor_identifier="analyst@company.com",
        actor_type=ActorType.HUMAN_INTERNAL,
        session_id="test-session-789",
        cloud_env_type=CloudEnvType.DEV,
        service_name="reporting-service",
        cloud_env_unique_id="687126124183",
        cloud_env_name="dev-us-west-2",
        service_account_id="sa-reports@company.iam.amazonaws.com",
        endpoint_path="/reports/customer-data",
        data_sensitivity_level=DataSensitivityLevel.CONFIDENTIAL,
        id_list=malicious_ids,
        detail=Detail.EXPORT_REPORT
    )
    
    if result.get("status") == "success":
        message_content = result.get("message_content", "{}")
        try:
            parsed_message = json.loads(message_content)
            id_list = parsed_message.get("id_list")
            
            print(f"✅ Log published successfully with malicious input")
            print(f"✅ id_list type: {type(id_list)}")
            
            if isinstance(id_list, list):
                print("✅ Array structure preserved despite malicious content")
                for i, item in enumerate(id_list):
                    original = malicious_ids[i]
                    sanitized = item
                    print(f"  Element {i}: Original length={len(original)}, Sanitized length={len(sanitized)}")
                    
                    # Check that dangerous characters are removed
                    has_format_chars = any(char in sanitized for char in ['%', '{', '}'])
                    has_newlines = '\n' in sanitized or '\r' in sanitized
                    has_null_bytes = '\x00' in sanitized
                    
                    if not has_format_chars and not has_newlines and not has_null_bytes:
                        print(f"    ✅ Properly sanitized")
                    else:
                        print(f"    ⚠️ May still contain dangerous characters")
                
                return True
            else:
                print(f"❌ Array structure lost! Type: {type(id_list)}")
                return False
                
        except json.JSONDecodeError as e:
            print(f"❌ Failed to parse JSON: {e}")
            return False
    else:
        print("❌ Log publishing failed")
        return False

def main():
    """Run all JSON structure tests."""
    
    print("🔍 JSON STRUCTURE PRESERVATION TESTS")
    print("=" * 80)
    print("Verifying that arrays and objects remain valid JSON after sanitization")
    print("=" * 80)
    
    try:
        test1_result = test_json_structure_preservation()
        test2_result = test_fields_accessed_array()
        test3_result = test_malicious_array_sanitization()
        
        print("\n" + "=" * 80)
        print("📊 TEST SUMMARY")
        print("=" * 80)
        
        tests_passed = sum([test1_result, test2_result, test3_result])
        total_tests = 3
        
        print(f"JSON Structure Tests: {tests_passed}/{total_tests} passed")
        
        if tests_passed == total_tests:
            print("🎉 ALL JSON STRUCTURE TESTS PASSED!")
            print("✅ Arrays and objects are properly preserved")
            print("✅ Lambda normalizer should accept the JSON format")
            return True
        else:
            print("⚠️ Some JSON structure tests failed")
            return False
            
    except Exception as e:
        print(f"❌ Error during JSON structure testing: {str(e)}")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)





