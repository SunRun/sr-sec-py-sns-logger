#!/usr/bin/env python3
"""
Unit tests for the security logging module.
Tests validation logic, error handling, and proper log generation.
"""

import unittest
from unittest.mock import patch, MagicMock
import json
from datetime import datetime, timezone

import security_logging_sns
from security_log_fields import (
    Status, ActorType, LogCategory, EventType, AuthProtocol, Detail, MfaType,
    HttpMethod, CloudEnvType, CloudServiceApiType, DataSensitivityLevel,
    EndpointSensitivity, InviteStatus, UserRole
)


class TestSecurityLogging(unittest.TestCase):
    """Test cases for security logging module."""

    def setUp(self):
        """Set up test fixtures before each test method."""
        # Initialize logging in test mode
        security_logging_sns.init_security_logging(test_mode=True)
        
        # Base log details for testing
        self.base_log_details = {
            "actor_identifier": "test@company.com",
            "actor_type": ActorType.HUMAN_INTERNAL,
            "session_id": "session-123",
            "cloud_env_type": CloudEnvType.TEST,
            "service_name": "test-service",
            "cloud_env_unique_id": "123456789012",
            "cloud_env_name": "test-env",
            "service_account_id": "sa-test@project.iam.gserviceaccount.com",
            "source_ip_address": "192.168.1.100",
            "cloud_service_api_type": CloudServiceApiType.AWS_LAMBDA,
        }

    def test_init_security_logging_with_params(self):
        """Test initialization with explicit parameters."""
        topic_arn = "arn:aws:sns:us-east-1:123456789012:test-topic"
        region = "us-east-1"
        
        security_logging_sns.init_security_logging(
            topic_arn=topic_arn,
            region_name=region,
            test_mode=True
        )
        
        # Should not raise an exception
        publisher = security_logging_sns._get_publisher()
        self.assertIsNotNone(publisher)

    def test_init_security_logging_missing_topic_arn(self):
        """Test initialization fails without topic ARN in production mode."""
        with patch.dict('os.environ', {}, clear=True):
            with self.assertRaises(ValueError) as context:
                security_logging_sns.init_security_logging(test_mode=False)
            
            self.assertIn("topic_arn must be provided", str(context.exception))

    def test_get_publisher_not_initialized(self):
        """Test that getting publisher fails if not initialized."""
        # Reset the global publisher
        security_logging_sns._sns_publisher = None
        
        with self.assertRaises(RuntimeError) as context:
            security_logging_sns._get_publisher()
        
        self.assertIn("Security logging not initialized", str(context.exception))
        
        # Re-initialize for other tests
        security_logging_sns.init_security_logging(test_mode=True)


class TestValidationFunctions(unittest.TestCase):
    """Test validation functions."""

    def test_get_valid_values_for_field(self):
        """Test getting valid values for different fields."""
        # Test event_type field
        valid_event_types = security_logging_sns._get_valid_values_for_field("event_type")
        self.assertIn(EventType.LOGIN_SUCCESS, valid_event_types)
        self.assertIn(EventType.API_REQUEST_FAILURE, valid_event_types)
        
        # Test actor_type field
        valid_actor_types = security_logging_sns._get_valid_values_for_field("actor_type")
        self.assertIn(ActorType.HUMAN_INTERNAL, valid_actor_types)
        self.assertIn(ActorType.SERVICE_PARTNER, valid_actor_types)
        
        # Test non-existent field
        empty_list = security_logging_sns._get_valid_values_for_field("non_existent_field")
        self.assertEqual(empty_list, [])

    def test_validate_standardized_field_valid_values(self):
        """Test validation with valid standardized values."""
        # Test valid actor_type
        result = security_logging_sns._validate_standardized_field("actor_type", ActorType.HUMAN_INTERNAL)
        self.assertTrue(result["valid"])
        
        # Test valid status
        result = security_logging_sns._validate_standardized_field("status", Status.SUCCESS)
        self.assertTrue(result["valid"])
        
        # Test empty value (should be valid - handled by required field validation)
        result = security_logging_sns._validate_standardized_field("actor_type", "")
        self.assertTrue(result["valid"])

    def test_validate_standardized_field_invalid_values(self):
        """Test validation with invalid values."""
        # Test invalid actor_type
        result = security_logging_sns._validate_standardized_field("actor_type", "invalid_actor")
        self.assertFalse(result["valid"])
        self.assertIn("Invalid actor_type value", result["message"])
        self.assertIn("Must use standardized values", result["message"])
        
        # Test invalid auth_protocol
        result = security_logging_sns._validate_standardized_field("auth_protocol", "invalid_protocol")
        self.assertFalse(result["valid"])
        self.assertIn("Invalid auth_protocol value", result["message"])

    def test_validate_standardized_field_detail_custom_allowed(self):
        """Test detail field allows custom text when flag is set."""
        # Test standardized detail value
        result = security_logging_sns._validate_standardized_field("detail", Detail.INVALID_CREDENTIALS)
        self.assertTrue(result["valid"])
        
        # Test custom detail value without flag (should fail)
        result = security_logging_sns._validate_standardized_field("detail", "custom success message")
        self.assertFalse(result["valid"])
        
        # Test custom detail value with flag (should pass)
        result = security_logging_sns._validate_standardized_field("detail", "custom success message", allow_custom_for_detail=True)
        self.assertTrue(result["valid"])

    def test_validate_base_log_fields_missing_required(self):
        """Test base log validation with missing required fields."""
        result = security_logging_sns._validate_base_log_fields(
            timestamp="2025-01-01T00:00:00Z",
            event_type=EventType.LOGIN_SUCCESS,
            # Missing other required fields
        )
        
        self.assertFalse(result["valid"])
        self.assertIn("Required base_log fields missing", result["message"])
        self.assertIn("missing_fields", result)

    def test_validate_base_log_fields_invalid_standardized_values(self):
        """Test base log validation with invalid standardized values."""
        result = security_logging_sns._validate_base_log_fields(
            timestamp="2025-01-01T00:00:00Z",
            event_type="invalid_event_type",  # Invalid
            log_category=LogCategory.AUTHN_SESSION,
            status=Status.SUCCESS,
            actor_identifier="test@company.com",
            actor_type=ActorType.HUMAN_INTERNAL,
            session_id="session-123",
            cloud_env_type=CloudEnvType.TEST,
            service_name="test-service",
            cloud_env_unique_id="123456789012",
            cloud_env_name="test-env",
            service_account_id="sa-test@project.iam",
        )
        
        self.assertFalse(result["valid"])
        self.assertIn("Invalid event_type value", result["message"])

    def test_validate_base_log_fields_valid(self):
        """Test base log validation with all valid fields."""
        result = security_logging_sns._validate_base_log_fields(
            timestamp="2025-01-01T00:00:00Z",
            event_type=EventType.LOGIN_SUCCESS,
            log_category=LogCategory.AUTHN_SESSION,
            status=Status.SUCCESS,
            actor_identifier="test@company.com",
            actor_type=ActorType.HUMAN_INTERNAL,
            session_id="session-123",
            cloud_env_type=CloudEnvType.TEST,
            service_name="test-service",
            cloud_env_unique_id="123456789012",
            cloud_env_name="test-env",
            service_account_id="sa-test@project.iam",
        )
        
        self.assertTrue(result["valid"])


class TestUserLoginFunction(unittest.TestCase):
    """Test user login logging function."""

    def setUp(self):
        """Set up test fixtures."""
        security_logging_sns.init_security_logging(test_mode=True)

    def test_user_login_success_valid(self):
        """Test successful user login with valid parameters."""
        result = security_logging_sns.log_user_login(
            actor_identifier="user@company.com",
            actor_type=ActorType.HUMAN_INTERNAL,
            session_id="session-123",
            cloud_env_type=CloudEnvType.TEST,
            service_name="test-service",
            cloud_env_unique_id="123456789012",
            cloud_env_name="test-env",
            service_account_id="sa-test@project.iam",
            user_agent="Mozilla/5.0",
            user_role=UserRole.ADMIN,
            detail="1st time login",
            login_successful=True
        )
        
        self.assertEqual(result["status"], "success")
        self.assertIn("message_content", result)
        
        # Parse the JSON message to verify structure
        message = json.loads(result["message_content"])
        self.assertEqual(message["event_type"], EventType.LOGIN_SUCCESS)
        self.assertEqual(message["status"], Status.SUCCESS)
        self.assertEqual(message["actor_type"], ActorType.HUMAN_INTERNAL)
        self.assertEqual(message["user_role"], UserRole.ADMIN)

    def test_user_login_failure_valid(self):
        """Test failed user login with valid parameters."""
        result = security_logging_sns.log_user_login(
            actor_identifier="attacker@external.com",
            actor_type=ActorType.HUMAN_CUSTOMER,
            session_id="session-456",
            cloud_env_type=CloudEnvType.PROD,
            service_name="auth-service",
            cloud_env_unique_id="123456789012",
            cloud_env_name="production",
            service_account_id="sa-auth@project.iam",
            user_agent="curl/7.68.0",
            user_role=UserRole.CUSTOMER_USER,
            detail=Detail.INVALID_CREDENTIALS,
            login_successful=False
        )
        
        self.assertEqual(result["status"], "success")
        
        # Parse the JSON message to verify structure
        message = json.loads(result["message_content"])
        self.assertEqual(message["event_type"], EventType.LOGIN_FAILURE)
        self.assertEqual(message["status"], Status.FAILURE)
        self.assertEqual(message["detail"], Detail.INVALID_CREDENTIALS)

    def test_user_login_missing_required_fields(self):
        """Test user login with missing required fields."""
        result = security_logging_sns.log_user_login(
            actor_identifier="user@company.com",
            # Missing other required fields
            user_agent="Mozilla/5.0",
            user_role=UserRole.ADMIN,
            detail="1st time login"
        )
        
        self.assertEqual(result["status"], "failure")
        self.assertIn("Required base_log fields missing", result["message"])

    def test_user_login_missing_event_specific_fields(self):
        """Test user login with missing event-specific fields."""
        result = security_logging_sns.log_user_login(
            actor_identifier="user@company.com",
            actor_type=ActorType.HUMAN_INTERNAL,
            session_id="session-123",
            cloud_env_type=CloudEnvType.TEST,
            service_name="test-service",
            cloud_env_unique_id="123456789012",
            cloud_env_name="test-env",
            service_account_id="sa-test@project.iam",
            # Missing event-specific fields
        )
        
        self.assertEqual(result["status"], "failure")
        self.assertIn("Required log_specifics fields missing", result["message"])

    def test_user_login_invalid_standardized_values(self):
        """Test user login with invalid standardized values."""
        result = security_logging_sns.log_user_login(
            actor_identifier="user@company.com",
            actor_type=ActorType.HUMAN_INTERNAL,  # Valid actor_type
            session_id="session-123",
            cloud_env_type=CloudEnvType.TEST,
            service_name="test-service",
            cloud_env_unique_id="123456789012",
            cloud_env_name="test-env",
            service_account_id="sa-test@project.iam",
            user_agent="Mozilla/5.0",
            user_role="invalid_role",  # Invalid user_role
            detail="1st time login"
        )
        
        self.assertEqual(result["status"], "failure")
        # Should catch the invalid user_role in event-specific validation
        self.assertIn("Invalid user_role value", result["message"])

    def test_user_login_without_detail_field(self):
        """Test user login without detail field (should be optional)."""
        result = security_logging_sns.log_user_login(
            actor_identifier="user@company.com",
            actor_type=ActorType.HUMAN_INTERNAL,
            session_id="session-123",
            cloud_env_type=CloudEnvType.TEST,
            service_name="test-service",
            cloud_env_unique_id="123456789012",
            cloud_env_name="test-env",
            service_account_id="sa-test@project.iam",
            user_agent="Mozilla/5.0",
            user_role=UserRole.ADMIN,
            # detail field omitted - should be optional
            login_successful=True
        )
        
        self.assertEqual(result["status"], "success")
        
        # Parse the JSON message to verify detail field is not present
        message = json.loads(result["message_content"])
        self.assertNotIn("detail", message)


class TestAPIRequestFunction(unittest.TestCase):
    """Test API request logging function."""

    def setUp(self):
        """Set up test fixtures."""
        security_logging_sns.init_security_logging(test_mode=True)

    def test_api_request_success_valid(self):
        """Test successful API request with valid parameters."""
        result = security_logging_sns.log_api_request_processed(
            actor_identifier="api-client-123",
            actor_type=ActorType.SERVICE_INTERNAL,
            session_id="api-session-789",
            cloud_env_type=CloudEnvType.PROD,
            service_name="api-gateway",
            cloud_env_unique_id="123456789012",
            cloud_env_name="production",
            service_account_id="sa-api@project.iam",
            auth_protocol=AuthProtocol.OAUTH2_JWT,
            endpoint_path="/api/v1/users/profile",
            http_method=HttpMethod.GET,
            endpoint_sensitivity=EndpointSensitivity.CONFIDENTIAL,
            detail="Successful API call",
            request_successful=True
        )
        
        self.assertEqual(result["status"], "success")
        
        # Parse the JSON message to verify structure
        message = json.loads(result["message_content"])
        self.assertEqual(message["event_type"], EventType.API_REQUEST_SUCCESS)
        self.assertEqual(message["auth_protocol"], AuthProtocol.OAUTH2_JWT)
        self.assertEqual(message["http_method"], HttpMethod.GET)

    def test_api_request_invalid_standardized_values(self):
        """Test API request with invalid standardized values."""
        result = security_logging_sns.log_api_request_processed(
            actor_identifier="api-client-123",
            actor_type=ActorType.SERVICE_INTERNAL,
            session_id="api-session-789",
            cloud_env_type=CloudEnvType.PROD,
            service_name="api-gateway",
            cloud_env_unique_id="123456789012",
            cloud_env_name="production",
            service_account_id="sa-api@project.iam",
            auth_protocol="invalid_protocol",  # Invalid
            endpoint_path="/api/v1/users/profile",
            http_method="INVALID_METHOD",  # Invalid
            endpoint_sensitivity="invalid_sensitivity",  # Invalid
            detail="API call",
        )
        
        self.assertEqual(result["status"], "failure")
        # Should catch the first invalid field
        self.assertIn("Invalid auth_protocol value", result["message"])


class TestUserInviteFunction(unittest.TestCase):
    """Test user invite logging function."""

    def setUp(self):
        """Set up test fixtures."""
        security_logging_sns.init_security_logging(test_mode=True)

    def test_user_invite_valid(self):
        """Test user invite with valid parameters."""
        result = security_logging_sns.log_user_invite_event(
            actor_identifier="admin@company.com",
            actor_type=ActorType.HUMAN_INTERNAL,
            session_id="session-admin-123",
            cloud_env_type=CloudEnvType.PROD,
            service_name="user-management",
            cloud_env_unique_id="123456789012",
            cloud_env_name="production",
            service_account_id="sa-mgmt@project.iam",
            target_user_email="newuser@company.com",
            assigned_role="developer",
            invite_status=InviteStatus.SENT
        )
        
        self.assertEqual(result["status"], "success")
        
        # Parse the JSON message to verify structure
        message = json.loads(result["message_content"])
        self.assertEqual(message["event_type"], EventType.INVITE_SENT)
        self.assertEqual(message["invite_status"], InviteStatus.SENT)

    def test_user_invite_invalid_status(self):
        """Test user invite with invalid invite status."""
        result = security_logging_sns.log_user_invite_event(
            actor_identifier="admin@company.com",
            actor_type=ActorType.HUMAN_INTERNAL,
            session_id="session-admin-123",
            cloud_env_type=CloudEnvType.PROD,
            service_name="user-management",
            cloud_env_unique_id="123456789012",
            cloud_env_name="production",
            service_account_id="sa-mgmt@project.iam",
            target_user_email="newuser@company.com",
            assigned_role="developer",
            invite_status="invalid_status"  # Invalid
        )
        
        self.assertEqual(result["status"], "failure")
        self.assertIn("Invalid invite_status value", result["message"])


class TestTimestampGeneration(unittest.TestCase):
    """Test automatic timestamp generation."""

    def setUp(self):
        """Set up test fixtures."""
        security_logging_sns.init_security_logging(test_mode=True)

    def test_timestamp_auto_generation(self):
        """Test that timestamp is auto-generated when not provided."""
        result = security_logging_sns.log_user_login(
            # No timestamp provided
            actor_identifier="user@company.com",
            actor_type=ActorType.HUMAN_INTERNAL,
            session_id="session-123",
            cloud_env_type=CloudEnvType.TEST,
            service_name="test-service",
            cloud_env_unique_id="123456789012",
            cloud_env_name="test-env",
            service_account_id="sa-test@project.iam",
            user_agent="Mozilla/5.0",
            user_role=UserRole.ADMIN,
            detail="1st time login"
        )
        
        self.assertEqual(result["status"], "success")
        
        # Parse the JSON message to verify timestamp is present
        message = json.loads(result["message_content"])
        self.assertIn("timestamp", message)
        
        # Verify timestamp format (should be ISO format)
        timestamp = message["timestamp"]
        # Should be able to parse as datetime
        parsed_time = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        self.assertIsInstance(parsed_time, datetime)

    def test_timestamp_provided(self):
        """Test that provided timestamp is used."""
        custom_timestamp = "2025-01-01T12:00:00.000000+00:00"
        
        result = security_logging_sns.log_user_login(
            timestamp=custom_timestamp,
            actor_identifier="user@company.com",
            actor_type=ActorType.HUMAN_INTERNAL,
            session_id="session-123",
            cloud_env_type=CloudEnvType.TEST,
            service_name="test-service",
            cloud_env_unique_id="123456789012",
            cloud_env_name="test-env",
            service_account_id="sa-test@project.iam",
            user_agent="Mozilla/5.0",
            user_role=UserRole.ADMIN,
            detail="1st time login"
        )
        
        self.assertEqual(result["status"], "success")
        
        # Parse the JSON message to verify custom timestamp is used
        message = json.loads(result["message_content"])
        self.assertEqual(message["timestamp"], custom_timestamp)


class TestErrorHandling(unittest.TestCase):
    """Test error handling and edge cases."""

    def setUp(self):
        """Set up test fixtures."""
        security_logging_sns.init_security_logging(test_mode=True)

    def test_empty_parameters(self):
        """Test function calls with completely empty parameters."""
        result = security_logging_sns.log_user_login()
        
        self.assertEqual(result["status"], "failure")
        self.assertIn("Required log_specifics fields missing", result["message"])

    def test_whitespace_only_parameters(self):
        """Test function calls with whitespace-only parameters."""
        result = security_logging_sns.log_user_login(
            actor_identifier="   ",  # Whitespace only
            actor_type="   ",
            session_id="   ",
            user_agent="   ",
            user_role="   ",
            detail="   "
        )
        
        self.assertEqual(result["status"], "failure")
        # Should be treated as missing fields
        self.assertIn("Required", result["message"])

    @patch('security_logging_sns._get_publisher')
    def test_publisher_exception_handling(self, mock_get_publisher):
        """Test handling of publisher exceptions."""
        # Mock publisher to raise an exception
        mock_publisher = MagicMock()
        mock_publisher.publish_message.side_effect = Exception("SNS Error")
        mock_get_publisher.return_value = mock_publisher
        
        result = security_logging_sns.log_user_login(
            actor_identifier="user@company.com",
            actor_type=ActorType.HUMAN_INTERNAL,
            session_id="session-123",
            cloud_env_type=CloudEnvType.TEST,
            service_name="test-service",
            cloud_env_unique_id="123456789012",
            cloud_env_name="test-env",
            service_account_id="sa-test@project.iam",
            user_agent="Mozilla/5.0",
            user_role=UserRole.ADMIN,
            detail="1st time login"
        )
        
        self.assertEqual(result["status"], "failure")
        self.assertIn("Error in log_user_login", result["message"])


if __name__ == '__main__':
    unittest.main()
