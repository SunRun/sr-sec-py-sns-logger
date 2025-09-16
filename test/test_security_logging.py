#!/usr/bin/env python3
"""
Basic tests for the security logging module.
Tests core functionality in test mode without requiring AWS credentials.
"""

import sys
import os
# Add parent directory to path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')))

import unittest
import json

import security_logging_sns
from security_log_fields import (
    Status, ActorType, EventType, AuthProtocol,
    HttpMethod, CloudEnvType, CloudServiceApiType, 
    EndpointSensitivity, UserRole
)


class TestSecurityLogging(unittest.TestCase):
    """Basic test cases for security logging module."""

    def setUp(self):
        """Set up test fixtures before each test method."""
        # Initialize logging in test mode
        security_logging_sns.init_security_logging(test_mode=True)

    def test_init_security_logging(self):
        """Test initialization in test mode."""
        security_logging_sns.init_security_logging(test_mode=True)
        # Should not raise an exception
        publisher = security_logging_sns._get_publisher()
        self.assertIsNotNone(publisher)

    def test_user_login_success(self):
        """Test successful user login logging."""
        result = security_logging_sns.log_user_login(
            event_type=EventType.LOGIN_SUCCESS,
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
            status=Status.SUCCESS
        )
        
        self.assertEqual(result["status"], "success")
        self.assertIn("message_content", result)
        
        # Parse the JSON message to verify structure
        message = json.loads(result["message_content"])
        self.assertEqual(message["event_type"], EventType.LOGIN_SUCCESS)
        self.assertEqual(message["status"], Status.SUCCESS)
        self.assertEqual(message["actor_type"], ActorType.HUMAN_INTERNAL)

    def test_api_request_success(self):
        """Test successful API request logging."""
        result = security_logging_sns.log_api_request(
            event_type=EventType.API_REQUEST_PROCESSED,
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
            authorization_status=Status.SUCCESS
        )
        
        self.assertEqual(result["status"], "success")
        
        # Parse the JSON message to verify structure
        message = json.loads(result["message_content"])
        self.assertEqual(message["event_type"], EventType.API_REQUEST_PROCESSED)
        self.assertEqual(message["auth_protocol"], AuthProtocol.OAUTH2_JWT)

    def test_missing_required_fields(self):
        """Test that missing required fields are handled gracefully."""
        result = security_logging_sns.log_user_login(
            # Only provide minimal parameters
            actor_identifier="user@company.com",
            user_agent="Mozilla/5.0"
        )
        
        # Should fail gracefully without crashing
        self.assertEqual(result["status"], "failure")
        self.assertIn("message", result)

    def test_invalid_field_values(self):
        """Test that invalid field values are handled gracefully."""
        result = security_logging_sns.log_user_login(
            event_type=EventType.LOGIN_SUCCESS,
            actor_identifier="user@company.com",
            actor_type="invalid_actor_type",  # Invalid value
            session_id="session-123",
            cloud_env_type=CloudEnvType.TEST,
            service_name="test-service",
            cloud_env_unique_id="123456789012",
            cloud_env_name="test-env",
            service_account_id="sa-test@project.iam",
            user_agent="Mozilla/5.0",
            user_role="invalid_role",  # Invalid value
            status=Status.SUCCESS
        )
        
        # Should fail gracefully without crashing
        self.assertEqual(result["status"], "failure")
        self.assertIn("message", result)


if __name__ == '__main__':
    unittest.main()