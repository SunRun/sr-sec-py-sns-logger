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
import time
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch, MagicMock

# Import the module using the parent directory path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')))
import security_logging_sns as SecurityLogging
from security_log_fields import *


class TestSecurityLogging(unittest.TestCase):
    """Basic test cases for security logging module."""

    def setUp(self):
        """Set up test fixtures before each test method."""
        # Initialize logging in test mode
        SecurityLogging.init_security_logging(test_mode=True)

    def test_init_security_logging(self):
        """Test initialization in test mode."""
        SecurityLogging.init_security_logging(test_mode=True)
        # Should not raise an exception
        publisher = SecurityLogging._get_publisher()
        self.assertIsNotNone(publisher)

    def test_user_login_success(self):
        """Test successful user login logging."""
        result = SecurityLogging.log_user_login(
            event_type=EventType.LOGIN_ATTEMPT,
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
            auth_protocol=AuthProtocol.FORM_BASED,
            detail=Detail.USER_INITIATED,
            status=Status.SUCCESS
        )
        
        self.assertEqual(result["status"], "success")
        self.assertTrue(result.get("test_mode", False))
        
        # In test mode, we just verify the call succeeded
        # The actual message structure is tested in the SNS publisher

    def test_api_request_success(self):
        """Test successful API request logging."""
        result = SecurityLogging.log_api_request(
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
        self.assertTrue(result.get("test_mode", False))

    def test_missing_required_fields(self):
        """Test that missing required fields are handled gracefully."""
        result = SecurityLogging.log_user_login(
            # Provide base required fields
            cloud_env_type=CloudEnvType.TEST,
            service_name="test-service",
            cloud_env_unique_id="123456789012",
            cloud_env_name="test-env",
            service_account_id="sa-test@project.iam",
            # Provide minimal event-specific parameters (missing or empty)
            actor_identifier="user@company.com",
            actor_type="",  # Empty - should trigger validation failure
            session_id="",  # Empty - should trigger validation failure
            event_type="",  # Empty - should trigger validation failure
            user_agent="Mozilla/5.0",
            user_role="",  # Empty - should trigger validation failure
            auth_protocol=AuthProtocol.FORM_BASED,
            status=""  # Empty - should trigger validation failure
        )
        
        # Should fail gracefully without crashing
        self.assertEqual(result["status"], "failure")
        self.assertIn("message", result)

    def test_invalid_field_values(self):
        """Test that invalid field values are handled gracefully."""
        result = SecurityLogging.log_user_login(
            event_type=EventType.LOGIN_ATTEMPT,
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
            auth_protocol=AuthProtocol.FORM_BASED,
            status=Status.SUCCESS
        )
        
        # Should fail gracefully without crashing
        self.assertEqual(result["status"], "failure")
        self.assertIn("message", result)


class TestFireAndForgetFunctionality(unittest.TestCase):
    """Test cases for fire-and-forget logging functionality."""

    def setUp(self):
        """Set up test fixtures before each test method."""
        # Initialize logging in test mode
        SecurityLogging.init_security_logging(test_mode=True)
        # Reset error handler to None for clean tests
        SecurityLogging._error_handler = None

    def test_set_error_handler(self):
        """Test setting custom error handler."""
        error_messages = []
        
        def test_error_handler(error_msg, event_type):
            error_messages.append((error_msg, event_type))
        
        # Set the error handler
        SecurityLogging.set_security_logging_error_handler(test_error_handler)
        
        # Verify it was set
        self.assertEqual(SecurityLogging._error_handler, test_error_handler)

    def test_fire_and_forget_success(self):
        """Test fire-and-forget with successful logging."""
        with ThreadPoolExecutor() as executor:
            # Submit a valid logging call
            future = executor.submit(
                SecurityLogging.log_user_login,
                event_type=EventType.LOGIN_ATTEMPT,
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
                auth_protocol=AuthProtocol.FORM_BASED,
                detail=Detail.USER_INITIATED,
                status=Status.SUCCESS
            )
            
            # Use fire-and-forget
            SecurityLogging.fire_and_forget(future, EventType.LOGIN_ATTEMPT)
            
            # Wait a moment for async processing
            time.sleep(0.1)
            
            # Should complete without errors
            self.assertTrue(future.done())
            result = future.result()
            self.assertEqual(result["status"], "success")

    def test_fire_and_forget_failure_with_handler(self):
        """Test fire-and-forget with failure and custom error handler."""
        error_messages = []
        
        def test_error_handler(error_msg, event_type):
            error_messages.append((error_msg, event_type))
        
        # Set the error handler
        SecurityLogging.set_security_logging_error_handler(test_error_handler)
        
        with ThreadPoolExecutor() as executor:
            # Submit an invalid logging call (empty required fields to trigger failure)
            future = executor.submit(
                SecurityLogging.log_user_login,
                # Provide all required fields but with empty values to trigger validation failure
                cloud_env_type=CloudEnvType.TEST,
                service_name="test-service",
                cloud_env_unique_id="123456789012",
                cloud_env_name="test-env",
                service_account_id="sa-test@project.iam",
                event_type="",  # Empty event type
                actor_identifier="",  # Empty actor
                actor_type=ActorType.HUMAN_INTERNAL,
                session_id="session-123",
                user_agent="",  # Empty user agent
                user_role="",  # Empty user role
                auth_protocol=AuthProtocol.FORM_BASED,
                status=""  # Empty status
            )
            
            # Use fire-and-forget
            SecurityLogging.fire_and_forget(future, EventType.LOGIN_ATTEMPT)
            
            # Wait a moment for async processing
            time.sleep(0.1)
            
            # Should have called error handler
            self.assertEqual(len(error_messages), 1)
            error_msg, event_type = error_messages[0]
            self.assertIn("Security logging failed", error_msg)
            self.assertEqual(event_type, EventType.LOGIN_ATTEMPT)

    def test_fire_and_forget_failure_without_handler(self):
        """Test fire-and-forget with failure and no custom error handler."""
        # Capture stderr to verify default error handling
        with patch('sys.stderr') as mock_stderr:
            with ThreadPoolExecutor() as executor:
                # Submit an invalid logging call (empty required fields)
                future = executor.submit(
                    SecurityLogging.log_user_login,
                    cloud_env_type=CloudEnvType.TEST,
                    service_name="test-service",
                    cloud_env_unique_id="123456789012",
                    cloud_env_name="test-env",
                    service_account_id="sa-test@project.iam",
                    event_type="",  # Empty to trigger failure
                    actor_identifier="",
                    actor_type=ActorType.HUMAN_INTERNAL,
                    session_id="session-123",
                    user_agent="",
                    user_role="",
                    auth_protocol=AuthProtocol.FORM_BASED,
                    status=""
                )
                
                # Use fire-and-forget
                SecurityLogging.fire_and_forget(future, EventType.LOGIN_ATTEMPT)
                
                # Wait a moment for async processing
                time.sleep(0.1)
                
                # Should have printed to stderr
                mock_stderr.write.assert_called()

    def test_fire_and_forget_exception_handling(self):
        """Test fire-and-forget handles exceptions in logging functions."""
        error_messages = []
        
        def test_error_handler(error_msg, event_type):
            error_messages.append((error_msg, event_type))
        
        SecurityLogging.set_security_logging_error_handler(test_error_handler)
        
        with ThreadPoolExecutor() as executor:
            # Create a future that will raise an exception
            def failing_function():
                raise ValueError("Test exception")
            
            future = executor.submit(failing_function)
            
            # Use fire-and-forget
            SecurityLogging.fire_and_forget(future, EventType.LOGIN_ATTEMPT)
            
            # Wait a moment for async processing
            time.sleep(0.1)
            
            # Should have called error handler with exception
            self.assertEqual(len(error_messages), 1)
            error_msg, event_type = error_messages[0]
            self.assertIn("Security logging error", error_msg)
            self.assertIn("Test exception", error_msg)
            self.assertEqual(event_type, EventType.LOGIN_ATTEMPT)

    def test_fire_and_forget_non_blocking(self):
        """Test that fire-and-forget is truly non-blocking."""
        start_time = time.time()
        
        with ThreadPoolExecutor() as executor:
            # Submit multiple logging calls
            futures = []
            for i in range(5):
                future = executor.submit(
                    SecurityLogging.log_user_login,
                    event_type=EventType.LOGIN_ATTEMPT,
                    actor_identifier=f"user{i}@company.com",
                    actor_type=ActorType.HUMAN_INTERNAL,
                    session_id=f"session-{i}",
                    cloud_env_type=CloudEnvType.TEST,
                    service_name="test-service",
                    cloud_env_unique_id="123456789012",
                    cloud_env_name="test-env",
                    service_account_id="sa-test@project.iam",
                    user_agent="Mozilla/5.0",
                    user_role=UserRole.ADMIN,
                    auth_protocol=AuthProtocol.FORM_BASED,
                    detail=Detail.USER_INITIATED,
                    status=Status.SUCCESS
                )
                futures.append(future)
                SecurityLogging.fire_and_forget(future, EventType.LOGIN_ATTEMPT)
        
        elapsed_time = time.time() - start_time
        
        # Should complete very quickly (non-blocking)
        # Even 5 calls should complete in well under 1 second
        self.assertLess(elapsed_time, 1.0, "Fire-and-forget should be non-blocking")

    def test_multiple_concurrent_fire_and_forget(self):
        """Test multiple concurrent fire-and-forget calls work correctly."""
        success_count = 0
        error_count = 0
        
        def test_error_handler(error_msg, event_type):
            nonlocal error_count
            error_count += 1
        
        SecurityLogging.set_security_logging_error_handler(test_error_handler)
        
        with ThreadPoolExecutor() as executor:
            futures = []
            
            # Submit mix of valid and invalid calls
            for i in range(10):
                if i % 2 == 0:
                    # Valid call
                    future = executor.submit(
                        SecurityLogging.log_user_login,
                        event_type=EventType.LOGIN_ATTEMPT,
                        actor_identifier=f"user{i}@company.com",
                        actor_type=ActorType.HUMAN_INTERNAL,
                        session_id=f"session-{i}",
                        cloud_env_type=CloudEnvType.TEST,
                        service_name="test-service",
                        cloud_env_unique_id="123456789012",
                        cloud_env_name="test-env",
                        service_account_id="sa-test@project.iam",
                        user_agent="Mozilla/5.0",
                        user_role=UserRole.ADMIN,
                        auth_protocol=AuthProtocol.FORM_BASED,
                        detail=Detail.USER_INITIATED,
                        status=Status.SUCCESS
                    )
                else:
                    # Invalid call (empty required fields)
                    future = executor.submit(
                        SecurityLogging.log_user_login,
                        cloud_env_type=CloudEnvType.TEST,
                        service_name="test-service",
                        cloud_env_unique_id="123456789012",
                        cloud_env_name="test-env",
                        service_account_id="sa-test@project.iam",
                        event_type="",  # Empty to trigger failure
                        actor_identifier="",
                        actor_type=ActorType.HUMAN_INTERNAL,
                        session_id="session-123",
                        user_agent="",
                        user_role="",
                        auth_protocol=AuthProtocol.FORM_BASED,
                        status=""
                    )
                
                futures.append(future)
                SecurityLogging.fire_and_forget(future, EventType.LOGIN_ATTEMPT)
            
            # Wait for all to complete
            time.sleep(0.2)
            
            # Count successful results
            for future in futures:
                if future.done():
                    try:
                        result = future.result()
                        if result.get("status") == "success":
                            success_count += 1
                    except:
                        pass
        
        # Should have 5 successes and 5 errors
        self.assertEqual(success_count, 5)
        self.assertEqual(error_count, 5)


if __name__ == '__main__':
    unittest.main()