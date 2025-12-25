from unittest import TestCase
import time

import valkey
from util import clean_acl, setup_ldap_users


class DeleteLdapUsersTest(TestCase):
    """Test cases for deleting users from ACL when they don't exist in LDAP"""

    def setUp(self):
        # Try to connect without auth first, if that fails, try with user1 credentials
        try:
            self.client = valkey.Valkey(host='localhost', port=6379, db=0, decode_responses=True, socket_connect_timeout=2)
            # Test if connection works
            self.client.ping()
        except (valkey.exceptions.ConnectionError, valkey.exceptions.TimeoutError, valkey.exceptions.AuthenticationError):
            # If unauthenticated connection fails, try with user1 (LDAP user)
            # user1's LDAP password is user1@123 (defined in test/ldap_users.txt)
            self.client = valkey.Valkey(host='localhost', port=6379, db=0, decode_responses=True, username='user1', password='user1@123')
        
        clean_acl(self.client)
        setup_ldap_users(self.client)
        
        # Wait for LDAP configuration to propagate
        time.sleep(1)

    def tearDown(self):
        # Clear exemption pattern
        self.client.config_set('ldap.exempted_users_regex', '')
        clean_acl(self.client)

    def test_delete_non_ldap_user_from_acl(self):
        """Test that a user is deleted from ACL when they don't exist in LDAP"""
        # Create a user in Valkey ACL that doesn't exist in LDAP
        self.client.execute_command('ACL', 'SETUSER', 'nonldapuser', 'ON', 'resetpass', '+@all', '~*')
        
        # Verify user exists in ACL
        acl_list = self.client.execute_command('ACL', 'LIST')
        self.assertTrue(any('nonldapuser' in user for user in acl_list))
        
        # Try to authenticate as this non-LDAP user (should fail and delete the user)
        with self.assertRaises(valkey.exceptions.AuthenticationError):
            test_client = valkey.Valkey(
                host='localhost',
                port=6379,
                username='nonldapuser',
                password='anypassword',
                decode_responses=True
            )
            test_client.ping()
        
        # Verify user was deleted from ACL
        acl_list = self.client.execute_command('ACL', 'LIST')
        self.assertFalse(any('nonldapuser' in user for user in acl_list))

    def test_exempted_user_not_deleted_on_auth_failure(self):
        """Test that exempted users are never deleted from ACL even on auth failure"""
        # Create an exempted user with a local password
        self.client.execute_command('ACL', 'SETUSER', 'exporter', 'ON', '>localpass', '+@all', '~*')
        
        # Set exemption pattern to match 'exporter'
        self.client.config_set('ldap.exempted_users_regex', '^exporter$')
        
        # Verify user exists in ACL
        acl_list = self.client.execute_command('ACL', 'LIST')
        self.assertTrue(any('exporter' in user for user in acl_list))
        
        # Try to authenticate with wrong password (should fail but NOT delete the user)
        with self.assertRaises(valkey.exceptions.AuthenticationError):
            test_client = valkey.Valkey(
                host='localhost',
                port=6379,
                username='exporter',
                password='wrongpassword',
                decode_responses=True
            )
            test_client.ping()
        
        # Verify user still exists in ACL (not deleted because it's exempted)
        acl_list = self.client.execute_command('ACL', 'LIST')
        self.assertTrue(any('exporter' in user for user in acl_list))
        
        # Now authenticate with correct password to verify it works
        exporter_client = valkey.Valkey(
            host='localhost',
            port=6379,
            username='exporter',
            password='localpass',
            decode_responses=True
        )
        self.assertTrue(exporter_client.ping())

    def test_ldap_user_deleted_after_removal_from_ldap(self):
        """Test that when a user exists in LDAP and ACL, but then gets deleted from LDAP,
        the next auth attempt deletes them from ACL"""
        # This test simulates the scenario where:
        # 1. User exists in both LDAP and ACL
        # 2. User is deleted from LDAP
        # 3. Next auth attempt should delete the user from ACL
        
        # Create a user that would exist in Valkey ACL but not in LDAP
        # (simulating a user that was deleted from LDAP)
        self.client.execute_command('ACL', 'SETUSER', 'deleteduser', 'ON', 'resetpass', '+@all', '~*')
        
        # Verify user exists in ACL
        acl_list = self.client.execute_command('ACL', 'LIST')
        self.assertTrue(any('deleteduser' in user for user in acl_list))
        
        # Try to authenticate as this user (should fail because not in LDAP)
        with self.assertRaises(valkey.exceptions.AuthenticationError):
            test_client = valkey.Valkey(
                host='localhost',
                port=6379,
                username='deleteduser',
                password='anypassword',
                decode_responses=True
            )
            test_client.ping()
        
        # Verify user was deleted from ACL
        acl_list = self.client.execute_command('ACL', 'LIST')
        self.assertFalse(any('deleteduser' in user for user in acl_list))

    def test_multiple_users_deleted_independently(self):
        """Test that multiple non-LDAP users can be deleted independently"""
        # Create multiple users in ACL that don't exist in LDAP
        self.client.execute_command('ACL', 'SETUSER', 'user_a', 'ON', 'resetpass', '+@all', '~*')
        self.client.execute_command('ACL', 'SETUSER', 'user_b', 'ON', 'resetpass', '+@all', '~*')
        
        # Verify both users exist
        acl_list = self.client.execute_command('ACL', 'LIST')
        self.assertTrue(any('user_a' in user for user in acl_list))
        self.assertTrue(any('user_b' in user for user in acl_list))
        
        # Try to auth as user_a (should fail and delete user_a)
        with self.assertRaises(valkey.exceptions.AuthenticationError):
            test_client = valkey.Valkey(
                host='localhost',
                port=6379,
                username='user_a',
                password='anypassword',
                decode_responses=True
            )
            test_client.ping()
        
        # Verify user_a was deleted but user_b still exists
        acl_list = self.client.execute_command('ACL', 'LIST')
        self.assertFalse(any('user_a' in user for user in acl_list))
        self.assertTrue(any('user_b' in user for user in acl_list))
        
        # Try to auth as user_b (should fail and delete user_b)
        with self.assertRaises(valkey.exceptions.AuthenticationError):
            test_client = valkey.Valkey(
                host='localhost',
                port=6379,
                username='user_b',
                password='anypassword',
                decode_responses=True
            )
            test_client.ping()
        
        # Verify user_b was also deleted
        acl_list = self.client.execute_command('ACL', 'LIST')
        self.assertFalse(any('user_b' in user for user in acl_list))

    def test_default_user_not_deleted(self):
        """Test that the default user is never deleted even if not exempted explicitly"""
        # The default user should always exist
        acl_list = self.client.execute_command('ACL', 'LIST')
        self.assertTrue(any('default' in user for user in acl_list))
        
        # Attempting to delete default user through ACL DELUSER should fail
        # (this is Valkey's built-in protection, not our code)
        with self.assertRaises(valkey.exceptions.ResponseError):
            self.client.execute_command('ACL', 'DELUSER', 'default')
        
        # Verify default user still exists
        acl_list = self.client.execute_command('ACL', 'LIST')
        self.assertTrue(any('default' in user for user in acl_list))

    def test_wrong_password_does_not_delete_user(self):
        """Test that entering wrong password for existing LDAP user does NOT delete them from ACL
        This prevents DoS attacks from password typos"""
        # First, successfully authenticate user1 to create their ACL entry
        user1_client = valkey.Valkey(
            host='localhost',
            port=6379,
            username='user1',
            password='user1@123',
            decode_responses=True
        )
        self.assertTrue(user1_client.ping())
        
        # Verify user1 exists in ACL
        acl_list = self.client.execute_command('ACL', 'LIST')
        self.assertTrue(any('user1' in user for user in acl_list))
        
        # Try to authenticate with WRONG password (should fail but NOT delete the user)
        with self.assertRaises(valkey.exceptions.AuthenticationError):
            test_client = valkey.Valkey(
                host='localhost',
                port=6379,
                username='user1',
                password='wrongpassword',
                decode_responses=True
            )
            test_client.ping()
        
        # Verify user1 still exists in ACL (NOT deleted because they exist in LDAP)
        acl_list = self.client.execute_command('ACL', 'LIST')
        self.assertTrue(any('user1' in user for user in acl_list))
        
        # Verify user1 can still authenticate with correct password
        user1_client_retry = valkey.Valkey(
            host='localhost',
            port=6379,
            username='user1',
            password='user1@123',
            decode_responses=True
        )
        self.assertTrue(user1_client_retry.ping())

