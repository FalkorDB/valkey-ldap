from unittest import TestCase

import valkey
from util import clean_acl, setup_ldap_users


class ExemptedUsersTest(TestCase):
    """Test cases for exempted users regex feature"""

    def setUp(self):
        self.client = valkey.Valkey(host='localhost', port=6379, db=0, decode_responses=True)
        clean_acl(self.client)

    def tearDown(self):
        # Clear exemption pattern
        self.client.config_set('ldap.exempted_users_regex', '')
        clean_acl(self.client)

    def test_exempted_user_uses_local_auth(self):
        """Test that exempted users bypass LDAP and use local authentication"""
        # Create a local user with password
        self.client.execute_command('ACL', 'SETUSER', 'exporter', 'ON', '>localpassword', '+@all', '~*')
        
        # Set exemption pattern to match 'exporter'
        self.client.config_set('ldap.exempted_users_regex', '^exporter$')
        
        # Try to authenticate with local password (should succeed)
        exporter_client = valkey.Valkey(
            host='localhost',
            port=6379,
            username='exporter',
            password='localpassword',
            decode_responses=True
        )
        
        # Should be able to ping
        self.assertTrue(exporter_client.ping())
        
    def test_non_exempted_user_uses_ldap(self):
        """Test that non-exempted users still use LDAP authentication"""
        setup_ldap_users(self.client)
        
        # Set exemption pattern that doesn't match normal LDAP users
        self.client.config_set('ldap.exempted_users_regex', '^(default|exporter)$')
        
        # LDAP user 'user1' should still authenticate via LDAP
        user1_client = valkey.Valkey(
            host='localhost',
            port=6379,
            username='user1',
            password='user1@123',
            decode_responses=True
        )
        
        # Should be able to ping
        self.assertTrue(user1_client.ping())
        
    def test_multiple_exempted_users_regex(self):
        """Test regex pattern matching multiple users"""
        # Create multiple local users
        self.client.execute_command('ACL', 'SETUSER', 'default', 'ON', '>adminpass', '+@all', '~*')
        self.client.execute_command('ACL', 'SETUSER', 'exporter', 'ON', '>exporterpass', '+@all', '~*')
        self.client.execute_command('ACL', 'SETUSER', 'replication', 'ON', '>replpass', '+@all', '~*')
        
        # Set exemption pattern to match all three
        self.client.config_set('ldap.exempted_users_regex', '^(default|exporter|replication)$')
        
        # All should authenticate with local passwords
        for username, password in [('default', 'adminpass'), ('exporter', 'exporterpass'), ('replication', 'replpass')]:
            user_client = valkey.Valkey(
                host='localhost',
                port=6379,
                username=username,
                password=password,
                decode_responses=True
            )
            self.assertTrue(user_client.ping(), f"User {username} should authenticate locally")
    
    def test_exemption_pattern_prefix(self):
        """Test regex pattern with prefix matching"""
        # Create users with prefix
        self.client.execute_command('ACL', 'SETUSER', 'metrics-reader', 'ON', '>pass1', '+@all', '~*')
        self.client.execute_command('ACL', 'SETUSER', 'metrics-writer', 'ON', '>pass2', '+@all', '~*')
        
        # Set exemption pattern to match 'metrics-*' prefix
        self.client.config_set('ldap.exempted_users_regex', '^metrics-.*$')
        
        # Both should authenticate with local passwords
        for username, password in [('metrics-reader', 'pass1'), ('metrics-writer', 'pass2')]:
            user_client = valkey.Valkey(
                host='localhost',
                port=6379,
                username=username,
                password=password,
                decode_responses=True
            )
            self.assertTrue(user_client.ping(), f"User {username} should authenticate locally")
    
    def test_clear_exemption_pattern(self):
        """Test clearing the exemption pattern"""
        # Set a pattern
        self.client.config_set('ldap.exempted_users_regex', '^exporter$')
        
        # Verify it's set
        pattern = self.client.config_get('ldap.exempted_users_regex')
        self.assertEqual(pattern['ldap.exempted_users_regex'], '^exporter$')
        
        # Clear it
        self.client.config_set('ldap.exempted_users_regex', '')
        
        # Verify it's cleared
        pattern = self.client.config_get('ldap.exempted_users_regex')
        self.assertEqual(pattern['ldap.exempted_users_regex'], '')
    
    def test_invalid_regex_pattern(self):
        """Test that invalid regex pattern is rejected"""
        # Try to set an invalid regex pattern
        with self.assertRaises(valkey.ResponseError):
            self.client.config_set('ldap.exempted_users_regex', '[invalid(regex')
