from unittest import TestCase
import docker
import valkey


class DockerServices:

    def __init__(self):
        self.client = docker.from_env()

    def assert_all_services_running(self):
        for ct in self.client.containers.list():
            assert ct.status == "running"

    def _find_container(self, name: str):
        for ct in self.client.containers.list():
            if ct.name == name:
                return ct
        return None

    def stop_service(self, name: str):
        ct = self._find_container(name)
        if ct is None:
            return None
        ct.kill()
        return ct

    def restart_service(self, serv):
        serv.restart()


DOCKER_SERVICES = DockerServices()


class LdapTestCase(TestCase):
    def setUp(self):
        vk = valkey.Valkey(host="localhost", port=6379, db=0)

        # LDAP server location
        vk.execute_command("CONFIG", "SET", "ldap.servers", "ldap://ldap ldap://ldap-2")

        # TLS configuration
        vk.execute_command(
            "CONFIG", "SET", "ldap.tls_ca_cert_path", "/valkey-ldap/valkey-ldap-ca.crt"
        )
        vk.execute_command(
            "CONFIG", "SET", "ldap.tls_cert_path", "/valkey-ldap/valkey-ldap-client.crt"
        )
        vk.execute_command(
            "CONFIG", "SET", "ldap.tls_key_path", "/valkey-ldap/valkey-ldap-client.key"
        )
        vk.execute_command("CONFIG", "SET", "ldap.use_starttls", "no")

        # Add users in Valkey
        vk.execute_command("ACL", "SETUSER", "user1", "ON", ">pass", "allcommands")
        vk.execute_command("ACL", "SETUSER", "u2", "ON", ">pass", "allcommands")

        self.vk = vk

    def tearDown(self):
        assert self.vk is not None, "Valkey instance should not be None"
        self.vk.close()
        self.vk = None


def parse_valkey_info_section(section: str) -> dict:
    result = {}
    lines = section.split("\n")
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            key, value = line.split("=", 1)
            result[key.strip()] = value.strip()
        else:
            dict_key, dict_values = line.split(":", 1)
            nested_dict = {}
            for key_value_pair in dict_values.split(","):
                key, value = key_value_pair.strip().split("=", 1)
                nested_dict[key.strip()] = value.strip()
            result[dict_key.strip()] = nested_dict
    return result


def clean_acl(client):
    """Remove all users except default from ACL"""
    acl_list = client.execute_command("ACL", "LIST")
    for user_line in acl_list:
        # Parse username from ACL LIST output (format: "user <username> ...")
        parts = user_line.split()
        if len(parts) >= 2 and parts[0] == "user":
            username = parts[1]
            # Don't delete the default user
            if username != "default":
                try:
                    client.execute_command("ACL", "DELUSER", username)
                except Exception:
                    # Ignore errors if user doesn't exist or can't be deleted
                    pass


def setup_ldap_users(client):
    """Setup LDAP users in Valkey for testing"""
    # Configure LDAP settings for testing
    client.execute_command("CONFIG", "SET", "ldap.servers", "ldap://ldap ldap://ldap-2")
    client.execute_command("CONFIG", "SET", "ldap.auth_mode", "search_and_bind")
    client.execute_command("CONFIG", "SET", "ldap.search_base", "dc=valkey,dc=io")
    client.execute_command("CONFIG", "SET", "ldap.search_filter", "(|(cn=%u)(uid=%u))")
    client.execute_command("CONFIG", "SET", "ldap.tls_ca_cert_path", "/valkey-ldap/valkey-ldap-ca.crt")
    client.execute_command("CONFIG", "SET", "ldap.tls_cert_path", "/valkey-ldap/valkey-ldap-client.crt")
    client.execute_command("CONFIG", "SET", "ldap.tls_key_path", "/valkey-ldap/valkey-ldap-client.key")
    client.execute_command("CONFIG", "SET", "ldap.use_starttls", "no")
    
    # Add LDAP users to ACL (they will authenticate via LDAP)
    # Based on test/ldap_users.txt, we have user1 and user2 (u2)
    client.execute_command("ACL", "SETUSER", "user1", "ON", "nopass", "allcommands", "allkeys")
    client.execute_command("ACL", "SETUSER", "u2", "ON", "nopass", "allcommands", "allkeys")
