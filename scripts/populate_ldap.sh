#!/bin/bash

# Wait for ldap server to be online
while true; do
    nc -z localhost 389 && break
done

ADMIN_PASSWD=admin123!
ADMIN_DN="cn=admin,dc=valkey,dc=io"
CONFIG_PASSWD=config

# Add custom schema for valkeyACL attribute (requires root/config access)
ldapadd -Y EXTERNAL -H ldapi:/// -f scripts/valkey-schema.ldif 2>/dev/null || \
  ldapadd -x -w ${CONFIG_PASSWD} -D cn=admin,cn=config -f scripts/valkey-schema.ldif

ldapadd -x -w ${ADMIN_PASSWD} -D ${ADMIN_DN} < test/ldap_users.txt
ldapadd -H ldap://localhost:390 -x -w ${ADMIN_PASSWD} -D ${ADMIN_DN} < test/ldap_users.txt
