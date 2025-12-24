# FalkorDB LDAP Multi-Tenant PoC - Quick Start Guide

## Quick Setup

```bash
# Navigate to the poc scripts directory
cd poc/scripts

# Run the automated setup script
bash start_poc.sh
```

The script will:
- Start all Docker services (LDAP, FalkorDB, Frontend)
- Populate LDAP with initial users and groups
- Create an exempted admin user in FalkorDB
- Display all connection details

## Access Points

- **Frontend Dashboard**: http://localhost:5000
- **FalkorDB**: localhost:6379
- **LDAP Server 1**: ldap://localhost:389
- **LDAP Server 2**: ldap://localhost:390

## Test Flow Checklist

### ✅ Step 1: Create Test User
- [ ] Open http://localhost:5000
- [ ] Create user: `testuser` / `test123`
- [ ] Verify user appears in "LDAP Users" list

### ✅ Step 2: Test Full Access
- [ ] Go to "Test User Permissions"
- [ ] Username: `testuser`, Password: `test123`
- [ ] Command: `INFO`
- [ ] ✓ Should succeed (user is in admins group with full access)

### ✅ Step 3: Reduce to Ping Only
- [ ] In "Manage Groups & Permissions", find `admins` group
- [ ] Click "Edit Permissions"
- [ ] Click "Ping Only" template
- [ ] Click "Update Permissions"

### ✅ Step 4: Verify Restricted Access
- [ ] Test with command: `PING` → ✓ Should succeed
- [ ] Test with command: `INFO` → ✗ Should fail (permission denied)
- [ ] Test with command: `SET key value` → ✗ Should fail

### ✅ Step 5: Delete Test User
- [ ] In "LDAP Users" section, click "Delete" on test user
- [ ] Confirm deletion
- [ ] User should disappear from list

### ✅ Step 6: Verify Deleted User Has No Access
- [ ] Try to test: `testuser` / `test123`
- [ ] ✗ Should fail with authentication error

### ✅ Step 7: Test Exempted Admin
- [ ] Check "LDAP Users" list → admin user NOT present
- [ ] Test permissions: `admin` / `adminpass`
- [ ] Command: `INFO` → ✓ Should succeed
- [ ] Command: `SET key value` → ✓ Should succeed

### ✅ Step 8: Check FalkorDB Logs
```bash
docker logs falkordb | grep -i "exempted\|skipped"
```
- [ ] Should see "skipped LDAP authentication" messages for admin user

### ✅ Step 9: Add Admin to LDAP (Optional)
```bash
docker exec -it ldap bash
ldapadd -x -w admin123! -D "cn=admin,dc=valkey,dc=io" << EOF
dn: cn=Admin User,ou=devops,dc=valkey,dc=io
objectClass: inetOrgPerson
cn: Admin User
sn: User
uid: admin
userPassword: adminpass
EOF
```

### ✅ Step 10: Verify Admin Still Has Full Access
- [ ] Even after adding to LDAP and a readonly group
- [ ] Admin should still have full access (exempted)
- [ ] Check logs for "exempted user" messages

## Common Commands

### Docker Management
```bash
# View all logs
docker-compose logs -f

# View specific service logs
docker logs falkordb
docker logs ldap
docker logs ldap-frontend

# Restart services
docker-compose restart

# Stop all services
docker-compose down

# Stop and remove volumes
docker-compose down -v
```

### FalkorDB/Redis Commands
```bash
# Connect to FalkorDB CLI
docker exec -it falkordb redis-cli

# List ACL users
ACL LIST

# Get user details
ACL GETUSER testuser

# Check loaded modules
MODULE LIST

# Test authentication
AUTH testuser test123
PING
```

### LDAP Commands
```bash
# Search all users
docker exec ldap ldapsearch -x -H ldap://localhost:389 \
  -b "ou=devops,dc=valkey,dc=io" \
  -D "cn=admin,dc=valkey,dc=io" -w admin123!

# Search all groups
docker exec ldap ldapsearch -x -H ldap://localhost:389 \
  -b "ou=groups,dc=valkey,dc=io" \
  -D "cn=admin,dc=valkey,dc=io" -w admin123!

# Add a user manually
docker exec ldap ldapadd -x -H ldap://localhost:389 \
  -D "cn=admin,dc=valkey,dc=io" -w admin123! << EOF
dn: cn=New User,ou=devops,dc=valkey,dc=io
objectClass: inetOrgPerson
cn: New User
sn: User
uid: newuser
userPassword: password123
EOF

# Delete a user
docker exec ldap ldapdelete -x -H ldap://localhost:389 \
  -D "cn=admin,dc=valkey,dc=io" -w admin123! \
  "cn=New User,ou=devops,dc=valkey,dc=io"
```

## ACL Rules Reference

| Template | ACL Rule | Description |
|----------|----------|-------------|
| Full Access | `+@all ~*` | All commands on all keys |
| Read Only | `+@read ~*` | Only read commands |
| Ping Only | `+ping ~*` | Only PING command |
| No Access | `-@all` | No commands allowed |
| Write Only | `+@write ~*` | Only write commands |
| Admin Commands | `+@admin ~*` | Administrative commands |

### Custom ACL Examples
```
# Read/Write on specific keys
+@all ~myapp:*

# Multiple command categories
+@read +@write ~*

# Exclude dangerous commands
+@all -@dangerous ~*

# Specific commands only
+GET +SET +DEL ~*

# Multiple key patterns
+@all ~user:* ~session:* ~cache:*
```

## Troubleshooting

### Frontend can't connect to LDAP
```bash
# Check LDAP is running
docker ps | grep ldap

# Test LDAP connection
docker exec ldap ldapsearch -x -H ldap://localhost:389 \
  -b "dc=valkey,dc=io" -D "cn=admin,dc=valkey,dc=io" -w admin123!
```

### Frontend can't connect to FalkorDB
```bash
# Check FalkorDB is running
docker ps | grep falkordb

# Test Redis connection
docker exec falkordb redis-cli PING
```

### User authentication fails
```bash
# Check user exists in LDAP
docker exec ldap ldapsearch -x -H ldap://localhost:389 \
  -b "ou=devops,dc=valkey,dc=io" "(uid=testuser)" \
  -D "cn=admin,dc=valkey,dc=io" -w admin123!

# Check FalkorDB LDAP module logs
docker logs falkordb | tail -50
```

### Permission denied errors
```bash
# Check group membership
docker exec ldap ldapsearch -x -H ldap://localhost:389 \
  -b "ou=groups,dc=valkey,dc=io" \
  -D "cn=admin,dc=valkey,dc=io" -w admin123!

# Check ACL rules in FalkorDB
docker exec falkordb redis-cli AUTH testuser test123
docker exec falkordb redis-cli ACL GETUSER testuser
```

## Architecture Overview

```
┌──────────────────────────────────────────────────────────┐
│                       Browser                            │
│                         ↓                                │
│                  http://localhost:5000                   │
└──────────────────────────────────────────────────────────┘
                           ↓
┌──────────────────────────────────────────────────────────┐
│                   Frontend (Flask)                       │
│  • User Management API                                   │
│  • Group Management API                                  │
│  • Permission Testing                                    │
└──────────────────────────────────────────────────────────┘
            ↓                              ↓
┌───────────────────────┐    ┌───────────────────────────┐
│   LDAP Server         │    │      FalkorDB             │
│   • Users             │    │   • Valkey LDAP Module    │
│   • Groups            │    │   • ACL Enforcement       │
│   • ACL Rules         │    │   • Exempted Users        │
└───────────────────────┘    └───────────────────────────┘
```

## Key Concepts

### Exempted Users
- Defined by `ldap.exempted_users_regex` in node.conf
- Bypass LDAP authentication
- Managed directly in Redis/FalkorDB
- Still authenticated, but ACLs from LDAP are ignored
- Useful for system users (monitoring, replication, etc.)

### LDAP Groups
- Stored in `ou=groups,dc=valkey,dc=io`
- `description` attribute contains ACL rules
- Members defined by `member` attribute
- Users can be in multiple groups
- ACL rules are combined for users in multiple groups

### Multi-Tenancy
- Each database instance can have its own LDAP organization
- Users and permissions are centrally managed
- Instance-level isolation through LDAP structure
- Supports future integration with enterprise LDAP

## Next Steps

1. **Production Hardening**
   - Use proper TLS certificates
   - Implement rate limiting
   - Add authentication to frontend
   - Use secrets management

2. **Enhanced Features**
   - Instance-level user isolation
   - Audit logging
   - User activity monitoring
   - Bulk user operations

3. **Integration**
   - Connect to enterprise LDAP (Active Directory, etc.)
   - API authentication (OAuth, JWT)
   - Monitoring and alerting
   - Backup and disaster recovery
