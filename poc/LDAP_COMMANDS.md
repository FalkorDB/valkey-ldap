# LDAP Command Reference & Examples

## Quick Setup - Shell Aliases

Add these to your `~/.zshrc` or `~/.bashrc`:

```bash
# LDAP connection aliases
alias ldap-search='docker exec ldap ldapsearch -x -H ldap://localhost:389 -D "cn=admin,dc=valkey,dc=io" -w admin123!'
alias ldap-add='docker exec ldap ldapadd -x -H ldap://localhost:389 -D "cn=admin,dc=valkey,dc=io" -w admin123!'
alias ldap-modify='docker exec ldap ldapmodify -x -H ldap://localhost:389 -D "cn=admin,dc=valkey,dc=io" -w admin123!'
alias ldap-delete='docker exec ldap ldapdelete -x -H ldap://localhost:389 -D "cn=admin,dc=valkey,dc=io" -w admin123!'

# Common searches
alias ldap-users='ldap-search -b "ou=devops,dc=valkey,dc=io" "(objectClass=inetOrgPerson)"'
alias ldap-groups='ldap-search -b "ou=groups,dc=valkey,dc=io" "(objectClass=groupOfNames)"'
alias ldap-all='ldap-search -b "dc=valkey,dc=io"'
```

After adding, reload your shell:
```bash
source ~/.zshrc  # or source ~/.bashrc
```

## Usage Examples

### 1. Search Operations

#### List all users
```bash
ldap-users

# Or with specific attributes
ldap-search -b "ou=devops,dc=valkey,dc=io" "(objectClass=inetOrgPerson)" cn uid mail
```

#### List all groups
```bash
ldap-groups

# With all attributes
ldap-search -b "ou=groups,dc=valkey,dc=io" "(objectClass=groupOfNames)" cn description member
```

#### Search for specific user
```bash
ldap-search -b "ou=devops,dc=valkey,dc=io" "(uid=muhammad)"

# Search by CN
ldap-search -b "ou=devops,dc=valkey,dc=io" "(cn=Muhammad Qadora)"
```

#### Search for groups a user belongs to
```bash
ldap-search -b "ou=groups,dc=valkey,dc=io" "(member=cn=Muhammad Qadora,ou=devops,dc=valkey,dc=io)"
```

### 2. Add Operations

#### Add a new user
```bash
ldap-add << EOF
dn: cn=John Doe,ou=devops,dc=valkey,dc=io
objectClass: inetOrgPerson
cn: John Doe
sn: Doe
uid: johndoe
userPassword: password123
mail: john.doe@example.com
EOF
```

#### Add a new group
```bash
ldap-add << EOF
dn: cn=developers,ou=groups,dc=valkey,dc=io
objectClass: groupOfNames
cn: developers
description: +@read +@write ~app:*
member: cn=Muhammad Qadora,ou=devops,dc=valkey,dc=io
EOF
```

#### Add multiple users at once
```bash
ldap-add << EOF
dn: cn=Alice Smith,ou=devops,dc=valkey,dc=io
objectClass: inetOrgPerson
cn: Alice Smith
sn: Smith
uid: alice
userPassword: alice123

dn: cn=Bob Johnson,ou=devops,dc=valkey,dc=io
objectClass: inetOrgPerson
cn: Bob Johnson
sn: Johnson
uid: bob
userPassword: bob123
EOF
```

### 3. Modify Operations

#### Change user password
```bash
ldap-modify << EOF
dn: cn=Muhammad Qadora,ou=devops,dc=valkey,dc=io
changetype: modify
replace: userPassword
userPassword: newpassword123
EOF
```

#### Update group ACL rules
```bash
ldap-modify << EOF
dn: cn=admins,ou=groups,dc=valkey,dc=io
changetype: modify
replace: description
description: +@all ~*
EOF
```

#### Add user to group
```bash
ldap-modify << EOF
dn: cn=developers,ou=groups,dc=valkey,dc=io
changetype: modify
add: member
member: cn=John Doe,ou=devops,dc=valkey,dc=io
EOF
```

#### Remove user from group
```bash
ldap-modify << EOF
dn: cn=developers,ou=groups,dc=valkey,dc=io
changetype: modify
delete: member
member: cn=John Doe,ou=devops,dc=valkey,dc=io
EOF
```

#### Add multiple attributes
```bash
ldap-modify << EOF
dn: cn=Muhammad Qadora,ou=devops,dc=valkey,dc=io
changetype: modify
add: mail
mail: muhammad@example.com
-
add: telephoneNumber
telephoneNumber: +1234567890
EOF
```

#### Replace multiple attributes
```bash
ldap-modify << EOF
dn: cn=developers,ou=groups,dc=valkey,dc=io
changetype: modify
replace: description
description: +@read ~*
-
add: member
member: cn=Alice Smith,ou=devops,dc=valkey,dc=io
EOF
```

### 4. Delete Operations

#### Delete a user
```bash
ldap-delete "cn=John Doe,ou=devops,dc=valkey,dc=io"
```

#### Delete a group
```bash
ldap-delete "cn=developers,ou=groups,dc=valkey,dc=io"
```

#### Delete with confirmation
```bash
# First check what you're deleting
ldap-search -b "cn=John Doe,ou=devops,dc=valkey,dc=io"

# Then delete
ldap-delete "cn=John Doe,ou=devops,dc=valkey,dc=io"
```

## Common ACL Patterns for Groups

### Read-only access
```bash
ldap-modify << EOF
dn: cn=readonly,ou=groups,dc=valkey,dc=io
changetype: modify
replace: description
description: +@read ~*
EOF
```

### Full access
```bash
description: +@all ~*
```

### Specific commands only
```bash
description: +ping +info +get ~*
```

### Key pattern restrictions
```bash
description: +@all ~myapp:*
```

### Multiple patterns
```bash
description: +@read +@write ~app:* ~cache:*
```

### Exclude dangerous commands
```bash
description: +@all -@dangerous ~*
```

## Advanced Examples

### Bulk user creation from file
```bash
cat > users.ldif << 'EOF'
dn: cn=User One,ou=devops,dc=valkey,dc=io
objectClass: inetOrgPerson
cn: User One
sn: One
uid: user1
userPassword: pass1

dn: cn=User Two,ou=devops,dc=valkey,dc=io
objectClass: inetOrgPerson
cn: User Two
sn: Two
uid: user2
userPassword: pass2
EOF

ldap-add < users.ldif
```

### Export all users to file
```bash
ldap-search -b "ou=devops,dc=valkey,dc=io" "(objectClass=inetOrgPerson)" > users_backup.ldif
```

### Reset all group permissions
```bash
for group in admins developers readonly; do
  ldap-modify << EOF
dn: cn=$group,ou=groups,dc=valkey,dc=io
changetype: modify
replace: description
description: +@all ~*
EOF
done
```

### Find all empty groups
```bash
ldap-search -b "ou=groups,dc=valkey,dc=io" "(objectClass=groupOfNames)" | grep -A 5 "dn:"
```

### Change password for all test users
```bash
for user in testuser1 testuser2 testuser3; do
  ldap-modify << EOF
dn: cn=$user,ou=devops,dc=valkey,dc=io
changetype: modify
replace: userPassword
userPassword: newpass123
EOF
done
```

## Troubleshooting Commands

### Check if LDAP server is running
```bash
docker ps | grep ldap
```

### Test LDAP connection
```bash
ldap-search -b "dc=valkey,dc=io" "(objectClass=*)" -LLL
```

### View LDAP server logs
```bash
docker logs ldap
docker logs ldap-2
```

### Check user authentication
```bash
docker exec ldap ldapwhoami -x -D "cn=Muhammad Qadora,ou=devops,dc=valkey,dc=io" -w "muhammad@123"
```

### Verify group membership
```bash
ldap-search -b "ou=groups,dc=valkey,dc=io" "(member=cn=Muhammad Qadora,ou=devops,dc=valkey,dc=io)" cn
```

### Count users and groups
```bash
echo "Users: $(ldap-users | grep -c '^dn:')"
echo "Groups: $(ldap-groups | grep -c '^dn:')"
```

## Quick Reference

| Command | Purpose |
|---------|---------|
| `ldap-search` | Search for entries |
| `ldap-add` | Add new entries |
| `ldap-modify` | Modify existing entries |
| `ldap-delete` | Delete entries |
| `ldap-users` | List all users |
| `ldap-groups` | List all groups |
| `ldap-all` | List everything |

## LDIF File Format

LDIF (LDAP Data Interchange Format) structure:

```ldif
# Comment lines start with #

# Entry 1
dn: distinguished_name
attribute1: value1
attribute2: value2

# Entry 2 (blank line separates entries)
dn: another_distinguished_name
attribute1: value1
```

### Modify format
```ldif
dn: entry_to_modify
changetype: modify
operation: attribute
attribute: value
-
operation: attribute
attribute: value
```

Operations: `add`, `delete`, `replace`

## Integration with Scripts

### Shell script to create user and add to group
```bash
#!/bin/bash

USERNAME="$1"
FULLNAME="$2"
PASSWORD="$3"
GROUP="$4"

# Create user
docker exec ldap ldapadd -x -H ldap://localhost:389 \
  -D "cn=admin,dc=valkey,dc=io" -w admin123! << EOF
dn: cn=${FULLNAME},ou=devops,dc=valkey,dc=io
objectClass: inetOrgPerson
cn: ${FULLNAME}
sn: ${FULLNAME##* }
uid: ${USERNAME}
userPassword: ${PASSWORD}
EOF

# Add to group
docker exec ldap ldapmodify -x -H ldap://localhost:389 \
  -D "cn=admin,dc=valkey,dc=io" -w admin123! << EOF
dn: cn=${GROUP},ou=groups,dc=valkey,dc=io
changetype: modify
add: member
member: cn=${FULLNAME},ou=devops,dc=valkey,dc=io
EOF
```

Usage:
```bash
./create_user.sh johndoe "John Doe" "password123" "developers"
```
