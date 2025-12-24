# FalkorDB LDAP Frontend

A web-based frontend application for managing LDAP users and testing FalkorDB/Redis permissions in a multi-tenant database-as-a-service environment.

## Features

- **User Management**
  - Create new LDAP users
  - View all existing users
  - Delete users
  - Update user passwords

- **Group & Permission Management**
  - View all LDAP groups
  - Update ACL rules for groups
  - Predefined ACL templates (Full Access, Read Only, Ping Only, etc.)
  - View group members

- **Permission Testing**
  - Test user authentication and authorization
  - Execute Redis commands with user credentials
  - View ACL information for users
  - Real-time feedback on permission restrictions

## Getting Started

### Prerequisites

- Docker and Docker Compose
- Built valkey-ldap module (`libvalkey_ldap.so`)

### Running the Application

1. **Start the services:**
   ```bash
   cd poc/scripts/docker
   docker-compose up -d
   ```

2. **Populate LDAP with initial data:**
   ```bash
   # From the project root
   bash poc/scripts/populate_ldap.sh
   ```

3. **Access the frontend:**
   Open your browser and navigate to: http://localhost:5000

## Test Flow

Follow this ideal test flow to verify the multi-tenant functionality:

### 1. Create Test User and Exempted Admin User

1. In the frontend, create a test user:
   - Full Name: `Test User`
   - Username: `testuser`
   - Surname: `User`
   - Password: `test123`

2. Create an exempted admin user directly in FalkorDB (exempted users bypass LDAP):
   ```bash
   docker exec -it falkordb redis-cli
   ACL SETUSER admin on >adminpass +@all ~*
   ```

### 2. Check Test User Has Full Access

1. Go to "Test User Permissions" section
2. Enter credentials:
   - Username: `testuser`
   - Password: `test123`
   - Command: `INFO`
3. Click "Test Connection & Permissions"
4. Verify the user can execute the command (full access via admins group)

### 3. Reduce Test User Permission to Ping Only

1. In "Manage Groups & Permissions" section, find the `admins` group
2. Click "Edit Permissions"
3. Click the "Ping Only" template button
4. Click "Update Permissions"

### 4. Show User Has Only Ping Permission

1. Test with PING command:
   - Username: `testuser`
   - Password: `test123`
   - Command: `PING`
   - Result: ✓ Success

2. Test with INFO command:
   - Username: `testuser`
   - Password: `test123`
   - Command: `INFO`
   - Result: ✗ Permission denied

### 5. Delete Test User

1. In the "LDAP Users" section, find `Test User`
2. Click "Delete" button
3. Confirm deletion

### 6. Show Test User No Longer Has Access

1. Try to test permissions:
   - Username: `testuser`
   - Password: `test123`
   - Command: `PING`
   - Result: ✗ Authentication failed (user not found in LDAP)

### 7. Show Admin User Not in LDAP

1. Check "LDAP Users" section - `admin` user is not listed
2. The admin user exists only in Redis as an exempted user

### 8. Check Admin Has Full Access

1. Test admin permissions:
   - Username: `admin`
   - Password: `adminpass`
   - Command: `INFO`
   - Result: ✓ Success (exempted user bypasses LDAP)

### 9. Add Exempted Admin to Read-Only Group

1. First add admin to LDAP:
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

2. In frontend, go to "Manage Groups & Permissions"
3. Find a read-only group (or create one)
4. Add admin user to the group

### 10. Verify Admin Still Has Full Access

1. Test admin permissions:
   - Username: `admin`
   - Password: `adminpass`
   - Command: `SET testkey testvalue`
   - Result: ✓ Success (exempted users ignore LDAP ACLs)

2. Check FalkorDB logs to see the skipped LDAP authentication message:
   ```bash
   docker logs falkordb | grep -i "exempted\|skipped"
   ```

## ACL Templates

The frontend provides predefined ACL templates:

- **Full Access**: `+@all ~*` - All commands, all keys
- **Read Only**: `+@read ~*` - Read commands only
- **Ping Only**: `+ping ~*` - Ping command only
- **No Access**: `-@all` - No commands allowed
- **Write Only**: `+@write ~*` - Write commands only
- **Admin Commands**: `+@admin ~*` - Administrative commands

## Architecture

```
┌─────────────┐      ┌─────────────┐      ┌─────────────┐
│   Browser   │─────▶│   Frontend  │─────▶│    LDAP     │
│             │      │   (Flask)   │      │   Server    │
└─────────────┘      └─────────────┘      └─────────────┘
                            │
                            ▼
                     ┌─────────────┐
                     │  FalkorDB   │
                     │   (Redis)   │
                     │   + LDAP    │
                     │   Module    │
                     └─────────────┘
```

## Environment Variables

The frontend can be configured using these environment variables:

- `LDAP_SERVER`: LDAP server URL (default: `ldap://ldap:389`)
- `LDAP_ADMIN_DN`: LDAP admin DN (default: `cn=admin,dc=valkey,dc=io`)
- `LDAP_ADMIN_PASSWORD`: LDAP admin password (default: `admin123!`)
- `LDAP_BASE_DN`: LDAP base DN (default: `dc=valkey,dc=io`)
- `REDIS_HOST`: Redis/FalkorDB host (default: `falkordb`)
- `REDIS_PORT`: Redis/FalkorDB port (default: `6379`)

## API Endpoints

The frontend exposes the following REST API endpoints:

- `GET /api/users` - List all LDAP users
- `POST /api/users` - Create a new user
- `DELETE /api/users/<dn>` - Delete a user
- `PUT /api/users/<dn>/password` - Update user password
- `GET /api/groups` - List all LDAP groups
- `PUT /api/groups/<cn>/permissions` - Update group ACL rules
- `POST /api/groups/<cn>/members` - Add user to group
- `DELETE /api/groups/<cn>/members` - Remove user from group
- `POST /api/test-connection` - Test Redis connection and permissions
- `GET /api/user-exists/<uid>` - Check if user exists

## Troubleshooting

### Cannot connect to LDAP
- Ensure the LDAP container is running: `docker ps | grep ldap`
- Check LDAP logs: `docker logs ldap`

### Cannot connect to FalkorDB
- Ensure FalkorDB container is running: `docker ps | grep falkordb`
- Check FalkorDB logs: `docker logs falkordb`
- Verify the LDAP module is loaded: `docker exec falkordb redis-cli MODULE LIST`

### Frontend not accessible
- Check if frontend is running: `docker ps | grep frontend`
- Check frontend logs: `docker logs ldap-frontend`
- Verify port 5000 is not in use: `lsof -i :5000`

## Development

To run the frontend locally for development:

```bash
cd poc/frontend

# Install dependencies
pip install -r requirements.txt

# Set environment variables
export LDAP_SERVER=ldap://localhost:389
export REDIS_HOST=localhost

# Run the app
python app.py
```

The application will be available at http://localhost:5000

## License

This project is part of the valkey-ldap module.
