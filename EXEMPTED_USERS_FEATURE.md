# Exempted Users Feature - Implementation Summary

## Overview
Added the ability to exempt certain users from LDAP authentication using regex patterns. This feature addresses the requirement to reduce LDAP server load from high-frequency service accounts (like Redis exporters, replication users, and monitoring tools) and ensures critical services remain operational even if LDAP becomes unavailable.

## Changes Made

### 1. Core Implementation Files

#### `Cargo.toml`
- Added `regex = "1.11.1"` dependency for pattern matching

#### `src/configs.rs`
- Added `LDAP_EXEMPTED_USERS_REGEX` configuration variable to store the regex pattern
- Added `EXEMPTED_USERS_REGEX_CACHE` mutex-protected cache for the compiled regex
- Implemented `get_exempted_users_regex_pattern()` to retrieve the pattern
- Implemented `is_user_exempted_from_ldap()` to check if a username matches the exemption pattern
- Implemented `exempted_users_regex_set_callback()` to validate and compile regex on configuration change

#### `src/lib.rs`
- Registered the new `exempted_users_regex` configuration option in the module's configuration section
- Set default value to empty string (no exemptions by default)
- Connected the validation callback for pattern changes

#### `src/auth.rs`
- Added exemption check at the start of `ldap_auth_blocking_callback()`
- Exempted users return `AUTH_NOT_HANDLED`, allowing Valkey to use local authentication
- Added debug logging for exempted users

### 2. Documentation

#### `README.md`
- Added detailed section "Exempting Users from LDAP Authentication" explaining:
  - Why exempt users (reduce LDAP load, ensure availability)
  - Common use cases (admin, replication, monitoring)
  - Configuration examples with regex patterns
  - Important notes about local passwords for exempted users
- Added entry in the Advanced Options configuration table
- Included practical setup examples

### 3. Test Files

#### `test/integration/test_exempted_users.py`
- Created comprehensive test suite covering:
  - Exempted users using local authentication
  - Non-exempted users still using LDAP
  - Multiple user exemption patterns
  - Prefix-based regex patterns
  - Clearing exemption patterns
  - Invalid regex rejection

#### `test/valkey-exempted-users.conf`
- Created example configuration file demonstrating:
  - LDAP setup with exempted users
  - Common exemption patterns
  - Local user creation for exempted accounts
  - Regular LDAP user setup

## How It Works

1. **Configuration**: Administrator sets `ldap.exempted_users_regex` with a regex pattern
2. **Validation**: The regex is validated and compiled when set; invalid patterns are rejected
3. **Caching**: The compiled regex is cached in memory for fast lookups
4. **Authentication Flow**: 
   - When a user attempts to authenticate, the username is checked against the cached regex
   - If it matches, `AUTH_NOT_HANDLED` is returned, triggering local Valkey authentication
   - If it doesn't match, normal LDAP authentication proceeds

## Usage Examples

### Basic Exemption
```bash
# Exempt specific users
CONFIG SET ldap.exempted_users_regex "^(default|exporter|replication)$"
```

### Pattern-Based Exemption
```bash
# Exempt all users starting with "metrics-"
CONFIG SET ldap.exempted_users_regex "^metrics-.*$"

# Exempt multiple patterns
CONFIG SET ldap.exempted_users_regex "^(admin|metrics-.*|repl-.*)$"
```

### Clear Exemptions
```bash
# Remove all exemptions
CONFIG SET ldap.exempted_users_regex ""
```

## Important Notes

1. **Local Passwords Required**: Exempted users MUST have local passwords configured in Valkey using `ACL SETUSER <username> >password`

2. **Regex Validation**: Invalid regex patterns are rejected with an error message

3. **Performance**: The regex check is very fast (O(1) cache lookup + regex match) and happens before any LDAP operations

4. **Security**: Exempted users are NOT less secure - they still require valid credentials, just against Valkey's local ACL instead of LDAP

5. **High Availability**: Exempting critical service accounts ensures they work even if LDAP is unavailable

## Testing

Run the integration tests:
```bash
./scripts/run_integration_tests.sh
```

The new test file `test_exempted_users.py` verifies:
- Exempted users authenticate locally
- Non-exempted users still use LDAP
- Regex pattern matching works correctly
- Invalid patterns are rejected
- Patterns can be cleared

## Configuration Reference

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `ldap.exempted_users_regex` | string | `""` | Regex pattern to exempt users from LDAP authentication |

## Build Status

✅ Code compiles successfully with no errors
✅ All existing functionality preserved
✅ New feature is backward compatible (disabled by default)
