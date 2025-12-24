#!/usr/bin/env python3
"""
Frontend application for managing LDAP users and testing FalkorDB permissions.
"""
import os
import re
import redis
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from ldap3 import Server, Connection, ALL, MODIFY_REPLACE, MODIFY_ADD, MODIFY_DELETE
from ldap3.core.exceptions import LDAPException

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')

# Configuration
LDAP_SERVER = os.environ.get('LDAP_SERVER', 'ldap://ldap:389')
LDAP_ADMIN_DN = os.environ.get('LDAP_ADMIN_DN', 'cn=admin,dc=valkey,dc=io')
LDAP_ADMIN_PASSWORD = os.environ.get('LDAP_ADMIN_PASSWORD', 'admin123!')
LDAP_BASE_DN = os.environ.get('LDAP_BASE_DN', 'dc=valkey,dc=io')
LDAP_USERS_OU = f'ou=devops,{LDAP_BASE_DN}'
LDAP_GROUPS_OU = f'ou=groups,{LDAP_BASE_DN}'
REDIS_HOST = os.environ.get('REDIS_HOST', 'falkordb')
REDIS_PORT = int(os.environ.get('REDIS_PORT', '6379'))

# Predefined ACL templates
ACL_TEMPLATES = {
    'full_access': '+@all ~*',
    'readonly': '+@read ~*',
    'ping_only': '+ping ~*',
    'no_access': '-@all',
    'write_only': '+@write ~*',
    'admin_commands': '+@admin ~*',
}


def get_ldap_connection():
    """Create and return an LDAP connection."""
    server = Server(LDAP_SERVER, get_info=ALL)
    conn = Connection(server, user=LDAP_ADMIN_DN, password=LDAP_ADMIN_PASSWORD, auto_bind=True)
    return conn


def get_redis_connection(username=None, password=None):
    """Create and return a Redis connection."""
    try:
        if username and password:
            return redis.Redis(
                host=REDIS_HOST,
                port=REDIS_PORT,
                username=username,
                password=password,
                decode_responses=True,
                socket_connect_timeout=5
            )
        else:
            return redis.Redis(
                host=REDIS_HOST,
                port=REDIS_PORT,
                decode_responses=True,
                socket_connect_timeout=5
            )
    except Exception as e:
        print(f"Error connecting to Redis: {e}")
        return None


@app.route('/')
def index():
    """Main page showing user management and testing interface."""
    return render_template('index.html', acl_templates=ACL_TEMPLATES)


@app.route('/api/users', methods=['GET'])
def list_users():
    """List all users in LDAP."""
    try:
        conn = get_ldap_connection()
        conn.search(
            search_base=LDAP_USERS_OU,
            search_filter='(objectClass=inetOrgPerson)',
            attributes=['cn', 'uid', 'sn', 'userPassword']
        )
        
        users = []
        for entry in conn.entries:
            users.append({
                'dn': entry.entry_dn,
                'cn': str(entry.cn),
                'uid': str(entry.uid),
                'sn': str(entry.sn)
            })
        
        conn.unbind()
        return jsonify({'success': True, 'users': users})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/groups', methods=['GET'])
def list_groups():
    """List all groups in LDAP."""
    try:
        conn = get_ldap_connection()
        conn.search(
            search_base=LDAP_GROUPS_OU,
            search_filter='(objectClass=groupOfNames)',
            attributes=['cn', 'description', 'member']
        )
        
        groups = []
        for entry in conn.entries:
            members = []
            if hasattr(entry, 'member'):
                members = [str(m) for m in entry.member]
            
            description = ''
            if hasattr(entry, 'description'):
                description = str(entry.description)
            
            groups.append({
                'dn': entry.entry_dn,
                'cn': str(entry.cn),
                'description': description,
                'members': members
            })
        
        conn.unbind()
        return jsonify({'success': True, 'groups': groups})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/groups', methods=['POST'])
def create_group():
    """Create a new group in LDAP."""
    try:
        data = request.json
        cn = data.get('cn')
        description = data.get('description', '+@read ~*')
        
        if not cn:
            return jsonify({'success': False, 'error': 'Group name (cn) is required'}), 400
        
        conn = get_ldap_connection()
        group_dn = f'cn={cn},{LDAP_GROUPS_OU}'
        
        # Create group with a dummy member (LDAP requires at least one member)
        # We'll use the first admin user or create a placeholder
        conn.search(
            search_base=LDAP_USERS_OU,
            search_filter='(objectClass=inetOrgPerson)',
            attributes=['cn'],
            size_limit=1
        )
        
        if not conn.entries:
            conn.unbind()
            return jsonify({'success': False, 'error': 'No users found to add as initial group member'}), 400
        
        first_user_dn = conn.entries[0].entry_dn
        
        conn.add(
            group_dn,
            object_class=['groupOfNames'],
            attributes={
                'cn': cn,
                'description': description,
                'member': [first_user_dn]
            }
        )
        
        if not conn.result['description'] == 'success':
            conn.unbind()
            return jsonify({'success': False, 'error': conn.result['message']}), 400
        
        conn.unbind()
        return jsonify({'success': True, 'message': f'Group {cn} created successfully'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/users', methods=['POST'])
def create_user():
    """Create a new user in LDAP."""
    try:
        data = request.json
        cn = data.get('cn')
        uid = data.get('uid')
        sn = data.get('sn')
        password = data.get('password')
        
        if not all([cn, uid, sn, password]):
            return jsonify({'success': False, 'error': 'Missing required fields'}), 400
        
        conn = get_ldap_connection()
        user_dn = f'cn={cn},{LDAP_USERS_OU}'
        
        conn.add(
            user_dn,
            object_class=['inetOrgPerson'],
            attributes={
                'cn': cn,
                'sn': sn,
                'uid': uid,
                'userPassword': password
            }
        )
        
        if not conn.result['description'] == 'success':
            conn.unbind()
            return jsonify({'success': False, 'error': conn.result['message']}), 400
        
        conn.unbind()
        return jsonify({'success': True, 'message': f'User {cn} created successfully'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/users/<path:user_dn>', methods=['DELETE'])
def delete_user(user_dn):
    """Delete a user from LDAP."""
    try:
        conn = get_ldap_connection()
        
        # First, remove user from all groups
        conn.search(
            search_base=LDAP_GROUPS_OU,
            search_filter='(objectClass=groupOfNames)',
            attributes=['cn', 'member']
        )
        
        for entry in conn.entries:
            if hasattr(entry, 'member'):
                members = [str(m) for m in entry.member]
                if user_dn in members:
                    # Remove user from this group
                    conn.modify(entry.entry_dn, {'member': [(MODIFY_DELETE, [user_dn])]})
        
        # Now delete the user
        conn.delete(user_dn)
        
        if not conn.result['description'] == 'success':
            conn.unbind()
            return jsonify({'success': False, 'error': conn.result['message']}), 400
        
        conn.unbind()
        return jsonify({'success': True, 'message': 'User deleted successfully'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/users/<path:user_dn>/password', methods=['PUT'])
def update_password(user_dn):
    """Update user password."""
    try:
        data = request.json
        new_password = data.get('password')
        
        if not new_password:
            return jsonify({'success': False, 'error': 'Password is required'}), 400
        
        conn = get_ldap_connection()
        conn.modify(user_dn, {'userPassword': [(MODIFY_REPLACE, [new_password])]})
        
        if not conn.result['description'] == 'success':
            conn.unbind()
            return jsonify({'success': False, 'error': conn.result['message']}), 400
        
        conn.unbind()
        return jsonify({'success': True, 'message': 'Password updated successfully'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/groups/<group_cn>/permissions', methods=['PUT'])
def update_group_permissions(group_cn):
    """Update group permissions (ACL rules)."""
    try:
        data = request.json
        acl_rules = data.get('acl_rules')
        
        if not acl_rules:
            return jsonify({'success': False, 'error': 'ACL rules are required'}), 400
        
        conn = get_ldap_connection()
        group_dn = f'cn={group_cn},{LDAP_GROUPS_OU}'
        
        conn.modify(group_dn, {'description': [(MODIFY_REPLACE, [acl_rules])]})
        
        if not conn.result['description'] == 'success':
            conn.unbind()
            return jsonify({'success': False, 'error': conn.result['message']}), 400
        
        conn.unbind()
        return jsonify({'success': True, 'message': 'Permissions updated successfully'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/groups/<group_cn>/members', methods=['POST'])
def add_user_to_group(group_cn):
    """Add a user to a group."""
    try:
        data = request.json
        user_dn = data.get('user_dn')
        
        if not user_dn:
            return jsonify({'success': False, 'error': 'User DN is required'}), 400
        
        conn = get_ldap_connection()
        group_dn = f'cn={group_cn},{LDAP_GROUPS_OU}'
        
        conn.modify(group_dn, {'member': [(MODIFY_ADD, [user_dn])]})
        
        if not conn.result['description'] == 'success':
            conn.unbind()
            return jsonify({'success': False, 'error': conn.result['message']}), 400
        
        conn.unbind()
        return jsonify({'success': True, 'message': f'User added to group {group_cn}'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/groups/<group_cn>/members', methods=['DELETE'])
def remove_user_from_group(group_cn):
    """Remove a user from a group."""
    try:
        data = request.json
        user_dn = data.get('user_dn')
        
        if not user_dn:
            return jsonify({'success': False, 'error': 'User DN is required'}), 400
        
        conn = get_ldap_connection()
        group_dn = f'cn={group_cn},{LDAP_GROUPS_OU}'
        
        conn.modify(group_dn, {'member': [(MODIFY_DELETE, [user_dn])]})
        
        if not conn.result['description'] == 'success':
            conn.unbind()
            return jsonify({'success': False, 'error': conn.result['message']}), 400
        
        conn.unbind()
        return jsonify({'success': True, 'message': f'User removed from group {group_cn}'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/test-connection', methods=['POST'])
def test_redis_connection():
    """Test Redis connection and permissions with given credentials."""
    try:
        data = request.json
        username = data.get('username')
        password = data.get('password')
        command = data.get('command', 'PING')
        
        if not username or not password:
            return jsonify({
                'success': False,
                'error': 'Username and password are required'
            }), 400
        
        # Test connection
        r = get_redis_connection(username, password)
        if not r:
            return jsonify({
                'success': False,
                'error': 'Failed to create Redis connection'
            }), 500
        
        result = {
            'connected': False,
            'authenticated': False,
            'command_result': None,
            'acl_list': None,
            'error': None
        }
        
        try:
            # Try to authenticate and ping
            r.ping()
            result['connected'] = True
            result['authenticated'] = True
            
            # Try to execute the requested command
            try:
                if command.upper() == 'PING':
                    cmd_result = r.ping()
                elif command.upper() == 'INFO':
                    cmd_result = r.info()
                elif command.upper().startswith('SET '):
                    parts = command.split(' ', 2)
                    if len(parts) >= 3:
                        cmd_result = r.set(parts[1], parts[2])
                    else:
                        cmd_result = 'Invalid SET command format'
                elif command.upper().startswith('GET '):
                    parts = command.split(' ', 1)
                    if len(parts) >= 2:
                        cmd_result = r.get(parts[1])
                    else:
                        cmd_result = 'Invalid GET command format'
                else:
                    # Try to execute as a raw command
                    cmd_result = r.execute_command(command)
                
                result['command_result'] = str(cmd_result)
            except redis.exceptions.ResponseError as cmd_err:
                result['command_result'] = f'Permission denied: {str(cmd_err)}'
            except Exception as cmd_err:
                result['command_result'] = f'Error: {str(cmd_err)}'
            
            # Try to get ACL info
            try:
                acl_info = r.execute_command('ACL', 'GETUSER', username)
                result['acl_list'] = str(acl_info)
            except:
                result['acl_list'] = 'Unable to retrieve ACL info'
            
            r.close()
            return jsonify({'success': True, 'result': result})
            
        except redis.exceptions.AuthenticationError as auth_err:
            result['error'] = f'Authentication failed: {str(auth_err)}'
            return jsonify({'success': False, 'result': result})
        except redis.exceptions.ConnectionError as conn_err:
            result['error'] = f'Connection error: {str(conn_err)}'
            return jsonify({'success': False, 'result': result})
        except Exception as e:
            result['error'] = str(e)
            return jsonify({'success': False, 'result': result})
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/user-exists/<uid>', methods=['GET'])
def check_user_exists(uid):
    """Check if a user exists in LDAP."""
    try:
        conn = get_ldap_connection()
        conn.search(
            search_base=LDAP_USERS_OU,
            search_filter=f'(uid={uid})',
            attributes=['cn']
        )
        
        exists = len(conn.entries) > 0
        conn.unbind()
        
        return jsonify({'success': True, 'exists': exists})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
