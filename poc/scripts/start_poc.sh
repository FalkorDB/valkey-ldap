#!/bin/bash

# Helper script to run the complete test flow for the LDAP multi-tenant PoC

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
COMPOSE_DIR="$SCRIPT_DIR/docker"

echo "🚀 Starting FalkorDB LDAP Multi-Tenant PoC"
echo "=========================================="

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_step() {
    echo -e "${BLUE}▶ $1${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_info() {
    echo -e "${YELLOW}ℹ $1${NC}"
}

# Step 1: Start services
print_step "Starting Docker Compose services..."
cd "$COMPOSE_DIR"
docker-compose up -d
print_success "Services started"

# Wait for services to be ready
print_step "Waiting for services to be ready..."
sleep 5

# Check if LDAP is ready
print_info "Waiting for LDAP server..."
timeout=30
while ! docker exec ldap ldapsearch -x -H ldap://localhost:389 -b "dc=valkey,dc=io" -D "cn=admin,dc=valkey,dc=io" -w admin123! > /dev/null 2>&1; do
    sleep 1
    timeout=$((timeout - 1))
    if [ $timeout -le 0 ]; then
        echo "❌ LDAP server did not start in time"
        exit 1
    fi
done
print_success "LDAP server is ready"

# Check if FalkorDB is ready
print_info "Waiting for FalkorDB..."
timeout=30
while ! docker exec falkordb redis-cli PING > /dev/null 2>&1; do
    sleep 1
    timeout=$((timeout - 1))
    if [ $timeout -le 0 ]; then
        echo "❌ FalkorDB did not start in time"
        exit 1
    fi
done
print_success "FalkorDB is ready"

# Check if Frontend is ready
print_info "Waiting for Frontend..."
timeout=30
while ! curl -s http://localhost:5000 > /dev/null 2>&1; do
    sleep 1
    timeout=$((timeout - 1))
    if [ $timeout -le 0 ]; then
        echo "❌ Frontend did not start in time"
        exit 1
    fi
done
print_success "Frontend is ready"

# Step 2: Populate LDAP
print_step "Populating LDAP with initial data..."
cd "$SCRIPT_DIR/.."
bash scripts/populate_ldap.sh
print_success "LDAP populated with users and groups"

# Step 3: Create exempted admin user in Redis
print_step "Creating exempted admin user in FalkorDB..."
docker exec falkordb redis-cli ACL SETUSER admin on '>adminpass' '+@all' '~*' > /dev/null
print_success "Exempted admin user created"

echo ""
echo "=========================================="
echo -e "${GREEN}✓ Setup Complete!${NC}"
echo "=========================================="
echo ""
echo "📋 Services Running:"
echo "  • LDAP Server: ldap://localhost:389"
echo "  • LDAP Server 2: ldap://localhost:390"
echo "  • FalkorDB: localhost:6379"
echo "  • Frontend: http://localhost:5000"
echo ""
echo "🔑 Default Credentials:"
echo "  • LDAP Admin: cn=admin,dc=valkey,dc=io / admin123!"
echo "  • Test User: muhammad / muhammad@123"
echo "  • Exempted Admin: admin / adminpass"
echo ""
echo "📝 Test Flow:"
echo "  1. Open http://localhost:5000 in your browser"
echo "  2. Create a test user"
echo "  3. Test user permissions with full access"
echo "  4. Reduce permissions to 'ping only'"
echo "  5. Verify restricted access"
echo "  6. Delete the test user"
echo "  7. Test exempted admin user (not in LDAP)"
echo "  8. Add admin to LDAP and verify still has full access"
echo ""
echo "🔍 Useful Commands:"
echo "  • View logs: docker-compose logs -f"
echo "  • Stop services: docker-compose down"
echo "  • Restart services: docker-compose restart"
echo "  • FalkorDB CLI: docker exec -it falkordb redis-cli"
echo "  • LDAP search: docker exec ldap ldapsearch -x -H ldap://localhost:389 -b \"dc=valkey,dc=io\" -D \"cn=admin,dc=valkey,dc=io\" -w admin123!"
echo ""
