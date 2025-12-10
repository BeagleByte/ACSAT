# Start PostgreSQL
```
sudo systemctl start postgresql
```
# Create database and user
```
sudo -u postgres psql << 'EOF'
CREATE USER cve_user WITH PASSWORD 'secure_password_here';
CREATE DATABASE cve_intelligence_db OWNER cve_user;
ALTER ROLE cve_user SET client_encoding TO 'utf8';
ALTER ROLE cve_user SET default_transaction_isolation TO 'read committed';
ALTER ROLE cve_user SET default_transaction_deferrable TO on;
ALTER ROLE cve_user SET timezone TO 'UTC';
GRANT ALL PRIVILEGES ON DATABASE cve_intelligence_db TO cve_user;
\c cve_intelligence_db cve_user
EOF
```

# Test connection
```
psql -U cve_user -d cve_intelligence_db -h localhost
```