# Download NIST JSON files first
# From: https://nvd.nist.gov/feeds/json/cve/1.1/

# Create directory
mkdir nist_data
cd nist_data

# Download (example for 2024 and 2023)
wget https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2024.json. gz
wget https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2023.json.gz

# Decompress
gunzip *.gz

# Go back and run import
cd ..
python import_nist_cves.py --init-db --dir nist_data/

# Or import single file
python import_nist_cves.py --file nist_data/nvdcve-1.1-2024.json