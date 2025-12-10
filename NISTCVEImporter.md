# Download NIST JSON files first - JSON 2.0 Feeds
# From: https://nvd.nist.gov/feeds/json/cve/2.0/

# Format
nvdcve-2.0-X.json


# run import
```
python NISTCVEImporter.py --dir ../CVE-Downloads/
```
# Or import single file
```
python NISTCVEImporter.py --file n../CVE-Downloads/nvdcve-2.0-2010.json
```