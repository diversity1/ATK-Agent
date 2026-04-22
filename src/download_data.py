import os
import sys
import urllib.request
import zipfile
import io

# Add the src directory to sys.path so we can import config and dataio
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
import config
from core.utils import ensure_dir
from dataio.load_attack import build_attack_index_from_raw

ATTACK_STIX_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
SIGMA_ZIP_URL = "https://github.com/SigmaHQ/sigma/archive/refs/heads/master.zip"

def download_attack_data():
    print("1. Downloading MITRE ATT&CK STIX data...")
    ensure_dir(config.ATTACK_DATA_DIR)
    
    raw_attack_path = config.RAW_ATTACK_PATH
    try:
        urllib.request.urlretrieve(ATTACK_STIX_URL, raw_attack_path)
        print(f"   Saved raw ATT&CK data to {raw_attack_path}")
        
        print("   Building simplified ATT&CK index from raw STIX data...")
        attack_index_path = config.ATTACK_INDEX_PATH
        index = build_attack_index_from_raw(raw_attack_path, attack_index_path)
        print(f"   Successfully built index with {len(index)} ATT&CK techniques at {attack_index_path}")
    except Exception as e:
        print(f"   Error downloading or parsing ATT&CK data: {e}")

def download_sigma_rules():
    print("\n2. Downloading official Sigma rules from GitHub...")
    ensure_dir(config.SIGMA_RULES_DIR)
    
    try:
        # Download the zip file into memory
        print("   Fetching zip file...")
        response = urllib.request.urlopen(SIGMA_ZIP_URL)
        zip_bytes = response.read()
        
        print("   Extracting Windows rules...")
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zip_ref:
            # We only want files under sigma-master/rules/windows/
            target_prefix = "sigma-master/rules/windows/"
            extracted_count = 0
            
            for file_info in zip_ref.infolist():
                if file_info.filename.startswith(target_prefix) and file_info.filename.endswith(".yml"):
                    # Calculate the relative path within the target directory
                    relative_path = file_info.filename[len(target_prefix):]
                    target_path = os.path.join(config.SIGMA_RULES_DIR, "windows", relative_path)
                    
                    # Ensure the subdirectories exist
                    ensure_dir(os.path.dirname(target_path))
                    
                    # Read from zip and write to file
                    with zip_ref.open(file_info) as source, open(target_path, "wb") as target:
                        target.write(source.read())
                    extracted_count += 1
                    
        print(f"   Successfully extracted {extracted_count} Windows Sigma rules into {os.path.join(config.SIGMA_RULES_DIR, 'windows')}")
    except Exception as e:
        print(f"   Error downloading or extracting Sigma rules: {e}")

def main():
    print("Starting Data Download...")
    download_attack_data()
    download_sigma_rules()
    print("\nDownload script complete! You can now run `python src/main.py` with real data.")

if __name__ == "__main__":
    main()
