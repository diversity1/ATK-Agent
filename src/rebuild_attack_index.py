import os
import sys

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

import config
from dataio.load_attack import build_attack_index_from_raw


def main():
    raw_path = config.RAW_ATTACK_PATH
    output_path = config.ATTACK_INDEX_PATH

    if not os.path.exists(raw_path):
        print(f"[Error] Raw STIX file not found: {raw_path}")
        print("  Please run: python src/download_data.py")
        sys.exit(1)

    print(f"Reading STIX data from: {raw_path}")
    index = build_attack_index_from_raw(raw_path, output_path)
    print(f"Built {len(index)} ATT&CK techniques")

    data_source_count = sum(1 for doc in index.values() if doc.get("data_sources"))
    detection_count = sum(1 for doc in index.values() if doc.get("detection"))
    print(f"Techniques with data sources: {data_source_count}")
    print(f"Techniques with detection text: {detection_count}")
    print(f"Saved enriched index to: {output_path}")

    for i, (tid, tech) in enumerate(index.items()):
        if i >= 3:
            break
        print(f"\n{tid}: {tech['name']}")
        print(f"  Tactics: {tech.get('tactics', [])}")
        print(f"  Data sources: {tech.get('data_sources', [])[:3]}")
        preview = (tech.get("detection", "") or "").replace("\n", " ")[:120]
        print(f"  Detection hint: {preview if preview else '(none)'}")


if __name__ == "__main__":
    main()
