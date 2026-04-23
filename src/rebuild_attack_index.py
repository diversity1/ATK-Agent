"""
rebuild_attack_index.py
从已下载的 raw_attack.json (STIX格式) 重建更丰富的 ATT&CK 索引。

新版索引相比旧版额外包含：
  - detection: 官方检测建议（对 RAG 语义索引极其有价值）
  - url: 技术的官方 ATT&CK 链接
  - data_sources: 数据源列表（用于 logsource 匹配）
  - is_subtechnique: 是否是子技术

用法:
  cd atkagent
  python src/rebuild_attack_index.py
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

RAW_PATH    = "data/attack/raw_attack.json"
OUTPUT_PATH = "data/attack/attack_techniques.json"


def build_index(raw_path: str, output_path: str) -> dict:
    print(f"Reading STIX data from: {raw_path}")
    with open(raw_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    index = {}
    skipped_deprecated = 0
    skipped_no_tid     = 0

    for obj in data.get("objects", []):
        # 只处理 ATT&CK 技术（attack-pattern）
        if obj.get("type") != "attack-pattern":
            continue

        # 跳过已废弃的技术
        if obj.get("x_mitre_deprecated", False) or obj.get("revoked", False):
            skipped_deprecated += 1
            continue

        # 提取 TID (Technique ID)
        ext_refs = obj.get("external_references", [])
        tid      = None
        url      = ""
        for ref in ext_refs:
            if ref.get("source_name") == "mitre-attack":
                tid = ref.get("external_id")
                url = ref.get("url", "")
                break

        if not tid:
            skipped_no_tid += 1
            continue

        # 提取战术
        kill_phases = obj.get("kill_chain_phases", [])
        tactics = [
            p["phase_name"] for p in kill_phases
            if p.get("kill_chain_name") == "mitre-attack"
        ]

        # 提取数据源（对于 logsource 匹配非常有用）
        data_sources = obj.get("x_mitre_data_sources", [])

        # 提取描述（完整）
        description = obj.get("description", "")

        # 提取官方检测建议（这是新增的关键字段！）
        detection = obj.get("x_mitre_detection", "")

        index[tid] = {
            "id":              tid,
            "name":            obj.get("name", ""),
            "description":     description,
            "detection":       detection,       # ← 新增：官方检测建议
            "tactics":         tactics,
            "platforms":       obj.get("x_mitre_platforms", []),
            "data_sources":    data_sources,    # ← 新增：数据源
            "url":             url,             # ← 新增：官方链接
            "is_subtechnique": obj.get("x_mitre_is_subtechnique", False),
        }

    print(f"  Built {len(index)} techniques")
    print(f"  Skipped {skipped_deprecated} deprecated/revoked")
    print(f"  Skipped {skipped_no_tid} without TID")

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(index, f, indent=2, ensure_ascii=False)

    size_mb = os.path.getsize(output_path) / 1024 / 1024
    print(f"  Saved → {output_path} ({size_mb:.1f} MB)")
    return index


if __name__ == "__main__":
    if not os.path.exists(RAW_PATH):
        print(f"[Error] Raw STIX file not found: {RAW_PATH}")
        print("  Please run: python src/download_data.py")
        sys.exit(1)

    index = build_index(RAW_PATH, OUTPUT_PATH)

    # 打印几个样例验证
    print("\n[Sample] First 3 entries:")
    for i, (tid, tech) in enumerate(index.items()):
        if i >= 3:
            break
        print(f"  {tid}: {tech['name']}")
        print(f"    Tactics: {tech['tactics']}")
        print(f"    Platforms: {tech['platforms']}")
        print(f"    Data sources: {tech['data_sources'][:3]}")
        detection_preview = tech['detection'][:80].replace('\n', ' ') if tech['detection'] else "(none)"
        print(f"    Detection hint: {detection_preview}...")
        print()

    print("Done! Now restart your pipeline to use the enriched index.")
