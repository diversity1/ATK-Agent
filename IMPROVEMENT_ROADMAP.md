# ATK-Agent Demo 到系统化落地改进路线

## 1. 当前项目定位

当前项目已经完成了一个面向 Sigma 检测规则的 ATT&CK 标签校验与修复原型。它能够解析 Sigma 规则，抽取规则标题、描述、日志来源、detection 逻辑和已有 ATT&CK 标签，再结合本地 ATT&CK 知识库进行候选技术召回、排序、校验和修复建议生成。

当前系统的核心价值不是简单地给规则自动打标签，而是辅助检测工程师判断规则已有 ATT&CK 标签是否合理，并输出保守的治理建议，例如保留标签、建议补充标签、疑似移除标签和是否需要人工复核。

如果希望将 demo 进一步发展成可落地系统，建议将项目定位升级为：

> 面向异构安全检测规则库的 ATT&CK 标签一致性校验、修复与覆盖治理系统。

这里的关键变化是：从“Sigma 规则映射 ATT&CK”升级为“多来源检测规则统一语义建模后进行 ATT&CK 标签治理”。

## 2. 需要解决的核心问题

### 2.1 当前不足

1. 输入格式仍然偏 Sigma
   - `ParsedRule` 中的 `product/category/service/detection_text` 更贴近 Sigma 的 logsource 结构。
   - Splunk 解析目前只是最小实现，尚不能充分抽取 SPL 查询中的字段、事件 ID、数据源和检测实体。

2. 缺少统一检测语义中间层
   - 当前主要是把规则转换为 `normalized_rule_text` 后进行检索。
   - 不同规则库的字段语义没有被归一化，例如 `CommandLine`、`process.command_line`、`ProcessCommandLine` 本质相同，但目前没有统一表示。

3. 检测逻辑结构化程度不够
   - Sigma detection 中的 AND / OR / NOT、字段修饰符、聚合条件、时间窗口没有形成统一 AST。
   - Splunk / KQL / EQL 这类查询语言中的过滤条件、聚合、管道命令也没有被结构化解析。

4. 数据源映射仍然硬编码
   - `src/tools/attack_retriever_tool.py` 中的 `LOGSOURCE_HINTS` 能工作，但更像经验规则。
   - 系统化后应引入字段本体、日志源本体和 ATT&CK data source / data component 映射。

5. 缺少跨库评测
   - 当前评测更偏工程验证。
   - 如果要证明系统价值，需要建立人工标注 gold set 和跨库等价规则集。

6. 产品闭环不足
   - 当前 Streamlit 页面可以展示单条规则分析结果。
   - 落地系统需要批量治理、人工复核队列、修复记录、覆盖矩阵和报告导出。

## 3. 总体改造架构

建议将系统改造成以下分层结构：

```text
异构规则输入
  -> Rule Adapter 层
  -> DetectionRuleIR 统一语义表示
  -> Semantic Extraction / Query Planning
  -> ATT&CK Candidate Retrieval
  -> Multi-evidence Reranking
  -> Alignment Verification
  -> Tag Repair Decision
  -> Human Review / Feedback
  -> Coverage Governance Report
```

每一层的职责如下：

1. Rule Adapter 层
   - 负责解析 Sigma、Splunk、Elastic、Sentinel 等不同规则格式。
   - 输出统一的 `DetectionRuleIR`。

2. DetectionRuleIR 层
   - 统一表达规则行为、日志源、观测实体、检测逻辑和已有标签。
   - 后续所有 Agent 都只依赖 IR，不直接依赖 Sigma / Splunk 细节。

3. ATT&CK 对齐层
   - 使用关键词、行为语义、数据源、平台、tactic 等多路证据召回和排序 ATT&CK technique。

4. 标签修复层
   - 判断已有标签是否合理。
   - 输出保守修复建议，而不是无条件自动覆盖原始标签。

5. 人工复核闭环
   - 记录分析师接受、拒绝、修改建议的结果。
   - 用反馈持续优化阈值、提示词和重排序策略。

## 4. 第一阶段：重构统一规则表示

### 4.1 新增 DetectionRuleIR

建议在 `src/core/schemas.py` 中新增：

```python
class DetectionRuleIR(BaseModel):
    rule_id: str
    source_type: str
    source_file: str = ""
    query_language: str = ""

    title: str = ""
    description: str = ""
    severity: str = ""
    status: str = ""

    platforms: List[str] = Field(default_factory=list)
    telemetry: List[str] = Field(default_factory=list)
    data_components: List[str] = Field(default_factory=list)

    observables: List[Dict[str, Any]] = Field(default_factory=list)
    entities: List[str] = Field(default_factory=list)
    detection_logic: Dict[str, Any] = Field(default_factory=dict)

    raw_tags: List[str] = Field(default_factory=list)
    existing_attack_tags: List[str] = Field(default_factory=list)

    behavior_summary: str = ""
    normalized_text: str = ""
```

字段含义：

| 字段 | 作用 |
|---|---|
| `source_type` | 规则来源，例如 `sigma`、`splunk`、`elastic`、`sentinel` |
| `query_language` | 查询语言，例如 `sigma_yaml`、`spl`、`kql`、`eql` |
| `telemetry` | 规范化日志类型，例如 `Process Creation`、`Registry Modification` |
| `data_components` | 对齐 ATT&CK data component，例如 `Process Command` |
| `observables` | 规则中检测到的实体和字段条件 |
| `entities` | 可检索实体，例如 `powershell.exe`、`rundll32.exe`、`4688` |
| `detection_logic` | 结构化后的检测逻辑 |
| `behavior_summary` | 面向 ATT&CK 映射的行为摘要 |
| `normalized_text` | 供 BM25 / dense retrieval 使用的统一文本 |

### 4.2 保留 ParsedRule 兼容层

短期内不要直接删除 `ParsedRule`，可以让 `ParsedRule` 继续存在，避免大范围破坏现有 pipeline。

建议过渡方式：

1. 新增 `DetectionRuleIR`。
2. 新增 `ir_to_parsed_rule()` 适配函数。
3. 先让现有 `AlignmentAgent` 继续处理 `ParsedRule`。
4. 后续再逐步让 `AlignmentAgent` 直接处理 `DetectionRuleIR`。

## 5. 第二阶段：建立多规则库 Adapter

### 5.1 新增目录结构

建议新增：

```text
src/parsers/
  __init__.py
  base.py
  sigma_adapter.py
  splunk_adapter.py
  registry.py
```

后续再扩展：

```text
  elastic_adapter.py
  sentinel_adapter.py
  chronicle_adapter.py
```

### 5.2 Adapter 统一接口

```python
class RuleAdapter(Protocol):
    source_type: str

    def parse(self, raw_rule: dict, file_path: str = "") -> DetectionRuleIR:
        ...
```

`registry.py` 提供：

```python
def get_rule_adapter(source_type: str) -> RuleAdapter:
    ...
```

### 5.3 Sigma Adapter 改造

将 `src/tools/rule_parser_tool.py` 中的 Sigma 解析逻辑迁移或封装到 `sigma_adapter.py`。

需要增强的点：

1. 提取 `logsource` 并转换为 `telemetry`。
2. 提取 `detection` 中的字段条件。
3. 保留 detection 的结构化逻辑。
4. 将字段名映射到统一 observable 类型。

示例：

```yaml
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine|contains: "Invoke-Expression"
```

应该转换为：

```json
{
  "platforms": ["Windows"],
  "telemetry": ["Process Creation"],
  "observables": [
    {
      "field": "CommandLine",
      "normalized_field": "process.command_line",
      "type": "command_line",
      "operator": "contains",
      "value": "Invoke-Expression"
    }
  ],
  "entities": ["Invoke-Expression"]
}
```

### 5.4 Splunk Adapter 做实

Splunk 是最建议优先支持的第二个规则库，因为它能证明项目从 Sigma 单库走向跨库。

需要从 SPL 中抽取：

1. `index`
2. `sourcetype`
3. `EventCode`
4. 字段过滤条件
5. 进程名、命令行、注册表路径、网络字段
6. `stats` / `where` / `bin` 等聚合条件
7. tags 中的 ATT&CK ID

示例：

```spl
index=wineventlog sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=1
Image="*\\powershell.exe" CommandLine="*-enc*"
```

应该转换为：

```json
{
  "source_type": "splunk",
  "query_language": "spl",
  "platforms": ["Windows"],
  "telemetry": ["Process Creation"],
  "data_components": ["Process Creation", "Process Command"],
  "observables": [
    {"type": "event_id", "value": "1"},
    {"type": "process_image", "value": "powershell.exe"},
    {"type": "command_line", "operator": "contains", "value": "-enc"}
  ],
  "entities": ["1", "powershell.exe", "-enc"]
}
```

## 6. 第三阶段：建立字段本体和数据源本体

### 6.1 新增知识目录

建议新增：

```text
src/knowledge/
  __init__.py
  field_ontology.py
  datasource_ontology.py
  eventcode_mapping.py
```

### 6.2 field_ontology.py

用于把不同规则库字段映射为统一语义字段。

示例：

```python
FIELD_ONTOLOGY = {
    "CommandLine": {
        "normalized": "process.command_line",
        "observable_type": "command_line",
        "data_component": "Process Command",
    },
    "process.command_line": {
        "normalized": "process.command_line",
        "observable_type": "command_line",
        "data_component": "Process Command",
    },
    "ProcessCommandLine": {
        "normalized": "process.command_line",
        "observable_type": "command_line",
        "data_component": "Process Command",
    },
}
```

### 6.3 datasource_ontology.py

用于把规则来源的数据源映射到统一 telemetry。

示例：

```python
DATASOURCE_ONTOLOGY = {
    "sigma:category:process_creation": {
        "telemetry": "Process Creation",
        "platforms": ["Windows", "Linux", "macOS"],
        "data_components": ["Process Creation", "Process Command"],
    },
    "splunk:eventcode:4688": {
        "telemetry": "Process Creation",
        "platforms": ["Windows"],
        "data_components": ["Process Creation", "Process Command"],
    },
    "splunk:eventcode:1": {
        "telemetry": "Process Creation",
        "platforms": ["Windows"],
        "data_components": ["Process Creation", "Process Command"],
    },
}
```

### 6.4 替换硬编码 LOGSOURCE_HINTS

当前 `LOGSOURCE_HINTS` 可以先保留，但应逐步改为从 ontology 中读取：

```text
DetectionRuleIR.telemetry
DetectionRuleIR.data_components
DetectionRuleIR.platforms
```

而不是依赖：

```text
parsed_rule.product
parsed_rule.category
parsed_rule.service
```

## 7. 第四阶段：改造 ATT&CK 对齐机制

### 7.1 AlignmentAgent 输入改造

目标状态：

```python
def process(self, rule_ir: DetectionRuleIR, semantic_profile=None, query_plan=None):
    ...
```

过渡状态：

```python
def process(self, parsed_rule: ParsedRule, rule_ir: DetectionRuleIR = None, ...):
    ...
```

短期建议先做过渡状态，减少破坏。

### 7.2 多证据评分

目前检索主要依赖文本召回、RRF 和 logsource 加权。系统化后建议形成多证据评分：

```text
final_score =
  behavior_score
  + entity_score
  + telemetry_score
  + platform_score
  + tactic_score
  + existing_tag_consistency_score
  - contradiction_penalty
```

其中：

| 分数 | 说明 |
|---|---|
| `behavior_score` | 规则行为描述与 ATT&CK technique 描述的相似度 |
| `entity_score` | 工具、命令、API、EventID 等实体匹配 |
| `telemetry_score` | 规则数据源与 ATT&CK data source / detection 字段匹配 |
| `platform_score` | Windows / Linux / Cloud 平台是否一致 |
| `tactic_score` | tactic 是否一致 |
| `existing_tag_consistency_score` | 原标签是否与候选存在父子或等价关系 |
| `contradiction_penalty` | 数据源、平台、行为明显矛盾时扣分 |

### 7.3 输出解释增强

`AlignmentResult` 中建议增加：

```python
score_breakdown: Dict[str, float]
matched_observables: List[Dict[str, Any]]
matched_data_sources: List[str]
contradictions: List[str]
```

这对落地和专利材料都很重要，因为它能说明系统不是黑盒打标签，而是基于多证据进行可解释判断。

## 8. 第五阶段：增强标签修复策略

当前修复动作包括：

```text
KEEP
SUPPLEMENT
POSSIBLE_MISMATCH
ABSTAIN
```

建议扩展为：

```text
KEEP
ADD_CANDIDATE
REMOVE_SUSPECT
REPLACE_SUSPECT
COARSEN_TO_PARENT
REFINE_TO_SUBTECHNIQUE
ABSTAIN
```

新增逻辑：

1. 如果已有标签是父技术，预测结果是高置信子技术，输出 `REFINE_TO_SUBTECHNIQUE`。
2. 如果已有标签是子技术，但证据只支持父技术，输出 `COARSEN_TO_PARENT`。
3. 如果已有标签与高置信预测结果 tactic 冲突，输出 `REMOVE_SUSPECT` 或 `REPLACE_SUSPECT`。
4. 如果候选之间分数接近，输出 `ABSTAIN` 并进入人工复核。

## 9. 第六阶段：建立评测体系

### 9.1 人工标注 Gold Set

建议先构建 100 条规则的小型 gold set，再扩展到 300 到 500 条。

每条样本至少包含：

```text
rule_id
source_type
raw_rule
gold_attack_tags
gold_rationale
analyst
review_date
```

### 9.2 跨库等价规则集

这是验证跨库泛化的关键。

构造方式：

```text
同一攻击行为：
  Sigma 版本
  Splunk SPL 版本
  Elastic EQL/KQL 版本
  Sentinel KQL 版本

期望：
  这些规则应映射到相同或高度一致的 ATT&CK technique。
```

示例行为：

1. PowerShell encoded command execution
2. rundll32 suspicious DLL execution
3. LSASS memory dump
4. scheduled task creation
5. registry run key persistence
6. suspicious DNS query
7. process injection indicator
8. remote service creation

### 9.3 噪声修复集

构造三类噪声：

1. 删除正确标签，测试补充能力。
2. 替换为错误标签，测试错标识别能力。
3. 父子技术混淆，测试粗细粒度修复能力。

### 9.4 推荐指标

```text
Top-1 Accuracy
Top-3 Accuracy
Macro Precision
Macro Recall
Macro F1
Missing Tag Recovery Rate
Wrong Tag Detection Rate
Parent-child Correction Rate
Abstain Precision
Human Review Reduction
Coverage Distortion Reduction
```

其中 `Coverage Distortion Reduction` 可以作为项目亮点指标：

```text
覆盖失真 = 自动/原始标签覆盖矩阵 与 gold 标签覆盖矩阵 的差异
覆盖失真降低率 = 修复前失真 - 修复后失真
```

## 10. 第七阶段：产品化功能

### 10.1 批量规则治理页面

当前页面偏单条分析。建议增加：

1. 规则库导入
2. 批量扫描任务
3. 分析结果列表
4. 高风险错标列表
5. 漏标建议列表
6. 低置信度列表
7. 人工复核队列

### 10.2 ATT&CK 覆盖矩阵

展示：

1. 原始标签覆盖矩阵
2. 修复建议后覆盖矩阵
3. 人工确认后覆盖矩阵
4. 变化最大的 tactic / technique
5. 可能是假覆盖的 technique
6. 可能漏覆盖的 technique

### 10.3 复核工作流

每条需要人工复核的规则应有：

```text
规则原文
原始标签
候选标签
证据表
冲突点
系统建议
确认 / 拒绝 / 修改
分析师备注
```

### 10.4 报告导出

建议支持：

1. JSONL 机器可读结果
2. CSV 规则治理清单
3. Markdown / HTML 汇报报告
4. ATT&CK coverage summary
5. 修复建议 diff

## 11. 第八阶段：服务化部署

如果从 demo 变成系统，建议将 Streamlit 演示层和后端能力拆开。

推荐后端结构：

```text
FastAPI
  POST /rules/analyze
  POST /rules/batch
  GET  /rules/{rule_id}/result
  GET  /coverage/attack-matrix
  POST /review/{rule_id}/feedback
```

数据存储：

```text
SQLite 起步
PostgreSQL 用于正式部署
FAISS / Chroma 用于向量检索
本地 JSON ATT&CK index 用于离线可复现模式
```

任务处理：

```text
同步模式：小批量或 demo
异步模式：RQ / Celery 处理大批量规则
```

## 12. 第九阶段：专利化材料准备

如果后续考虑申请专利，建议不要把创新点描述成“使用 LLM 映射 ATT&CK”。这个表述过宽，也容易落入已有工作。

更适合提炼为：

> 一种面向异构安全检测规则库的 ATT&CK 标签一致性校验与修复方法、系统、设备及存储介质。

可提炼的技术特征：

1. 将异构检测规则解析为统一检测语义 IR。
2. 基于字段本体、日志源本体和 ATT&CK data source 的三方语义对齐。
3. 融合行为、实体、数据源、平台、tactic、已有标签关系的多证据排序。
4. 对已有 ATT&CK 标签进行父子技术关系、冲突关系和缺失关系校验。
5. 根据置信度、证据冲突和覆盖影响生成保守修复动作。
6. 利用人工复核反馈对阈值、排序权重和规则库适配策略进行校准。
7. 通过覆盖失真降低指标评估修复前后的 ATT&CK 覆盖质量。

建议准备的材料：

1. 系统架构图
2. 规则解析到 IR 的流程图
3. 多证据评分流程图
4. 标签修复决策流程图
5. 人工反馈闭环流程图
6. 实验数据和指标对比
7. 与传统关键词匹配、单纯 LLM 映射、人工维护标签的对比表

## 13. 推荐实施顺序

### Milestone 1：IR 与 Sigma 适配重构

目标：

1. 新增 `DetectionRuleIR`。
2. 新增 Sigma adapter。
3. 现有 pipeline 可以通过 IR 兼容层继续运行。

预计修改：

```text
src/core/schemas.py
src/tools/rule_parser_tool.py
src/parsers/sigma_adapter.py
src/parsers/registry.py
```

验收标准：

1. 原有 Sigma 规则批处理不报错。
2. 每条规则都能输出结构化 `DetectionRuleIR`。
3. `normalized_text` 与现有检索效果基本一致。

### Milestone 2：Splunk 适配器

目标：

1. 支持解析 Splunk SPL 规则。
2. 能抽取 EventCode、sourcetype、字段条件和实体。
3. Splunk 规则能进入同一 ATT&CK 对齐流程。

预计修改：

```text
src/parsers/splunk_adapter.py
src/dataio/load_rules.py
src/pipelines/process_rule_batch.py
src/main.py
```

验收标准：

1. 至少 30 条 Splunk 样例可以被解析。
2. Sigma 与 Splunk 的等价规则能够得到相近 top3 结果。

### Milestone 3：字段本体和数据源本体

目标：

1. 建立统一字段映射。
2. 建立日志源到 ATT&CK data component 的映射。
3. 替换部分 `LOGSOURCE_HINTS` 硬编码逻辑。

预计修改：

```text
src/knowledge/field_ontology.py
src/knowledge/datasource_ontology.py
src/knowledge/eventcode_mapping.py
src/tools/attack_retriever_tool.py
```

验收标准：

1. `CommandLine`、`process.command_line`、`ProcessCommandLine` 可归一到同一字段。
2. Sysmon Event ID 1、Windows 4688、Sigma process_creation 可归一到 `Process Creation`。

### Milestone 4：多证据排序与解释

目标：

1. 对候选 technique 形成评分拆解。
2. 输出规则证据、ATT&CK 证据和冲突点。
3. 降低纯文本相似度导致的错配。

预计修改：

```text
src/tools/attack_retriever_tool.py
src/agents/alignment_agent.py
src/llm/rerank.py
src/core/schemas.py
```

验收标准：

1. 每个候选结果包含 `score_breakdown`。
2. 低数据源匹配或平台冲突的候选会被降权。
3. 页面能展示主要证据。

### Milestone 5：标签修复策略增强

目标：

1. 支持父技术 / 子技术粒度修复。
2. 支持替换、移除、降级、细化等动作。
3. 提高人工复核建议质量。

预计修改：

```text
src/agents/repair_agent.py
src/tools/tag_validator_tool.py
src/core/schemas.py
```

验收标准：

1. 可以区分 `COARSEN_TO_PARENT` 和 `REFINE_TO_SUBTECHNIQUE`。
2. 错标不会被直接自动写入 `final_tags`。
3. 高风险修改进入 `needs_review=True`。

### Milestone 6：评测集与指标

目标：

1. 构建人工 gold set。
2. 构建跨库等价规则集。
3. 增加覆盖失真指标。

预计修改：

```text
data/eval/
src/evaluation/
```

验收标准：

1. 能一键运行评测。
2. 输出 top-k、修复准确率、abstain、覆盖失真降低等指标。
3. 有实验结果可用于论文、汇报或专利材料。

当前实现：

1. 已新增最小 gold set：`data/eval/gold_rules.jsonl`。
2. 已新增 gold set 评测脚本：`src/evaluation/run_gold_eval.py`。
3. 已支持跨库等价组一致性评测，例如 Sigma/Splunk 对同一行为的 Top-1 是否一致。
4. 已输出 `Top-1/Top-3 Accuracy`、`Compatible Top-1/Top-3 Accuracy`、`Recommendation F1`、`Action Accuracy`、`Coverage Distortion Reduction`、`Parent-child Correction Rate`。
5. 可执行 `python src/evaluation/run_gold_eval.py --write-telemetry` 生成 Enterprise Telemetry 页面所需的 `data/outputs/` 数据。
6. 已新增真实规则库数据构建脚本：`src/evaluation/build_real_world_dataset.py`。
7. 已新增标签修复实验脚本：`src/evaluation/run_noise_repair_eval.py`。
8. 已新增治理效果实验脚本：`src/evaluation/run_governance_eval.py`。
9. 当前已能从本地 `data/sigma_rules/` 抽取真实 SigmaHQ 规则，并可接入本地 Splunk Security Content 仓库。

### Milestone 7：治理工作台

目标：

1. 从单条规则分析扩展为批量规则治理。
2. 增加人工复核队列。
3. 增加覆盖矩阵和报告导出。

预计修改：

```text
src/app.py
src/dataio/save_results.py
src/tools/coverage_analyzer_tool.py
```

验收标准：

1. 能上传或加载一批规则。
2. 能筛选错标、漏标、低置信度规则。
3. 能导出治理报告。

当前实现：

1. `Enterprise Telemetry` 已升级为治理工作台。
2. 支持读取本地 `data/outputs/rule_results.csv`，也支持上传外部 `rule_results.csv`。
3. 支持 Overview、Rule Governance、Review Queue、Coverage、Export 五个工作区。
4. 支持按来源、动作、置信度和是否需要复核筛选规则。
5. 支持人工复核反馈记录到 `data/outputs/review_feedback.jsonl`。
6. 支持导出 Markdown 治理报告：`data/outputs/governance_report.md`。
7. 已新增报告生成工具：`src/tools/governance_report_tool.py`。

## 14. 最小可行升级路径

如果时间有限，建议优先做以下最小闭环：

1. 新增 `DetectionRuleIR`。
2. 做实 Sigma adapter。
3. 做实 Splunk adapter。
4. 新增字段本体和数据源本体。
5. 准备 50 条 Sigma + Splunk 等价样例。
6. 让系统输出跨库一致性评测结果。
7. 在页面增加“规则治理结果列表”和“人工复核建议”。

完成这个闭环后，项目就不再只是 demo，而是具备系统雏形：

```text
多规则库输入
  -> 统一语义 IR
  -> ATT&CK 标签校验
  -> 修复建议
  -> 人工复核
  -> 覆盖治理评估
```

## 15. 最终目标形态

最终系统可以形成以下能力：

1. 输入任意一批检测规则。
2. 自动识别规则来源和查询语言。
3. 将规则转换为统一检测语义。
4. 自动校验已有 ATT&CK 标签。
5. 发现漏标、错标、过粗标签和疑似过期标签。
6. 输出保守修复建议和证据。
7. 支持分析师人工确认。
8. 生成修复前后的 ATT&CK 覆盖矩阵。
9. 记录反馈并持续优化映射效果。

这时项目的系统价值可以表述为：

> 将分散、异构、质量不一致的检测规则标签，转化为可解释、可复核、可度量的 ATT&CK 覆盖治理流程。
