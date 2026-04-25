# ATK-Agent: ATT&CK Tag Validation and Repair for Detection Rules

一个面向安全检测规则的 ATT&CK 标签校验与修复系统。项目当前支持 Sigma 与 Splunk 规则输入，通过统一检测语义 IR、字段/数据源本体、MITRE ATT&CK 知识库、混合检索排序和可选 LLM 推理，对规则已有 ATT&CK 标签进行校验、补充、细化、降级和疑似错配提示，并生成覆盖分析结果。

## 1. 项目定位

在实际安全运营中，检测规则的 ATT&CK 标签常见以下问题：

- 没有标签，难以做 ATT&CK 覆盖统计
- 标签粒度过粗，只标父技术，不标子技术
- 原有标签错误或过时
- 同类规则标签标准不一致，影响规则治理质量

本项目的目标不是简单地“给规则打标签”，而是构建一个较为保守、可解释、可人工复核的 ATT&CK 标签校验与修复流程。

一句话概括：

> 将异构检测规则规约为统一行为语义，再结合日志来源上下文和 ATT&CK 官方检测知识，自动判断规则 ATT&CK 标签是否合理，并输出保留、新增候选、细化到子技术、降级到父技术、疑似替换、疑似移除或放弃判断等结果。

## 2. 项目能做什么

当前系统支持：

- 解析 Sigma 规则的标题、描述、日志来源和 detection 逻辑
- 解析 Splunk JSON / SPL / TXT 规则中的 search、EventCode、sourcetype、字段条件和 ATT&CK 标签
- 将不同规则库规约为统一 `DetectionRuleIR`
- 基于字段本体归一化 `CommandLine`、`process.command_line`、`ProcessCommandLine` 等同义字段
- 基于数据源本体归一化 Sigma logsource、Splunk EventCode 和 ATT&CK data component
- 从本地 ATT&CK 索引中召回候选 Technique/Sub-technique
- 结合行为、实体、数据源、平台、tactic、已有标签关系和冲突惩罚做多证据候选排序
- 通过 LLM 或启发式方法输出 `top1 / top3 / confidence`
- 对原有 ATT&CK 标签进行一致性比较
- 输出保守的修复建议：
  - `final_tags`
  - `suggested_add_tags`
  - `suspect_remove_tags`
  - `needs_review`
- 输出候选评分拆解：
  - `entity_score`
  - `telemetry_score`
  - `platform_score`
  - `tactic_score`
  - `existing_tag_score`
  - `contradiction_penalty`
- 统计按 Technique / Tactic 的覆盖情况
- 提供 Streamlit 可视化页面进行单条规则分析和人工反馈记录

## 3. 系统架构

系统采用职责清晰的多 Agent 流水线结构：

- `ParsingAgent`  
  负责调用不同规则库 Adapter，并构建统一检测语义 IR
- `AlignmentAgent`  
  负责 ATT&CK 候选召回与排序
- `RepairAgent`  
  负责标签校验、修复决策与复核建议
- `ManagerAgent`  
  负责整条处理链路的编排

当前代码已增加 LangGraph 编排增强层：

- `LangGraphManagerAgent`  
  基于 `StateGraph` 将解析、对齐、修复和复核入口建模为显式工作流节点
- `human_review_gate`  
  当修复结果 `needs_review=True` 时进入人工复核门控节点，当前默认记录 `review_status=pending`，保留后续接入 interrupt/resume 的扩展空间

核心编排入口：

- 批处理入口：[src/main.py](src/main.py)
- Web 页面入口：[src/app.py](src/app.py)
- 总控 Agent：[src/agents/manager_agent.py](src/agents/manager_agent.py)
- LangGraph 编排：[src/agents/langgraph_orchestrator.py](src/agents/langgraph_orchestrator.py)
- 规则 Adapter：[src/parsers/](src/parsers/)
- 字段/数据源本体：[src/knowledge/](src/knowledge/)

### 3.1 统一检测语义 IR

系统新增 `DetectionRuleIR`，用于将 Sigma、Splunk 等异构规则规约为统一结构。后续语义抽取、检索、候选排序和修复策略都优先使用 IR 中的规范化信号，而不是直接依赖某一种规则格式。

核心字段包括：

- `source_type`
- `query_language`
- `platforms`
- `telemetry`
- `data_components`
- `observables`
- `entities`
- `detection_logic`
- `existing_attack_tags`
- `normalized_text`

这使得系统从“Sigma 到 ATT&CK”升级为“异构规则到统一行为语义，再到 ATT&CK 标签治理”。

### 3.2 Agent 编排状态图

LangGraph 版本保留原有确定性解析、检索和修复策略，同时新增多段 LLM Agent。当前状态图如下：

```text
START
  -> parse_rule
  -> semantic_extract
  -> plan_queries
  -> align_attack
  -> verify_alignment
  -> repair_tags
  -> review_brief        # needs_review=True 时生成
  -> human_review_gate  # needs_review=True 时进入
  -> finalize
  -> END
```

每个节点读写同一个图状态：

- `raw_rule`
- `parsed_rule`
- `semantic_profile`
- `query_plan`
- `alignment_result`
- `verification_result`
- `repair_result`
- `review_brief`
- `errors`
- `graph_trace`
- `review_status`

这样做的好处是：算法逻辑仍然稳定可复用，同时大模型不再只做候选重排，而是参与语义抽取、检索查询规划、候选验证和人工复核说明生成。离线或 API 不可用时，这些节点会自动回退到启发式实现。

### 3.3 LLM Agent 分工

- `SemanticExtractionAgent`  
  从规则标题、描述、日志源和 detection 中抽取攻击行为画像，输出 `main_behavior`、`observables`、`tools_or_binaries`、`likely_tactics`、`required_data_sources`。
- `QueryPlannerAgent`  
  基于语义画像生成多路检索 query，包括关键词 query、行为 query、数据源 query 和 tactic query。
- `AlignmentAgent`  
  基于多查询召回候选，再通过 LLM 或启发式方法输出 `top1/top3/confidence` 和证据。
- `VerificationAgent`  
  对 `AlignmentAgent` 的结论做反向一致性验证，并对置信度做小幅校准。
- `ReviewAssistantAgent`  
  当结果需要人工复核时，生成面向分析师的复核问题、摘要、证据表和建议选项。

## 4. 核心算法流程

### Step 1. 异构规则解析与统一语义化

实现位置：

- [src/tools/rule_parser_tool.py](src/tools/rule_parser_tool.py)
- [src/parsers/sigma_adapter.py](src/parsers/sigma_adapter.py)
- [src/parsers/splunk_adapter.py](src/parsers/splunk_adapter.py)
- [src/knowledge/field_ontology.py](src/knowledge/field_ontology.py)
- [src/knowledge/datasource_ontology.py](src/knowledge/datasource_ontology.py)

系统会从 Sigma / Splunk 规则中提取：

- `title`
- `description`
- `logsource.product`
- `logsource.category`
- `logsource.service`
- `detection`
- Splunk `search`
- Splunk `EventCode`
- Splunk `sourcetype`
- 字段条件与检测实体
- 原有 `tags`

解析结果会进入统一 `DetectionRuleIR`，其中包含：

- `platforms`
- `telemetry`
- `data_components`
- `observables`
- `entities`
- `detection_logic`
- `normalized_text`

其中，`detection` 或 SPL 查询会被抽取为结构化 observables，例如：

- EventID
- 命令行特征
- PowerShell 关键字
- 可疑脚本内容

最终构造出一个面向检索和证据评分的规则语义文本：

- Rule title
- Description
- Platforms
- Telemetry
- Data Components
- Detection indicators
- Structured observables

注意：当前版本不会再把原有 ATT&CK 标签直接拼进检索 query，以避免错误旧标签对召回结果造成污染。

### Step 2. ATT&CK 本地知识索引构建

实现位置：

- [src/dataio/load_attack.py](src/dataio/load_attack.py)
- [src/rebuild_attack_index.py](src/rebuild_attack_index.py)

系统会从 `raw_attack.json` 中构建本地 `attack_techniques.json` 索引。当前索引已支持从新版 STIX 结构中提取：

- `name`
- `description`
- `tactics`
- `platforms`
- `detection`
- `data_sources`
- `log_sources`
- `url`
- `is_subtechnique`

这意味着候选检索不再只依赖 technique 名称和描述，而是显式利用了 ATT&CK 官方检测知识。

### Step 3. 候选 Technique 检索

实现位置：[src/tools/attack_retriever_tool.py](src/tools/attack_retriever_tool.py)

当前检索器为混合检索结构：

1. `BM25` 稀疏检索  
   用于命令词、工具名、脚本关键词、EventID 等精确特征匹配

2. `Dense Retrieval` 向量检索（可选）  
   使用 sentence-transformers，默认可关闭，适合离线稳定运行场景

3. `RRF` 融合排序  
   将 BM25 和 Dense 的排名通过 Reciprocal Rank Fusion 融合

4. `IR Telemetry / Data Component` 匹配加分  
   系统会优先根据统一 IR 中的：

- `platforms`
- `telemetry`
- `data_components`
- `observables`
- `entities`

去匹配 technique 的：

- `data_sources`
- `log_sources`
- `platforms`
- `detection`

旧版 `product/category/service` 仍作为兼容信号保留。

5. 多证据解释评分  
   每个候选会生成可解释评分拆解：

- `entity_score`
- `telemetry_score`
- `platform_score`
- `tactic_score`
- `existing_tag_score`
- `contradiction_penalty`
- `evidence_bonus`

最终为每个候选技术生成：

- `retrieval_score`
- `bm25_score`
- `dense_score`（若启用）
- `logsource_score`
- `score_breakdown`
- `matched_observables`
- `matched_data_sources`
- `contradictions`

### Step 4. 候选重排

实现位置：

- [src/agents/alignment_agent.py](src/agents/alignment_agent.py)
- [src/llm/rerank.py](src/llm/rerank.py)
- [src/llm/prompts.py](src/llm/prompts.py)

如果配置了可用的 LLM，系统会对召回候选进行一次推理式重排；否则使用启发式排序。

输出包括：

- `top1`
- `top3`
- `confidence`
- `reason`
- `abstain`

当前启发式置信度会综合考虑：

- 候选第一名得分
- 第一名与第二名的分差
- `logsource_score`
- `entity_score`
- `telemetry_score`
- `contradiction_penalty`
- 是否存在标签提示

### Step 5. 标签校验与修复策略

实现位置：

- [src/agents/repair_agent.py](src/agents/repair_agent.py)
- [src/tools/tag_validator_tool.py](src/tools/tag_validator_tool.py)

系统会将：

- 原有 ATT&CK 标签
- 预测 `top3`

进行比较，支持：

- exact match
- 父技术 / 子技术关系判断
- mismatch score 计算

最终修复动作包括：

- `KEEP`
- `ADD_CANDIDATE`
- `REFINE_TO_SUBTECHNIQUE`
- `COARSEN_TO_PARENT`
- `REPLACE_SUSPECT`
- `REMOVE_SUSPECT`
- `ABSTAIN`

其中：

- `ADD_CANDIDATE`：原规则缺少有效 ATT&CK 标签，系统提出候选标签。
- `REFINE_TO_SUBTECHNIQUE`：原规则标的是父技术，证据支持更具体的子技术。
- `COARSEN_TO_PARENT`：原规则标的是子技术，但证据只支持父技术。
- `REPLACE_SUSPECT`：原有标签与高置信预测明显不兼容，建议人工复核替换。
- `REMOVE_SUSPECT`：原有标签证据不足或与候选证据冲突，建议人工复核移除。
- `ABSTAIN`：置信度不足，不做自动判断。

当前版本的关键改进是：

> 不再无脑把 `top3` 直接合并进最终标签。

而是把输出拆成：

- `final_tags`  
  系统愿意自动保留或自动落盘的标签
- `suggested_add_tags`  
  建议新增，但不直接写入最终标签
- `suspect_remove_tags`  
  怀疑有问题、建议人工复核的旧标签
- `needs_review`  
  是否需要人工审核

这使系统更适合真实 SOC 规则治理场景。

### Step 6. 批量覆盖分析

实现位置：[src/tools/coverage_analyzer_tool.py](src/tools/coverage_analyzer_tool.py)

批处理完成后，系统会统计：

- Technique 覆盖分布
- Tactic 覆盖分布

输出文件位于 `data/outputs/`。

## 5. 组会可讲的核心亮点

如果用于组会汇报，建议重点强调以下四点：

### 5.1 从“规则文本匹配”升级为“跨库规则语义映射”

系统不只看规则标题，而是显式解析 Sigma detection、Splunk SPL、字段条件、检测实体和日志来源，并统一进入 `DetectionRuleIR`。

### 5.2 引入 ATT&CK 官方检测知识

候选技术索引中不仅包含 technique 描述，还包含：

- `detection`
- `data_sources`
- `log_sources`

这让映射过程更贴近 ATT&CK 官方知识结构。

### 5.3 引入字段本体与数据源对齐机制

通过字段本体和数据源本体，将 `CommandLine`、`process.command_line`、`ProcessCommandLine` 等字段归一到同一语义，并让“规则来自什么日志”与“该 ATT&CK 技术通常通过什么数据源检测”建立联系。

### 5.4 引入多证据评分拆解

候选排序不仅看文本相似度，还会输出实体、数据源、平台、tactic、旧标签一致性和冲突惩罚等评分拆解，便于分析师解释为什么某个 technique 排在前面。

### 5.5 修复策略从激进自动合并改为保守建议式输出

这让系统不仅能给结果，还能给出：

- 自动保留项
- 建议新增项
- 建议细化到子技术
- 建议降级到父技术
- 疑似移除项
- 是否需要人工复核

更适合作为规则治理辅助系统，而不是黑盒自动打标器。

## 6. 项目意义

本项目的意义主要体现在三个层面。

### 6.1 提升检测规则资产质量

帮助安全团队发现：

- 漏标规则
- 错标规则
- 粒度不一致规则

从而提升规则集的可维护性与一致性。

### 6.2 支撑 ATT&CK 覆盖分析

更可靠的标签意味着更可信的：

- ATT&CK 覆盖统计
- tactic 分布分析
- detection gap 分析

### 6.3 支持人机协同的规则治理流程

系统不是替代分析师，而是先给出较高质量建议，再交给人工确认，支持 Human-in-the-Loop 的安全知识维护闭环。

## 7. 项目目录

```text
atkagent/
├─ data/
│  ├─ attack/
│  │  ├─ raw_attack.json
│  │  └─ attack_techniques.json
│  ├─ sigma_rules/
│  ├─ splunk_rules/
│  └─ outputs/
├─ src/
│  ├─ agents/
│  ├─ core/
│  ├─ dataio/
│  ├─ evaluation/
│  ├─ knowledge/
│  ├─ llm/
│  ├─ parsers/
│  ├─ pipelines/
│  ├─ tools/
│  ├─ app.py
│  ├─ main.py
│  ├─ rebuild_attack_index.py
│  └─ download_data.py
├─ requirements.txt
└─ README.md
```

## 8. 快速开始

### 8.1 安装依赖

```bash
pip install -r requirements.txt
```

### 8.2 准备数据

如果仓库中已经有 `data/attack/raw_attack.json` 和规则数据，可以直接使用。  
如果希望重新下载官方数据：

```bash
python src/download_data.py
```

如果希望手动重建 ATT&CK 索引：

```bash
python src/rebuild_attack_index.py
```

### 8.3 批处理运行

```bash
python src/main.py
```

批处理会同时扫描：

- `data/sigma_rules/`
- `data/splunk_rules/`

Splunk 规则支持 `.json`、`.spl`、`.txt` 输入。JSON 中常见字段可以是 `search`、`query`、`spl`、`name`、`description`、`tags`。

运行后结果会输出到：

- `data/outputs/rule_results.jsonl`
- `data/outputs/rule_results.csv`
- `data/outputs/coverage_summary.csv`
- `data/outputs/coverage_by_tactic.csv`
- `data/outputs/run_report.json`

### 8.4 启动页面

推荐先以稳定离线模式启动：

```powershell
$env:ENABLE_LLM='False'
$env:ENABLE_DENSE_RETRIEVAL='False'
python -m streamlit run src/app.py
```

浏览器访问：

```text
http://localhost:8501
```

### 8.5 启用 LLM / Dense Retrieval

如果你的网络、模型或 API 已配置完成，可以开启：

```powershell
$env:ENABLE_LLM='True'
$env:ENABLE_DENSE_RETRIEVAL='True'
python -m streamlit run src/app.py
```

### 8.6 公开部署到 Streamlit Cloud

本项目是 Streamlit/Python 应用，GitHub Pages 不能直接运行后端 Python 服务。推荐部署方式是：

```text
GitHub 仓库 -> Streamlit Community Cloud -> *.streamlit.app 公共链接
```

项目根目录已提供云端入口：

```text
streamlit_app.py
```

部署时在 Streamlit Community Cloud 中选择：

- Repository：你的 GitHub 仓库
- Branch：`main`
- Main file path：`streamlit_app.py`

如果只是公开演示，可以在 Streamlit Secrets 中关闭在线模型：

```toml
ENABLE_LLM = "False"
ENABLE_DENSE_RETRIEVAL = "False"
```

如果希望启用 LLM Agent，在 Streamlit Secrets 中配置：

```toml
ENABLE_LLM = "True"
ENABLE_DENSE_RETRIEVAL = "False"
LLM_PROVIDER = "openai"
LLM_MODEL = "qwen-plus"
LLM_API_KEY = "your-api-key"
LLM_API_BASE = "https://your-compatible-endpoint/v1"
```

更完整的部署步骤见 [DEPLOYMENT.md](DEPLOYMENT.md)。

### 8.7 治理工作台

Streamlit 页面包含两个主要视图：

- `Real-time Sandbox`：单条 Sigma/Splunk 规则即时分析。
- `Enterprise Telemetry`：批量规则治理工作台。

`Enterprise Telemetry` 会读取：

- `data/outputs/rule_results.csv`
- `data/outputs/coverage_summary.csv`
- `data/outputs/coverage_by_tactic.csv`

如果没有数据，可先运行：

```bash
python src/evaluation/run_gold_eval.py --write-telemetry
```

治理工作台支持：

- 上传 `rule_results.csv`
- 查看规则治理概览
- 按来源、动作、置信度筛选规则
- 查看人工复核队列
- 记录复核反馈到 `data/outputs/review_feedback.jsonl`
- 查看 Technique / Tactic 覆盖
- 导出 Markdown 治理报告 `data/outputs/governance_report.md`

## 9. 关键配置项

配置文件位置：[src/config.py](src/config.py)

常用环境变量：

- `ENABLE_LLM`  
  是否启用 LLM 语义抽取、查询规划、候选重排、验证和复核说明生成
- `ENABLE_DENSE_RETRIEVAL`  
  是否启用向量检索
- `EMBEDDING_MODEL`  
  向量模型名称
- `EMBEDDING_LOCAL_FILES_ONLY`  
  是否只使用本地模型文件
- `TOP_K_RETRIEVAL`  
  候选召回数
- `MISMATCH_THRESHOLD`  
  错配判定阈值
- `ABSTAIN_THRESHOLD`  
  放弃判断阈值
- `LOGSOURCE_MATCH_WEIGHT`  
  日志来源匹配分在检索中的加权强度
- `LLM_PROVIDER`
- `LLM_MODEL`
- `LLM_API_KEY`
- `LLM_API_BASE`

## 10. 当前输出语义说明

单条规则最终记录中常见字段含义如下：

- `predicted_top1`  
  当前最可能的 ATT&CK 技术
- `predicted_top3`  
  候选前三技术
- `confidence`  
  当前结果置信度
- `action`  
  修复动作类型
- `final_tags`  
  自动保留/自动生效的最终标签
- `suggested_add_tags`  
  建议新增标签
- `suspect_remove_tags`  
  建议复核或移除的旧标签
- `needs_review`  
  是否应进入人工复核
- `orchestration_mode`  
  当前编排方式，`langgraph` 表示通过 LangGraph 状态图执行
- `graph_trace`  
  单条规则经过的图节点轨迹，例如 `parse_rule -> semantic_extract -> plan_queries -> align_attack -> verify_alignment -> repair_tags -> finalize`
- `review_status`  
  人工复核状态，当前包括 `not_required` / `pending`
- `semantic_main_behavior`  
  LLM/启发式语义抽取到的主要检测行为
- `semantic_extraction_mode`  
  语义抽取模式，`llm` 或 `heuristic`
- `query_plan`  
  多路 ATT&CK 检索查询列表
- `verification_verdict`  
  验证 Agent 对候选映射的结论，例如 `accept` / `revise` / `reject`
- `verification_reason`  
  验证 Agent 给出的校验说明
- `review_question`  
  需要人工复核时给分析师的问题
- `review_summary`  
  面向人工复核的简短说明
- `source_type`  
  规则来源，例如 `sigma` 或 `splunk`
- `query_language`  
  查询语言，例如 `sigma_yaml` 或 `spl`
- `platforms`  
  统一后的平台信息，例如 `Windows`
- `telemetry`  
  统一后的日志/遥测类型，例如 `Process Creation`
- `data_components`  
  对齐 ATT&CK 的数据组件，例如 `Process Command`
- `entities`  
  从规则中抽取的关键实体，例如 `powershell.exe`、`4688`
- `score_breakdown`  
  top1 候选的多证据评分拆解
- `matched_data_sources`  
  规则数据源与 ATT&CK 候选命中的数据源证据
- `contradictions`  
  候选证据中的冲突点，例如平台不一致

## 11. 实验设计与当前结果

评估代码位于 [src/evaluation/](src/evaluation/)。当前仓库里已经跑完并保留了 4 组实验产物，覆盖“跨库一致性”“真实规则治理”“噪声标签修复”和“基础 silver sanity check”。批量实验与单条测试共用同一套 LangGraph/Agent 处理链路，是否调用大模型由 `ENABLE_LLM`、`LLM_API_KEY`、`LLM_API_BASE` 等配置决定；如果需要强制离线复现实验，可以显式传入 `--disable-llm`。报告中的 `enable_llm` 表示本次运行是否开启了 LLM 开关，`llm_available` 表示客户端是否真的可用。

### 11.1 当前实验总览

| 实验 | 目的 | 数据集 | 当前产物 |
| --- | --- | --- | --- |
| Gold Set 跨库一致性实验 | 验证 Sigma 与 Splunk 等价规则能否映射到一致 ATT&CK 技术 | `data/eval/gold_rules.jsonl`，8 条样本，4 个等价组 | `data/outputs/gold_eval_report.json` |
| 真实规则库治理实验 | 看系统在真实 SigmaHQ 规则上能发现多少治理动作 | `data/eval/real_world_rules.jsonl`，80 条真实 Sigma 规则 | `data/outputs/governance_eval_report.json`、`data/outputs/governance_report.md` |
| 标签修复噪声实验 | 人为破坏标签后，测试系统能否识别错标、补标和父子技术粒度问题 | `data/eval/noisy_rules.jsonl`，80 条混合噪声样本 | `data/outputs/noise_repair_report.json` |
| Silver Eval / Sanity Check | 对批处理输出做基础指标检查 | `data/outputs/rule_results.*`，8 条演示记录 | `data/outputs/eval_report.json` |

几个输出字段需要先区分清楚：

- `final_tags`：系统愿意自动保留或自动落盘的保守结果。
- `suggested_add_tags` / `recommended_tags`：系统建议分析师复核后新增的标签。
- `suspect_remove_tags`：系统认为可能有问题、建议人工复核移除的旧标签。
- `needs_review`：是否进入人工复核队列。

因此，`Final Tag F1` 衡量的是“自动落盘结果”，`Recommendation F1` 衡量的是“自动结果 + 建议结果”。本项目刻意采用保守策略，所以有些实验中 `Final Tag F1` 会低于 `Recommendation F1`，这不是运行错误，而是“先不乱改，再交给分析师复核”的设计选择。

### 11.2 实验一：Gold Set 跨库一致性

这个实验使用项目内置的小型人工/半人工评测集，重点验证同一攻击行为在 Sigma 与 Splunk 两种规则格式下是否能得到一致的 ATT&CK 映射。

数据集：

- 文件：`data/eval/gold_rules.jsonl`
- 样本数：8 条
- 来源：4 条 Sigma，4 条 Splunk
- 等价组：4 组，分别覆盖 PowerShell encoded command、LSASS dump、scheduled task creation、registry run key persistence

运行命令：

```bash
python src/evaluation/run_gold_eval.py
```

如果希望同时生成 Streamlit 工作台演示数据：

```bash
python src/evaluation/run_gold_eval.py --write-telemetry
```

当前结果，来自 `data/outputs/gold_eval_report.json`：

| 指标 | 当前值 |
| --- | --- |
| Top-1 Accuracy | 100.00% |
| Top-3 Accuracy | 100.00% |
| Compatible Top-1 / Top-3 Accuracy | 100.00% / 100.00% |
| Action Accuracy | 100.00% |
| Cross-library Top-1 Consistency | 100.00% |
| Recommendation Precision / Recall / F1 | 41.67% / 100.00% / 58.33% |
| Final Tag Precision / Recall / F1 | 8.33% / 25.00% / 12.50% |
| Parent-child Correction Rate | 100.00% |

这个实验说明：在小规模等价规则集上，系统能稳定把 Sigma 与 Splunk 的同类规则映射到一致的 ATT&CK 技术；同时也暴露了保守落盘策略的影响：系统经常把更细粒度子技术放到建议项里，而不是直接写进 `final_tags`。

主要输出：

- `data/outputs/gold_eval_report.json`
- `data/outputs/gold_eval_results.jsonl`
- `data/outputs/gold_eval_results.csv`

### 11.3 实验二：真实 SigmaHQ 规则治理

这个实验回答的问题是：把系统放到真实规则库上，它会发现多少需要治理的标签问题，能产出多大的人工复核队列。

当前真实规则数据来自仓库内的 `data/sigma_rules/`，由脚本抽取为：

```text
data/sigma_rules/
  -> src/evaluation/build_real_world_dataset.py
  -> data/eval/real_world_rules.jsonl
```

当前数据规模：

- 文件：`data/eval/real_world_rules.jsonl`
- 规则数：80 条真实 Sigma 规则
- 来源：Sigma 80 条
- 等价组：56 组
- 标签来源：原始开源规则中的 ATT&CK 标签，作为 silver label，不等同于人工确认的 gold label

构建数据集：

```bash
python src/evaluation/build_real_world_dataset.py \
  --sigma-root data/sigma_rules \
  --max-sigma 200 \
  --output data/eval/real_world_rules.jsonl
```

运行治理实验：

```bash
python src/evaluation/run_governance_eval.py \
  --fixtures data/eval/real_world_rules.jsonl \
  --write-telemetry
```

当前治理结果，来自 `data/outputs/governance_eval_report.json` 和 `data/outputs/governance_report.md`：

| 指标 | 当前值 |
| --- | --- |
| Total rules | 80 |
| Average confidence | 90.10% |
| Rules with governance actions | 44 |
| Rules requiring review | 42 |
| Suggested additions | 97 |
| Suspect removals | 48 |
| KEEP | 36 |
| REFINE_TO_SUBTECHNIQUE | 5 |
| REPLACE_SUSPECT | 39 |

当前映射质量指标：

| 指标 | 当前值 |
| --- | --- |
| Top-1 Accuracy | 35.00% |
| Top-3 Accuracy | 48.75% |
| Compatible Top-1 / Top-3 Accuracy | 38.75% / 51.25% |
| Final Tag Precision / Recall / F1 | 100.00% / 100.00% / 100.00% |
| Recommendation Precision / Recall / F1 | 64.29% / 100.00% / 73.18% |
| Original unique techniques | 66 |
| Final unique techniques | 66 |
| Recommended unique techniques | 110 |

这里的 `Final Tag F1=100%` 要结合保守策略理解：治理实验使用原规则标签作为 silver label，系统在 `final_tags` 中保留了原有可自动落盘标签，所以 final 覆盖不会轻易破坏原始标签；真正用于发现潜在治理空间的是 `suggested_add_tags`、`suspect_remove_tags` 和 `needs_review`。

主要输出：

- `data/outputs/governance_eval_report.json`
- `data/outputs/governance_eval_results.jsonl`
- `data/outputs/governance_eval_results.csv`
- `data/outputs/governance_report.md`
- `data/outputs/rule_results.csv`
- `data/outputs/coverage_summary.csv`
- `data/outputs/coverage_by_tactic.csv`

当前 `coverage_by_tactic.csv` 中，规则覆盖较多的 tactic 包括 `defense-evasion`、`persistence`、`privilege-escalation`、`execution`、`discovery` 和 `credential-access`。

如果本地加入 Splunk Security Content，可以进一步构建 Sigma + Splunk 的真实跨库治理实验：

```bash
python src/evaluation/build_real_world_dataset.py \
  --sigma-root data/sigma_rules \
  --splunk-root data/external/security_content \
  --max-sigma 300 \
  --max-splunk 300 \
  --output data/eval/real_world_rules.jsonl
```

当前仓库里的真实规则库实验只包含 Sigma，因此 `cross_library_consistency.evaluated_groups=0` 是预期结果。

### 11.4 实验三：标签修复噪声实验

这个实验回答的问题是：如果原始规则标签被人为破坏，系统能否发现错标、漏标和父子技术粒度问题。

噪声构造方式：

- 输入：`data/eval/real_world_rules.jsonl`
- 输出：`data/eval/noisy_rules.jsonl`
- 噪声类型：`mixed`
- 噪声比例：0.5
- 随机种子：11

支持的噪声类型：

- `missing_tag`：删除原有 ATT&CK 标签，测试补标能力。
- `wrong_technique`：替换为错误技术，测试错标识别能力。
- `parent_child`：把子技术降为父技术，测试细化到子技术能力。
- `mixed`：混合以上多种噪声。

运行命令：

```bash
python src/evaluation/run_noise_repair_eval.py \
  --fixtures data/eval/real_world_rules.jsonl \
  --noise mixed \
  --ratio 0.5 \
  --output-json data/outputs/noise_repair_report.json
```

当前结果，来自 `data/outputs/noise_repair_report.json`：

| 指标 | 当前值 |
| --- | --- |
| Total records | 80 |
| Top-1 Accuracy | 17.50% |
| Top-3 Accuracy | 33.75% |
| Compatible Top-1 / Top-3 Accuracy | 22.50% / 37.50% |
| Action Accuracy | 87.50% |
| Action evaluated | 48 |
| Final Tag Precision / Recall / F1 | 40.63% / 41.25% / 40.83% |
| Recommendation Precision / Recall / F1 | 29.46% / 51.25% / 34.92% |
| Parent-child Correction Rate | 63.64% |
| Mean CDR / Recommended Mean CDR | 40.63% / 44.48% |

这组实验比治理实验更难，因为标签被主动污染。它更适合用来展示系统的“修复动作判断能力”，尤其是 `Action Accuracy`、`Parent-child Correction Rate` 和 `suspect_remove_tags` 队列，而不是单纯追求 Top-1。

主要输出：

- `data/eval/noisy_rules.jsonl`
- `data/outputs/noise_repair_report.json`
- `data/outputs/noise_repair_results.jsonl`
- `data/outputs/noise_repair_results.csv`

### 11.5 实验四：Silver Eval / 基础回归检查

这个实验用于快速检查批处理输出的整体指标是否能正常生成，规模较小，更像工程 sanity check。

运行命令：

```bash
python src/evaluation/run_eval.py
```

当前结果，来自 `data/outputs/eval_report.json`：

| 指标 | 当前值 |
| --- | --- |
| Total records | 8 |
| Silver evaluated | 6 |
| Macro Precision / Recall / F1 | 22.22% / 66.67% / 33.33% |
| Top-1 / Top-3 Accuracy | 0.00% / 66.67% |
| Repair Accuracy | 100.00% |
| Abstain Ratio | 0.00% |

这组结果主要用于确认评估脚本、输出字段和基础统计链路是通的；当前 README 中真正建议重点展示的是前三组实验。

## 12. 当前局限

当前版本仍有一些边界：

- Sigma 支持较完整，Splunk 已支持基础 SPL 字段抽取、EventCode、sourcetype 和 ATT&CK 标签解析，但复杂 SPL 管道、宏、lookup、子查询和聚合语义仍需增强
- LLM 重排效果依赖外部接口稳定性
- 多证据启发式排序已具备可解释评分拆解，但权重仍需通过 gold set 继续校准
- 评估目前更偏工程验证，后续仍建议建立人工标注 gold set

## 13. 后续可扩展方向

- 引入人工标注数据集，构建更可信的 gold evaluation
- 继续扩展字段本体、数据源本体和 EventCode 映射
- 增强 Splunk 复杂 SPL、Elastic EQL/KQL、Sentinel KQL 等规则格式支持
- 引入 reranker 或 cross-encoder 提升候选重排质量
- 建立 Sigma/Splunk/Elastic/Sentinel 等价规则集，评估跨库一致性
- 利用人工反馈数据做持续学习或偏好优化

## 14. 项目总结

ATK-Agent 的核心价值在于：

> 将检测规则解析、ATT&CK 检索、日志来源对齐、标签修复和覆盖分析整合到一个可解释、可复核、可运行的系统中。

它既可以作为规则治理工具，也可以作为 ATT&CK 覆盖分析、异构规则库语义对齐和安全知识治理的研究原型。
