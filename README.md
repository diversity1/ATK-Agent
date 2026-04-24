# ATK-Agent: ATT&CK Tag Validation and Repair for Detection Rules

一个面向安全检测规则的 ATT&CK 标签校验与修复系统。项目以 Sigma 规则为主要输入，结合 MITRE ATT&CK 知识库、检索排序和可选 LLM 推理，对规则已有 ATT&CK 标签进行校验、补充和疑似错配提示，并生成覆盖分析结果。

## 1. 项目定位

在实际安全运营中，检测规则的 ATT&CK 标签常见以下问题：

- 没有标签，难以做 ATT&CK 覆盖统计
- 标签粒度过粗，只标父技术，不标子技术
- 原有标签错误或过时
- 同类规则标签标准不一致，影响规则治理质量

本项目的目标不是简单地“给规则打标签”，而是构建一个较为保守、可解释、可人工复核的 ATT&CK 标签校验与修复流程。

一句话概括：

> 将检测规则语义、日志来源上下文和 ATT&CK 官方检测知识结合起来，自动判断规则 ATT&CK 标签是否合理，并输出保留、补充、疑似错配或放弃判断等结果。

## 2. 项目能做什么

当前系统支持：

- 解析 Sigma 规则的标题、描述、日志来源和 detection 逻辑
- 从本地 ATT&CK 索引中召回候选 Technique/Sub-technique
- 结合 `detection`、`data_sources`、`log_sources`、`platforms` 做候选排序
- 通过 LLM 或启发式方法输出 `top1 / top3 / confidence`
- 对原有 ATT&CK 标签进行一致性比较
- 输出保守的修复建议：
  - `final_tags`
  - `suggested_add_tags`
  - `suspect_remove_tags`
  - `needs_review`
- 统计按 Technique / Tactic 的覆盖情况
- 提供 Streamlit 可视化页面进行单条规则分析和人工反馈记录

## 3. 系统架构

系统采用职责清晰的多 Agent 流水线结构：

- `ParsingAgent`  
  负责规则解析与语义表示构建
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

### 3.1 Agent 编排状态图

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

### 3.2 LLM Agent 分工

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

### Step 1. 规则解析与语义化

实现位置：[src/tools/rule_parser_tool.py](src/tools/rule_parser_tool.py)

系统会从规则中提取：

- `title`
- `description`
- `logsource.product`
- `logsource.category`
- `logsource.service`
- `detection`
- 原有 `tags`

其中，`detection` 会被递归抽取关键字符串，例如：

- EventID
- 命令行特征
- PowerShell 关键字
- 可疑脚本内容

最终构造出一个面向检索的规则语义文本：

- Rule title
- Description
- Log Source
- Detection indicators

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

4. `LogSource / DataSource` 匹配加分  
   这是当前版本的重要增强点。系统会根据规则的：

- `product`
- `category`
- `service`
- detection 中出现的 EventID 和关键词

去匹配 technique 的：

- `data_sources`
- `log_sources`
- `platforms`
- `detection`

最终为每个候选技术生成：

- `retrieval_score`
- `bm25_score`
- `dense_score`（若启用）
- `logsource_score`

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
- `SUPPLEMENT`
- `POSSIBLE_MISMATCH`
- `ABSTAIN`

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

### 5.1 从“规则文本匹配”升级为“规则语义映射”

系统不只看规则标题，而是显式解析 detection 逻辑和 logsource 信息。

### 5.2 引入 ATT&CK 官方检测知识

候选技术索引中不仅包含 technique 描述，还包含：

- `detection`
- `data_sources`
- `log_sources`

这让映射过程更贴近 ATT&CK 官方知识结构。

### 5.3 引入日志来源与数据源对齐机制

通过 `logsource_score`，让“规则来自什么日志”与“该 ATT&CK 技术通常通过什么数据源检测”建立联系。

### 5.4 修复策略从激进自动合并改为保守建议式输出

这让系统不仅能给结果，还能给出：

- 自动保留项
- 建议新增项
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
│  └─ outputs/
├─ src/
│  ├─ agents/
│  ├─ core/
│  ├─ dataio/
│  ├─ evaluation/
│  ├─ llm/
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

## 11. 评估模块

评估代码位于 [src/evaluation/](src/evaluation/)。

可执行：

```bash
python src/evaluation/run_eval.py
```

当前支持的指标包括：

- Macro Precision / Recall / F1
- Top-K Accuracy
- Repair Accuracy
- Abstain Ratio
- Confidence Distribution
- Coverage Distortion Reduction

## 12. 当前局限

当前版本仍有一些边界：

- Sigma 支持较完整，Splunk 解析仍是最小实现
- LLM 重排效果依赖外部接口稳定性
- 启发式排序仍有进一步优化空间
- 评估目前更偏工程验证，后续仍建议建立人工标注 gold set

## 13. 后续可扩展方向

- 引入人工标注数据集，构建更可信的 gold evaluation
- 优化 logsource 到 ATT&CK data source 的映射词典
- 增强 Splunk / 其他规则格式支持
- 引入 reranker 或 cross-encoder 提升候选重排质量
- 利用人工反馈数据做持续学习或偏好优化

## 14. 项目总结

ATK-Agent 的核心价值在于：

> 将检测规则解析、ATT&CK 检索、日志来源对齐、标签修复和覆盖分析整合到一个可解释、可复核、可运行的系统中。

它既可以作为规则治理工具，也可以作为 ATT&CK 覆盖分析和安全知识对齐的研究原型。
