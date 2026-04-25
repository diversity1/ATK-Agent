import streamlit as st
import os
import sys
import pandas as pd
import json
import datetime
import plotly.express as px
import plotly.graph_objects as go

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
import config
from core.registry import registry
from llm.client import LLMClient
from agents.langgraph_orchestrator import create_manager_agent
from dataio.load_attack import load_attack_index, build_attack_index_from_raw, attack_index_is_enriched
from core.utils import ensure_dir
from tools.governance_report_tool import (
    GOVERNANCE_ACTIONS,
    REVIEW_ACTIONS,
    build_governance_summary,
    parse_list_cell,
    render_markdown_report,
    save_markdown_report,
    truthy,
)

# 必须是第一个调用的 Streamlit 命令
st.set_page_config(page_title="ATK-Agent Sentinel", layout="wide", page_icon="🛡️", initial_sidebar_state="expanded")

# ==========================================
# 💎 高级企业级 CSS 注入 (Cyber-Security Theme)
# ==========================================
st.markdown("""
<style>
    /* 隐藏顶部默认白条 */
    header[data-testid="stHeader"] {
        background: transparent;
    }
    
    /* 标题特效 */
    .hero-title {
        background: -webkit-linear-gradient(45deg, #60a5fa, #34d399, #38bdf8);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        font-size: 3.5rem;
        font-weight: 900;
        margin-bottom: 0px;
        letter-spacing: -1px;
    }
    .hero-subtitle {
        color: #cbd5e1;
        font-size: 1.2rem;
        font-weight: 400;
        margin-top: 0px;
        margin-bottom: 30px;
        letter-spacing: 1px;
        text-transform: uppercase;
    }

    /* 自定义数据卡片 (Glassmorphism) */
    .metric-card {
        background: rgba(30, 41, 59, 0.4);
        border: 1px solid #475569;
        border-radius: 12px;
        padding: 20px;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.2);
        text-align: center;
    }
    .metric-title {
        font-size: 0.9rem;
        color: #e2e8f0;
        text-transform: uppercase;
        letter-spacing: 1px;
        font-weight: 700;
    }
    .metric-value {
        font-size: 2.5rem;
        color: #ffffff;
        font-weight: 900;
        margin: 10px 0;
        text-shadow: 0 0 15px rgba(59, 130, 246, 0.4);
    }
    .metric-delta.positive { color: #34d399; font-weight: bold;}
    .metric-delta.neutral { color: #cbd5e1; font-weight: bold;}

    /* 标签设计 */
    .tag-container { margin: 10px 0; display: flex; flex-wrap: wrap; gap: 8px;}
    .cyber-tag {
        background: #1e293b;
        color: #f8fafc;
        padding: 6px 14px;
        border-radius: 6px;
        font-size: 0.85rem;
        font-weight: 700;
        border: 1px solid #64748b;
        font-family: 'Consolas', monospace;
    }
    .cyber-tag.new {
        background: rgba(16, 185, 129, 0.2);
        color: #34d399;
        border: 1px solid #34d399;
    }
    .cyber-tag.original {
        background: #334155;
        color: #f1f5f9;
    }

    /* 终端风格的文本框 */
    .stTextArea textarea {
        font-family: 'Consolas', monospace !important;
        font-size: 1rem !important;
    }
    
    /* 按钮美化 */
    .stButton>button {
        background: linear-gradient(90deg, #2563eb, #1d4ed8) !important;
        color: #ffffff !important;
        border: none;
        border-radius: 8px;
        font-weight: 800 !important;
        padding: 0.5rem 1rem;
    }
    .stButton>button:hover {
        background: linear-gradient(90deg, #3b82f6, #2563eb) !important;
    }
</style>
""", unsafe_allow_html=True)

# ==========================================
# 🧠 系统初始化
# ==========================================
@st.cache_resource
def init_system():
    if not os.path.exists(config.ATTACK_INDEX_PATH):
        if not os.path.exists(config.RAW_ATTACK_PATH):
            return None
        attack_index = build_attack_index_from_raw(config.RAW_ATTACK_PATH, config.ATTACK_INDEX_PATH)
    else:
        attack_index = load_attack_index(config.ATTACK_INDEX_PATH)
    if not attack_index_is_enriched(attack_index) and os.path.exists(config.RAW_ATTACK_PATH):
        attack_index = build_attack_index_from_raw(config.RAW_ATTACK_PATH, config.ATTACK_INDEX_PATH)
    registry.register("attack_index", attack_index)
    llm_client = LLMClient()
    registry.register("llm_client", llm_client)
    manager = create_manager_agent()
    registry.register("manager_agent", manager)
    return manager

manager = init_system()

def save_feedback(state, accepted: bool):
    ensure_dir(config.OUTPUTS_DIR)
    fb_path = os.path.join(config.OUTPUTS_DIR, "feedback.jsonl")
    tp = state.alignment_result.thought_process if state.alignment_result else None
    record = {
        "timestamp": datetime.datetime.now().isoformat(),
        "rule_id": state.parsed_rule.rule_id if state.parsed_rule else "unknown",
        "title": state.parsed_rule.title if state.parsed_rule else "",
        "action": state.repair_result.action,
        "accepted": accepted,
        "cot_thought_process": tp
    }
    with open(fb_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def save_row_review_feedback(row: dict, decision: str, comment: str = ""):
    ensure_dir(config.OUTPUTS_DIR)
    fb_path = os.path.join(config.OUTPUTS_DIR, "review_feedback.jsonl")
    record = {
        "timestamp": datetime.datetime.now().isoformat(),
        "rule_id": row.get("rule_id", "unknown"),
        "title": row.get("title", ""),
        "action": row.get("action", ""),
        "decision": decision,
        "comment": comment,
        "suggested_add_tags": parse_list_cell(row.get("suggested_add_tags", [])),
        "suspect_remove_tags": parse_list_cell(row.get("suspect_remove_tags", [])),
    }
    with open(fb_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def _records_from_df(df: pd.DataFrame) -> list:
    if df is None or df.empty:
        return []
    return df.fillna("").to_dict(orient="records")


def _review_mask(df: pd.DataFrame) -> pd.Series:
    if df.empty:
        return pd.Series(dtype=bool)
    needs_review = df.get("needs_review", pd.Series(False, index=df.index)).apply(truthy)
    action_review = df.get("action", pd.Series("", index=df.index)).isin(REVIEW_ACTIONS)
    suspect = df.get("suspect_remove_tags", pd.Series("", index=df.index)).apply(lambda value: len(parse_list_cell(value)) > 0)
    return needs_review | action_review | suspect


def _format_list_cell(value) -> str:
    return ", ".join(str(item) for item in parse_list_cell(value))

# ==========================================
# 🎛️ 侧边栏设置
# ==========================================
with st.sidebar:
    st.markdown("### 🛡️ **ATK-Agent Core**")
    st.markdown("SOC Automation Platform")
    st.divider()
    
    view_mode = st.radio("NAVIGATION", ["⚡ Real-time Sandbox", "🛰️ Enterprise Telemetry"], index=0, label_visibility="collapsed")
    
    st.divider()
    st.markdown("#### ENGINE SETTINGS")
    source_type = st.selectbox("Rule Source", ["sigma", "splunk"], index=0)
    confidence_th = st.slider("Silver Standard Threshold", min_value=0.5, max_value=0.99, value=0.85, step=0.01)
    top_k = st.number_input("RAG Retrieval Top-K", min_value=1, max_value=20, value=10)
    st.caption("Adjusts precision vs recall tradeoff for the RAG alignment.")
    
    st.divider()
    st.success("🟢 Hybrid Index Loaded")
    st.success("🟢 LLM Gateway Active")
    st.success("🟢 CoT Module Ready")

# ==========================================
# 🚀 头部 Hero 区域
# ==========================================
st.markdown('<div class="hero-title">ATK-Agent Sentinel</div>', unsafe_allow_html=True)
st.markdown('<div class="hero-subtitle">Cognitive ATT&CK Tagging & Repair Engine</div>', unsafe_allow_html=True)

if not manager:
    st.error("🚨 CRITICAL FAILURE: ATT&CK Index not found. Execute `python src/rebuild_attack_index.py`.")
    st.stop()

# ==========================================
# 视图 1: ⚡ 实时交互沙盒
# ==========================================
if view_mode == "⚡ Real-time Sandbox":
    default_sigma_rule = """title: Sample Suspicious PowerShell
id: 1234-5678
description: Detects suspicious powershell execution
logsource:
  product: windows
  service: powershell
detection:
  selection:
    EventID: 4104
    ScriptBlockText|contains: 'Invoke-Expression'
  condition: selection
tags:
  - attack.execution
  - attack.t1059
"""
    default_splunk_rule = """index=wineventlog sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=1 Image="*\\powershell.exe" CommandLine="*-enc*"
"""
    
    col_editor, col_result = st.columns([1, 1.4], gap="large")
    
    with col_editor:
        st.markdown("#### 📜 Rule Payload")
        st.caption("Paste raw Sigma YAML or Splunk SPL detection logic.")
        default_rule = default_sigma_rule if source_type == "sigma" else default_splunk_rule
        rule_text = st.text_area("payload", value=default_rule, height=450, label_visibility="collapsed")
        
        col_btn1, col_btn2 = st.columns([3, 1])
        with col_btn1:
            analyze_btn = st.button("🚀 EXECUTE COGNITIVE ALIGNMENT", use_container_width=True)
            
    with col_result:
        st.markdown("#### 🧠 Agent Telemetry")
        st.caption("Live reasoning and repair results.")
        
        if 'current_state' not in st.session_state:
            st.session_state.current_state = None
            
        if analyze_btn:
            import yaml
            try:
                if source_type == "sigma":
                    raw_rule = yaml.safe_load(rule_text)
                else:
                    raw_rule = {"name": "Ad-hoc Splunk SPL", "search": rule_text}
                with st.spinner("Initiating Vector Search & CoT Pipeline..."):
                    st.session_state.current_state = manager.run_one_rule(raw_rule, source_type=source_type)
            except Exception as e:
                st.error(f"Syntax Parse Error: {str(e)}")
                st.session_state.current_state = None

        state = st.session_state.current_state
        
        if state:
            if state.errors:
                st.error(f"🚨 Pipeline Error: {state.errors}")
            else:
                action = state.repair_result.action
                
                # 高级行动面板
                action_config = {
                    "KEEP": {"color": "#3b82f6", "icon": "✅", "desc": "Rule is aligned."},
                    "ADD_CANDIDATE": {"color": "#10b981", "icon": "✨", "desc": "Candidate tag proposed."},
                    "REFINE_TO_SUBTECHNIQUE": {"color": "#38bdf8", "icon": "🎯", "desc": "More specific sub-technique found."},
                    "COARSEN_TO_PARENT": {"color": "#f59e0b", "icon": "↥", "desc": "Only parent technique is supported."},
                    "REPLACE_SUSPECT": {"color": "#f97316", "icon": "⚠️", "desc": "Replacement requires review."},
                    "REMOVE_SUSPECT": {"color": "#ef4444", "icon": "⛔", "desc": "Existing tag is suspect."},
                    "ABSTAIN": {"color": "#64748b", "icon": "⏸️", "desc": "Confidence below threshold."},
                    "SUPPLEMENT": {"color": "#10b981", "icon": "✨", "desc": "Coverage enhanced."},
                    "POSSIBLE_MISMATCH": {"color": "#f59e0b", "icon": "⚠️", "desc": "Deviation detected."},
                }.get(action, {"color": "#fff", "icon": "❓", "desc": ""})
                
                st.markdown(f"""
                <div style='background: rgba(15, 23, 42, 0.8); border: 1px solid {action_config["color"]}50; border-left: 4px solid {action_config["color"]}; padding: 20px; border-radius: 8px; display: flex; align-items: center; justify-content: space-between;'>
                    <div>
                        <div style='color: {action_config["color"]}; font-size: 0.9rem; font-weight: 800; letter-spacing: 1px; margin-bottom: 4px;'>AGENT DECISION</div>
                        <div style='color: #f8fafc; font-size: 1.5rem; font-weight: 700;'>{action_config["icon"]} {action}</div>
                        <div style='color: #94a3b8; font-size: 0.9rem; margin-top: 5px;'>{state.repair_result.repair_reason}</div>
                    </div>
                    <div style='text-align: right;'>
                        <div style='color: #64748b; font-size: 0.8rem;'>Confidence Score</div>
                        <div style='color: {action_config["color"]}; font-size: 2rem; font-weight: 900;'>{(state.alignment_result.confidence * 100):.1f}%</div>
                    </div>
                </div>
                """, unsafe_allow_html=True)
                
                # 标签演变可视化
                orig_tags = state.parsed_rule.existing_attack_tags
                final_tags = state.repair_result.final_tags
                suggested_tags = state.repair_result.suggested_add_tags
                suspect_remove_tags = state.repair_result.suspect_remove_tags
                
                st.write("")
                st.markdown("##### 🧬 Technique Vector Mapping")
                
                c_old, c_arrow, c_new = st.columns([4, 1, 4])
                with c_old:
                    st.caption("LEGACY TAGS")
                    if orig_tags:
                        tags_html = "".join([f"<span class='cyber-tag original'>{t}</span>" for t in orig_tags])
                        st.markdown(f"<div class='tag-container'>{tags_html}</div>", unsafe_allow_html=True)
                    else:
                        st.markdown("<span style='color: #64748b;'>[NO DATA]</span>", unsafe_allow_html=True)
                        
                with c_arrow:
                    st.markdown("<div style='text-align: center; font-size: 2rem; color: #334155; margin-top: 10px;'>➔</div>", unsafe_allow_html=True)
                    
                with c_new:
                    st.caption("FINAL TAGS")
                    tags_html = ""
                    for t in final_tags:
                        if t not in orig_tags:
                            tags_html += f"<span class='cyber-tag new'>+ {t}</span>"
                        else:
                            tags_html += f"<span class='cyber-tag original'>{t}</span>"
                    st.markdown(f"<div class='tag-container'>{tags_html}</div>", unsafe_allow_html=True)

                if suggested_tags:
                    st.caption("SUGGESTED ADDITIONS")
                    tags_html = "".join([f"<span class='cyber-tag new'>+ {t}</span>" for t in suggested_tags])
                    st.markdown(f"<div class='tag-container'>{tags_html}</div>", unsafe_allow_html=True)

                if suspect_remove_tags:
                    st.caption("SUSPECT TAGS TO REVIEW")
                    tags_html = "".join([f"<span class='cyber-tag original'>{t}</span>" for t in suspect_remove_tags])
                    st.markdown(f"<div class='tag-container'>{tags_html}</div>", unsafe_allow_html=True)
                
                st.write("")
                
                # 人类反馈机制
                st.markdown("##### 👩‍💻 Human-in-the-Loop Validation")
                col_y, col_n = st.columns(2)
                with col_y:
                    if st.button("✅ ACKNOWLEDGE & MERGE", use_container_width=True):
                        save_feedback(state, accepted=True)
                        st.toast('Telemetry logged for RLHF fine-tuning.', icon='✅')
                with col_n:
                    if st.button("❌ REJECT OVERRIDE", use_container_width=True):
                        save_feedback(state, accepted=False)
                        st.toast('Correction logged for RLHF fine-tuning.', icon='❌')
                
                # 透明度追踪
                with st.expander("🔍 VIEW PIPELINE TRACE (CoT & RAG)"):
                    st.markdown("###### 0. LANGGRAPH ORCHESTRATION TRACE")
                    trace = getattr(state, "graph_trace", [])
                    review_status = getattr(state, "review_status", "not_required")
                    if trace:
                        st.code(" -> ".join(trace))
                    st.caption(f"review_status={review_status}")

                    if state.parsed_rule:
                        st.markdown("###### 0.1 NORMALIZED RULE IR")
                        st.json({
                            "source_type": state.parsed_rule.source_type,
                            "query_language": state.parsed_rule.query_language,
                            "platforms": state.parsed_rule.platforms,
                            "telemetry": state.parsed_rule.telemetry,
                            "data_components": state.parsed_rule.data_components,
                            "entities": state.parsed_rule.entities[:20],
                        })

                    st.markdown("###### 1. LLM SEMANTIC PROFILE")
                    semantic_profile = getattr(state, "semantic_profile", None)
                    if semantic_profile:
                        st.json(semantic_profile.model_dump())

                    st.markdown("###### 2. LLM QUERY PLAN")
                    query_plan = getattr(state, "query_plan", None)
                    if query_plan:
                        st.json(query_plan.model_dump())

                    st.markdown("###### 3. HYBRID RAG CANDIDATES")
                    df_cands = pd.DataFrame([{
                        "TID": c.technique_id, 
                        "Name": c.technique_name, 
                        "BM25": f"{c.why.get('bm25_score', 0):.2f}",
                        "LogSrc": f"{c.why.get('logsource_score', 0):.2f}",
                        "Entity": f"{c.score_breakdown.get('entity_score', 0):.2f}",
                        "DataSrc": f"{c.score_breakdown.get('telemetry_score', 0):.2f}",
                        "Platform": f"{c.score_breakdown.get('platform_score', 0):.2f}",
                        "Penalty": f"{c.score_breakdown.get('contradiction_penalty', 0):.2f}",
                        "Queries": c.why.get("query_count", 1),
                        "Fusion": f"{c.retrieval_score:.3f}"
                    } for c in state.alignment_result.retrieved_candidates[:5]])
                    st.dataframe(df_cands, use_container_width=True, hide_index=True)

                    if getattr(state.alignment_result, "score_breakdown", None):
                        st.markdown("###### 3.1 TOP CANDIDATE EVIDENCE")
                        st.json({
                            "score_breakdown": state.alignment_result.score_breakdown,
                            "matched_data_sources": state.alignment_result.matched_data_sources,
                            "matched_observables": state.alignment_result.matched_observables,
                            "contradictions": state.alignment_result.contradictions,
                        })
                    
                    st.markdown("###### 4. ALIGNMENT REASONING")
                    if getattr(state.alignment_result, "thought_process", None):
                        tp = state.alignment_result.thought_process
                        st.info(f"**Extracted Vectors:** {tp.get('step1_extracted_behavior', '')}")
                        st.success(f"**Tactic Goal:** {tp.get('step2_tactic_goal', '')}")
                        st.warning(f"**Technique Logic:** {tp.get('step3_technique_matching', '')}")
                    if getattr(state.alignment_result, "evidence_from_rule", None):
                        st.write("Rule evidence:", state.alignment_result.evidence_from_rule)
                    if getattr(state.alignment_result, "evidence_from_attack", None):
                        st.write("ATT&CK evidence:", state.alignment_result.evidence_from_attack)

                    st.markdown("###### 5. VERIFICATION AGENT")
                    verification_result = getattr(state, "verification_result", None)
                    if verification_result:
                        st.json(verification_result.model_dump())

                    review_brief = getattr(state, "review_brief", None)
                    if review_brief:
                        st.markdown("###### 6. REVIEW ASSISTANT BRIEF")
                        st.json(review_brief.model_dump())

        else:
            st.info("System Ready. Awaiting payload...")

# ==========================================
# 视图 2: 🛰️ 企业全景大盘
# ==========================================
elif view_mode == "🛰️ Enterprise Telemetry":
    rule_results_path = os.path.join(config.OUTPUTS_DIR, "rule_results.csv")
    tactic_path = os.path.join(config.OUTPUTS_DIR, "coverage_by_tactic.csv")
    tech_path = os.path.join(config.OUTPUTS_DIR, "coverage_summary.csv")

    uploaded_results = st.file_uploader("Upload rule_results.csv", type=["csv"])
    if uploaded_results is not None:
        df_results = pd.read_csv(uploaded_results)
        df_tactic = pd.DataFrame(columns=["Key", "Count"])
        df_tech = pd.DataFrame(columns=["Key", "Count"])
        st.caption("Using uploaded result file. Coverage charts use local coverage files only when available.")
    elif os.path.exists(rule_results_path):
        df_results = pd.read_csv(rule_results_path)
        df_tactic = pd.read_csv(tactic_path) if os.path.exists(tactic_path) else pd.DataFrame(columns=["Key", "Count"])
        df_tech = pd.read_csv(tech_path) if os.path.exists(tech_path) else pd.DataFrame(columns=["Key", "Count"])
    else:
        df_results = pd.DataFrame()
        df_tactic = pd.DataFrame(columns=["Key", "Count"])
        df_tech = pd.DataFrame(columns=["Key", "Count"])

    if not df_results.empty:
        df_results["confidence"] = pd.to_numeric(df_results.get("confidence", 0.0), errors="coerce").fillna(0.0)
        if "needs_review" not in df_results.columns:
            df_results["needs_review"] = False

        total_rules = len(df_results)
        actions = df_results["action"].value_counts()
        repaired_count = sum(actions.get(action, 0) for action in [
            "ADD_CANDIDATE",
            "REFINE_TO_SUBTECHNIQUE",
            "COARSEN_TO_PARENT",
            "REPLACE_SUSPECT",
            "REMOVE_SUSPECT",
            "SUPPLEMENT",
            "POSSIBLE_MISMATCH",
        ])
        avg_conf = df_results['confidence'].mean() * 100
        review_count = int(_review_mask(df_results).sum())
        low_conf_count = int((df_results["confidence"] < confidence_th).sum())
        summary = build_governance_summary(_records_from_df(df_results))

        # 自定义大屏 KPI 卡片
        st.markdown(f"""
        <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin-bottom: 30px;">
            <div class="metric-card">
                <div class="metric-title">Rules Ingested</div>
                <div class="metric-value">{total_rules:,}</div>
                <div class="metric-delta neutral">Target: Sigma/Splunk</div>
            </div>
            <div class="metric-card">
                <div class="metric-title">Governance Actions</div>
                <div class="metric-value">{repaired_count:,}</div>
                <div class="metric-delta positive">↑ {(repaired_count/total_rules)*100:.1f}% Impact</div>
            </div>
            <div class="metric-card">
                <div class="metric-title">Review Queue</div>
                <div class="metric-value">{review_count:,}</div>
                <div class="metric-delta neutral">Analyst Validation</div>
            </div>
            <div class="metric-card">
                <div class="metric-title">Agent Confidence</div>
                <div class="metric-value">{avg_conf:.1f}%</div>
                <div class="metric-delta positive">Avg Output Certainty</div>
            </div>
        </div>
        """, unsafe_allow_html=True)

        tab_overview, tab_rules, tab_review, tab_coverage, tab_export = st.tabs([
            "Overview",
            "Rule Governance",
            "Review Queue",
            "Coverage",
            "Export",
        ])

        with tab_overview:
            col_chart1, col_chart2 = st.columns([1, 2])

            with col_chart1:
                st.markdown("##### Action Matrix")
                fig_pie = go.Figure(data=[go.Pie(
                    labels=actions.index,
                    values=actions.values,
                    hole=0.6,
                    marker=dict(colors=['#3b82f6', '#10b981', '#f59e0b', '#64748b', '#ef4444'],
                                line=dict(color='#0b1120', width=2))
                )])
                fig_pie.update_layout(
                    paper_bgcolor='rgba(0,0,0,0)',
                    plot_bgcolor='rgba(0,0,0,0)',
                    font=dict(color='#94a3b8'),
                    margin=dict(t=0, b=0, l=0, r=0),
                    showlegend=True,
                    legend=dict(orientation="h", yanchor="bottom", y=-0.2, xanchor="center", x=0.5)
                )
                st.plotly_chart(fig_pie, use_container_width=True)

            with col_chart2:
                st.markdown("##### Confidence Distribution")
                fig_hist = px.histogram(df_results, x="confidence", nbins=12, color_discrete_sequence=['#10b981'])
                fig_hist.update_layout(
                    paper_bgcolor='rgba(0,0,0,0)',
                    plot_bgcolor='rgba(0,0,0,0)',
                    font=dict(color='#94a3b8'),
                    xaxis=dict(gridcolor='#1e293b', title="Confidence"),
                    yaxis=dict(gridcolor='#1e293b', title="Rules"),
                    margin=dict(t=10, b=0, l=0, r=0)
                )
                st.plotly_chart(fig_hist, use_container_width=True)

            st.markdown("##### Governance Summary")
            st.json(summary)

        with tab_rules:
            st.markdown("##### Rule Governance Workbench")
            filter_cols = st.columns([1, 1, 1, 1])
            with filter_cols[0]:
                selected_sources = st.multiselect(
                    "Source",
                    sorted([s for s in df_results.get("source_type", pd.Series(dtype=str)).dropna().unique()]),
                    default=sorted([s for s in df_results.get("source_type", pd.Series(dtype=str)).dropna().unique()]),
                )
            with filter_cols[1]:
                selected_actions = st.multiselect(
                    "Action",
                    sorted([a for a in df_results["action"].dropna().unique()]),
                    default=sorted([a for a in df_results["action"].dropna().unique()]),
                )
            with filter_cols[2]:
                min_conf = st.slider("Min Confidence", 0.0, 1.0, 0.0, 0.05)
            with filter_cols[3]:
                review_only = st.checkbox("Review only", value=False)

            filtered = df_results.copy()
            if selected_sources and "source_type" in filtered.columns:
                filtered = filtered[filtered["source_type"].isin(selected_sources)]
            if selected_actions:
                filtered = filtered[filtered["action"].isin(selected_actions)]
            filtered = filtered[filtered["confidence"] >= min_conf]
            if review_only:
                filtered = filtered[_review_mask(filtered)]

            display_cols = [
                "rule_id", "title", "source_type", "action", "confidence",
                "existing_attack_tags", "predicted_top1", "suggested_add_tags",
                "suspect_remove_tags", "needs_review", "reason",
            ]
            display_cols = [col for col in display_cols if col in filtered.columns]
            st.caption(f"Showing {len(filtered)} of {len(df_results)} rules. Low confidence below sidebar threshold: {low_conf_count}.")
            st.dataframe(filtered[display_cols], use_container_width=True, hide_index=True)

        with tab_review:
            st.markdown("##### Analyst Review Queue")
            review_df = df_results[_review_mask(df_results)].copy()
            if review_df.empty:
                st.success("No rules currently require analyst review.")
            else:
                review_df["review_label"] = review_df.apply(
                    lambda row: f"{row.get('rule_id', 'unknown')} | {row.get('action', '')} | {row.get('title', '')}",
                    axis=1,
                )
                selected_label = st.selectbox("Rule", review_df["review_label"].tolist())
                selected_row = review_df[review_df["review_label"] == selected_label].iloc[0].to_dict()

                detail_left, detail_right = st.columns([1, 1])
                with detail_left:
                    st.markdown("###### Rule")
                    st.write("Rule ID:", selected_row.get("rule_id", ""))
                    st.write("Title:", selected_row.get("title", ""))
                    st.write("Source:", selected_row.get("source_type", ""))
                    st.write("Action:", selected_row.get("action", ""))
                    st.write("Confidence:", f"{float(selected_row.get('confidence', 0.0)):.2%}")
                    st.write("Reason:", selected_row.get("reason", ""))
                with detail_right:
                    st.markdown("###### Tags")
                    st.write("Existing:", _format_list_cell(selected_row.get("existing_attack_tags", [])))
                    st.write("Predicted Top-3:", _format_list_cell(selected_row.get("predicted_top3", [])))
                    st.write("Suggested Add:", _format_list_cell(selected_row.get("suggested_add_tags", [])))
                    st.write("Suspect Remove:", _format_list_cell(selected_row.get("suspect_remove_tags", [])))

                st.markdown("###### Evidence")
                st.json({
                    "score_breakdown": selected_row.get("score_breakdown", {}),
                    "matched_data_sources": selected_row.get("matched_data_sources", []),
                    "contradictions": selected_row.get("contradictions", []),
                    "verification": selected_row.get("verification_reason", ""),
                })

                comment = st.text_area("Analyst comment", height=90)
                btn_cols = st.columns(3)
                with btn_cols[0]:
                    if st.button("Accept Recommendation", use_container_width=True):
                        save_row_review_feedback(selected_row, "accept", comment)
                        st.success("Review feedback saved.")
                with btn_cols[1]:
                    if st.button("Reject Recommendation", use_container_width=True):
                        save_row_review_feedback(selected_row, "reject", comment)
                        st.success("Review feedback saved.")
                with btn_cols[2]:
                    if st.button("Needs More Context", use_container_width=True):
                        save_row_review_feedback(selected_row, "needs_more_context", comment)
                        st.success("Review feedback saved.")

        with tab_coverage:
            cov_left, cov_right = st.columns([1, 1])
            with cov_left:
                st.markdown("##### Tactic Density Profile")
                if not df_tactic.empty:
                    fig_bar = px.area(df_tactic, x="Key", y="Count", color_discrete_sequence=['#3b82f6'])
                    fig_bar.update_layout(
                        paper_bgcolor='rgba(0,0,0,0)',
                        plot_bgcolor='rgba(0,0,0,0)',
                        font=dict(color='#94a3b8'),
                        xaxis=dict(showgrid=False, title=""),
                        yaxis=dict(gridcolor='#1e293b', title="Density"),
                        margin=dict(t=10, b=0, l=0, r=0)
                    )
                    fig_bar.update_traces(mode='lines+markers', fill='tozeroy', marker=dict(size=8, color='#10b981'))
                    st.plotly_chart(fig_bar, use_container_width=True)
                else:
                    st.info("No tactic coverage CSV found.")

            with cov_right:
                st.markdown("##### Top Technique Signatures")
                if not df_tech.empty:
                    df_tech_sorted = df_tech.sort_values(by="Count", ascending=False).head(15)
                    fig_tech = px.bar(df_tech_sorted, x="Count", y="Key", orientation='h', color="Count",
                                      color_continuous_scale=px.colors.sequential.Tealgrn)
                    fig_tech.update_layout(
                        paper_bgcolor='rgba(0,0,0,0)',
                        plot_bgcolor='rgba(0,0,0,0)',
                        font=dict(color='#94a3b8'),
                        xaxis=dict(gridcolor='#1e293b', title="Signal Count"),
                        yaxis=dict(showgrid=False, title="", autorange="reversed"),
                        margin=dict(t=0, b=0, l=0, r=0),
                        coloraxis_showscale=False
                    )
                    st.plotly_chart(fig_tech, use_container_width=True)
                else:
                    st.info("No technique coverage CSV found.")

            st.markdown("##### Coverage Tables")
            table_left, table_right = st.columns(2)
            with table_left:
                st.dataframe(df_tactic, use_container_width=True, hide_index=True)
            with table_right:
                st.dataframe(df_tech.sort_values(by="Count", ascending=False) if not df_tech.empty else df_tech, use_container_width=True, hide_index=True)

        with tab_export:
            st.markdown("##### Export Governance Report")
            markdown = render_markdown_report(
                _records_from_df(df_results),
                df_tactic.to_dict(orient="records"),
                df_tech.sort_values(by="Count", ascending=False).to_dict(orient="records") if not df_tech.empty else [],
            )
            report_path = os.path.join(config.OUTPUTS_DIR, "governance_report.md")
            if st.button("Generate Markdown Report", use_container_width=True):
                save_markdown_report(markdown, report_path)
                st.success(f"Report saved to {report_path}")
            st.download_button(
                "Download Markdown Report",
                data=markdown,
                file_name="governance_report.md",
                mime="text/markdown",
                use_container_width=True,
            )
            st.text_area("Report Preview", markdown, height=420)

    else:
        st.info(
            "No enterprise telemetry data found. Run `python src/main.py` for real rule batches, "
            "or run `python src/evaluation/run_gold_eval.py --write-telemetry` to generate the built-in gold-set demo data."
        )
