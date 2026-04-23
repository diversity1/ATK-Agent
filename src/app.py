import streamlit as st
import os
import sys
import pandas as pd
import json
import datetime
import plotly.express as px

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
import config
from core.registry import registry
from llm.client import LLMClient
from agents.manager_agent import ManagerAgent
from dataio.load_attack import load_attack_index
from core.utils import ensure_dir

# Initialize core system once
@st.cache_resource
def init_system():
    if not os.path.exists(config.ATTACK_INDEX_PATH):
        return None
        
    attack_index = load_attack_index(config.ATTACK_INDEX_PATH)
    registry.register("attack_index", attack_index)
    
    llm_client = LLMClient()
    registry.register("llm_client", llm_client)
    
    manager = ManagerAgent()
    registry.register("manager_agent", manager)
    return manager

st.set_page_config(page_title="ATK-Agent Pro", layout="wide", page_icon="🎯")

# Premium Custom CSS
st.markdown("""
<style>
    /* Main Layout */
    .block-container {
        padding-top: 2rem;
        padding-bottom: 2rem;
        max-width: 95%;
    }
    
    /* Headers */
    h1 {
        color: #1E3A8A;
        font-family: 'Inter', sans-serif;
        font-weight: 800;
        margin-bottom: 0.5rem;
    }
    h3 {
        color: #374151;
        font-family: 'Inter', sans-serif;
        font-weight: 600;
    }
    
    /* Cards and Containers */
    .css-1r6slb0 {
        background-color: #f8fafc;
        border-radius: 12px;
        border: 1px solid #e2e8f0;
        padding: 20px;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
    }
    
    /* Tags */
    .tag-original {
        background: linear-gradient(135deg, #f1f5f9 0%, #e2e8f0 100%);
        color: #475569;
        padding: 6px 12px;
        border-radius: 20px;
        margin: 4px;
        display: inline-block;
        font-size: 0.9em;
        font-weight: 600;
        border: 1px solid #cbd5e1;
        box-shadow: 0 1px 2px rgba(0,0,0,0.05);
        transition: all 0.2s ease;
    }
    .tag-new {
        background: linear-gradient(135deg, #dcfce7 0%, #bbf7d0 100%);
        color: #166534;
        padding: 6px 12px;
        border-radius: 20px;
        margin: 4px;
        display: inline-block;
        font-size: 0.9em;
        font-weight: 700;
        border: 1px solid #86efac;
        box-shadow: 0 1px 2px rgba(0,0,0,0.05);
        transition: all 0.2s ease;
    }
    .tag-new:hover, .tag-original:hover {
        transform: translateY(-2px);
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
    }
    
    /* Text Area */
    .stTextArea textarea {
        background-color: #1e1e1e;
        color: #d4d4d4;
        font-family: 'Consolas', monospace;
        border-radius: 8px;
        border: 1px solid #333;
    }
    
    /* Metric Cards */
    [data-testid="stMetricValue"] {
        font-size: 2.5rem;
        font-weight: 800;
        color: #2563eb;
    }
    
    /* Buttons */
    .stButton>button {
        border-radius: 8px;
        font-weight: 600;
        letter-spacing: 0.5px;
        transition: all 0.3s ease;
    }
</style>
""", unsafe_allow_html=True)

st.title("🎯 ATK-Agent Pro Workspace")
st.markdown("##### *Advanced AI-Driven ATT&CK Tag Validation & Repair System*")
st.markdown("---")

manager = init_system()
if not manager:
    st.error("🚨 ATT&CK Index not found. Please run `python src/download_data.py` or index reconstruction first.")
    st.stop()

# Helper function to save feedback
def save_feedback(state, accepted: bool):
    ensure_dir(config.OUTPUTS_DIR)
    fb_path = os.path.join(config.OUTPUTS_DIR, "feedback.jsonl")
    
    tp = None
    if state.alignment_result and state.alignment_result.thought_process:
        tp = state.alignment_result.thought_process
        
    record = {
        "timestamp": datetime.datetime.now().isoformat(),
        "rule_id": state.parsed_rule.rule_id if state.parsed_rule else "unknown",
        "title": state.parsed_rule.title if state.parsed_rule else "",
        "predicted_top1": state.alignment_result.top1 if state.alignment_result else None,
        "accepted": accepted,
        "cot_thought_process": tp
    }
    with open(fb_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")

tab1, tab2 = st.tabs(["⚡ Live Interactive Sandbox", "📈 Batch Analytics Dashboard"])

with tab1:
    default_rule = """title: Sample Suspicious PowerShell
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
    
    col_input, col_output = st.columns([1, 1.2], gap="large")
    
    with col_input:
        st.markdown("### 📝 Input Detection Rule")
        rule_text = st.text_area("Paste Sigma YAML Rule Here", value=default_rule, height=500, label_visibility="collapsed")
        analyze_btn = st.button("🚀 Analyze & Repair with ATK-Agent", type="primary", use_container_width=True)
        
    with col_output:
        st.markdown("### ✨ Agent Intelligence")
        
        if 'current_state' not in st.session_state:
            st.session_state.current_state = None
            
        if analyze_btn:
            import yaml
            try:
                raw_rule = yaml.safe_load(rule_text)
                with st.spinner("🧠 Initializing Hybrid RAG & CoT Reasoning..."):
                    st.session_state.current_state = manager.run_one_rule(raw_rule, source_type="sigma")
            except Exception as e:
                st.error(f"Error processing rule: {str(e)}")
                st.session_state.current_state = None

        state = st.session_state.current_state
        
        if state:
            if state.errors:
                st.error(f"🚨 Errors occurred: {state.errors}")
            else:
                action = state.repair_result.action
                
                # Action Banner
                action_color = {
                    "KEEP": "#3b82f6",          # Blue
                    "SUPPLEMENT": "#10b981",    # Green
                    "POSSIBLE_MISMATCH": "#f59e0b", # Orange
                    "ABSTAIN": "#6b7280"        # Gray
                }.get(action, "#000000")
                
                st.markdown(f"""
                <div style='background-color: {action_color}15; border-left: 6px solid {action_color}; padding: 15px; border-radius: 4px; margin-bottom: 20px;'>
                    <h3 style='margin:0; color:{action_color};'>Decision: {action}</h3>
                    <p style='margin:5px 0 0 0; font-size:1.1em;'>{state.repair_result.repair_reason}</p>
                </div>
                """, unsafe_allow_html=True)
                
                # Tag Comparison
                st.markdown("#### 🏷️ Tag Evolution")
                col_orig, col_rep = st.columns(2)
                
                orig_tags = state.parsed_rule.existing_attack_tags
                final_tags = state.repair_result.final_tags
                
                with col_orig:
                    st.caption("ORIGINAL TAGS")
                    if orig_tags:
                        html_tags = " ".join([f"<span class='tag-original'>{t}</span>" for t in orig_tags])
                        st.markdown(html_tags, unsafe_allow_html=True)
                    else:
                        st.write("*None*")
                        
                with col_rep:
                    st.caption("REPAIRED TAGS")
                    html_tags = ""
                    for t in final_tags:
                        if t not in orig_tags:
                            html_tags += f"<span class='tag-new'>🎯 {t}</span> "
                        else:
                            html_tags += f"<span class='tag-original'>{t}</span> "
                    st.markdown(html_tags, unsafe_allow_html=True)
                
                st.markdown("---")
                
                # Human-in-the-Loop Feedback (Direction 3)
                st.markdown("##### 👩‍💻 Expert Validation (Human-in-the-Loop)")
                st.caption("Help improve the agent by confirming or rejecting this repair. Feedback is logged for future fine-tuning.")
                
                col_y, col_n = st.columns(2)
                with col_y:
                    if st.button("✅ Approve Repair", use_container_width=True):
                        save_feedback(state, accepted=True)
                        st.toast('Feedback saved to feedback.jsonl!', icon='✅')
                with col_n:
                    if st.button("❌ Reject Repair", use_container_width=True):
                        save_feedback(state, accepted=False)
                        st.toast('Feedback saved to feedback.jsonl!', icon='❌')
                
                st.markdown("---")
                
                # Transparency Trace
                with st.expander("🔍 Inside the Agent's Mind (CoT Trace)", expanded=False):
                    st.markdown("**1. RAG Retrieved Candidates (Top 5)**")
                    cands = [{"Technique ID": c.technique_id, "Score": f"{c.retrieval_score:.3f}", "Name": c.technique_name} 
                             for c in state.alignment_result.retrieved_candidates[:5]]
                    st.dataframe(cands, use_container_width=True, hide_index=True)
                    
                    st.markdown("**2. Chain-of-Thought Reasoning**")
                    if getattr(state.alignment_result, "thought_process", None):
                        tp = state.alignment_result.thought_process
                        st.success(f"**Step 1 (Extract):** {tp.get('step1_extracted_behavior', '')}")
                        st.info(f"**Step 2 (Tactic):** {tp.get('step2_tactic_goal', '')}")
                        st.warning(f"**Step 3 (Technique):** {tp.get('step3_technique_matching', '')}")
                    
                    st.markdown(f"**Final Confidence:** `{state.alignment_result.confidence:.2f}`")

        else:
            st.info("👈 Paste a rule and click Analyze to view the magic here.")

with tab2:
    st.markdown("### 📊 Enterprise Repair Analytics")
    st.markdown("Visualizing the impact of the ATK-Agent across the entire Sigma ruleset.")
    
    rule_results_path = os.path.join(config.OUTPUTS_DIR, "rule_results.csv")
    tactic_path = os.path.join(config.OUTPUTS_DIR, "coverage_by_tactic.csv")
    tech_path = os.path.join(config.OUTPUTS_DIR, "coverage_summary.csv")
    
    if os.path.exists(rule_results_path) and os.path.exists(tactic_path) and os.path.exists(tech_path):
        df_results = pd.read_csv(rule_results_path)
        df_tactic = pd.read_csv(tactic_path)
        df_tech = pd.read_csv(tech_path)
        
        # KPIs
        total_rules = len(df_results)
        actions = df_results["action"].value_counts()
        supplemented = actions.get("SUPPLEMENT", 0)
        mismatch = actions.get("POSSIBLE_MISMATCH", 0)
        repaired_count = supplemented + mismatch
        
        col_k1, col_k2, col_k3, col_k4 = st.columns(4)
        col_k1.metric("Total Rules Processed", f"{total_rules:,}")
        col_k2.metric("Enhanced / Repaired", f"{repaired_count:,}", f"{(repaired_count/total_rules)*100:.1f}%")
        col_k3.metric("Kept As-Is", f"{actions.get('KEEP', 0):,}")
        col_k4.metric("Avg LLM Confidence", f"{df_results['confidence'].mean():.2f}")
        
        st.markdown("---")
        
        # Action Distribution Pie Chart
        col_pie, col_bar = st.columns([1, 1.5])
        
        with col_pie:
            st.subheader("Agent Actions Breakdown")
            fig_pie = px.pie(values=actions.values, names=actions.index, hole=0.45,
                             color_discrete_map={
                                 "KEEP": "#3b82f6", 
                                 "SUPPLEMENT": "#10b981", 
                                 "POSSIBLE_MISMATCH": "#f59e0b",
                                 "ABSTAIN": "#9ca3af"
                             })
            fig_pie.update_layout(margin=dict(t=30, b=0, l=0, r=0), showlegend=True)
            st.plotly_chart(fig_pie, use_container_width=True)
            
        with col_bar:
            st.subheader("Tactic Coverage Profile")
            fig_bar = px.bar(df_tactic, x="Key", y="Count", text="Count",
                             color="Count", color_continuous_scale=px.colors.sequential.Blues)
            fig_bar.update_layout(xaxis_title="", yaxis_title="Number of Tags", 
                                  xaxis={'categoryorder':'total descending'},
                                  margin=dict(t=30, b=0, l=0, r=0))
            st.plotly_chart(fig_bar, use_container_width=True)
            
        st.subheader("Top 15 Most Detected Techniques")
        df_tech_sorted = df_tech.sort_values(by="Count", ascending=False).head(15)
        fig_tech = px.bar(df_tech_sorted, x="Key", y="Count", text="Count",
                          color="Count", color_continuous_scale=px.colors.sequential.Teal)
        fig_tech.update_layout(xaxis_title="", yaxis_title="Number of Tags",
                               margin=dict(t=30, b=0, l=0, r=0))
        st.plotly_chart(fig_tech, use_container_width=True)
        
    else:
        st.warning("No batch output found. Please run `python src/main.py` first to generate reports.")
