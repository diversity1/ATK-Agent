import streamlit as st
import os
import sys
import pandas as pd
import json
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

st.set_page_config(page_title="ATT&CK Tag Repair Agent", layout="wide", page_icon="🛡️")

# Custom CSS for better styling
st.markdown("""
<style>
    .reportview-container {
        margin-top: -2em;
    }
    .st-emotion-cache-1y4p8pa {
        padding-top: 2rem;
    }
    .tag-original {
        background-color: #e0e0e0; color: #333; padding: 4px 8px; border-radius: 4px; margin: 2px; display: inline-block;
    }
    .tag-new {
        background-color: #d4edda; color: #155724; padding: 4px 8px; border-radius: 4px; margin: 2px; display: inline-block; border: 1px solid #c3e6cb;
    }
</style>
""", unsafe_allow_html=True)

st.title("🛡️ ATT&CK Tag Validation & Repair Agent")
st.markdown("Automate the validation, enrichment, and repair of MITRE ATT&CK tags on detection rules using LLM reasoning.")

manager = init_system()
if not manager:
    st.error("ATT&CK Index not found. Please run `python src/download_data.py` first.")
    st.stop()

tab1, tab2 = st.tabs(["🔍 Single Rule Analyzer (Interactive)", "📊 Batch Coverage Dashboard (Report)"])

with tab1:
    st.markdown("### Test the Agent on a Single Rule")
    
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
    
    with st.container():
        col_input, col_output = st.columns([1, 1.2])
        
        with col_input:
            rule_text = st.text_area("Paste Sigma YAML Rule Here", value=default_rule, height=400)
            analyze_btn = st.button("🚀 Analyze & Repair Rule", type="primary", use_container_width=True)
            
        with col_output:
            if analyze_btn:
                import yaml
                try:
                    raw_rule = yaml.safe_load(rule_text)
                    with st.spinner("🧠 Agent is thinking..."):
                        state = manager.run_one_rule(raw_rule, source_type="sigma")
                    
                    if state.errors:
                        st.error(f"Errors occurred: {state.errors}")
                    else:
                        st.markdown("### ✨ Repair Results")
                        action = state.repair_result.action
                        
                        # Define color mapping for actions
                        action_color = {
                            "KEEP": "blue",
                            "SUPPLEMENT": "green",
                            "POSSIBLE_MISMATCH": "orange",
                            "ABSTAIN": "grey"
                        }.get(action, "black")
                        
                        st.markdown(f"**Agent Decision:** <span style='color:{action_color}; font-weight:bold; font-size: 1.2em;'>{action}</span>", unsafe_allow_html=True)
                        st.caption(state.repair_result.repair_reason)
                        
                        st.markdown("#### Tag Comparison")
                        col_orig, col_rep = st.columns(2)
                        
                        orig_tags = state.parsed_rule.existing_attack_tags
                        final_tags = state.repair_result.final_tags
                        
                        with col_orig:
                            st.info("**Original Tags (Before)**")
                            if orig_tags:
                                html_tags = " ".join([f"<span class='tag-original'>{t}</span>" for t in orig_tags])
                                st.markdown(html_tags, unsafe_allow_html=True)
                            else:
                                st.write("*None*")
                                
                        with col_rep:
                            st.success("**Repaired Tags (After)**")
                            html_tags = ""
                            for t in final_tags:
                                if t not in orig_tags:
                                    html_tags += f"<span class='tag-new'>➕ {t}</span> "
                                else:
                                    html_tags += f"<span class='tag-original'>{t}</span> "
                            st.markdown(html_tags, unsafe_allow_html=True)
                        
                        st.divider()
                        
                        with st.expander("⚙️ View Agent Inner Workings (Trace)"):
                            st.markdown("**1. Retriever Candidates (Top 5)**")
                            cands = [{"ID": c.technique_id, "Score": f"{c.retrieval_score:.2f}", "Name": c.technique_name} 
                                     for c in state.alignment_result.retrieved_candidates[:5]]
                            st.dataframe(cands, width='stretch')
                            
                            st.markdown("**2. LLM Reranking & Reasoning (Chain of Thought)**")
                            if getattr(state.alignment_result, "thought_process", None):
                                tp = state.alignment_result.thought_process
                                st.info(f"**Step 1 (Extract):** {tp.get('step1_extracted_behavior', '')}")
                                st.info(f"**Step 2 (Tactic):** {tp.get('step2_tactic_goal', '')}")
                                st.success(f"**Step 3 (Technique):** {tp.get('step3_technique_matching', '')}")
                            
                            st.write(f"**Confidence:** `{state.alignment_result.confidence:.2f}`")
                            st.markdown(f"**Final Reason:** {state.alignment_result.reason}")

                except Exception as e:
                    st.error(f"Error processing rule: {str(e)}")
            else:
                st.info("👈 Click the button to analyze the rule and see the repair effects here.")

with tab2:
    st.markdown("### Batch Repair Effects Dashboard")
    st.markdown("Visualizing the impact of the Agent across the entire rule dataset.")
    
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
        col_k1.metric("Total Rules Processed", total_rules)
        col_k2.metric("Rules Enhanced / Repaired", repaired_count, f"{(repaired_count/total_rules)*100:.1f}%")
        col_k3.metric("Rules Kept As-Is", actions.get("KEEP", 0))
        col_k4.metric("Avg LLM Confidence", f"{df_results['confidence'].mean():.2f}")
        
        st.divider()
        
        # Action Distribution Pie Chart
        col_pie, col_bar = st.columns([1, 1.5])
        
        with col_pie:
            st.subheader("Agent Actions Breakdown")
            fig_pie = px.pie(values=actions.values, names=actions.index, hole=0.4,
                             color_discrete_sequence=px.colors.qualitative.Pastel)
            fig_pie.update_layout(margin=dict(t=0, b=0, l=0, r=0))
            st.plotly_chart(fig_pie, width='stretch')
            
        with col_bar:
            st.subheader("Tactic Coverage Profile")
            fig_bar = px.bar(df_tactic, x="Key", y="Count", text="Count",
                             color="Count", color_continuous_scale=px.colors.sequential.Blues)
            fig_bar.update_layout(xaxis_title="ATT&CK Tactic", yaxis_title="Number of Tags", 
                                  xaxis={'categoryorder':'total descending'},
                                  margin=dict(t=0, b=0, l=0, r=0))
            st.plotly_chart(fig_bar, width='stretch')
            
        st.subheader("Top 15 Most Detected Techniques")
        df_tech_sorted = df_tech.sort_values(by="Count", ascending=False).head(15)
        fig_tech = px.bar(df_tech_sorted, x="Key", y="Count", text="Count",
                          color="Count", color_continuous_scale=px.colors.sequential.Teal)
        fig_tech.update_layout(xaxis_title="ATT&CK Technique", yaxis_title="Number of Tags",
                               margin=dict(t=0, b=0, l=0, r=0))
        st.plotly_chart(fig_tech, width='stretch')
        
    else:
        st.warning("No batch output found. Please run `python src/main.py` first to generate reports.")
