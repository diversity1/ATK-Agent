# ATT&CK Tag Validation & Repair Agent

A lightweight multi-agent workflow for ATT&CK tag validation and repair on detection rules.

## Setup

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Configure environment (optional, for LLM):
   ```bash
   export LLM_PROVIDER=openai
   export LLM_API_KEY=your-key
   ```

3. Run pipeline:
   ```bash
   python src/main.py
   ```
