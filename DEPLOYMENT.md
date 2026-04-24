# Deploy ATK-Agent as a Public Web App

This project is a Streamlit app, so GitHub stores the code but does not run the
Python server. The simplest public URL is Streamlit Community Cloud:

```text
GitHub repository -> Streamlit Community Cloud -> https://your-app.streamlit.app
```

## 1. Before Pushing

Keep secrets out of GitHub. The repository already ignores:

```text
.env
.env.*
.streamlit/secrets.toml
data/outputs/
```

The app can run without an LLM key. In that mode it uses heuristic fallbacks for
semantic extraction, query planning, verification, and review summaries.

## 2. Push to GitHub

Create a GitHub repository, then run these commands from the project root:

```bash
git init
git add .
git commit -m "Deploy ATK-Agent Streamlit app"
git branch -M main
git remote add origin https://github.com/<your-username>/<your-repo>.git
git push -u origin main
```

If this repository already has a remote, use:

```bash
git remote -v
git push
```

## 3. Deploy on Streamlit Community Cloud

1. Go to `https://share.streamlit.io`.
2. Sign in with GitHub and connect your account.
3. Click `Create app`.
4. Select your repository and branch.
5. Set the entrypoint file to:

```text
streamlit_app.py
```

6. In `Advanced settings`, choose a supported Python version such as `3.11` or
   `3.12`.
7. Optional: paste secrets if you want online LLM mode.

Example secrets:

```toml
ENABLE_LLM = "True"
ENABLE_DENSE_RETRIEVAL = "False"
LLM_PROVIDER = "openai"
LLM_MODEL = "qwen-plus"
LLM_API_KEY = "your-api-key"
LLM_API_BASE = "https://your-compatible-endpoint/v1"
```

For a fully offline public demo, use:

```toml
ENABLE_LLM = "False"
ENABLE_DENSE_RETRIEVAL = "False"
```

8. Click `Deploy`.

After deployment, Streamlit gives you a URL like:

```text
https://your-custom-subdomain.streamlit.app
```

Anyone can open that link if the app is public.

## 4. Optional GitHub README Badge

After deployment, add this to `README.md` and replace the URL:

```markdown
[![Open in Streamlit](https://static.streamlit.io/badges/streamlit_badge_black_white.svg)](https://your-custom-subdomain.streamlit.app)
```

## 5. Notes

- `requirements.txt` is optimized for cloud deployment and excludes heavy dense
  retrieval packages by default.
- To enable dense retrieval locally, install:

```bash
pip install -r requirements-optional.txt
```

- The local ATT&CK index at `data/attack/attack_techniques.json` is included so
  the app can start without downloading MITRE data.
