# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Environment Setup

This project uses **UV** as the package manager and **Python 3.12**.

To set up the development environment:

```bash
# Install UV if not already installed
# (see https://docs.astral.sh/uv/getting-started/installation/)

# Install dependencies and create virtual environment
uv sync

# Activate the virtual environment
source .venv/bin/activate
```

## Running the Project

```bash
# Run the main script
python main.py

# Or using UV
uv run python main.py
```

## GitHub Integration

The project includes a GitHub Actions workflow (`.github/workflows/claude.yaml`) that:
- Triggers on issues, PRs, and review comments
- Uses the `anthropics/claude-code-action` for automated code review
- Routes API requests through `https://open.bigmodel.cn/api/anthropic` (not the default Anthropic endpoint)

## Architecture

This is a minimal starter project with a single entry point (`main.py`). Expand as needed.
