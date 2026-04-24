"""Presidency App - Main Entry Point."""

import logging
from pathlib import Path

import streamlit as st

from src.config import load_config
from src.logging_config import setup_logging
from src.ui.dashboard import render_main


def main() -> None:
    """Run the Streamlit application."""
    # Setup logging
    logger = setup_logging()
    logger.info("Starting Presidency SOC App")

    # Load configuration
    config = load_config()
    logger.info("Configuration loaded successfully")

    # Page configuration
    st.set_page_config(
        page_title="Offline SIEM",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded",
    )

    # Render the main UI
    render_main()

    logger.info("App rendered successfully")


if __name__ == "__main__":
    main()