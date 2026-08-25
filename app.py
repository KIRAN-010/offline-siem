"""Offline SIEM — Streamlit application entry point."""

import streamlit as st

from src.config import load_config
from src.logging_config import setup_logging
from src.ui.dashboard import render_main


def main() -> None:
    """Run the Offline SIEM application."""
    logger = setup_logging()
    load_config()

    st.set_page_config(
        page_title="Offline SIEM",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded",
    )

    st.markdown(
        """
        <style>
        [data-testid="stToolbar"] button:first-child {visibility: hidden; display: none;}
        [data-testid="stDecoration"] {visibility: hidden; display: none;}
        footer {visibility: hidden; display: none;}
        </style>
        """,
        unsafe_allow_html=True,
    )

    logger.info("Starting Offline SIEM")
    render_main()


if __name__ == "__main__":
    main()
