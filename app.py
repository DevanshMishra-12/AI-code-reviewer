import streamlit as st
from reviewer import AICodeReviewer  # change name if your file is 'reviwer.py'

st.set_page_config(page_title="AI Code Reviewer", page_icon="🧠")

st.title("🧠 AI Code Reviewer")
st.write("Paste your Python code below and get an instant review.")

code = st.text_area("Your Python code:", height=300, placeholder="Paste code here...")

if st.button("Analyze Code"):
    if not code.strip():
        st.warning("Please paste some code first.")
    else:
        reviewer = AICodeReviewer()
        reviewer.load_code(code)
        reviewer.analyze()
        report = reviewer.get_report()

        st.subheader("Review Report")
        st.text(report)
