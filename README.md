# AI-code-reviewer

📘 AI Code Reviewer – Python + Streamlit
An intelligent Python code-review tool that automatically analyzes code for:
🔥 Syntax errors
🧠 Undefined variables
🎨 Style issues (PEP8)
📝 Missing docstrings
⚠️ Complexity problems
💬 Comment quality issues
⭐ Python best-practice violations
Built with Python AST, pycodestyle, and a clean Streamlit web interface.

🚀 Features
✔ Automated Code Analysis
The tool scans Python source code for:
Missing or short docstrings
Undefined variables (ignores built-ins like print, range)
Structural issues (empty loops/blocks)
PEP8 violations via pycodestyle
Comment formatting problems
Overly complex functions
Long string literals (best practice warnings)

✔ Streamlit Web App Interface

Users can:
Paste Python code
OR upload a .py file
Click Analyze Code
Instantly receive a structured report grouped by severity:
HIGH
MEDIUM
LOW

📂 Project Structure
ai-code-reviewer/
│-- app.py
│-- reviewer.py
│-- requirements.txt
│-- README.md

app.py → Streamlit UI
reviewer.py → Full analysis engine
requirements.txt → Required dependencies

🛠️ Installation
1. Clone the repository
git clone https://github.com/your-username/ai-code-reviewer.git
cd ai-code-reviewer

2. Install dependencies
pip install -r requirements.txt

Contents of requirements.txt:
streamlit
pycodestyle

(Optional pinned versions)
streamlit==1.40.0
pycodestyle==2.12.0

▶️ Usage
Run the Streamlit app:
streamlit run app.py

Your browser will open automatically at:
http://localhost:8501

💻 How It Works
Step 1 — Input Code
Paste code or upload a file.

Step 2 — Analyzer Engine
reviewer.py:
Parses code using Python’s built-in AST
Runs multiple custom checks
Runs PEP8 style validation
Groups issues by severity

Step 3 — Display
app.py shows:
Detailed, human-readable report
Clean formatting in Streamlit
Severity grouping for easy debugging

🧪 Example Input
print("hello")
range(5)
msg

Example Output
HIGH Priority Issues:
Line 3: Variable 'msg' is used but not defined
MEDIUM Priority Issues:
Missing docstring in Module

📌 Why This Project?
This project is perfect for:
Students learning Python
Developers who want quick static analysis
Building lightweight CI tools
Improving code quality before commits
Showcasing Python + Streamlit skills in a portfolio

🌐 Deployment (Optional)
You can deploy this on:
▶ Streamlit Cloud (free)
Push your repo to GitHub
Go to https://share.streamlit.io
Select your repo
Deploy
▶ Render / HuggingFace Spaces
Also supported, works out-of-the-box.

🤝 Contributing
Pull requests are welcome!
