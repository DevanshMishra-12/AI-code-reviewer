#!/usr/bin/env python3
"""
AI Code Reviewer - A Python script for automated code analysis and improvement suggestions.

This script analyzes Python code for common issues, style violations, and potential
improvements, providing detailed feedback to help developers write better code.

Usage:
    python reviewer.py path/to/file.py
    # or just run without args to see the built-in example analysis.
"""

import ast
import sys
import pycodestyle
from typing import List, Set, Dict, Optional
from dataclasses import dataclass
from pathlib import Path


@dataclass
class CodeIssue:
    """Data class to store information about code issues."""
    line_number: int
    issue_type: str
    message: str
    severity: str  # 'HIGH', 'MEDIUM', 'LOW'


class AICodeReviewer:
    """
    A comprehensive code review tool that analyzes Python code for various issues
    and provides improvement suggestions.
    """

    def __init__(self):
        """Initialize the AICodeReviewer with empty issue lists and configuration."""
        self.issues: List[CodeIssue] = []
        self.source_code: str = ""
        self.ast_tree: Optional[ast.AST] = None

        # Configure severity levels for different types of issues
        self.severity_levels: Dict[str, str] = {
            'syntax_error': 'HIGH',
            'undefined_variable': 'HIGH',
            'style_violation': 'MEDIUM',
            'missing_docstring': 'MEDIUM',
            'docstring_quality': 'LOW',
            'comment_issue': 'LOW',
            'complexity_issue': 'MEDIUM',
            'best_practice': 'LOW',
            'file_error': 'HIGH',
        }

    def load_file(self, file_path: str) -> bool:
        """
        Load Python code from a file.

        Args:
            file_path (str): Path to the Python file to analyze

        Returns:
            bool: True if file was successfully loaded, False otherwise
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                self.source_code = file.read()
            return True
        except Exception as e:
            self.issues.append(
                CodeIssue(
                    0,
                    'file_error',
                    f"Error loading file '{file_path}': {str(e)}",
                    self.severity_levels['file_error'],
                )
            )
            return False

    def load_code(self, code: str) -> None:
        """
        Load Python code from a string.

        Args:
            code (str): Python code to analyze
        """
        self.source_code = code

    def analyze(self) -> None:
        """
        Perform comprehensive code analysis by running all available checks.
        """
        self.issues = []  # Reset issues list before new analysis

        # Parse AST
        try:
            self.ast_tree = ast.parse(self.source_code)
        except SyntaxError as e:
            self.issues.append(
                CodeIssue(
                    e.lineno or 0,
                    'syntax_error',
                    f"Syntax Error: {str(e)}",
                    self.severity_levels['syntax_error'],
                )
            )
            return

        # Run all analysis checks
        self._check_syntax()
        self._check_style()
        self._check_docstrings()
        self._check_complexity()
        self._check_variables()
        self._check_comments()
        self._check_best_practices()

    def _check_syntax(self) -> None:
        """Check for basic structural issues (like empty blocks)."""
        if self.ast_tree is None:
            return

        for node in ast.walk(self.ast_tree):
            # Check for empty code blocks
            if isinstance(node, (ast.For, ast.While, ast.If, ast.With, ast.AsyncWith, ast.AsyncFor)):
                if not node.body:
                    self.issues.append(
                        CodeIssue(
                            getattr(node, 'lineno', 0),
                            'syntax_error',
                            f"Empty {node.__class__.__name__} block found",
                            self.severity_levels['syntax_error'],
                        )
                    )

    def _check_style(self) -> None:
        """Check code style using pycodestyle."""
        style_guide = pycodestyle.StyleGuide(quiet=True)

        temp_file = Path('temp_code_review.py')
        try:
            temp_file.write_text(self.source_code, encoding='utf-8')
            report = style_guide.check_files([temp_file])

            # pycodestyle stores errors in _deferred_print (semi-private API).
            deferred = getattr(report, "_deferred_print", [])
            for line_number, offset, code, text, doc in deferred:
                self.issues.append(
                    CodeIssue(
                        line_number,
                        'style_violation',
                        f"{code}: {text}",
                        self.severity_levels['style_violation'],
                    )
                )
        finally:
            if temp_file.exists():
                temp_file.unlink()

    def _check_docstrings(self) -> None:
        """Check for missing or inadequate docstrings."""
        if self.ast_tree is None:
            return

        for node in ast.walk(self.ast_tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Module)):
                lineno = getattr(node, "lineno", 0)
                docstring = ast.get_docstring(node)

                if not docstring:
                    self.issues.append(
                        CodeIssue(
                            lineno,
                            'missing_docstring',
                            f"Missing docstring in {node.__class__.__name__}",
                            self.severity_levels['missing_docstring'],
                        )
                    )
                else:
                    if len(docstring.strip()) < 10:
                        self.issues.append(
                            CodeIssue(
                                lineno,
                                'docstring_quality',
                                f"Short or uninformative docstring in {node.__class__.__name__}",
                                self.severity_levels['docstring_quality'],
                            )
                        )

    def _check_complexity(self) -> None:
        """Check for code complexity issues based on statement count."""
        if self.ast_tree is None:
            return

        for node in ast.walk(self.ast_tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                num_statements = len(list(ast.walk(node)))
                if num_statements > 50:
                    self.issues.append(
                        CodeIssue(
                            node.lineno,
                            'complexity_issue',
                            f"Function '{node.name}' is too complex ({num_statements} AST nodes)",
                            self.severity_levels['complexity_issue'],
                        )
                    )

    def _check_variables(self) -> None:
        """Check for undefined and unused variables (simple static analysis)."""

        if self.ast_tree is None:
            return

        defined_vars: Set[str] = set()
        used_vars: Set[str] = set()

        # Proper builtins set
        builtins_set = set(dir(__builtins__))

        usage_lines: Dict[str, int] = {}

        for node in ast.walk(self.ast_tree):

            # --- Defined variables ---
            # Assignment targets
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                defined_vars.add(node.id)

            # Function arguments
            if isinstance(node, ast.arg):
                defined_vars.add(node.arg)

            # Imports
            if isinstance(node, ast.Import):
                for alias in node.names:
                    name = alias.asname or alias.name.split(".")[0]
                    defined_vars.add(name)

            if isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    name = alias.asname or alias.name
                    defined_vars.add(name)

            # --- Used variables ---
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                used_vars.add(node.id)
                usage_lines.setdefault(node.id, getattr(node, "lineno", 0))

        # Filter out builtins
        undefined_vars = {
            v for v in used_vars - defined_vars if v not in builtins_set
        }

        for var in undefined_vars:
            self.issues.append(
                CodeIssue(
                    usage_lines.get(var, 0),
                    "undefined_variable",
                    f"Variable '{var}' is used but not defined",
                    self.severity_levels["undefined_variable"],
                )
            )

    def _check_comments(self) -> None:
        """Analyze code comments for quality and formatting."""
        lines = self.source_code.splitlines()
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith('#'):
                # Check for empty comments
                if len(stripped) == 1:
                    self.issues.append(
                        CodeIssue(
                            i,
                            'comment_issue',
                            "Empty comment found",
                            self.severity_levels['comment_issue'],
                        )
                    )
                # Check for space after '#'
                elif len(stripped) > 1 and stripped[1] != ' ':
                    self.issues.append(
                        CodeIssue(
                            i,
                            'comment_issue',
                            "Comments should have a space after '#'",
                            self.severity_levels['comment_issue'],
                        )
                    )
                # Check for TODO comments
                elif 'TODO' in stripped.upper():
                    self.issues.append(
                        CodeIssue(
                            i,
                            'comment_issue',
                            "TODO comment found - Consider addressing it",
                            self.severity_levels['comment_issue'],
                        )
                    )

    def _check_best_practices(self) -> None:
        """Check for violations of simple Python best practices."""
        if self.ast_tree is None:
            return

        for node in ast.walk(self.ast_tree):
            # Check for excessive line length in string literals
            text = None

            # Python 3.8+: string literals are ast.Constant
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                text = node.value
            # Older Python: ast.Str
            elif isinstance(node, ast.Str):
                text = node.s

            if text is not None and len(text) > 79:
                self.issues.append(
                    CodeIssue(
                        getattr(node, 'lineno', 0),
                        'best_practice',
                        "String literal is too long (> 79 characters)",
                        self.severity_levels['best_practice'],
                    )
                )

    def get_report(self) -> str:
        """
        Generate a detailed report of all issues found during analysis.

        Returns:
            str: Formatted report of all issues
        """
        if not self.issues:
            return "No issues found. Code looks good! 🎉"

        # Sort issues by severity and line number
        severity_order = {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2}
        sorted_issues = sorted(
            self.issues,
            key=lambda x: (severity_order.get(x.severity, 3), x.line_number)
        )

        report = ["Code Review Report", "=================\n"]

        # Group issues by severity
        for severity in ['HIGH', 'MEDIUM', 'LOW']:
            severity_issues = [i for i in sorted_issues if i.severity == severity]
            if severity_issues:
                report.append(f"{severity} Priority Issues:")
                report.append("-" * 30)
                for issue in severity_issues:
                    location = f"Line {issue.line_number}: " if issue.line_number else ""
                    report.append(f"{location}{issue.message}")
                report.append("")

        return "\n".join(report)


def main() -> None:
    """Main function to demonstrate the AI Code Reviewer usage."""
    example_code = """
def calculate_sum(numbers):
    #bad comment
    total = sum(numbers)
    print(undefined_variable)  # This will raise an issue
    return total

class ExampleClass:
    def method_without_docstring(self):
        pass

    def complicated_method(self):
        # TODO: Simplify this method
        result = 0
        for i in range(100):
            for j in range(100):
                for k in range(100):
                    result += i * j * k
        return result
"""

    reviewer = AICodeReviewer()

    if len(sys.argv) > 1:
        file_path = sys.argv[1]
        if not reviewer.load_file(file_path):
            # If loading failed, just print the issues we have (file_error)
            print(reviewer.get_report())
            return
    else:
        reviewer.load_code(example_code)

    reviewer.analyze()
    print(reviewer.get_report())


if __name__ == "__main__":
    main()
