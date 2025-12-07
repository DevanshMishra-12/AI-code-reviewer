#!/usr/bin/env python3
"""
AI Code Reviewer - A Python script for automated code analysis and improvement suggestions.

This script analyzes Python code for common issues, style violations, and potential
improvements, providing detailed feedback to help developers write better code.
"""

import ast
import sys
import pycodestyle
import builtins
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
        self.issues: List[CodeIssue] = []
        self.source_code: str = ""
        self.ast_tree: Optional[ast.AST] = None

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

    # ---------------------------------------------------------
    # Loaders
    # ---------------------------------------------------------
    def load_file(self, file_path: str) -> bool:
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                self.source_code = file.read()
            return True
        except Exception as e:
            self.issues.append(
                CodeIssue(0, 'file_error',
                          f"Error loading file '{file_path}': {str(e)}",
                          self.severity_levels['file_error'])
            )
            return False

    def load_code(self, code: str) -> None:
        self.source_code = code

    # ---------------------------------------------------------
    # Main Analysis
    # ---------------------------------------------------------
    def analyze(self) -> None:
        self.issues = []

        try:
            self.ast_tree = ast.parse(self.source_code)
        except SyntaxError as e:
            self.issues.append(
                CodeIssue(e.lineno or 0, 'syntax_error',
                          f"Syntax Error: {str(e)}",
                          self.severity_levels['syntax_error'])
            )
            return

        self._check_syntax()
        self._check_style()
        self._check_docstrings()
        self._check_complexity()
        self._check_variables()
        self._check_comments()
        self._check_best_practices()

    # ---------------------------------------------------------
    # Individual Checks
    # ---------------------------------------------------------
    def _check_syntax(self) -> None:
        if self.ast_tree is None:
            return

        for node in ast.walk(self.ast_tree):
            if isinstance(node, (ast.For, ast.While, ast.If, ast.With, ast.AsyncWith, ast.AsyncFor)):
                if not node.body:
                    self.issues.append(
                        CodeIssue(node.lineno, 'syntax_error',
                                  f"Empty {node.__class__.__name__} block found",
                                  self.severity_levels['syntax_error'])
                    )

    def _check_style(self) -> None:
        style_guide = pycodestyle.StyleGuide(quiet=True)
        temp_file = Path("temp_code_review.py")

        try:
            temp_file.write_text(self.source_code, encoding="utf-8")
            result = style_guide.check_files([temp_file])

            deferred = getattr(result, "_deferred_print", [])
            for line_number, offset, code, text, doc in deferred:
                self.issues.append(
                    CodeIssue(line_number, "style_violation",
                              f"{code}: {text}",
                              self.severity_levels['style_violation'])
                )
        finally:
            if temp_file.exists():
                temp_file.unlink()

    def _check_docstrings(self) -> None:
        if self.ast_tree is None:
            return

        for node in ast.walk(self.ast_tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Module)):
                lineno = getattr(node, "lineno", 0)
                docstring = ast.get_docstring(node)

                if not docstring:
                    self.issues.append(
                        CodeIssue(lineno, 'missing_docstring',
                                  f"Missing docstring in {node.__class__.__name__}",
                                  self.severity_levels['missing_docstring'])
                    )
                else:
                    if len(docstring.strip()) < 10:
                        self.issues.append(
                            CodeIssue(lineno, 'docstring_quality',
                                      f"Short or uninformative docstring in {node.__class__.__name__}",
                                      self.severity_levels['docstring_quality'])
                        )

    def _check_complexity(self) -> None:
        if self.ast_tree is None:
            return

        for node in ast.walk(self.ast_tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                nodes = list(ast.walk(node))
                if len(nodes) > 50:
                    self.issues.append(
                        CodeIssue(node.lineno, 'complexity_issue',
                                  f"Function '{node.name}' is too complex ({len(nodes)} AST nodes)",
                                  self.severity_levels['complexity_issue'])
                    )

    def _check_variables(self) -> None:
        """Correctly checks undefined variables without flagging built-ins."""
        if self.ast_tree is None:
            return

        defined: Set[str] = set()
        used: Set[str] = set()
        builtins_set = set(dir(builtins))
        usage_lines: Dict[str, int] = {}

        for node in ast.walk(self.ast_tree):

            # Defined variables
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                defined.add(node.id)

            if isinstance(node, ast.arg):
                defined.add(node.arg)

            if isinstance(node, ast.Import):
                for alias in node.names:
                    defined.add(alias.asname or alias.name.split('.')[0])

            if isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    defined.add(alias.asname or alias.name)

            # Used variables
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                used.add(node.id)
                usage_lines.setdefault(node.id, node.lineno)

        # Undefined variables = used but not defined and not built-ins
        undefined = {v for v in used - defined if v not in builtins_set}

        for var in undefined:
            self.issues.append(
                CodeIssue(usage_lines.get(var, 0),
                          'undefined_variable',
                          f"Variable '{var}' is used but not defined",
                          self.severity_levels['undefined_variable'])
            )

    def _check_comments(self) -> None:
        lines = self.source_code.splitlines()
        for i, line in enumerate(lines, 1):
            stripped = line.strip()

            if stripped.startswith("#"):
                if stripped == "#":
                    self.issues.append(
                        CodeIssue(i, 'comment_issue', "Empty comment found",
                                  self.severity_levels['comment_issue'])
                    )
                elif stripped[1] != " ":
                    self.issues.append(
                        CodeIssue(i, 'comment_issue',
                                  "Comments should have a space after '#'",
                                  self.severity_levels['comment_issue'])
                    )
                elif "TODO" in stripped.upper():
                    self.issues.append(
                        CodeIssue(i, 'comment_issue',
                                  "TODO comment found - Consider addressing it",
                                  self.severity_levels['comment_issue'])
                    )

    def _check_best_practices(self) -> None:
        if self.ast_tree is None:
            return

        for node in ast.walk(self.ast_tree):
            text = None

            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                text = node.value
            elif isinstance(node, ast.Str):
                text = node.s

            if text and len(text) > 79:
                self.issues.append(
                    CodeIssue(node.lineno,
                              'best_practice',
                              "String literal is too long (> 79 characters)",
                              self.severity_levels['best_practice'])
                )

    # ---------------------------------------------------------
    # Report
    # ---------------------------------------------------------
    def get_report(self) -> str:
        if not self.issues:
            return "No issues found. Code looks good! 🎉"

        severity_order = {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2}

        sorted_issues = sorted(
            self.issues,
            key=lambda x: (severity_order[x.severity], x.line_number)
        )

        report = ["Code Review Report", "=================\n"]

        for severity in ['HIGH', 'MEDIUM', 'LOW']:
            current = [i for i in sorted_issues if i.severity == severity]
            if current:
                report.append(f"{severity} Priority Issues:")
                report.append("-" * 30)
                for issue in current:
                    prefix = f"Line {issue.line_number}: " if issue.line_number else ""
                    report.append(f"{prefix}{issue.message}")
                report.append("")

        return "\n".join(report)


# ---------------------------------------------------------
# CLI Launcher
# ---------------------------------------------------------
def main() -> None:
    example_code = """
def calculate_sum(numbers):
    #bad comment
    total = sum(numbers)
    print(undefined_variable)
    return total
"""

    reviewer = AICodeReviewer()

    if len(sys.argv) > 1:
        file_path = sys.argv[1]
        if not reviewer.load_file(file_path):
            print(reviewer.get_report())
            return
    else:
        reviewer.load_code(example_code)

    reviewer.analyze()
    print(reviewer.get_report())


if __name__ == "__main__":
    main()
