"""
test_utils.py - Unit tests for utility functions.
"""

import os
import tempfile
import pytest

from src.utils import count_lines, find_local_file


def test_count_lines_normal():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("line1\nline2\nline3\n")
        tmp = f.name
    assert count_lines(tmp) == 3
    os.unlink(tmp)


def test_count_lines_empty():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n\n\n")
        tmp = f.name
    assert count_lines(tmp) == 0
    os.unlink(tmp)


def test_count_lines_missing_file():
    assert count_lines("/nonexistent/path/file.txt") == 0


def test_find_local_file_not_found():
    result = find_local_file("this_file_does_not_exist_xyz.txt")
    assert result is None
