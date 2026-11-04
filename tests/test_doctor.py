"""
Tests for EnvironmentDoctor diagnostics and environment verification.
"""

import pytest
from unittest.mock import MagicMock, patch
from system.doctor import EnvironmentDoctor, CheckResult

def test_doctor_core_checks():
    doctor = EnvironmentDoctor()
    results = doctor.check_core()
    py_check = next((r for r in results if r.name == "Python"), None)
    assert py_check is not None
    assert py_check.status == "PASS"

def test_doctor_security_checks():
    doctor = EnvironmentDoctor()
    results = doctor.check_security_and_sandbox()
    names = [r.name for r in results]
    assert "Policy engine" in names
    assert "Kill switch" in names
    assert "Tool registry" in names
    
    pe_check = next(r for r in results if r.name == "Policy engine")
    assert pe_check.status == "PASS"

def test_doctor_filesystem_checks(tmp_path, monkeypatch):
    monkeypatch.setattr("system.doctor.get_global_config_dir", lambda: tmp_path)
    doctor = EnvironmentDoctor()
    results = doctor.check_filesystem()
    global_dir_check = next(r for r in results if r.name == "Global config directory")
    assert global_dir_check.status == "PASS"

def test_doctor_overall_verdict():
    doctor = EnvironmentDoctor()
    verdict, results = doctor.run_all()
    assert verdict in ("PASS", "WARN", "FAIL")
    assert len(results) >= 8
