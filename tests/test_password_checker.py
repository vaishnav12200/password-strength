import pytest

from analyzer.password_checker import PasswordStrengthAnalyzer


a = PasswordStrengthAnalyzer()


def test_common_passwords_are_very_weak():
    res = a.analyze("password")
    assert res["strength_score"] <= 20
    assert res["bucket"] == "Very Weak"

    res = a.analyze("123456")
    assert res["strength_score"] <= 20
    assert res["bucket"] == "Very Weak"

    res = a.analyze("111111")
    assert res["strength_score"] <= 20
    assert res["bucket"] == "Very Weak"


def test_empty_is_errorish():
    res = a.analyze("")
    assert res["strength_score"] == 0
    assert res["bucket"] == "Very Weak"


def test_good_password_scores_high():
    res = a.analyze("Tr0ub4dor&3")
    assert res["strength_score"] >= 60

