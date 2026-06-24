import math
import re
from dataclasses import dataclass
from typing import Dict, List, Tuple


COMMON_PASSWORDS = {
    # A small built-in set (no external fetching).
    "123456",
    "123456789",
    "12345",
    "qwerty",
    "password",
    "admin",
    "admin123",
    "letmein",
    "welcome",
    "football",
    "iloveyou",
    "monkey",
    "dragon",
    "princess",
    "abc123",
    "111111",
    "11111111",
    "000000",
    "654321",
    "master",
    "sunshine",
    "password1",
    "passw0rd",
}


COMMON_WORDS = {
    # For dictionary word checks. Keep modest and local.
    "password",
    "admin",
    "user",
    "username",
    "login",
    "welcome",
    "qwerty",
    "letmein",
    "monkey",
    "dragon",
    "princess",
    "football",
    "baseball",
    "computer",
    "internet",
    "security",
    "shield",
    "crypto",
    "bitcoin",
    "ethereum",
    "love",
    "iloveyou",
    "master",
    "sunshine",
}


KEYBOARD_ROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm"]


@dataclass
class PatternHit:
    name: str
    severity: str  # "low" | "med" | "high"
    evidence: str


class PasswordStrengthAnalyzer:
    """
    Local-only password analyzer:
    - Never logs or stores the password.
    - Computes a 0-100 score, entropy estimate, and pattern/risk flags.
    """

    def __init__(self) -> None:
        # Precompile regexes for speed.
        self._re_digits = re.compile(r"\d")
        self._re_lower = re.compile(r"[a-z]")
        self._re_upper = re.compile(r"[A-Z]")
        self._re_special = re.compile(r"[^A-Za-z0-9]")
        self._re_letters = re.compile(r"[A-Za-z]")
        self._re_whitespace = re.compile(r"\s")

        # Simple tokenization for dictionary checks.
        self._splitter = re.compile(r"[\W_]+", re.UNICODE)

    def analyze(self, password: str) -> Dict:
        password = "" if password is None else str(password)

        # Error handling
        if len(password) == 0:
            return self._empty_result()

        # Normalize only for checks (never for storage).
        length = len(password)

        composition = self._composition_bits(password)
        pattern_hits = self._detect_patterns(password)
        security_checks = self._security_checks(password)

        complexity_score = self._complexity_score(composition)
        length_score = self._length_score(length)
        pattern_penalty = self._pattern_penalty(pattern_hits)
        security_penalty = self._security_penalty(security_checks)

        raw_score = length_score + complexity_score - pattern_penalty - security_penalty

        # Hard calibration for obviously weak/common patterns.
        # These are common real-world passwords; ensure they consistently fall into the lowest buckets.
        has_common = any(h.name == "Common Password" for h in security_checks)
        if has_common:
            raw_score -= 60

        # Very strong repeated-sequence signals should also heavily reduce scores.
        has_strong_repeats = any(h.name == "Repeated Characters" and h.severity in ("med", "high") for h in pattern_hits)
        if has_strong_repeats:
            raw_score -= 35

        strength_score = max(0, min(100, int(round(raw_score))))


        entropy_bits = self._estimate_entropy_bits(composition, password)
        entropy_label = self._entropy_label(entropy_bits)

        overall_security_score = self._overall_security_score(
            strength_score=strength_score,
            entropy_bits=entropy_bits,
            pattern_hits=pattern_hits,
            security_checks=security_checks,
        )

        attack_estimates = self._attack_estimation(
            password=password,
            strength_score=strength_score,
            entropy_bits=entropy_bits,
            pattern_hits=pattern_hits,
            security_checks=security_checks,
        )

        recommendations = self._recommendations(
            password=password,
            strength_score=strength_score,
            pattern_hits=pattern_hits,
            security_checks=security_checks,
        )

        score_bucket = self._strength_bucket(strength_score)
        display_risk = self._risk_level(overall_security_score, strength_score)

        return {
            "length": length,
            "strength_score": strength_score,
            "bucket": score_bucket,
            "progress_label": score_bucket,
            "entropy_bits": round(entropy_bits, 2),
            "entropy_label": entropy_label,
            "overall_security_score": overall_security_score,
            "risk_level": display_risk,
            "detailed": {
                "length_score": length_score,
                "complexity_score": complexity_score,
                "entropy_score": self._entropy_score(entropy_bits),
                "pattern_detection": [
                    {"name": h.name, "severity": h.severity, "evidence": h.evidence}
                    for h in pattern_hits
                ],
                "security_checks": [
                    {"name": h.name, "severity": h.severity, "evidence": h.evidence}
                    for h in security_checks
                ],
            },
            "recommendations": recommendations,
            "attack_estimates": attack_estimates,
            # Frontend can render these directly for immediate educational value.
            "input_feedback": self._input_feedback(password),
        }

    def _empty_result(self) -> Dict:
        return {
            "length": 0,
            "strength_score": 0,
            "bucket": "Very Weak",
            "progress_label": "Very Weak",
            "entropy_bits": 0.0,
            "entropy_label": "Low Entropy",
            "overall_security_score": 0,
            "risk_level": "High",
            "detailed": {
                "length_score": 0,
                "complexity_score": 0,
                "entropy_score": 0,
                "pattern_detection": [],
                "security_checks": [],
            },
            "recommendations": [
                "Enter a password to analyze.",
            ],
            "attack_estimates": {
                "brute_force": "Instantly",
                "dictionary": "Instantly",
                "credential_stuffing": "Instantly",
            },
            "input_feedback": {
                "type": "error",
                "message": "Password cannot be empty.",
            },
        }

    def _composition_bits(self, password: str) -> Dict[str, bool]:
        has_lower = bool(self._re_lower.search(password))
        has_upper = bool(self._re_upper.search(password))
        has_digits = bool(self._re_digits.search(password))
        has_special = bool(self._re_special.search(password))
        return {
            "lower": has_lower,
            "upper": has_upper,
            "digits": has_digits,
            "special": has_special,
        }

    def _length_score(self, length: int) -> float:
        # Piecewise scoring favoring length > 12
        if length < 6:
            return 10
        if length < 8:
            return 25
        if length < 10:
            return 40
        if length < 12:
            return 55
        if length < 14:
            return 70
        if length < 16:
            return 80
        return 90

    def _complexity_score(self, composition: Dict[str, bool]) -> float:
        categories = sum(1 for k, v in composition.items() if v)
        # categories: 0..4
        if categories <= 1:
            return 5
        if categories == 2:
            return 25
        if categories == 3:
            return 45
        return 60

    def _pattern_penalty(self, hits: List[PatternHit]) -> float:
        penalty = 0.0
        for h in hits:
            if h.severity == "high":
                penalty += 18
            elif h.severity == "med":
                penalty += 10
            else:
                penalty += 5
        # Cap penalty.
        return min(60, penalty)

    def _security_penalty(self, hits: List[PatternHit]) -> float:
        penalty = 0.0
        for h in hits:
            if h.severity == "high":
                penalty += 22
            elif h.severity == "med":
                penalty += 12
            else:
                penalty += 7
        return min(70, penalty)

    def _strength_bucket(self, strength_score: int) -> str:
        if strength_score < 20:
            return "Very Weak"
        if strength_score < 40:
            return "Weak"
        if strength_score < 60:
            return "Moderate"
        if strength_score < 80:
            return "Strong"
        return "Very Strong"

    def _entropy_score(self, entropy_bits: float) -> float:
        # Map entropy (bits) to a 0-60 scale
        # ~ 0-40 => low, 40-60 => medium, 60+ => high
        if entropy_bits <= 30:
            return 10
        if entropy_bits <= 45:
            return 25
        if entropy_bits <= 60:
            return 40
        return 55

    def _estimate_entropy_bits(self, composition: Dict[str, bool], password: str) -> float:
        # Very common approach: bits ~= log2(pool^length).
        pool = 0
        if composition["lower"]:
            pool += 26
        if composition["upper"]:
            pool += 26
        if composition["digits"]:
            pool += 10
        if composition["special"]:
            # approximate special set
            pool += 33

        if pool <= 0:
            return 0.0

        length = len(password)

        # Penalize repeated chars / patterns a bit by lowering effective length.
        unique_chars = len(set(password))
        repeat_factor = max(0.7, min(1.0, unique_chars / max(1, length)))
        effective_length = length * repeat_factor

        return effective_length * math.log2(pool)

    def _entropy_label(self, entropy_bits: float) -> str:
        if entropy_bits < 35:
            return "Low Entropy"
        if entropy_bits < 55:
            return "Medium Entropy"
        return "High Entropy"

    def _overall_security_score(
        self,
        strength_score: int,
        entropy_bits: float,
        pattern_hits: List[PatternHit],
        security_checks: List[PatternHit],
    ) -> int:
        # Blend: strength_score is primary; entropy contributes; hits reduce.
        entropy_component = int(min(20, entropy_bits / 10))
        penalties = 0
        for h in pattern_hits + security_checks:
            penalties += 8 if h.severity == "high" else 4 if h.severity == "med" else 2
        final = strength_score + entropy_component - penalties
        return max(0, min(100, final))

    def _detect_patterns(self, password: str) -> List[PatternHit]:
        hits: List[PatternHit] = []
        length = len(password)

        if length >= 4:
            # Repeated characters (e.g., aaaaaa)
            if self._has_repeated_run(password, min_run=4):
                run_char, run_len = self._max_run(password)
                hits.append(
                    PatternHit(
                        name="Repeated Characters",
                        severity="high" if run_len >= 6 else "med",
                        evidence=f"'{run_char}' repeated {run_len} times",
                    )
                )

        # Sequential patterns (letters or digits): e.g. 1234, abcde, cdef
        seq = self._find_sequential(password)
        if seq:
            start, end, kind, step = seq
            hits.append(
                PatternHit(
                    name="Sequential Pattern",
                    severity="high" if len(start) >= 5 else "med",
                    evidence=f"{kind} sequence {start}->{end} (step {step:+d})",
                )
            )

        # Keyboard patterns: qwertyui or asdfg etc
        kb = self._find_keyboard_pattern(password)
        if kb:
            row, seq_str = kb
            hits.append(
                PatternHit(
                    name="Keyboard Pattern",
                    severity="high" if len(seq_str) >= 6 else "med",
                    evidence=f"Row '{row}' contains sequence '{seq_str}'",
                )
            )

        # Common personal info patterns (lightweight heuristic)
        # e.g. includes "name", "email" isn't possible here; do generic: "my", "your", "admin"
        lowered = password.lower()
        if any(tok in lowered for tok in ["admin", "user", "username", "password", "welcome"]):
            hits.append(
                PatternHit(
                    name="Personal/Brand-like Pattern",
                    severity="med",
                    evidence="Contains a common label (admin/user/password/etc.)",
                )
            )

        # Consecutive numbers (e.g. 112233)
        if self._has_consecutive_numbers(password, min_len=4):
            hits.append(
                PatternHit(
                    name="Consecutive Numbers",
                    severity="med",
                    evidence="Contains a run of consecutive digits",
                )
            )

        # Also: repeated small substrings
        if self._has_repeated_substring(password, min_sub_len=2, min_repeats=2):
            hits.append(
                PatternHit(
                    name="Repeated Substrings",
                    severity="low",
                    evidence="Repeats a substring multiple times",
                )
            )

        # Flag whitespace - often accidental and reduces effective strength
        if self._re_whitespace.search(password):
            hits.append(
                PatternHit(
                    name="Whitespace",
                    severity="low",
                    evidence="Contains whitespace characters",
                )
            )

        return hits

    def _security_checks(self, password: str) -> List[PatternHit]:
        hits: List[PatternHit] = []
        lowered = password.lower().strip()

        if lowered in COMMON_PASSWORDS:
            hits.append(
                PatternHit(
                    name="Common Password",
                    severity="high",
                    evidence=f"Matches known common password '{lowered}'",
                )
            )

        # dictionary words inside password
        tokens = [t for t in self._splitter.split(lowered) if t]
        for word in tokens:
            if word in COMMON_WORDS:
                hits.append(
                    PatternHit(
                        name="Dictionary Word",
                        severity="med",
                        evidence=f"Contains word '{word}'",
                    )
                )

        # common words embedded without separators: scan for substrings
        # Keep conservative to avoid too many false positives.
        for w in ("password", "admin", "qwerty", "welcome", "letmein"):
            if w in lowered:
                hits.append(
                    PatternHit(
                        name="Dictionary Word",
                        severity="med",
                        evidence=f"Contains '{w}'",
                    )
                )
                break

        # consecutive digits/letters are patterns but also a security check.
        if self._has_repeated_digit_pattern(password) and length_check(password, 5, 25):
            hits.append(
                PatternHit(
                    name="Digit Repetition Pattern",
                    severity="high",
                    evidence="Digit repetition pattern detected",
                )
            )

        if self._looks_like_year_or_birthdate(lowered):
            hits.append(
                PatternHit(
                    name="Potential Personal Info",
                    severity="med",
                    evidence="Looks like a year/birthdate-like number sequence",
                )
            )

        return hits

    def _attack_estimation(
        self,
        password: str,
        strength_score: int,
        entropy_bits: float,
        pattern_hits: List[PatternHit],
        security_checks: List[PatternHit],
    ) -> Dict[str, str]:
        # Estimate times from entropy. This is an approximation for UI/education.
        # Assumptions (rough): attacker tries 1e6 guesses/sec for brute force,
        # dictionary/crack depends on known patterns.
        guesses_total = max(1.0, 2 ** entropy_bits)

        # If patterns/security checks flag common passwords, dictionary becomes near-instant.
        is_common = any(h.name == "Common Password" and h.severity in ("med", "high") for h in security_checks)
        has_sequences = any(h.name in ("Sequential Pattern", "Keyboard Pattern") for h in pattern_hits)
        has_repeats = any(h.name == "Repeated Characters" for h in pattern_hits)

        # Brute force: depends on entropy.
        brute_seconds = guesses_total / 1e6

        # Dictionary: reduced search space.
        if is_common or has_sequences or has_repeats:
            dict_seconds = brute_seconds / 1e6
        else:
            dict_seconds = brute_seconds / 1e3

        # Credential stuffing: depends mostly on whether it looks like common passwords.
        if is_common:
            stuffing_seconds = 1
        elif has_sequences:
            stuffing_seconds = 60 * 10  # ~10 minutes
        else:
            stuffing_seconds = brute_seconds / 1e3

        return {
            "brute_force": self._format_crack_time(brute_seconds),
            "dictionary": self._format_crack_time(dict_seconds),
            "credential_stuffing": self._format_crack_time(stuffing_seconds),
        }

    def _format_crack_time(self, seconds: float) -> str:
        if seconds <= 1:
            return "Instantly"
        if seconds < 60:
            return "Seconds"
        if seconds < 3600:
            return "Minutes"
        if seconds < 86400:
            return "Hours"
        if seconds < 86400 * 365:
            return "Days"
        if seconds < 86400 * 365 * 100:
            return "Years"
        if seconds < 86400 * 365 * 1000:
            return "Centuries"
        return "Centuries"

    def _recommendations(
        self,
        password: str,
        strength_score: int,
        pattern_hits: List[PatternHit],
        security_checks: List[PatternHit],
    ) -> List[str]:
        composition = self._composition_bits(password)
        rec: List[str] = []

        if len(password) < 12:
            rec.append("Increase password length (aim for 12+ characters).")

        if not composition["upper"]:
            rec.append("Add uppercase letters.")
        if not composition["lower"]:
            rec.append("Add lowercase letters.")
        if not composition["digits"]:
            rec.append("Add numbers.")
        if not composition["special"]:
            rec.append("Add special characters (e.g., !@#$%).")

        if any(h.name == "Common Password" for h in security_checks):
            rec.append("Avoid common passwords and predictable substitutions.")

        if any(h.name in ("Sequential Pattern", "Keyboard Pattern") for h in pattern_hits):
            rec.append("Avoid sequential and keyboard patterns like '1234' or 'qwerty'.")

        if any(h.name == "Repeated Characters" for h in pattern_hits):
            rec.append("Avoid repeating characters (e.g., 'aaaaaa' or '111111').")

        # Always include guidance for uniqueness
        rec.append("Use a unique password per account to reduce breach impact (password reuse is dangerous).")

        # Ensure bounded list
        seen = set()
        out: List[str] = []
        for item in rec:
            if item not in seen:
                out.append(item)
                seen.add(item)
            if len(out) >= 7:
                break
        return out

    def _risk_level(self, overall_security_score: int, strength_score: int) -> str:
        # Map to High/Med/Low
        if overall_security_score >= 80 or strength_score >= 80:
            return "Low"
        if overall_security_score >= 50 or strength_score >= 50:
            return "Medium"
        return "High"

    def _input_feedback(self, password: str) -> Dict:
        # lightweight educational message
        if self._re_whitespace.search(password):
            return {"type": "warning", "message": "Whitespace detected—this may reduce usability and can be a pattern."}
        if len(password) < 8:
            return {"type": "warning", "message": "Short password—length is one of the strongest predictors of resistance to guessing."}
        return {"type": "info", "message": "Analysis computed locally in your browser/server (no password storage)."}
    def _has_repeated_run(self, password: str, min_run: int) -> bool:
        ch = None
        run = 0
        for c in password:
            if c == ch:
                run += 1
            else:
                ch = c
                run = 1
            if run >= min_run:
                return True
        return False

    def _max_run(self, password: str) -> Tuple[str, int]:
        best_ch = ""
        best_len = 0
        ch = None
        run = 0
        for c in password:
            if c == ch:
                run += 1
            else:
                if run > best_len and ch is not None:
                    best_ch = ch
                    best_len = run
                ch = c
                run = 1
        if run > best_len and ch is not None:
            best_ch = ch
            best_len = run
        return best_ch, best_len

    def _find_sequential(self, password: str):
        # Detect sequences of length >=4 with step +/-1 for letters/digits.
        if len(password) < 4:
            return None

        lowered = password.lower()
        # digits
        digits = [c for c in password if c.isdigit()]
        # But we need contiguous sequences in original string.
        for i in range(len(password) - 3):
            s = password[i:i + 4]
            if all(c.isdigit() for c in s):
                step = int(s[1]) - int(s[0])
                if step in (1, -1):
                    ok = True
                    for j in range(1, 4):
                        if int(s[j]) - int(s[j - 1]) != step:
                            ok = False
                            break
                    if ok:
                        # Extend
                        start_idx = i
                        step_val = step
                        j = i + 4
                        while j < len(password) and password[j].isdigit():
                            prev = int(password[j - 1])
                            if int(password[j]) - prev != step_val:
                                break
                            j += 1
                        seq = password[start_idx:j]
                        return (seq[0], seq[-1], "Digits", step_val)

            if all(c.isalpha() for c in s):
                a0 = ord(lowered[i])
                # Determine if alphabetic step.
                step = ord(lowered[i + 1]) - ord(lowered[i])
                if step in (1, -1):
                    ok = True
                    for j in range(i + 1, i + 4):
                        if ord(lowered[j]) - ord(lowered[j - 1]) != step:
                            ok = False
                            break
                    if ok:
                        # Extend
                        k = i + 4
                        while k < len(password) and password[k].isalpha():
                            if ord(lowered[k]) - ord(lowered[k - 1]) != step:
                                break
                            k += 1
                        seq = password[i:k]
                        return (seq[0], seq[-1], "Letters", step)

        return None

    def _find_keyboard_pattern(self, password: str):
        # Find contiguous substring of len>=4 that appears in keyboard rows.
        pw_lower = password.lower()
        for row in KEYBOARD_ROWS:
            for i in range(len(row)):
                # try starting at row position
                # scan for contiguous match
                if i + 4 <= len(row):
                    # brute search for any substring from pw inside row
                    # (keep simple)
                    pass
            # check for any 4+ consecutive run in this row
            for i in range(len(pw_lower) - 3):
                sub = pw_lower[i:i + 4]
                if sub in row:
                    # extend match
                    start = i
                    end = i + 4
                    while end < len(pw_lower):
                        if pw_lower[start:end + 1] in row:
                            end += 1
                        else:
                            break
                    return (row, pw_lower[start:end])
        return None

    def _has_consecutive_numbers(self, password: str, min_len: int = 4) -> bool:
        if len(password) < min_len:
            return False
        # check contiguous ascending/descending digit runs with step +/-1
        for i in range(len(password) - min_len + 1):
            chunk = password[i:i + min_len]
            if not all(c.isdigit() for c in chunk):
                continue
            step = int(chunk[1]) - int(chunk[0])
            if step not in (1, -1):
                continue
            ok = True
            for j in range(2, min_len):
                if int(chunk[j]) - int(chunk[j - 1]) != step:
                    ok = False
                    break
            if ok:
                return True
        return False

    def _has_repeated_substring(self, password: str, min_sub_len: int = 2, min_repeats: int = 2) -> bool:
        n = len(password)
        if n < min_sub_len * min_repeats:
            return False
        for sub_len in range(min_sub_len, min_sub_len + 3):
            for i in range(0, n - sub_len * min_repeats + 1):
                sub = password[i:i + sub_len]
                count = 0
                for j in range(0, n - sub_len + 1, sub_len):
                    if password[j:j + sub_len] == sub:
                        count += 1
                if count >= min_repeats and len(sub) >= 2:
                    return True
        return False

    def _has_repeated_digit_pattern(self, password: str) -> bool:
        if not password:
            return False
        lowered = password.strip()
        if not all(c.isdigit() for c in lowered):
            return False
        # Check if all digits same (e.g. 111111)
        return len(set(lowered)) == 1

    def _looks_like_year_or_birthdate(self, lowered: str) -> bool:
        # simplistic heuristics: 4-digit years or 6-8 digit patterns like 199012 or 01011990
        if re.fullmatch(r"(19|20)\d{2}", lowered):
            return True
        if re.fullmatch(r"\d{6,8}", lowered):
            return True
        return False


def length_check(s: str, lo: int, hi: int) -> bool:
    return lo <= len(s) <= hi
