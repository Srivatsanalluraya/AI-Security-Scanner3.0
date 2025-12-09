#!/usr/bin/env python3
"""
security_policy.py

Enforces security policies based on vulnerability analysis.
- Calculates vulnerability proportions
- Decides allow/restrict based on HIGH severity threshold (25%)
- Provides detailed policy reporting
"""

from typing import Dict, List, Tuple
from collections import defaultdict


class SecurityPolicy:
    """Enforces security policies on scan results."""
    
    HIGH_THRESHOLD = 25.0  # Block if HIGH >= 25%
    
    def __init__(self, issues: List[Dict]):
        self.issues = issues
        self.proportions = self._calculate_proportions()
        self.status, self.message, self.allow_push = self._evaluate_policy()
    
    def _calculate_proportions(self) -> Dict[str, float]:
        """Calculate percentage of each severity."""
        if not self.issues:
            return {"HIGH": 0.0, "MEDIUM": 0.0, "LOW": 0.0}
        
        counts = defaultdict(int)
        for issue in self.issues:
            sev = issue.get("severity", "UNKNOWN").upper()
            counts[sev] += 1
        
        total = len(self.issues)
        return {
            "HIGH": round((counts.get("HIGH", 0) / total) * 100, 1),
            "MEDIUM": round((counts.get("MEDIUM", 0) / total) * 100, 1),
            "LOW": round((counts.get("LOW", 0) / total) * 100, 1)
        }
    
    def _evaluate_policy(self) -> Tuple[str, str, bool]:
        """Evaluate if push should be allowed."""
        if not self.issues:
            return "PASS", "✅ No vulnerabilities found - Push allowed", True
        
        high_pct = self.proportions["HIGH"]
        
        if high_pct >= self.HIGH_THRESHOLD:
            msg = f"❌ BLOCKED: {high_pct}% HIGH severity (≥{self.HIGH_THRESHOLD}% threshold)"
            return "BLOCKED", msg, False
        else:
            msg = f"⚠️  WARNING: {high_pct}% HIGH severity - Review recommended but push allowed"
            return "WARNING", msg, True
    
    def get_report(self) -> str:
        """Get formatted policy report."""
        lines = [
            "\n" + "="*70,
            "🔐 SECURITY POLICY ENFORCEMENT REPORT",
            "="*70,
            "",
            f"Total Issues: {len(self.issues)}",
            f"Status: {self.status}",
            f"Message: {self.message}",
            "",
            "Severity Breakdown:",
            f"  • HIGH:   {self.proportions['HIGH']}% (Threshold: {self.HIGH_THRESHOLD}%)",
            f"  • MEDIUM: {self.proportions['MEDIUM']}%",
            f"  • LOW:    {self.proportions['LOW']}%",
            "",
            f"Push Allowed: {'YES ✅' if self.allow_push else 'NO ❌'}",
            "="*70 + "\n"
        ]
        return "\n".join(lines)
    
    def get_exit_code(self) -> int:
        """Get exit code for enforcement (0=allow, 1=block)."""
        return 0 if self.allow_push else 1
