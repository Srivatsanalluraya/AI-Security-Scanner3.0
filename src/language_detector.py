#!/usr/bin/env python3
"""
language_detector.py

Detects programming languages in the workspace and determines
which security scanners to run.
"""

import os
from pathlib import Path
from typing import Dict, Set


class LanguageDetector:
    """Detects languages in workspace based on file extensions and manifest files."""
    
    LANGUAGE_INDICATORS = {
        "python": {
            "extensions": [".py"],
            "files": ["requirements.txt", "setup.py", "pyproject.toml", "Pipfile"]
        },
        "javascript": {
            "extensions": [".js", ".jsx", ".ts", ".tsx"],
            "files": ["package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"]
        },
        "java": {
            "extensions": [".java"],
            "files": ["pom.xml", "build.gradle", "build.gradle.kts", "gradle.properties"]
        },
        "go": {
            "extensions": [".go"],
            "files": ["go.mod", "go.sum"]
        }
    }
    
    def __init__(self, workspace: str):
        self.workspace = Path(workspace)
        self.detected_languages = set()
    
    def detect(self) -> Set[str]:
        """Detect all languages present in the workspace."""
        if not self.workspace.exists():
            return set()
        
        detected = set()
        
        for language, indicators in self.LANGUAGE_INDICATORS.items():
            # Check for manifest files in root
            for manifest in indicators["files"]:
                if (self.workspace / manifest).exists():
                    detected.add(language)
                    break
            
            # Check for source files with matching extensions
            if language not in detected:
                for ext in indicators["extensions"]:
                    # Use rglob to search recursively
                    if any(self.workspace.rglob(f"*{ext}")):
                        detected.add(language)
                        break
        
        self.detected_languages = detected
        return detected
    
    def get_scanner_config(self) -> Dict[str, bool]:
        """Return which scanners should be enabled based on detected languages."""
        if not self.detected_languages:
            self.detect()
        
        config = {
            # Python scanners
            "bandit": "python" in self.detected_languages,
            "pip_audit": "python" in self.detected_languages,
            
            # JavaScript/Node.js scanners
            "npm_audit": "javascript" in self.detected_languages,
            "eslint": "javascript" in self.detected_languages,
            
            # Java scanners
            "spotbugs": "java" in self.detected_languages,
            "dependency_check_java": "java" in self.detected_languages,
            
            # Go scanners
            "gosec": "go" in self.detected_languages,
            "nancy": "go" in self.detected_languages,
            
            # Universal scanners (run for all languages)
            "semgrep": True,
            "trivy": True
        }
        
        return config
    
    def get_semgrep_configs(self) -> list:
        """Get appropriate Semgrep rulesets based on detected languages."""
        if not self.detected_languages:
            self.detect()
        
        configs = []
        
        if "python" in self.detected_languages:
            configs.append("p/python")
        
        if "javascript" in self.detected_languages:
            configs.extend(["p/javascript", "p/typescript", "p/react"])
        
        if "java" in self.detected_languages:
            configs.append("p/java")
        
        if "go" in self.detected_languages:
            configs.append("p/golang")
        
        # Always include security configs
        configs.append("p/security-audit")
        configs.append("p/owasp-top-ten")
        
        return list(set(configs))  # Remove duplicates
    
    def get_language_summary(self) -> str:
        """Get a human-readable summary of detected languages."""
        if not self.detected_languages:
            self.detect()
        
        if not self.detected_languages:
            return "No languages detected"
        
        lang_names = {
            "python": "Python",
            "javascript": "JavaScript/TypeScript/Node.js",
            "java": "Java",
            "go": "Go"
        }
        
        detected_names = [lang_names.get(lang, lang.title()) for lang in sorted(self.detected_languages)]
        return ", ".join(detected_names)


def main():
    """Standalone execution for testing."""
    import sys
    workspace = sys.argv[1] if len(sys.argv) > 1 else "."
    
    detector = LanguageDetector(workspace)
    languages = detector.detect()
    
    print(f"Detected languages: {detector.get_language_summary()}")
    print(f"\nScanner configuration:")
    for scanner, enabled in detector.get_scanner_config().items():
        status = "✓" if enabled else "✗"
        print(f"  {status} {scanner}")
    
    print(f"\nSemgrep configs: {', '.join(detector.get_semgrep_configs())}")


if __name__ == "__main__":
    main()
