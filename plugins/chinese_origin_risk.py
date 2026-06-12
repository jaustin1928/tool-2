# plugins/chinese_origin_risk.py
import re

class ChineseOriginRiskPlugin:
    """
    Analyzes normalized SBOM components to identify software dependencies 
    originating from specific Chinese associated organizations. 
    """
    def __init__(self):
        self.name = "Chinese Origin Risk Analyzer"
        self.findings = [] 
        
        # 1. The Corporate Entity Feed
        self.watchlist = [
            "alibaba", "tencent", "huawei", "baidu", "bytedance",
            "deepseek", "high-flyer", "zte", "dji", "hikvision", 
            "dahua", "megvii", "sensetime", "netease", "xiaomi", "kingsoft"
        ]

        # 2. The Infrastructure Feed (Regex Patterns)
        # Matches domain endings like '.cn/' or '.cn"' and Java namespaces starting with 'cn.'
        self.regex_watchlist = [
            r"\.cn\b",  # Matches the end of a .cn domain
            r"\bcn\."   # Matches the start of a Java package (e.g., cn.hutool)
        ]

    def run(self, components):
        print(f"[*] Running Plugin: {self.name}...")
        
        for comp in components:
            # Seed search with primary identifiers
            search_elements = [comp.name, comp.publisher, comp.purl]
            
            # Extract and append custom vendor properties
            for prop in comp.properties:
                search_elements.append(str(prop.get('value', '')))
                
            # Flatten into a single lowercase string for rapid scanning
            search_string = " ".join(search_elements).lower()
            
            flagged = False
            trigger_reason = ""

            # Check Corporate Watchlist (Standard Strings)
            for indicator in self.watchlist:
                if indicator in search_string:
                    flagged = True
                    trigger_reason = indicator
                    break
            
            # Check Infrastructure Watchlist (Regex) if not already flagged
            if not flagged:
                for pattern in self.regex_watchlist:
                    match = re.search(pattern, search_string)
                    if match:
                        flagged = True
                        trigger_reason = f"Infrastructure Regex Match ({pattern})"
                        break

            # If either feed caught something, log it
            if flagged:
                self.findings.append({
                    "Component": comp.name,
                    "Trigger": trigger_reason,
                    "PURL": comp.purl
                })