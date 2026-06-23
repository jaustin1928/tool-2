# plugins/copyleft_finder.py
import re

class copyleft_finder:
    """
    Certain Open Source Software Licenses require derivative work to also be Open Source, known as copyleft. 
    This can be problematic for organizations who seek to create closed-source work. 
    This plugin seeks to identify licenses in dependencies that require such licenses.
    """

    def __init__(self):
        self.name = "Copyleft License Finder"
        self.findings = [] 
        self.summary = "" 

        # Add or remove licenses here.
        self.strongCopyLeft = [
            "gpl", "agpl", "sspl", "eupl", "osl"
        ]
        self.weakCopyLeft = [
            "mpl", "lgpl", "epl", "cddl", "cecill"
        ]

    def run(self, components):
        print(f"[*] Running Plugin: {self.name}...")
        
        # Dynamically build the dictionary based on the lists above
        all_indicators = self.strongCopyLeft + self.weakCopyLeft
        tally = {indicator: 0 for indicator in all_indicators}
        
        for comp in components:
            search_elements = comp.licenses
            search_string = " ".join(search_elements).lower()

            flagged = False
            # Turn this into a list to hold multiple triggers
            trigger_reasons = [] 

            # Check for strong and weak copyleft elements
            for indicator in all_indicators:
                # (?<![a-z]) ensures 'gpl' isn't preceded by a letter (prevents agpl/lgpl overlap)
                # (?![a-uwyz]) ensures it isn't followed by a letter EXCEPT 'v' (allows gplv3)
                pattern = r'(?<![a-z])' + re.escape(indicator) + r'(?![a-uwyz])'
                
                if re.search(pattern, search_string):
                    flagged = True
                    trigger_reasons.append(indicator) # Append instead of overwrite
                    tally[indicator] += 1
            if flagged:
                self.findings.append({
                    "Component": comp.name,
                    # Join the list of triggers together (e.g., "gpl, lgpl")
                    "Trigger": ", ".join(trigger_reasons), 
                    "License": comp.licenses,
                    "PURL": comp.purl
                })
                
        # Dynamically build the summary string
        if self.findings:
            tally_strings = [f"{key.upper()}: {count}" for key, count in tally.items()]
            self.summary = f"Total Violations: {len(self.findings)} | " + " | ".join(tally_strings)