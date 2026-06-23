import json
import sys
import os
import importlib.util
import inspect

# ==========================================
# 0. DUAL LOGGER UTILITY
# ==========================================
class DualLogger:
    """
    Intercepts sys.stdout to duplicate console output to a log file.
    """
    def __init__(self, filepath):
        self.terminal = sys.stdout
        self.log = open(filepath, "w", encoding="utf-8")

    def write(self, message):
        self.terminal.write(message)
        self.log.write(message)

    def flush(self):
        self.terminal.flush()
        self.log.flush()

# ==========================================
# 1. THE DATA MODEL
# ==========================================
class NormalizedComponent:
    """
    A unified data structure to hold software component metadata.
    This abstracts away the structural differences between various SBOM 
    formats (like CycloneDX and SPDX), allowing downstream plugins to operate 
    on a standardized object regardless of the original file format.
    """
    def __init__(self, name, version, publisher, author, purl, component_type, hashes, properties, licenses):
        self.name = name                     # The canonical name of the software package or dependency
        self.version = version               # The specific release version, commit, or build number
        self.publisher = publisher           # The vendor or organization distributing the package (e.g., 'Alibaba Group')
        self.author = author                 # The original creator, individual developer, or originator of the code
        self.purl = purl                     # Package URL (PURL) identifying the ecosystem and locator (e.g., pkg:maven/...)
        self.component_type = component_type # The structural classification (e.g., 'library', 'framework', 'application')
        self.hashes = hashes                 # Cryptographic checksums for integrity verification (e.g., {'SHA-256': '...'})
        self.properties = properties         # Custom key-value pairs containing vendor-specific metadata or hidden traits
        self.licenses = licenses             # An array of extracted license identifiers or expressions (e.g., ['Apache-2.0'])

# ==========================================
# 2. THE CORE INGESTION ENGINE
# ==========================================
class SBOMParser:
    """
    Handles the reading, format detection, and parsing of SBOM files.
    Converts raw JSON into a flat list of NormalizedComponent objects.
    """
    def __init__(self, filepath):
        self.filepath = filepath
        self.components = [] 

    def load(self):
        print(f"[*] Initializing Ingestion Engine for: {self.filepath}")
        try:
            peek_data = None
            for enc in ['utf-8', 'utf-16']:
                try:
                    with open(self.filepath, 'r', encoding=enc) as f:
                        peek_data = json.load(f)
                    break 
                except (UnicodeDecodeError, json.JSONDecodeError):
                    continue
            
            if not peek_data:
                print("[ERROR] Failed to read file or detect valid JSON.")
                return []

            if 'bomFormat' in peek_data and peek_data['bomFormat'] == 'CycloneDX':
                return self.parse_cyclonedx(peek_data)
            elif 'spdxVersion' in peek_data:
                return self.parse_spdx(peek_data)
            else:
                print("[ERROR] Unknown SBOM format. Must be CycloneDX or SPDX JSON.")
                return []
                
        except Exception as e:
            print(f"[ERROR] Auto-detection failed: {e}")
            return []

    def parse_cyclonedx(self, sbom):
        print(f"[ENGINE] Detected Format: CycloneDX {sbom.get('specVersion', 'Unknown')}")
        
        components_to_process = []
        if 'metadata' in sbom and 'component' in sbom['metadata']:
            components_to_process.append(sbom['metadata']['component'])
        
        components_to_process.extend(sbom.get('components', []))

        def extract_components(comp_list):
            for comp in comp_list:
                
                # 1. License Extraction
                extracted_licenses = []
                for lic_item in comp.get('licenses', []):
                    if 'license' in lic_item:
                        lic = lic_item['license']
                        extracted_licenses.append(lic.get('id', lic.get('name', 'Unknown')))
                    elif 'expression' in lic_item:
                        extracted_licenses.append(lic_item['expression'])

                # 2. Hash Extraction (List to Dictionary mapping)
                extracted_hashes = {}
                for h in comp.get('hashes', []):
                    if 'alg' in h and 'content' in h:
                        extracted_hashes[h['alg']] = h['content']

                # Normalize the component
                norm_comp = NormalizedComponent(
                    name=comp.get('name', 'Unknown'),
                    version=comp.get('version', 'Unknown'),
                    publisher=comp.get('supplier', {}).get('name', 'Unknown'),
                    author=comp.get('author', 'Unknown'),
                    purl=comp.get('purl', 'N/A'),
                    component_type=comp.get('type', 'Unknown').lower(),
                    hashes=extracted_hashes,
                    properties=comp.get('properties', []),
                    licenses=extracted_licenses
                )
                self.components.append(norm_comp)
                
                if 'components' in comp:
                    extract_components(comp['components'])

        extract_components(components_to_process)
        print(f"[ENGINE] Recursively normalized {len(self.components)} components.\n")
        return self.components

    def parse_spdx(self, sbom):
        print(f"[ENGINE] Detected Format: {sbom.get('spdxVersion', 'SPDX')}")
        raw_packages = sbom.get('packages', [])
        
        for pkg in raw_packages:
            
            # 1. PURL Extraction
            extracted_purl = "N/A"
            for ref in pkg.get('externalRefs', []):
                if ref.get('referenceType') == 'purl':
                    extracted_purl = ref.get('referenceLocator')
                    break

            # 2. License Extraction
            raw_lic = pkg.get('licenseConcluded', 'NOASSERTION')
            
            # If SPDX explicitly declares it doesn't know the concluded license, check the declared license
            if raw_lic in ('NOASSERTION', 'NONE'):
                raw_lic = pkg.get('licenseDeclared', 'NOASSERTION')
                
            extracted_licenses = [raw_lic] if raw_lic not in ('NOASSERTION', 'NONE') else []

            # 3. Hash Extraction (SPDX format to Standard Mapping)
            extracted_hashes = {}
            for chk in pkg.get('checksums', []):
                algo = chk.get('algorithm', '')
                content = chk.get('checksumValue', '')
                
                # Align SPDX naming (SHA256) with CycloneDX standard (SHA-256)
                if algo.startswith('SHA') and not algo.startswith('SHA-'):
                    algo = algo.replace('SHA', 'SHA-')
                    
                extracted_hashes[algo] = content

            # Normalize the component
            norm_comp = NormalizedComponent(
                name=pkg.get('name', 'Unknown'),
                version=pkg.get('versionInfo', 'Unknown'),
                publisher=pkg.get('supplier', 'Unknown'),
                author=pkg.get('originator', 'Unknown'),
                purl=extracted_purl,
                component_type=pkg.get('primaryPackagePurpose', 'Unknown').lower(),
                hashes=extracted_hashes,
                properties=[], 
                licenses=extracted_licenses 
            )
            self.components.append(norm_comp)
            
        print(f"[ENGINE] Normalized {len(self.components)} SPDX packages.\n")
        return self.components

# ==========================================
# 3. DYNAMIC PLUGIN MANAGER
# ==========================================
def discover_plugins(plugin_dir="plugins"):
    available_plugins = []
    if not os.path.exists(plugin_dir):
        os.makedirs(plugin_dir)
        return available_plugins

    for filename in os.listdir(plugin_dir):
        if filename.endswith(".py"):
            module_name = filename[:-3]
            filepath = os.path.join(plugin_dir, filename)

            spec = importlib.util.spec_from_file_location(module_name, filepath)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            for name, obj in inspect.getmembers(module, inspect.isclass):
                if obj.__module__ == module.__name__:
                    try:
                        instance = obj()
                        if hasattr(instance, 'run') and hasattr(instance, 'name'):
                            available_plugins.append({
                                "id": module_name,
                                "name": instance.name,
                                "instance": instance
                            })
                    except Exception:
                        pass
                        
    return available_plugins

# ==========================================
# 4. EXECUTION & CLI ROUTING
# ==========================================
if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] in ['-h', '--help']:
        print("[!] Usage: python3 sbom_engine.py <path_to_sbom.json> [--log output.log] [plugin_id_1 plugin_id_2]")
        print("           Leave plugin arguments blank to view available options")
        print("")
        print("    Example: python3 sbom_engine.py ./sample_sboms/app_bom.json plugin_name1")
        print("    Example: python3 sbom_engine.py ./sample_sboms/app_bom.json --log results.txt")
        sys.exit(1)
        
    # Check for the optional --log flag and extract the filename
    log_file = None
    if "--log" in sys.argv:
        try:
            log_idx = sys.argv.index("--log")
            log_file = sys.argv[log_idx + 1]
            
            # Remove the flag and filename from sys.argv so plugin parsing isn't disrupted
            sys.argv.pop(log_idx)
            sys.argv.pop(log_idx)
            
            # Attach our custom logger to sys.stdout
            sys.stdout = DualLogger(log_file)
        except IndexError:
            print("[!] Error: The --log flag requires a filename (e.g., --log results.txt)")
            sys.exit(1)

    # Normalize the path for cross-platform compatibility
    target_file = os.path.normpath(sys.argv[1])
    requested_plugins = sys.argv[2:] 
    
    engine = SBOMParser(target_file)
    normalized_data = engine.load()
    
    if not normalized_data:
        sys.exit(1) 

    discovered = discover_plugins()
    if not discovered:
        print("⚠️ No plugins found in the 'plugins' directory.")
        sys.exit(0)

    plugins_to_run = []

    if requested_plugins:
        for req in requested_plugins:
            match = next((p for p in discovered if p["id"] == req), None)
            if match:
                plugins_to_run.append(match)
            else:
                print(f"[!] Warning: Plugin '{req}' not found.")
    else:
        print("========================================")
        print(" 🧩 AVAILABLE COMPLIANCE PLUGINS")
        print("========================================")
        for idx, p in enumerate(discovered):
            print(f"  [{idx + 1}] {p['name']} (ID: {p['id']})")
        print(f"  [{len(discovered) + 1}] Run All Modules")
        
        print("\nType the numbers of the modules to run (comma-separated), or press Enter to exit.")
        choice = input("➜ ")

        if not choice.strip():
            print("Execution cancelled.")
            sys.exit(0)

        choices = [c.strip() for c in choice.split(',')]
        for c in choices:
            if c.isdigit():
                num = int(c)
                if num == len(discovered) + 1:
                    plugins_to_run = discovered
                    break
                elif 1 <= num <= len(discovered):
                    plugins_to_run.append(discovered[num-1])

    print("\n" + "="*40)
    for p in plugins_to_run:
        plugin = p["instance"]
        plugin.run(normalized_data)
        
        print("-" * 40)
        print(f"📋 RESULTS: {plugin.name} 📋")
        print("-" * 40)
        
        if not plugin.findings:
            print("✅ Clean: No policy violations found.\n")
        else:
            # --- THE LOOP: Prints the individual findings ---
            for finding in plugin.findings:
                component_name = finding.get("Component", "Unknown Component")
                print(f"⚠️ Flagged: {component_name}")
                
                for key, value in finding.items():
                    if key != "Component":
                        formatted_key = str(key).capitalize() if key.islower() else key
                        print(f"   {formatted_key}: {value}")
                print("")
            
            # --- THE SUMMARY ---
            if hasattr(plugin, 'summary') and plugin.summary:
                print("-" * 40)
                print(f"📊 PLUGIN SUMMARY: {plugin.summary}")
                print("-" * 40 + "\n")