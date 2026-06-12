# Tool 2 - SBOM Normalization and Parsing Engine with Plugin Support

> **Warning:** This is a project made by a dude in a random class for a proof-of-concept project. Do not actually make decisions based on this.

## About
Software Bill of Materials (SBOMs) are a newer concept where software ships with an attestation of what dependencies and components are used in the codebase. The two most common formats are SPDX and CycloneDX. 

This project is designed to normalize the output between these two formats and create a framework where plugins can be utilized.

## Prerequisites
This project should work with just Python 3 and does not require any non-standard libraries. 

## Project Structure
```text
.
├── .gitignore
├── README.md
├── sbom_engine.py
├── plugins/
│   ├── chinese_origin_risk.py
│   └── copyleft_finder.py
└── sample_sboms/
    ├── Alibaba_Dragonwell_Standard_25.0.3.0.3.9_aarch64_linux-sbom.json
    ├── apache_rocketmq_cyclonedx.json
    ├── apache_rocketmq_spdx.json
    └── Python-3.12.13.tgz.spdx.json
```

## Usage

1. Clone the repository:
```bash
git clone https://github.com/jaustin1928/tool-2/
cd tool-2
```

To run the tool, call the engine, pass the path to the SBOM, and provide the names of the plugins that are located in the plugins directory:
```bash
python3 sbom_engine.py <path\to\sbom> [plugin-name-1 plugin-name-2]
```

You can also interactively select the plugin by leaving the plugin-name arguments blank:
```bash
python3 sbom_engine.py <path\to\sbom> 
```

## Test
I have provided some sample SBOMs in the `sample_sboms` directory. Feel free to find additional SBOMs on your own. the Alibaba and two rocketmq SBOMs should flag as Chinese origin.

Example usage: 
```bash
python3 sbom_engine.py .\sample_sboms\Alibaba_Dragonwell_Standard_25.0.3.0.3.9_aarch64_linux-sbom.json
```