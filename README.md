# Comparative Study of Endpoint Protection Systems Against Common Malware Attacks

An empirical evaluation framework designed to quantify the detection capability, cloud telemetry dependency, resource overhead, and post-remediation recovery metrics of commercial Endpoint Protection Systems (EPS) against a stratified corpus of 2,000 active malware samples.

## 🔬 Experimental Parameters
- **Target Operating System:** Microsoft Windows 11 Workstation base state.
- **Tested Platforms:** Windows Defender, Malwarebytes Premium, Kaspersky Endpoint Security, CrowdStrike Falcon.
- **Corpus Dimension:** 2,000 unique cryptographic payloads (Ransomware, Trojans, Spyware, Worms, Rootkits, Fileless Scripts).
- **Stratification Method:** Evaluated into distinct tiers derived from historical VirusTotal analytical engine detection counts:
  - **Known Stratum:** >= 40 active scanning engines flagged positive.
  - **Moderate Stratum:** 6 to 39 active scanning engines flagged positive.
  - **Zero-Day Stratum:** 0 to 5 active scanning engines flagged positive.

## 📂 Repository Directory Layout
- `/pipeline`: Hosts `replicate_pipeline.py` which interfaces with external APIs to fetch dataset metadata and handle routing criteria.
- `/artifacts`: Contains PowerShell network isolation modules for Arm B configurations and structural documentation mapping ETW telemetry parameters.

## 🚀 Execution Blueprint
To run the validation pass of the automated classification pipeline engine, establish your environment credentials and execute:
```bash
python pipeline/replicate_pipeline.py

```
📝 Authors and Research Affiliation
Efi, Asianabasi Enefiok (efiasianabasi@gmail.com)

Department of Computer Engineering, Faculty of Engineering, University of Uyo, Akwa Ibom State, Nigeria.
