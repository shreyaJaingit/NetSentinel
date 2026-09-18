# NetSentinel - Data Directory

This directory stores datasets used for training and evaluating NetSentinel models.

## Security & Data Handling Rules
1. **Never commit raw datasets**: Large CSV and PCAP files are ignored by `.gitignore` to prevent repository bloat and accidental data exposure.
2. **Offline Only**: Only authorized, offline datasets (e.g., CIC-IDS2017, UNSW-NB15) should be placed here.
3. **No Sensitive Records**: Do not store real personal identifiers, enterprise credentials, or internal production packet captures here.
4. **Provenance**: In Phase 1, we will document the exact dataset source, version, license, and sampling script before processing.
