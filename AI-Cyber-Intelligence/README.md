┌─────────────────────────────────────────────────────┐
│              ATTACK SIMULATION LAYER                │
│         Atomic Red Team (Windows VM)                │
│    Simulates real APT techniques safely             │
└──────────────────┬──────────────────────────────────┘
                   │ generates events
        ┌──────────▼──────────┐
        │   DETECTION LAYER   │
        │  Wazuh (SIEM/EDR)   │◄── receives logs
        │  Velociraptor (DFIR)│◄── forensic collection
        └──────────┬──────────┘
                   │ alerts feed into
        ┌──────────▼──────────┐
        │  INTELLIGENCE LAYER │
        │  MITRE ATT&CK       │
        │  Navigator          │
        │  Maps coverage gaps │
        └──────────┬──────────┘
                   │ informs
        ┌──────────▼──────────┐
        │   RESPONSE LAYER    │
        │  IR Playbooks       │
        │  Incident Reports   │
        │  GitHub Portfolio   │
        └─────────────────────┘