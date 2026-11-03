# Third-Party Notices

The project is licensed under Apache License 2.0; this notice lists direct
dependencies and other identified third-party material. Each third-party
component remains subject to its own license and notices. This summary does not
replace those license texts.

## Backend dependencies

Versions below are from `requirements-lock.txt` where pinned. License
identifiers are based on the projects' published licensing information.

| Component | Locked version | License |
| --- | --- | --- |
| FastAPI | 0.142.2 | MIT |
| httpx | 0.28.1 | BSD-3-Clause |
| Matplotlib | 3.11.2 | PSF |
| NumPy | 2.5.3 | BSD-3-Clause and additional licenses for bundled components |
| pandas | 3.0.6 | BSD-3-Clause |
| Pydantic | 2.13.5 | MIT |
| pytest | 9.1.1 | MIT |
| python-dotenv | 1.2.4 | BSD-3-Clause |
| PyYAML | 6.0.3 | MIT |
| ReportLab | 5.0.1 | BSD-3-Clause |
| SQLAlchemy | 2.1.3 | MIT |
| Uvicorn | Declared in `requirements.txt` | BSD-3-Clause |

## Frontend dependencies

Versions and SPDX license identifiers are taken from `frontend/package-lock.json`.

| Component | Locked version | License |
| --- | --- | --- |
| `@vitejs/plugin-react` | 4.7.0 | MIT |
| React | 18.3.1 | MIT |
| React DOM | 18.3.1 | MIT |
| Recharts | 2.15.4 | MIT |
| Vite | 5.4.21 | MIT |

The lockfiles also include transitive dependencies. Review their package
metadata and retain their license and attribution notices when redistributing
bundles or other distributions.

## MITRE ATT&CK

This project references MITRE ATT&CK tactics and technique identifiers for
detection mapping. ATT&CK is a MITRE resource and trademark; its use is subject
to the [MITRE ATT&CK Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/).
The required attribution for reproduced ATT&CK material is:

> © 2026 The MITRE Corporation. This work is reproduced and distributed with
> the permission of The MITRE Corporation.

This project is not endorsed by MITRE.

## Included sample data

Per [`data/DATASET.md`](data/DATASET.md), the bundled event datasets and the
`LAB-TI` threat-intelligence feed are controlled synthetic samples created for
development and testing. The feed uses reserved documentation IP addresses;
it is not a live threat-intelligence feed. No external public dataset or
third-party threat feed is identified in the current repository. Verify any
future dataset or feed's license, attribution, and redistribution terms before
including it.
