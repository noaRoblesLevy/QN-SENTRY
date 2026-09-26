# 8. Risks and Mitigation

| Risk | Likelihood | Impact | Mitigation / fallback |
|---|---|---|---|
| **Scope too large** for the available time | Medium | High | MoSCoW prioritisation (*Must/Should/Could*); end-to-end MVP by week 3; feature freeze on 25/10. *Should* features are dropped first. |
| **Integration problems** between modules | Medium | High | Common data model and finding format defined in week 1; first end-to-end integration in week 3 instead of at the end. |
| **External sources unavailable or rate-limited** (crt.sh is regularly slow; HIBP requires a paid API key) | High | Medium | Timeouts, retries and caching; alternative Certificate Transparency source (e.g. Cert Spotter API); local breach test dataset for the demo. |
| **New domains not yet visible** in passive OSINT sources | Medium | Medium | Register domains in week 1; supplement passive discovery with DNS brute-forcing using a wordlist (dnsx). |
| **Tool output changes** or tools behave inconsistently | Low | Medium | Each tool is wrapped in its own module using JSON output; tool versions are pinned in the Docker images. |
| **Learning curve** of React, Celery or unfamiliar tools | Medium | Medium | Use a ready-made UI component library; start with a minimal version; share knowledge through code reviews. |
| **Google Cloud costs** exceed the available credits | Low | Low | A single small VM; budget alert in Google Cloud; shut down the VM when not in use. |
| **Team member unavailable** (illness, workload of other courses) | Medium | High | Code reviews so both members know the whole codebase; documentation kept up to date; problems reported to the lecturer early. |
| **Accidental scanning of third parties** | Low | High | Target allowlist enforced by the platform; tests exclusively on our own domains. |
| **Live demo fails** (network, cloud, external sources) | Medium | High | Backup demo video; pre-computed scan results available in the dashboard; demo rehearsed in advance. |
