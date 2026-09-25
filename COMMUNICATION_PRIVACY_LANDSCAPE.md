# Communication Privacy Testing: Competitive and Collaboration Landscape

**Research date:** 25 September 2026<br>
**Scope:** Consumer and cross-platform chat apps, email clients, webmail, and adjacent privacy/security evaluation tools.

## Executive conclusion

I did **not** find a mature, independent, continuously updated project that combines chat apps and email clients in one reproducible public pass/fail matrix comparable to [PrivacyTests.org](https://privacytests.org/).

The gap is real, but the opportunity is narrower than “build another privacy scorecard.” The defensible position is:

> **An open, versioned, behavioral test program that measures communication tools under explicit threat models and configurations, publishes reproducible evidence, and tracks remediation over time.**

The closest existing assets are complementary rather than a single competitor:

- [PrivacyTests.org](https://privacytests.org/) supplies the benchmark model: default-settings tests, simple pass/fail outcomes, open code, and longitudinal results.
- [Email Privacy Tester](https://www.emailprivacytester.com/) supplies the strongest existing email-client canary suite.
- [Honeymessages](https://github.com/honeymessages/honeymessages-framework) supplies a proven black-box method for detecting whether messenger services inspect or crawl message content.
- [Mozilla Nothing Personal](https://www.mozillafoundation.org/en/nothing-personal/) is the closest current consumer editorial competitor, but it reviews only three messengers and does not publish an executable benchmark.
- [OpenWPM](https://github.com/openwpm/OpenWPM), [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF), and [Exodus Privacy](https://github.com/Exodus-Privacy/exodus) provide reusable measurement components rather than a communication-tool leaderboard.

The main barrier is not the results website. It is sustaining a reproducible lab across app versions, operating systems, account types, network locations, and provider-specific behavior.

## Market taxonomy

The landscape falls into four categories:

1. **Behavioral benchmark:** executable tests, comparable runs, longitudinal public results.
2. **Editorial scorecard/review:** expert or policy-based ratings with limited reproducibility.
3. **Research framework:** strong methodology and artifacts, but usually a one-off study.
4. **Infrastructure/component:** generic static/dynamic analysis that can be incorporated into a benchmark.

A communications benchmark should combine category 1 with carefully selected components from categories 3 and 4, while borrowing evaluation criteria from category 2.

## Direct and near-direct competitive landscape

| Project | Owner | Coverage and method | Reproducibility and public results | Status as of 25 Sep 2026 | Competitive implication |
|---|---|---|---|---|---|
| [PrivacyTests.org](https://privacytests.org/) | Arthur Edelstein, independent | Automated browser privacy tests under default settings; large unified pass/fail/unsupported matrix, displayed as “No. 101” | Fully open source, MIT; raw results and independently runnable tests | **Active.** Site updated 22 Sep 2026; repository has about 1.2k stars | The format and governance benchmark. It also demonstrates that vendors respond to longitudinal public evidence. It does not test communication tools. |
| [Email Privacy Tester](https://www.emailprivacytester.com/) | Mike Cardwell / Grepular | Sends crafted test email to a user's inbox and detects remote loading through HTTP, DNS, SNI, TCP, HTML/MIME, calendar, vCard, attachment, SVG, prefetch, preconnect, and related vectors | Self-hostable and open source; the current repository metadata declares GPL-3.0; dynamic results for one test account, but no maintained cross-client public leaderboard | **Active.** GitLab activity on 14 Aug 2026; source contains extensive 2026 additions | The closest email competitor and the best immediate upstream collaborator. It tests a client configuration, not a normalized product matrix. |
| [Honeymessages](https://github.com/honeymessages/honeymessages-framework) | TU Braunschweig researchers | Black-box honey messages, monitored pages, unique URLs/emails, HTTP(S), WebSocket, and WebRTC observations; the paper evaluated 105 platforms | MIT executable artifact; paper documents methodology and findings, but there is no current consumer leaderboard | **Research artifact.** Last repository push 13 Jul 2024 | Strongest reusable chat-side methodology and a potential research partner. Needs productization, broader coverage, and recurring runs. |
| [Mozilla Nothing Personal](https://www.mozillafoundation.org/en/nothing-personal/) | Mozilla Foundation | Hands-on reviews of Signal, iMessage, and WhatsApp; 20 hours per initial messenger review; package inspection plus Charles Proxy/Wireshark; 10-point score covering defaults, collection, track record, and mitigability | Public editorial pages, but not public executable tests or raw lab artifacts | **Active.** Launched Oct 2025; detailed methodology published 15 Jul 2026 | Closest attention and trust competitor for messenger reviews. Limited to three products, email is absent, and the aggregate score is manual. |
| [Privacy Not Included](https://www.mozillafoundation.org/en/nothing-personal/privacy-not-included-sunset/) | Mozilla Foundation | Broad consumer privacy buyer’s guide based primarily on public research and policy review | Public editorial archive; no executable benchmark | **Archived 11 Aug 2026** in favor of Nothing Personal product reviews | Demonstrates demand for consumer privacy guidance, but also why Mozilla moved from broad checklists toward hands-on testing. |
| [EFF Secure Messaging Scorecard](https://www.eff.org/pages/secure-messaging-scorecard) | EFF, ProPublica, Princeton | More than 30 chat, email, voice, and messaging products in 2014; seven feature/evidence criteria | Public but historical; not behaviorally reproducible | **Retired and explicitly described as out of date.** EFF warned that a single scorecard oversimplifies security | Important negative lesson: avoid a one-number “privacy score” and avoid treating cryptographic claims as measured behavior. |
| [Privacy Guides: email clients](https://www.privacyguides.org/en/email-clients/) and [real-time communication](https://www.privacyguides.org/en/real-time-communication/) | Privacy Guides nonprofit community | Expert criteria for open source, encryption, identifiers, forward secrecy, audits, threat models, and developer self-submission | Public content and open source; recommendations are reviewed by multiple people, but not automatically tested | **Active.** Pages updated 24 May 2026; repository active 24 Sep 2026 | Strong criteria and distribution partner, but it deliberately recommends a small set of qualifying products rather than ranking the whole market. |

## Adjacent consumer and commercial competitors

| Project | Inputs and output | What it does well | Gap for a PrivacyTests-style communication benchmark |
|---|---|---|---|
| [Harvard Transparency Hub](https://hub.transparency.berkmancenter.org/) | Archived privacy policies, terms, community standards, and transparency reports; over 300 companies and roughly 20,000 documents | Excellent longitudinal policy dataset and comparison UI | Policy documents are not runtime behavior. Useful as a policy-conformance data source, not as the core test engine. AGPL-3.0. |
| [Incogni Social Media Privacy Ranking 2025](https://blog.incogni.com/social-media-privacy-2025) | 15 major social/chat platforms scored on 14 criteria covering policies, app-store data, AI use, controls, fines, and deletion | Clear methodology and broad consumer presentation | Mostly declarations and app-store metadata; no controlled behavioral experiment. Commercial incentive to sell data-removal services. |
| [Surfshark messaging-app study](https://surfshark.com/research/chart/messaging-apps-privacy) | Ten popular iOS messaging apps; encryption claims, app-store data types, tracking, and AI features | Current, easy-to-read comparison | Static evidence and vendor claims, not observed traffic or default-client behavior. Commercial editorial content. |
| [Consumer Reports](https://www.consumerreports.org/) and major technology publications | Buying guides, Signal usage advice, and feature reviews | Strong consumer usability and security expertise | I found no living, cross-product, reproducible communication privacy benchmark comparable to PrivacyTests.org. Most current output is editorial. |
| [AppCensus](http://appcensus.io/) | Commercial static/dynamic analysis of mobile-app permissions, SDKs, network transfers, versions, and store-label consistency | Mature B2B privacy-engineering workflow and version comparisons | Subscription product aimed at app owners and privacy teams; not a public consumer communications leaderboard. Methodology and results are not fully open. |
| Enterprise email-security gateways such as [Proofpoint](https://www.proofpoint.com/us/products/email-dlp-encryption) and [Mimecast](https://www.mimecast.com/products/email-security) | DLP, anti-phishing, attachment scanning, encryption, archiving, and compliance controls | Real enterprise budgets and operational integration | They test organizational security and data-loss controls, not whether a consumer communication client exposes the user to tracking or metadata. Different buyer and threat model. |
| OONI and connectivity tests | Reachability, censorship, DNS, and network-access measurements | Strong global measurement operations | Tests whether communication is accessible, not whether it is private. Useful supporting infrastructure, not a privacy benchmark. |

## Reusable research and infrastructure

| Project | Best use in this project | License/status | Important limitation |
|---|---|---|---|
| [PrivacyTests.org source](https://github.com/privacytests/privacytests) | Result schema, test-runner structure, evidence presentation, versioned comparisons, and project governance | MIT; highly active | Written around browsers; requires a new identity/config model for communications |
| [Honeymessages framework](https://github.com/honeymessages/honeymessages-framework) | Messenger content-processing and link-preview canaries | MIT; research artifact from 2024 | Framework is not a maintained benchmark; attribution rules and anti-abuse controls need productization |
| [Email Privacy Tester v3](https://gitlab.com/grepular/ept3) | Email MIME/HTML vectors plus HTTP, DNS, SNI, and TCP watchers | GPL-3.0 per current repository metadata; active | Confirm relicensing and attribution terms before adapting the corpus; existing interface is per-account rather than comparative |
| [OpenWPM](https://github.com/openwpm/OpenWPM) | Webmail HTML/JavaScript, storage, cookies, requests, and browser instrumentation | GPLv3; active in Sep 2026 | Web-only and not designed for native email clients or mobile apps |
| [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) | APK/IPA static analysis, permissions, SDKs, endpoints, and dynamic mobile testing | GPLv3; very active | General security scanner, not a longitudinal privacy benchmark; certificate pinning and iOS automation remain difficult |
| [Exodus Privacy](https://github.com/Exodus-Privacy/exodus) | Android tracker classification, APK reports, and community-maintained tracker knowledge | AGPL-3.0; active nonprofit infrastructure | Primarily static Android analysis; a presence finding does not prove a tracker activated or received user data |
| [Princeton CITP email-tracking artifacts](https://github.com/citp/email_tracking) | Research corpus, OpenWPM methodology, and findings on embedded email trackers | Code/data from PETS 2018; not recently updated and no repository license detected | Valuable research, not a maintained production test runner |
| [2026 Android messenger comparison](https://arxiv.org/abs/2603.29668) | Reproducible scenarios, MobSF integration, kernel-level network attribution, permissions, and ten-run methodology | CC BY 4.0 paper; code/data on Zenodo | One Android study of three apps from one location; not a recurring public service |
| [FCM push-notification study](https://petsymposium.org/popets/2024/popets-2024-0151.php) | Test design for observing data sent to Google’s push infrastructure | 2024 paper and supplemental artifacts | Android-specific; reproducing FCM interception requires substantial instrumentation |

### License decision

All new first-party code will be licensed under **AGPL-3.0-only**. The strongest reusable components use mixed licenses:

- PrivacyTests.org and Honeymessages are MIT-licensed and can be adapted with attribution.
- Email Privacy Tester, OpenWPM, and MobSF are GPLv3-family projects. Combining them with AGPL-covered first-party work requires preserving all notices and applying the AGPL's corresponding-source and network-use terms to the combined covered work; obtain legal review before distribution.
- Exodus Privacy and Harvard Transparency Hub are AGPLv3-family projects.
- Some useful automation tools, including Appium and Playwright, use Apache-2.0. Apache-2.0 is generally compatible with AGPL-3.0-only when its notices, attribution, patent, and license requirements are preserved. Keep externally served tools separately licensed where that simplifies operations, but do not present process isolation as an automatic exemption; have counsel confirm the boundary.

Preserve upstream notices, generate an SBOM and license manifest, and avoid presenting process isolation as an automatic exemption. For distributed copies and network use, provide the corresponding AGPL source and notices as required by the license.

## Where the market is open

A credible new product can own the intersection of these properties:

1. **Behavioral rather than policy-based:** execute the same controlled scenarios against each tool.
2. **Chat and email in one program:** apply shared evidence, provenance, and UI conventions while keeping channel-specific tests.
3. **Configuration-aware:** identify each result by product, platform, version/build, provider/account type, network vantage, and default versus hardened configuration.
4. **Threat-model-specific:** show which adversary or observer a test addresses.
5. **No opaque global score:** use per-test `pass`, `fail`, `inconclusive`, `not applicable`, and `unsupported` outcomes.
6. **Evidence provenance:** publish test versions, timestamps, package hashes, sanitized traces, analysis code, and repeat counts.
7. **Longitudinal:** preserve historical results and show remediation or regression after updates.
8. **Independently reproducible:** another lab or researcher can rerun the suite.
9. **Vendor-responsive but impartial:** give providers a bounded verification/remediation window without giving them veto power.

The important strategic distinction is **configuration-aware measurement**. Chat products often tightly couple client and service. Email clients usually separate client, account provider, OAuth scopes, and mail server. A row labeled merely “Thunderbird” or “Outlook” is scientifically ambiguous. The benchmark should use subjects such as:

`Thunderbird 141 on macOS 15 + Gmail consumer account + default settings`

rather than collapsing all variables into a product logo.

## Recommended collaboration shortlist

### Tier 1: co-design and core technology

1. **PrivacyTests.org / Arthur Edelstein**
   - Best fit for benchmark methodology, longitudinal result design, reproducibility, vendor engagement, and governance.
   - The existing project is MIT-licensed and explicitly invites contributions.
   - Public contact: `contact@privacytests.org`.
   - [Project](https://privacytests.org/about) · [USENIX presentation](https://www.usenix.org/conference/pepr23/presentation/edelstein)

2. **Email Privacy Tester / Mike Cardwell**
   - Best fit for the email test corpus, MIME edge cases, DNS/SNI observation, and self-hostable infrastructure.
   - Project is active and technically much closer to email privacy than any editorial scorecard.
   - Collaboration should agree on GPLv3 compatibility and maintenance ownership early.
   - [Project](https://www.emailprivacytester.com/about) · [Source](https://gitlab.com/grepular/ept3)

3. **Honeymessages / TU Braunschweig**
   - Best fit for black-box chat canaries, link-preview analysis, and academic validation.
   - MIT artifact lowers reuse friction; Robin Kirchner’s current profile explicitly lists messenger privacy as a research area.
   - [Paper](https://petsymposium.org/popets/2024/popets-2024-0099.php) · [Artifact](https://github.com/honeymessages/honeymessages-framework) · [Author contact](https://www.tu-braunschweig.de/en/ias/staff/robin-kirchner)

4. **OpenWPM maintainers**
   - Best fit for webmail and browser-rendering measurements and a proven model for privacy measurement infrastructure.
   - Active in 2026; GPLv3.
   - [Project](https://github.com/openwpm/OpenWPM)

### Tier 2: methodology review, independent validation, and distribution

5. **Privacy Guides**
   - Review threat models, product-selection criteria, and usability; potentially link to or publish benchmark findings while retaining editorial independence.
   - [Contact and criteria](https://www.privacyguides.org/en/about)

6. **EFF and the Citizen Lab**
   - Useful for threat-model review, responsible disclosure, vendor accountability, and independent replication. EFF’s own retirement of the Secure Messaging Scorecard is essential design guidance.
   - [EFF messaging lessons](https://www.eff.org/deeplinks/2018/03/secure-messaging-more-secure-mess) · [EFF contact](https://www.eff.org/about/contact) · [Citizen Lab research](https://citizenlab.ca/research/)

7. **Mozilla Foundation / Nothing Personal**
   - Potential editorial reach and methodological exchange. Their three-app hands-on review program is the nearest public precedent.
   - Independence, funding, and publication rights should be explicit to preserve credibility.
   - [Methodology](https://www.mozillafoundation.org/en/nothing-personal/privacy-review-methodology)

8. **Harvard Applied Social Media Lab / Transparency Hub**
   - Policy-history data source and research collaborator for comparing observed behavior with public claims.
   - AGPL-3.0; formal research access is available.
   - [Researchers](https://hub.transparency.berkmancenter.org/about/researchers)

### Tier 3: engineering components or specialist validation

9. **MobSF and Exodus Privacy maintainers** for native-app analysis, tracker classification, and Android permissions.
10. **UC Berkeley/ICSI push-notification researchers** for FCM payload test design and Android instrumentation expertise.
11. **AUEB/NTUA Android measurement researchers** for the 2026 static/dynamic messenger methodology.
12. **Academic or regional device labs** for independent replication from different network vantage points.

## Collaboration model and governance

A neutral consortium is stronger than a single organization owning the methodology.

Recommended safeguards:

- Publish a conflict-of-interest and funding policy before accepting a communication vendor as a sponsor.
- Give sponsors access to the same public methodology and dashboards as everyone else.
- Allow vendors to verify attribution and submit remediation evidence, but not to remove or delay adverse results.
- Version every test. Never rewrite a historical result after methodology changes.
- Publish a pre-publication review window, with security-sensitive issues handled separately.
- Require two independent reviewers for test promotion and result adjudication.
- Use synthetic accounts, synthetic contacts, and canary domains; never collect real-user communications.
- Publish failed, inconclusive, and flaky tests alongside successful ones.
- Make the test corpus and raw sanitized evidence downloadable in machine-readable formats.

## Recommended first product wedge

Start with email because it is easier to instrument reproducibly and has an existing FOSS upstream:

1. Adapt the Email Privacy Tester corpus under an agreed license.
2. Test five clearly defined configurations, for example:
   - Apple Mail + Gmail consumer account
   - Thunderbird + the same Gmail account
   - FairEmail + the same account through IMAP
   - Gmail web
   - Outlook web + Microsoft consumer account
3. Publish a small set of defensible tests:
   - remote content on message open
   - DNS prefetch and SNI/preconnect leakage
   - IP and user-agent exposure
   - content fetched from calendar, vCard, SVG, and nested messages
   - background/prefetch behavior
   - link warning and referrer behavior
4. Run enough repetitions to report confidence and platform variance.
5. Add a chat pilot using Honeymessages for three controlled messenger accounts and the FCM test design.
6. Only after the evidence pipeline is stable, add policy-conformance and store-label comparison.

This produces a credible public artifact early instead of attempting a full cross-platform matrix before the lab is reproducible.

## Product and research cautions

- **Do not publish one overall privacy grade.** EFF explicitly rejected that model after user research and methodological criticism.
- **Do not claim E2EE from a black-box traffic test alone.** Protocol claims, source review, and audits are evidence classes, not runtime pass/fail tests.
- **Do not conflate provider, client, OS, CDN, and push service.** Attribution is a first-class research problem.
- **Do not compare “Gmail” with “Proton” as if they were the same layer.** Separate service, account configuration, and client.
- **Expect A/B tests and regional behavior.** A single run is not a stable product property.
- **Treat certificate pinning, ECH, QUIC, and native TLS as measurement constraints**, not automatically as privacy failures.
- **Review terms of service and app-store rules before automation.** Use dedicated research accounts and document the basis for each interaction.
- **Publish remediation history.** A benchmark that only shames products will be less effective than one that rewards verified improvement.

## Strategic moat

The weak moat would be a pretty scorecard or a proprietary questionnaire. The durable moat is the accumulated evidence system:

- reproducible test corpus;
- controlled accounts and device lab;
- configuration and version provenance;
- longitudinal result dataset;
- independent replication network;
- trusted methodology and remediation history;
- strong vendor and academic relationships.

## Primary sources

- [PrivacyTests.org results and about page](https://privacytests.org/about)
- [PrivacyTests.org source](https://github.com/privacytests/privacytests)
- [Email Privacy Tester](https://www.emailprivacytester.com/)
- [Email Privacy Tester source](https://gitlab.com/grepular/ept3)
- [Honeymessages paper](https://petsymposium.org/popets/2024/popets-2024-0099.php)
- [Honeymessages source](https://github.com/honeymessages/honeymessages-framework)
- [Mozilla Nothing Personal](https://www.mozillafoundation.org/en/nothing-personal/)
- [Mozilla review methodology](https://www.mozillafoundation.org/en/nothing-personal/privacy-review-methodology)
- [Privacy Not Included archive notice](https://www.mozillafoundation.org/en/nothing-personal/privacy-not-included-sunset/)
- [EFF Secure Messaging Scorecard](https://www.eff.org/pages/secure-messaging-scorecard)
- [EFF: why the scorecard was retired](https://www.eff.org/deeplinks/2018/03/secure-messaging-more-secure-mess)
- [Privacy Guides real-time communication](https://www.privacyguides.org/en/real-time-communication/)
- [Privacy Guides email clients](https://www.privacyguides.org/en/email-clients/)
- [Harvard Transparency Hub](https://hub.transparency.berkmancenter.org/)
- [Incogni Social Media Privacy Ranking 2025](https://blog.incogni.com/social-media-privacy-2025)
- [Surfshark messaging-app study](https://surfshark.com/research/chart/messaging-apps-privacy)
- [OpenWPM](https://github.com/openwpm/OpenWPM)
- [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF)
- [Exodus Privacy](https://github.com/Exodus-Privacy/exodus)
- [Princeton CITP email tracking artifacts](https://github.com/citp/email_tracking)
- [FCM push-notification study](https://petsymposium.org/popets/2024/popets-2024-0151.php)
- [2026 Android messenger comparison](https://arxiv.org/abs/2603.29668)

## Research limitations

- This is a public-source landscape review, not an exhaustive census of private/internal projects.
- Search results contained numerous new commercial and SEO-oriented “privacy score” sites. Projects without traceable authorship, primary evidence, or executable methodology were not treated as authoritative competitors.
- Repository activity dates were checked through GitHub/GitLab APIs where available. A recent commit does not by itself establish sustained maintenance, product quality, or organizational sustainability.
- This report is product and research strategy, not legal advice. License compatibility, account terms, privacy laws, and interception rules should be reviewed by qualified counsel before implementation.
