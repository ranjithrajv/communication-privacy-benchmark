# Email Privacy Tester Deployment

The canonical email wedge will run a pinned upstream Email Privacy Tester source commit
and image digest behind a private authenticated gateway. The Python harness correlates
an opaque EPT test code with its run/probe ID and adjudicates exported observations.

Do not call undocumented EPT routes directly from benchmark code, access its database,
scrape its UI, or use its public SaaS for canonical measurements. Preserve GPL notices
and corresponding source when distributing the upstream application or modifications.
