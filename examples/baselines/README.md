# Runs the examples use

The `loot-host/` directories of the 17 stock-install runs that
`examples/fleet` and `examples/fleet-zones` take as their hosts and as the
stock installs they compare against. They are copied unchanged from
[firru-os-baselines](https://github.com/ouspg/firru-os-baselines) (commit
f1f9f8ba), where each run also has its recipe, provenance, scans and traffic.

The layout is that of a firru-os-baselines checkout, so `FIRRU_BASELINES`
can point here. The file times are those of your checkout, not of the
collection; the run's `recipe/PROVENANCE` in firru-os-baselines records when
it ran.

The data are licensed under
[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) by firru-os-baselines,
not under firru's Apache License. Text collected from the installed systems
(firewall rule names and descriptions, package metadata) remains its authors'.
