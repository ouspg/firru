"""
firru — Network policy generation toolkit for aerleon.

Library modules:
    firru.tokens       Token normalisation and IP utilities
    firru.ss           Linux ss output parsing
    firru.discovery    Host data discovery (Linux ss / Windows CSV)
    firru.site_profile  What site/ says: heuristics.py and policy.py as one Profile
    firru.annotator    IP → aerleon token resolution via prefix trees
    firru.arkime       Arkime session API client and flow normalisation
    firru.githist      Git-history blob/tree readers
    firru.iptrees      CIDR-set membership via prefix trees (firru.prefixes)
    firru.comments     Tag-aware policy comment handling (the comment contract)
    firru.policy       Port-surface resolver + diff classification

CLI entry points (installed via pyproject.toml):
    firru               The policy-YAML editing core. Verbs:
      firru synth         loot JSON → staged host policy YAML
      firru propose       edits from observed flows, as tagged firru commands
      firru check         what a policy refuses of the traffic, answered or not
      firru merge-zones   per-host policies → per-zone firewall policy
      firru diff          preview / emit-commands for a policy delta
      firru add-term      copy a term by name from a proposal or loot
      firru set-source    set a term's source-address
      firru rm            remove a term

    Acquisition (ss/pcap → JSON):  loot-listeners, audit-services, loot-flows, …
    Converters (aerleon YAML → target):  aerleon-to-nftables, -calico, -vyos, …
"""
