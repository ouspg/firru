# firru edit-services add def/funny.yml TCP_4949 4949/tcp  # unnamed: munin-nodex1; 1 host(s)
# + HTTP 80/tcp  (apache2; 1 host(s)) beyond the baseline
# + SSH 22/tcp  (sshd; 1 host(s)) beyond the baseline
firru synth --input loot/ --output policies/staged --defs def --overwrite
firru diff policies/pol/mon1.yml policies/staged/mon1.yml --defs def
firru diff policies/pol/web1.yml policies/staged/web1.yml --defs def
firru diff policies/pol/win1.yml policies/staged/win1.yml --defs def
