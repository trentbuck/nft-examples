These are my example Linux firewalls.

The nftables ones are from 2020:

:nftables-host.nft: basic server firewall.  Dual stack.
:nftables-router.nft: basic router firewall.  Dual stack.  Includes optional example IPS.

The xtables (iptables) ones are from 2012 to 2019:

:iptab: basic router firewall (NOTE: legacy IP only!)
:iptab.ips: as ``iptab``, plus an purely in-kernel equivalent of fail2ban or sshguard_.
:iptab.nat: as ``iptab``, plus NAT and "port forwarding".

This also has the initial draft for Emacs nft syntax highlighting.
See also https://debbugs.gnu.org/cgi/bugreport.cgi?bug=36759

.. _sshguard: https://sshguard.net/
