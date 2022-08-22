These are my example Linux firewalls.

The nftables ones are from 2020:

:nftables-host.nft: basic server firewall.  Dual stack.
:nftables-router.nft: basic router firewall.  Dual stack.  Includes optional example IPS.
:nftables-failsafe.nft: deny-all failure loaded via systemd OnFailure=.

The xtables (iptables) ones are from 2012 to 2019:

:iptab: basic router firewall (NOTE: legacy IP only!)
:iptab.ips: as ``iptab``, plus an purely in-kernel equivalent of fail2ban or sshguard_.
:iptab.nat: as ``iptab``, plus NAT and "port forwarding".

This also has the initial draft for Emacs nft syntax highlighting.
See also https://debbugs.gnu.org/cgi/bugreport.cgi?bug=36759

Test an nft ruleset by loading it into a dummy network namespace::

    bash5$ sudo ip netns add delete-me
    bash5$ sudo ip netns exec delete-me nft -f nftables-host.nft
    nftables-host.nft:129:83-92: Error: No symbol type information
            ip daddr 224.0.0.252  ether daddr 01:00:5E:00:00:FC  udp dport 5355  log  log-prefix "FIXME: allow this LLMNR packet? "
                                                                                      ^^^^^^^^^^
    bash5$ sudo ip netns exec delete-me nft -i
    nft>


.. _sshguard: https://sshguard.net/
