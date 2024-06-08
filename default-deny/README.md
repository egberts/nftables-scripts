Actual output of `net list ruleset` of this default-deny firewall


```
table inet filter {
	counter packets_bad {
		packets 378084 bytes 107229008
	}

	counter udp_all {
		comment "UDP on all interfaces"
		packets 1397 bytes 112360
	}

	counter accepted_udp_all {
		packets 0 bytes 0
	}

	counter lo_input {
		packets 468 bytes 28482
	}

	counter unexpected_lo_input {
		packets 0 bytes 0
	}

	counter red_input_tcp {
		packets 0 bytes 0
	}

	counter unexpected_red_input_tcp {
		packets 0 bytes 0
	}

	counter red_input_udp {
		packets 165818 bytes 51425979
	}

	counter red_input_udp_final {
		packets 0 bytes 0
	}

	counter red_input_icmp {
		packets 0 bytes 0
	}

	counter unexpected_red_input_icmp {
		packets 0 bytes 0
	}

	counter red_input_igmp {
		packets 0 bytes 0
	}

	counter unexpected_red_input_igmp {
		packets 0 bytes 0
	}

	counter red_input {
		packets 183843 bytes 53162907
	}

	counter red_input_final {
		packets 3244 bytes 703948
	}

	counter green_input_tcp {
		packets 0 bytes 0
	}

	counter unexpected_green_input_tcp {
		packets 0 bytes 0
	}

	counter green_input_udp {
		packets 67 bytes 21976
	}

	counter unexpected_green_input_udp {
		comment "Unexpected UDP for green zone, type filter, hook input"
		packets 0 bytes 0
	}

	counter green_input_icmp {
		packets 0 bytes 0
	}

	counter unexpected_green_input_icmp {
		packets 0 bytes 0
	}

	counter green_input {
		packets 67 bytes 21976
	}

	counter unexpected_green_input {
		packets 0 bytes 0
	}

	counter blue_input_tcp {
		packets 0 bytes 0
	}

	counter blue_input_tcp_final {
		packets 0 bytes 0
	}

	counter blue_input_udp {
		packets 295 bytes 96760
	}

	counter unexpected_blue_input_udp {
		packets 0 bytes 0
	}

	counter blue_input {
		packets 295 bytes 96760
	}

	counter blue_input_final {
		packets 0 bytes 0
	}

	counter filter_input {
		packets 437783 bytes 831978200
	}

	counter filter_input_dropped {
		packets 437783 bytes 831978200
	}

	counter red_forward_tcp {
		packets 0 bytes 0
	}

	counter unexpected_red_forward_tcp {
		packets 0 bytes 0
	}

	counter red_forward_udp {
		packets 0 bytes 0
	}

	counter red_forward_udp_final {
		packets 0 bytes 0
	}

	counter red_forward_icmp {
		packets 0 bytes 0
	}

	counter unexpected_red_forward_icmp {
		packets 0 bytes 0
	}

	counter red_forward_igmp {
		packets 0 bytes 0
	}

	counter unexpected_red_forward_igmp {
		packets 0 bytes 0
	}

	counter red_forward {
		packets 3 bytes 216
	}

	counter red_forward_final {
		packets 0 bytes 0
	}

	counter green_forward_tcp {
		packets 208 bytes 10080
	}

	counter unexpected_green_forward_tcp {
		packets 0 bytes 0
	}

	counter green_forward_udp {
		packets 2892 bytes 210189
	}

	counter unexpected_green_forward_udp {
		comment "Unexpected UDP for green zone, type filter, hook forward"
		packets 1730 bytes 131480
	}

	counter green_forward_icmp {
		packets 1 bytes 84
	}

	counter unexpected_green_forward_icmp {
		packets 0 bytes 0
	}

	counter green_forward {
		packets 3101 bytes 220353
	}

	counter unexpected_green_forward {
		packets 0 bytes 0
	}

	counter blue_forward_tcp {
		packets 0 bytes 0
	}

	counter blue_forward_tcp_final {
		packets 0 bytes 0
	}

	counter blue_forward_udp {
		packets 1982 bytes 147428
	}

	counter unexpected_blue_forward_udp {
		packets 1626 bytes 123576
	}

	counter blue_forward_icmp {
		packets 0 bytes 0
	}

	counter unexpected_blue_forward_icmp {
		packets 0 bytes 0
	}

	counter blue_forward {
		packets 1982 bytes 147428
	}

	counter blue_forward_final {
		packets 0 bytes 0
	}

	counter filter_forward {
		packets 42965 bytes 296038299
	}

	counter unexpected_filter_forward {
		packets 0 bytes 0
	}

	chain bad_packets {
		counter name "packets_bad"
		tcp flags != syn ct state new log prefix "FIRST PACKET IS NOT SYN" counter packets 0 bytes 0 drop
		tcp flags & (fin | syn) == fin | syn log prefix "SCANNER1" counter packets 0 bytes 0 drop
		tcp flags & (syn | rst) == syn | rst log prefix "SCANNER2" counter packets 0 bytes 0 drop
		tcp flags & (fin | syn | rst | psh | ack | urg) < fin log prefix "SCANNER3" counter packets 0 bytes 0 drop
		tcp flags & (fin | syn | rst | psh | ack | urg) == fin | psh | urg log prefix "SCANNER4" counter packets 0 bytes 0 drop
		ct state invalid log prefix "Invalid conntrack state: " flags all counter packets 0 bytes 0 counter packets 0 bytes 0 drop
		counter packets 189291 bytes 53649640 comment "not-so-bad packets allowed"
		counter name "packets_bad"
		tcp flags != syn ct state new log prefix "FIRST PACKET IS NOT SYN" counter packets 0 bytes 0 drop
		tcp flags & (fin | syn) == fin | syn log prefix "SCANNER1" counter packets 0 bytes 0 drop
		tcp flags & (syn | rst) == syn | rst log prefix "SCANNER2" counter packets 0 bytes 0 drop
		tcp flags & (fin | syn | rst | psh | ack | urg) < fin log prefix "SCANNER3" counter packets 0 bytes 0 drop
		tcp flags & (fin | syn | rst | psh | ack | urg) == fin | psh | urg log prefix "SCANNER4" counter packets 0 bytes 0 drop
		ct state invalid log prefix "Invalid conntrack state: " flags all counter packets 0 bytes 0 counter packets 0 bytes 0 drop
		counter packets 188793 bytes 53579368 comment "not-so-bad packets allowed"
	}

	chain input_all_udp {
		counter packets 1397 bytes 112360
		counter name "udp_all"
		ip protocol udp counter packets 1397 bytes 112360 reject comment "reject IPv4 UDP input with ICMP port unreachable"
		ip6 nexthdr udp counter packets 0 bytes 0 reject comment "reject IPv6 UDP input with ICMPv6 port unreachable"
		counter name "accepted_udp_all"
		counter packets 0 bytes 0
		counter packets 0 bytes 0
		counter name "udp_all"
		ip protocol udp counter packets 0 bytes 0 reject comment "reject IPv4 UDP input with ICMP port unreachable"
		ip6 nexthdr udp counter packets 0 bytes 0 reject comment "reject IPv6 UDP input with ICMPv6 port unreachable"
		counter name "accepted_udp_all"
		counter packets 0 bytes 0
	}

	chain input_lo {
		counter packets 468 bytes 28482
		counter name "lo_input"
		counter packets 468 bytes 28482 accept
		counter name "unexpected_lo_input"
		counter packets 0 bytes 0
		counter packets 0 bytes 0
		counter name "lo_input"
		counter packets 0 bytes 0 accept
		counter name "unexpected_lo_input"
		counter packets 0 bytes 0
	}

	chain input_red_tcp {
		counter name "red_input_tcp"
		tcp sport 443 counter packets 0 bytes 0 accept
		tcp sport 80 counter packets 0 bytes 0 accept
		tcp sport 53 counter packets 0 bytes 0 accept
		tcp dport 53 counter packets 0 bytes 0 accept
		tcp dport 22 counter packets 0 bytes 0 accept
		tcp dport 922 counter packets 0 bytes 0 accept
		tcp dport { 139, 445 } counter packets 0 bytes 0 drop comment "silently drop NetBios"
		counter name "unexpected_red_input_tcp"
		log prefix "input_red_tcp" counter packets 0 bytes 0 drop comment "input_red_tcp"
		counter name "red_input_tcp"
		tcp sport 443 counter packets 0 bytes 0 accept
		tcp sport 80 counter packets 0 bytes 0 accept
		tcp sport 53 counter packets 0 bytes 0 accept
		tcp dport 53 counter packets 0 bytes 0 accept
		tcp dport 22 counter packets 0 bytes 0 accept
		tcp dport 922 counter packets 0 bytes 0 accept
		tcp dport { 139, 445 } counter packets 0 bytes 0 drop comment "silently drop NetBios"
		counter name "unexpected_red_input_tcp"
		log prefix "input_red_tcp" counter packets 0 bytes 0 drop comment "input_red_tcp"
	}

	chain input_red_udp {
		counter packets 165818 bytes 51425979
		counter name "red_input_udp"
		udp sport 67 udp dport 68 counter packets 25 bytes 9187 accept
		udp dport 53 counter packets 0 bytes 0 accept
		udp sport 53 counter packets 0 bytes 0 accept
		udp sport 123 udp dport 123 counter packets 0 bytes 0 accept
		ip daddr 224.0.0.251 udp dport 1900 counter packets 0 bytes 0 drop
		ip daddr 224.0.0.251 udp dport 5353 counter packets 164346 bytes 51299884 drop
		udp dport { 137, 138 } counter packets 50 bytes 4548 drop comment "silently drop NetBios"
		counter packets 1397 bytes 112360 jump input_all_udp
		counter name "red_input_udp_final"
		log prefix "input_red_udp" counter packets 0 bytes 0 drop comment "input_red_udp"
		counter packets 0 bytes 0
		counter name "red_input_udp"
		udp sport 67 udp dport 68 counter packets 0 bytes 0 accept
		udp dport 53 counter packets 0 bytes 0 accept
		udp sport 53 counter packets 0 bytes 0 accept
		udp sport 123 udp dport 123 counter packets 0 bytes 0 accept
		ip daddr 224.0.0.251 udp dport 1900 counter packets 0 bytes 0 drop
		ip daddr 224.0.0.251 udp dport 5353 counter packets 0 bytes 0 drop
		udp dport { 137, 138 } counter packets 0 bytes 0 drop comment "silently drop NetBios"
		counter packets 0 bytes 0 jump input_all_udp
		counter name "red_input_udp_final"
		log prefix "input_red_udp" counter packets 0 bytes 0 drop comment "input_red_udp"
	}

	chain input_red_icmp {
		counter packets 0 bytes 0
		counter name "red_input_icmp"
		icmpv6 type mld2-listener-report icmpv6 code no-route counter packets 0 bytes 0 drop
		icmpv6 type nd-neighbor-advert icmpv6 code no-route counter packets 0 bytes 0 drop
		log prefix "input_red_icmp" counter packets 0 bytes 0 drop
		ip protocol icmp limit rate 4/second accept
		ip6 nexthdr ipv6-icmp limit rate 4/second accept
		counter name "unexpected_red_input_icmp"
		log prefix "input_red_icmp" counter packets 0 bytes 0 drop
		counter packets 0 bytes 0
		counter name "red_input_icmp"
		icmpv6 type mld2-listener-report icmpv6 code no-route counter packets 0 bytes 0 drop
		icmpv6 type nd-neighbor-advert icmpv6 code no-route counter packets 0 bytes 0 drop
		log prefix "input_red_icmp" counter packets 0 bytes 0 drop
		ip protocol icmp limit rate 4/second accept
		ip6 nexthdr ipv6-icmp limit rate 4/second accept
		counter name "unexpected_red_input_icmp"
		log prefix "input_red_icmp" counter packets 0 bytes 0 drop
	}

	chain input_red_igmp {
		counter packets 0 bytes 0
		counter name "red_input_igmp"
		ip protocol igmp counter packets 0 bytes 0 accept comment "Accept IGMP"
		counter name "unexpected_red_input_igmp"
		counter packets 0 bytes 0 log prefix "input_red_igmp " drop
		counter packets 0 bytes 0
		counter name "red_input_igmp"
		ip protocol igmp counter packets 0 bytes 0 accept comment "Accept IGMP"
		counter name "unexpected_red_input_igmp"
		counter packets 0 bytes 0 log prefix "input_red_igmp " drop
	}

	chain input_red {
		counter packets 183843 bytes 53162907
		counter name "red_input"
		ip saddr 121.12.242.43 counter packets 0 bytes 0 drop
		ip daddr 127.0.0.0/8 counter packets 0 bytes 0 drop comment "drop invalid loopback traffic"
		ip6 daddr ::1 counter packets 0 bytes 0 drop comment "drop invalid loopback traffic"
		ip saddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/24, 192.168.2.0-192.168.255.255 } log prefix "stray_packet" counter packets 0 bytes 0 drop comment "stray packet"
		ip protocol tcp ct state new counter packets 0 bytes 0 jump input_red_tcp
		ip protocol udp ct state new counter packets 165818 bytes 51425979 jump input_red_udp
		ip protocol icmp ct state new counter packets 0 bytes 0 jump input_red_icmp
		meta l4proto ipv6-icmp counter packets 11852 bytes 927536 accept comment "Accept ICMPv6"
		ip protocol igmp counter packets 2929 bytes 105444 accept comment "Accept IGMP"
		counter name "red_input_final"
		counter packets 3244 bytes 703948 log prefix "input_red" drop comment "input_red"
		counter packets 0 bytes 0
		counter name "red_input"
		ip saddr 121.12.242.43 counter packets 0 bytes 0 drop
		ip daddr 127.0.0.0/8 counter packets 0 bytes 0 drop comment "drop invalid loopback traffic"
		ip6 daddr ::1 counter packets 0 bytes 0 drop comment "drop invalid loopback traffic"
		ip saddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/24, 192.168.2.0-192.168.255.255 } log prefix "stray_packet" counter packets 0 bytes 0 drop comment "stray packet"
		ip protocol tcp ct state new counter packets 0 bytes 0 jump input_red_tcp
		ip protocol udp ct state new counter packets 0 bytes 0 jump input_red_udp
		ip protocol icmp ct state new counter packets 0 bytes 0 jump input_red_icmp
		meta l4proto ipv6-icmp counter packets 0 bytes 0 accept comment "Accept ICMPv6"
		ip protocol igmp counter packets 0 bytes 0 accept comment "Accept IGMP"
		counter name "red_input_final"
		counter packets 0 bytes 0 log prefix "input_red" drop comment "input_red"
	}

	chain input_green_tcp {
		counter packets 0 bytes 0
		counter name "green_input_tcp"
		tcp dport 22 counter packets 0 bytes 0 accept
		tcp dport 922 counter packets 0 bytes 0 accept
		tcp dport 2222 counter packets 0 bytes 0 accept
		tcp dport 2224 counter packets 0 bytes 0 accept
		counter name "unexpected_green_input_tcp"
		counter packets 0 bytes 0 log prefix "green_input_tcp_dropped" drop
		counter packets 0 bytes 0
		counter name "green_input_tcp"
		tcp dport 22 counter packets 0 bytes 0 accept
		tcp dport 922 counter packets 0 bytes 0 accept
		tcp dport 2222 counter packets 0 bytes 0 accept
		tcp dport 2224 counter packets 0 bytes 0 accept
		counter name "unexpected_green_input_tcp"
		counter packets 0 bytes 0 log prefix "green_input_tcp_dropped" drop
	}

	chain input_green_udp {
		counter packets 67 bytes 21976
		counter name "green_input_udp"
		udp sport 68 udp dport 67 counter packets 67 bytes 21976 accept
		udp sport 123 udp dport 123 counter packets 0 bytes 0 accept
		counter packets 0 bytes 0 jump input_all_udp
		counter name "unexpected_green_input_udp"
		counter packets 0 bytes 0 log prefix "input_green_udp " drop
		counter packets 0 bytes 0
		counter name "green_input_udp"
		udp sport 68 udp dport 67 counter packets 0 bytes 0 accept
		udp sport 123 udp dport 123 counter packets 0 bytes 0 accept
		counter packets 0 bytes 0 jump input_all_udp
		counter name "unexpected_green_input_udp"
		counter packets 0 bytes 0 log prefix "input_green_udp " drop
	}

	chain input_green_icmp {
		counter packets 0 bytes 0
		counter name "green_input_icmp"
		ip protocol icmp icmp type { destination-unreachable, router-advertisement, time-exceeded, parameter-problem } limit rate 100/second accept
		ip protocol icmp icmp type echo-request limit rate over 1/second counter packets 0 bytes 0 drop
		ip protocol icmp icmp type echo-request counter packets 0 bytes 0 accept
		ip6 nexthdr ipv6-icmp icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } limit rate 100/second accept
		ip6 nexthdr ipv6-icmp icmpv6 type echo-request limit rate over 1/second counter packets 0 bytes 0 drop
		ip6 nexthdr ipv6-icmp icmpv6 type echo-request counter packets 0 bytes 0 accept
		meta l4proto icmp counter packets 0 bytes 0 accept comment "Accept ICMP"
		ip6 nexthdr ipv6-icmp icmpv6 type destination-unreachable counter packets 0 bytes 0 accept
		ip6 nexthdr ipv6-icmp icmpv6 type packet-too-big counter packets 0 bytes 0 accept
		ip6 nexthdr ipv6-icmp icmpv6 type time-exceeded counter packets 0 bytes 0 accept
		ip6 nexthdr ipv6-icmp icmpv6 type parameter-problem counter packets 0 bytes 0 accept
		ip6 nexthdr ipv6-icmp icmpv6 type echo-reply counter packets 0 bytes 0 accept
		ip6 nexthdr ipv6-icmp icmpv6 type nd-router-advert counter packets 0 bytes 0 accept
		ip6 nexthdr ipv6-icmp icmpv6 type nd-neighbor-solicit counter packets 0 bytes 0 accept
		ip6 nexthdr ipv6-icmp icmpv6 type nd-neighbor-advert counter packets 0 bytes 0 accept
		ip protocol icmp icmp type echo-request counter packets 0 bytes 0 accept
		ip protocol icmp icmp type echo-request counter packets 0 bytes 0 accept
		ip protocol icmp icmp type echo-reply counter packets 0 bytes 0 accept
		ip protocol icmp icmp type destination-unreachable counter packets 0 bytes 0 accept
		ip protocol icmp icmp type router-advertisement counter packets 0 bytes 0 accept
		ip protocol icmp icmp type time-exceeded counter packets 0 bytes 0 accept
		ip protocol icmp icmp type parameter-problem counter packets 0 bytes 0 accept
		ip protocol icmp icmp type source-quench counter packets 0 bytes 0 drop
		ip protocol icmp icmp type redirect counter packets 0 bytes 0 drop
		ip protocol icmp icmp type router-solicitation counter packets 0 bytes 0 drop
		ip protocol icmp icmp type timestamp-request counter packets 0 bytes 0 drop
		ip protocol icmp icmp type timestamp-reply counter packets 0 bytes 0 drop
		ip protocol icmp icmp type info-request counter packets 0 bytes 0 drop
		ip protocol icmp icmp type info-reply counter packets 0 bytes 0 drop
		ip protocol icmp icmp type address-mask-request counter packets 0 bytes 0 drop
		ip protocol icmp icmp type address-mask-reply counter packets 0 bytes 0 drop
		counter name "unexpected_green_input_icmp"
		log prefix "input_green_icmp" drop comment "input_green_icmp"
		counter packets 0 bytes 0
		counter name "green_input_icmp"
		ip protocol icmp icmp type { destination-unreachable, router-advertisement, time-exceeded, parameter-problem } limit rate 100/second accept
		ip protocol icmp icmp type echo-request limit rate over 1/second counter packets 0 bytes 0 drop
		ip protocol icmp icmp type echo-request counter packets 0 bytes 0 accept
		ip6 nexthdr ipv6-icmp icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } limit rate 100/second accept
		ip6 nexthdr ipv6-icmp icmpv6 type echo-request limit rate over 1/second counter packets 0 bytes 0 drop
		ip6 nexthdr ipv6-icmp icmpv6 type echo-request counter packets 0 bytes 0 accept
		meta l4proto icmp counter packets 0 bytes 0 accept comment "Accept ICMP"
		ip6 nexthdr ipv6-icmp icmpv6 type destination-unreachable counter packets 0 bytes 0 accept
		ip6 nexthdr ipv6-icmp icmpv6 type packet-too-big counter packets 0 bytes 0 accept
		ip6 nexthdr ipv6-icmp icmpv6 type time-exceeded counter packets 0 bytes 0 accept
		ip6 nexthdr ipv6-icmp icmpv6 type parameter-problem counter packets 0 bytes 0 accept
		ip6 nexthdr ipv6-icmp icmpv6 type echo-reply counter packets 0 bytes 0 accept
		ip6 nexthdr ipv6-icmp icmpv6 type nd-router-advert counter packets 0 bytes 0 accept
		ip6 nexthdr ipv6-icmp icmpv6 type nd-neighbor-solicit counter packets 0 bytes 0 accept
		ip6 nexthdr ipv6-icmp icmpv6 type nd-neighbor-advert counter packets 0 bytes 0 accept
		ip protocol icmp icmp type echo-request counter packets 0 bytes 0 accept
		ip protocol icmp icmp type echo-request counter packets 0 bytes 0 accept
		ip protocol icmp icmp type echo-reply counter packets 0 bytes 0 accept
		ip protocol icmp icmp type destination-unreachable counter packets 0 bytes 0 accept
		ip protocol icmp icmp type router-advertisement counter packets 0 bytes 0 accept
		ip protocol icmp icmp type time-exceeded counter packets 0 bytes 0 accept
		ip protocol icmp icmp type parameter-problem counter packets 0 bytes 0 accept
		ip protocol icmp icmp type source-quench counter packets 0 bytes 0 drop
		ip protocol icmp icmp type redirect counter packets 0 bytes 0 drop
		ip protocol icmp icmp type router-solicitation counter packets 0 bytes 0 drop
		ip protocol icmp icmp type timestamp-request counter packets 0 bytes 0 drop
		ip protocol icmp icmp type timestamp-reply counter packets 0 bytes 0 drop
		ip protocol icmp icmp type info-request counter packets 0 bytes 0 drop
		ip protocol icmp icmp type info-reply counter packets 0 bytes 0 drop
		ip protocol icmp icmp type address-mask-request counter packets 0 bytes 0 drop
		ip protocol icmp icmp type address-mask-reply counter packets 0 bytes 0 drop
		counter name "unexpected_green_input_icmp"
		log prefix "input_green_icmp" drop comment "input_green_icmp"
	}

	chain input_green {
		counter packets 67 bytes 21976
		counter name "green_input"
		iif "br0" ip daddr != 192.168.132.0/24 ip daddr != 255.255.255.255 counter packets 0 bytes 0 log prefix "input_green_wrong_subnet " drop
		ip daddr 127.0.0.0/8 counter packets 0 bytes 0 drop comment "drop invalid loopback traffic"
		ip6 daddr ::1 counter packets 0 bytes 0 drop
		ip protocol tcp ct state new counter packets 0 bytes 0 jump input_green_tcp
		ip protocol udp ct state new counter packets 67 bytes 21976 jump input_green_udp
		ip protocol icmp ct state new counter packets 0 bytes 0 jump input_green_icmp
		counter name "unexpected_green_input"
		counter packets 0 bytes 0 log prefix "input_green" drop
		counter packets 0 bytes 0
		counter name "green_input"
		iif "br0" ip daddr != 192.168.132.0/24 ip daddr != 255.255.255.255 counter packets 0 bytes 0 log prefix "input_green_wrong_subnet " drop
		ip daddr 127.0.0.0/8 counter packets 0 bytes 0 drop comment "drop invalid loopback traffic"
		ip6 daddr ::1 counter packets 0 bytes 0 drop
		ip protocol tcp ct state new counter packets 0 bytes 0 jump input_green_tcp
		ip protocol udp ct state new counter packets 0 bytes 0 jump input_green_udp
		ip protocol icmp ct state new counter packets 0 bytes 0 jump input_green_icmp
		counter name "unexpected_green_input"
		counter packets 0 bytes 0 log prefix "input_green" drop
	}

	chain input_blue_tcp {
		counter packets 0 bytes 0
		counter name "blue_input_tcp"
		tcp dport 22 counter packets 0 bytes 0 accept
		counter name "blue_input_tcp_final"
		counter packets 0 bytes 0 log prefix "input_blue_tcp" drop comment "input_blue_tcp"
		counter packets 0 bytes 0
		counter name "blue_input_tcp"
		tcp dport 22 counter packets 0 bytes 0 accept
		counter name "blue_input_tcp_final"
		counter packets 0 bytes 0 log prefix "input_blue_tcp" drop comment "input_blue_tcp"
	}

	chain input_blue_udp {
		counter packets 295 bytes 96760
		counter name "blue_input_udp"
		udp sport 68 udp dport 67 counter packets 295 bytes 96760 accept
		udp dport 53 counter packets 0 bytes 0 accept
		udp sport 123 udp dport 123 counter packets 0 bytes 0 accept
		counter packets 0 bytes 0 jump input_all_udp
		counter name "unexpected_blue_input_udp"
		counter packets 0 bytes 0 log prefix "input_blue_udp " drop comment "unexpected UDP drop at filter input blue"
		counter packets 0 bytes 0
		counter name "blue_input_udp"
		udp sport 68 udp dport 67 counter packets 0 bytes 0 accept
		udp dport 53 counter packets 0 bytes 0 accept
		udp sport 123 udp dport 123 counter packets 0 bytes 0 accept
		counter packets 0 bytes 0 jump input_all_udp
		counter name "unexpected_blue_input_udp"
		counter packets 0 bytes 0 log prefix "input_blue_udp " drop comment "unexpected UDP drop at filter input blue"
	}

	chain input_blue {
		counter packets 295 bytes 96760
		counter name "blue_input"
		iif "virbr0" ip daddr != 192.168.100.0/24 ip daddr != 255.255.255.255 counter packets 0 bytes 0 log prefix "input_blue_wrong_subnet " drop
		ip daddr 127.0.0.0/8 counter packets 0 bytes 0 drop comment "drop invalid loopback traffic"
		ip6 daddr ::1 counter packets 0 bytes 0 drop comment "drop invalid loopback traffic"
		ip protocol tcp ct state new counter packets 0 bytes 0 jump input_blue_tcp
		ip protocol udp ct state new counter packets 295 bytes 96760 jump input_blue_udp
		counter name "blue_input_final"
		counter packets 0 bytes 0 log prefix "input_blue" drop
		counter packets 0 bytes 0
		counter name "blue_input"
		iif "virbr0" ip daddr != 192.168.100.0/24 ip daddr != 255.255.255.255 counter packets 0 bytes 0 log prefix "input_blue_wrong_subnet " drop
		ip daddr 127.0.0.0/8 counter packets 0 bytes 0 drop comment "drop invalid loopback traffic"
		ip6 daddr ::1 counter packets 0 bytes 0 drop comment "drop invalid loopback traffic"
		ip protocol tcp ct state new counter packets 0 bytes 0 jump input_blue_tcp
		ip protocol udp ct state new counter packets 0 bytes 0 jump input_blue_udp
		counter name "blue_input_final"
		counter packets 0 bytes 0 log prefix "input_blue" drop
	}

	chain input {
		type filter hook input priority filter; policy accept;
		counter packets 437783 bytes 831978200
		counter name "filter_input"
		counter name "filter_input_dropped"
		ct state established,related counter packets 253110 bytes 778668075 accept
		iif "lo" counter packets 468 bytes 28482 jump input_lo
		ct state invalid counter packets 0 bytes 0 drop
		counter packets 184205 bytes 53281643 jump bad_packets
		iif "wlp4s0" counter packets 183843 bytes 53162907 jump input_red
		iif "br0" counter packets 67 bytes 21976 jump input_green
		iif "virbr0" counter packets 295 bytes 96760 jump input_blue
		counter name "filter_input_dropped"
		counter packets 0 bytes 0 log prefix "input " drop comment "input"
		counter packets 0 bytes 0
		counter name "filter_input"
		counter name "filter_input_dropped"
		ct state established,related counter packets 0 bytes 0 accept
		iif "lo" counter packets 0 bytes 0 jump input_lo
		ct state invalid counter packets 0 bytes 0 drop
		counter packets 0 bytes 0 jump bad_packets
		iif "wlp4s0" counter packets 0 bytes 0 jump input_red
		iif "br0" counter packets 0 bytes 0 jump input_green
		iif "virbr0" counter packets 0 bytes 0 jump input_blue
		counter name "filter_input_dropped"
		counter packets 0 bytes 0 log prefix "input " drop comment "input"
	}

	chain forward_red_tcp {
		counter name "red_forward_tcp"
		tcp sport 443 counter packets 0 bytes 0 accept
		tcp sport 53 counter packets 0 bytes 0 accept
		tcp dport 53 counter packets 0 bytes 0 accept
		tcp dport 22 counter packets 0 bytes 0 accept
		tcp sport 80 counter packets 0 bytes 0 accept
		tcp dport 873 counter packets 0 bytes 0 accept comment "forward red to rsync server"
		tcp dport 922 counter packets 0 bytes 0 accept
		tcp dport { 139, 445 } counter packets 0 bytes 0 drop comment "silently drop NetBios"
		counter name "unexpected_red_forward_tcp"
		log prefix "forward_red_tcp" counter packets 0 bytes 0 drop comment "forward_red_tcp"
		counter name "red_forward_tcp"
		tcp sport 443 counter packets 0 bytes 0 accept
		tcp sport 53 counter packets 0 bytes 0 accept
		tcp dport 53 counter packets 0 bytes 0 accept
		tcp dport 22 counter packets 0 bytes 0 accept
		tcp sport 80 counter packets 0 bytes 0 accept
		tcp dport 873 counter packets 0 bytes 0 accept comment "forward red to rsync server"
		tcp dport 922 counter packets 0 bytes 0 accept
		tcp dport { 139, 445 } counter packets 0 bytes 0 drop comment "silently drop NetBios"
		counter name "unexpected_red_forward_tcp"
		log prefix "forward_red_tcp" counter packets 0 bytes 0 drop comment "forward_red_tcp"
	}

	chain forward_red_udp {
		counter packets 0 bytes 0
		counter name "red_forward_udp"
		udp sport 67 udp dport 68 counter packets 0 bytes 0 accept
		udp dport 53 counter packets 0 bytes 0 accept
		udp sport 53 counter packets 0 bytes 0 accept
		udp sport 123 udp dport 123 counter packets 0 bytes 0 accept
		ip daddr 224.0.0.251 udp dport 1900 counter packets 0 bytes 0 drop
		ip daddr 224.0.0.251 udp dport 5353 counter packets 0 bytes 0 drop
		udp dport { 137, 138 } counter packets 0 bytes 0 drop comment "silently drop NetBios"
		counter name "red_forward_udp_final"
		log prefix "forward_red_udp" counter packets 0 bytes 0 drop comment "forward_red_udp"
		counter packets 0 bytes 0
		counter name "red_forward_udp"
		udp sport 67 udp dport 68 counter packets 0 bytes 0 accept
		udp dport 53 counter packets 0 bytes 0 accept
		udp sport 53 counter packets 0 bytes 0 accept
		udp sport 123 udp dport 123 counter packets 0 bytes 0 accept
		ip daddr 224.0.0.251 udp dport 1900 counter packets 0 bytes 0 drop
		ip daddr 224.0.0.251 udp dport 5353 counter packets 0 bytes 0 drop
		udp dport { 137, 138 } counter packets 0 bytes 0 drop comment "silently drop NetBios"
		counter name "red_forward_udp_final"
		log prefix "forward_red_udp" counter packets 0 bytes 0 drop comment "forward_red_udp"
	}

	chain forward_red_icmp {
		counter packets 0 bytes 0
		counter name "red_forward_icmp"
		icmpv6 type mld2-listener-report icmpv6 code no-route counter packets 0 bytes 0 drop
		icmpv6 type nd-neighbor-advert icmpv6 code no-route counter packets 0 bytes 0 drop
		log prefix "forward_red_icmp" counter packets 0 bytes 0 drop
		ip protocol icmp limit rate 4/second accept
		ip6 nexthdr ipv6-icmp limit rate 4/second accept
		counter name "unexpected_red_forward_icmp"
		log prefix "forward_red_icmp" counter packets 0 bytes 0 drop
		counter packets 0 bytes 0
		counter name "red_forward_icmp"
		icmpv6 type mld2-listener-report icmpv6 code no-route counter packets 0 bytes 0 drop
		icmpv6 type nd-neighbor-advert icmpv6 code no-route counter packets 0 bytes 0 drop
		log prefix "forward_red_icmp" counter packets 0 bytes 0 drop
		ip protocol icmp limit rate 4/second accept
		ip6 nexthdr ipv6-icmp limit rate 4/second accept
		counter name "unexpected_red_forward_icmp"
		log prefix "forward_red_icmp" counter packets 0 bytes 0 drop
	}

	chain forward_red_igmp {
		counter packets 0 bytes 0
		counter name "red_forward_igmp"
		ip protocol igmp counter packets 0 bytes 0 accept comment "Accept IGMP"
		counter name "unexpected_red_forward_igmp"
		counter packets 0 bytes 0 log prefix "forward_red_igmp " drop
		counter packets 0 bytes 0
		counter name "red_forward_igmp"
		ip protocol igmp counter packets 0 bytes 0 accept comment "Accept IGMP"
		counter name "unexpected_red_forward_igmp"
		counter packets 0 bytes 0 log prefix "forward_red_igmp " drop
	}

	chain forward_red {
		counter packets 3 bytes 216
		counter name "red_forward"
		ip saddr 121.12.242.43 counter packets 0 bytes 0 drop
		ip daddr 127.0.0.0/8 counter packets 0 bytes 0 drop comment "drop invalid loopback traffic"
		ip6 daddr ::1 counter packets 0 bytes 0 drop comment "drop invalid loopback traffic"
		ip saddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/24, 192.168.2.0-192.168.255.255 } log prefix "stray_packet" counter packets 0 bytes 0 drop comment "stray packet"
		ip protocol tcp ct state new counter packets 0 bytes 0 jump forward_red_tcp
		ip protocol udp ct state new counter packets 0 bytes 0 jump forward_red_udp
		ip protocol icmp ct state new counter packets 0 bytes 0 jump forward_red_icmp
		meta l4proto ipv6-icmp counter packets 3 bytes 216 accept comment "Accept ICMPv6"
		ip protocol igmp counter packets 0 bytes 0 accept comment "Accept IGMP"
		counter name "red_forward_final"
		counter packets 0 bytes 0 log prefix "forward_red" drop comment "forward_red"
		counter packets 0 bytes 0
		counter name "red_forward"
		ip saddr 121.12.242.43 counter packets 0 bytes 0 drop
		ip daddr 127.0.0.0/8 counter packets 0 bytes 0 drop comment "drop invalid loopback traffic"
		ip6 daddr ::1 counter packets 0 bytes 0 drop comment "drop invalid loopback traffic"
		ip saddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/24, 192.168.2.0-192.168.255.255 } log prefix "stray_packet" counter packets 0 bytes 0 drop comment "stray packet"
		ip protocol tcp ct state new counter packets 0 bytes 0 jump forward_red_tcp
		ip protocol udp ct state new counter packets 0 bytes 0 jump forward_red_udp
		ip protocol icmp ct state new counter packets 0 bytes 0 jump forward_red_icmp
		meta l4proto ipv6-icmp counter packets 0 bytes 0 accept comment "Accept ICMPv6"
		ip protocol igmp counter packets 0 bytes 0 accept comment "Accept IGMP"
		counter name "red_forward_final"
		counter packets 0 bytes 0 log prefix "forward_red" drop comment "forward_red"
	}

	chain forward_green_tcp {
		counter packets 208 bytes 10080
		counter name "green_forward_tcp"
		tcp dport 22 counter packets 0 bytes 0 accept
		tcp dport 53 counter packets 0 bytes 0 accept
		tcp dport 80 counter packets 0 bytes 0 accept
		tcp dport 443 counter packets 15 bytes 732 accept
		tcp dport 873 counter packets 193 bytes 9348 accept comment "forward green rsync"
		tcp dport 922 counter packets 0 bytes 0 accept
		counter name "unexpected_green_forward_tcp"
		counter packets 0 bytes 0 log prefix "green_forward_tcp_dropped" drop
		counter packets 0 bytes 0
		counter name "green_forward_tcp"
		tcp dport 22 counter packets 0 bytes 0 accept
		tcp dport 53 counter packets 0 bytes 0 accept
		tcp dport 80 counter packets 0 bytes 0 accept
		tcp dport 443 counter packets 0 bytes 0 accept
		tcp dport 873 counter packets 0 bytes 0 accept comment "forward green rsync"
		tcp dport 922 counter packets 0 bytes 0 accept
		counter name "unexpected_green_forward_tcp"
		counter packets 0 bytes 0 log prefix "green_forward_tcp_dropped" drop
	}

	chain forward_green_udp {
		counter packets 2892 bytes 210189
		counter name "green_forward_udp"
		udp dport 53 counter packets 1162 bytes 78709 accept
		udp sport 53 counter packets 0 bytes 0 accept
		udp sport 123 udp dport 123 counter packets 0 bytes 0 accept
		counter name "unexpected_green_forward_udp"
		counter packets 1730 bytes 131480 log prefix "forward_green_udp " drop
		counter packets 0 bytes 0
		counter name "green_forward_udp"
		udp dport 53 counter packets 0 bytes 0 accept
		udp sport 53 counter packets 0 bytes 0 accept
		udp sport 123 udp dport 123 counter packets 0 bytes 0 accept
		counter name "unexpected_green_forward_udp"
		counter packets 0 bytes 0 log prefix "forward_green_udp " drop
	}

	chain forward_green_icmp {
		counter packets 1 bytes 84
		counter name "green_forward_icmp"
		ip protocol icmp icmp type { destination-unreachable, router-advertisement, time-exceeded, parameter-problem } limit rate 100/second accept
		ip protocol icmp icmp type echo-request limit rate over 1/second counter packets 0 bytes 0 drop
		ip protocol icmp icmp type echo-request counter packets 1 bytes 84 accept
		ip6 nexthdr ipv6-icmp icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } limit rate 100/second accept
		ip6 nexthdr ipv6-icmp icmpv6 type echo-request limit rate over 1/second counter packets 0 bytes 0 drop
		ip6 nexthdr ipv6-icmp icmpv6 type echo-request counter packets 0 bytes 0 accept
		meta l4proto icmp counter packets 0 bytes 0 accept comment "Accept ICMP"
		ip6 nexthdr ipv6-icmp icmpv6 type destination-unreachable counter packets 0 bytes 0 accept
		ip6 nexthdr ipv6-icmp icmpv6 type packet-too-big counter packets 0 bytes 0 accept
		ip6 nexthdr ipv6-icmp icmpv6 type time-exceeded counter packets 0 bytes 0 accept
		ip6 nexthdr ipv6-icmp icmpv6 type parameter-problem counter packets 0 bytes 0 accept
		ip6 nexthdr ipv6-icmp icmpv6 type echo-reply counter packets 0 bytes 0 accept
		ip6 nexthdr ipv6-icmp icmpv6 type nd-router-advert counter packets 0 bytes 0 accept
		ip6 nexthdr ipv6-icmp icmpv6 type nd-neighbor-solicit counter packets 0 bytes 0 accept
		ip6 nexthdr ipv6-icmp icmpv6 type nd-neighbor-advert counter packets 0 bytes 0 accept
		ip protocol icmp icmp type echo-request counter packets 0 bytes 0 accept
		ip protocol icmp icmp type echo-request counter packets 0 bytes 0 accept
		ip protocol icmp icmp type echo-reply counter packets 0 bytes 0 accept
		ip protocol icmp icmp type destination-unreachable counter packets 0 bytes 0 accept
		ip protocol icmp icmp type router-advertisement counter packets 0 bytes 0 accept
		ip protocol icmp icmp type time-exceeded counter packets 0 bytes 0 accept
		ip protocol icmp icmp type parameter-problem counter packets 0 bytes 0 accept
		ip protocol icmp icmp type source-quench counter packets 0 bytes 0 drop
		ip protocol icmp icmp type redirect counter packets 0 bytes 0 drop
		ip protocol icmp icmp type router-solicitation counter packets 0 bytes 0 drop
		ip protocol icmp icmp type timestamp-request counter packets 0 bytes 0 drop
		ip protocol icmp icmp type timestamp-reply counter packets 0 bytes 0 drop
		ip protocol icmp icmp type info-request counter packets 0 bytes 0 drop
		ip protocol icmp icmp type info-reply counter packets 0 bytes 0 drop
		ip protocol icmp icmp type address-mask-request counter packets 0 bytes 0 drop
		ip protocol icmp icmp type address-mask-reply counter packets 0 bytes 0 drop
		counter name "unexpected_green_forward_icmp"
		log prefix "forward_green_icmp" drop comment "forward_green_icmp"
		counter packets 0 bytes 0
		counter name "green_forward_icmp"
		ip protocol icmp icmp type { destination-unreachable, router-advertisement, time-exceeded, parameter-problem } limit rate 100/second accept
		ip protocol icmp icmp type echo-request limit rate over 1/second counter packets 0 bytes 0 drop
		ip protocol icmp icmp type echo-request counter packets 0 bytes 0 accept
		ip6 nexthdr ipv6-icmp icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } limit rate 100/second accept
		ip6 nexthdr ipv6-icmp icmpv6 type echo-request limit rate over 1/second counter packets 0 bytes 0 drop
		ip6 nexthdr ipv6-icmp icmpv6 type echo-request counter packets 0 bytes 0 accept
		meta l4proto icmp counter packets 0 bytes 0 accept comment "Accept ICMP"
		ip6 nexthdr ipv6-icmp icmpv6 type destination-unreachable counter packets 0 bytes 0 accept
		ip6 nexthdr ipv6-icmp icmpv6 type packet-too-big counter packets 0 bytes 0 accept
		ip6 nexthdr ipv6-icmp icmpv6 type time-exceeded counter packets 0 bytes 0 accept
		ip6 nexthdr ipv6-icmp icmpv6 type parameter-problem counter packets 0 bytes 0 accept
		ip6 nexthdr ipv6-icmp icmpv6 type echo-reply counter packets 0 bytes 0 accept
		ip6 nexthdr ipv6-icmp icmpv6 type nd-router-advert counter packets 0 bytes 0 accept
		ip6 nexthdr ipv6-icmp icmpv6 type nd-neighbor-solicit counter packets 0 bytes 0 accept
		ip6 nexthdr ipv6-icmp icmpv6 type nd-neighbor-advert counter packets 0 bytes 0 accept
		ip protocol icmp icmp type echo-request counter packets 0 bytes 0 accept
		ip protocol icmp icmp type echo-request counter packets 0 bytes 0 accept
		ip protocol icmp icmp type echo-reply counter packets 0 bytes 0 accept
		ip protocol icmp icmp type destination-unreachable counter packets 0 bytes 0 accept
		ip protocol icmp icmp type router-advertisement counter packets 0 bytes 0 accept
		ip protocol icmp icmp type time-exceeded counter packets 0 bytes 0 accept
		ip protocol icmp icmp type parameter-problem counter packets 0 bytes 0 accept
		ip protocol icmp icmp type source-quench counter packets 0 bytes 0 drop
		ip protocol icmp icmp type redirect counter packets 0 bytes 0 drop
		ip protocol icmp icmp type router-solicitation counter packets 0 bytes 0 drop
		ip protocol icmp icmp type timestamp-request counter packets 0 bytes 0 drop
		ip protocol icmp icmp type timestamp-reply counter packets 0 bytes 0 drop
		ip protocol icmp icmp type info-request counter packets 0 bytes 0 drop
		ip protocol icmp icmp type info-reply counter packets 0 bytes 0 drop
		ip protocol icmp icmp type address-mask-request counter packets 0 bytes 0 drop
		ip protocol icmp icmp type address-mask-reply counter packets 0 bytes 0 drop
		counter name "unexpected_green_forward_icmp"
		log prefix "forward_green_icmp" drop comment "forward_green_icmp"
	}

	chain forward_green {
		counter packets 3101 bytes 220353
		counter name "green_forward"
		ip daddr 127.0.0.0/8 counter packets 0 bytes 0 drop comment "drop invalid loopback traffic"
		ip6 daddr ::1 counter packets 0 bytes 0 drop
		ip protocol tcp ct state new counter packets 208 bytes 10080 jump forward_green_tcp
		ip protocol udp ct state new counter packets 2892 bytes 210189 jump forward_green_udp
		ip protocol icmp ct state new counter packets 1 bytes 84 jump forward_green_icmp
		counter name "unexpected_green_forward"
		counter packets 0 bytes 0 log prefix "forward_green" drop
		counter packets 0 bytes 0
		counter name "green_forward"
		ip daddr 127.0.0.0/8 counter packets 0 bytes 0 drop comment "drop invalid loopback traffic"
		ip6 daddr ::1 counter packets 0 bytes 0 drop
		ip protocol tcp ct state new counter packets 0 bytes 0 jump forward_green_tcp
		ip protocol udp ct state new counter packets 0 bytes 0 jump forward_green_udp
		ip protocol icmp ct state new counter packets 0 bytes 0 jump forward_green_icmp
		counter name "unexpected_green_forward"
		counter packets 0 bytes 0 log prefix "forward_green" drop
	}

	chain forward_blue_tcp {
		counter packets 0 bytes 0
		counter name "blue_forward_tcp"
		tcp dport 22 counter packets 0 bytes 0 accept
		tcp dport 53 counter packets 0 bytes 0 accept
		tcp dport 80 counter packets 0 bytes 0 accept
		tcp dport 443 counter packets 0 bytes 0 accept
		tcp dport 873 counter packets 0 bytes 0 accept comment "forward blue rsync "
		counter name "blue_forward_tcp_final"
		counter packets 0 bytes 0 log prefix "forward_blue_tcp" drop comment "input_blue_tcp"
		counter packets 0 bytes 0
		counter name "blue_forward_tcp"
		tcp dport 22 counter packets 0 bytes 0 accept
		tcp dport 53 counter packets 0 bytes 0 accept
		tcp dport 80 counter packets 0 bytes 0 accept
		tcp dport 443 counter packets 0 bytes 0 accept
		tcp dport 873 counter packets 0 bytes 0 accept comment "forward blue rsync "
		counter name "blue_forward_tcp_final"
		counter packets 0 bytes 0 log prefix "forward_blue_tcp" drop comment "input_blue_tcp"
	}

	chain forward_blue_udp {
		counter packets 1982 bytes 147428
		counter name "blue_forward_udp"
		udp sport 67 udp dport 68 counter packets 0 bytes 0 accept
		udp sport 68 udp dport 67 counter packets 0 bytes 0 accept
		udp dport 53 counter packets 356 bytes 23852 accept
		udp sport 53 counter packets 0 bytes 0 accept
		udp sport 123 udp dport 123 counter packets 0 bytes 0 accept
		counter name "unexpected_blue_forward_udp"
		counter packets 1626 bytes 123576 log prefix "forward_blue_udp " drop comment "unexpected UDP drop at filter forward blue"
		counter packets 0 bytes 0
		counter name "blue_forward_udp"
		udp sport 67 udp dport 68 counter packets 0 bytes 0 accept
		udp sport 68 udp dport 67 counter packets 0 bytes 0 accept
		udp dport 53 counter packets 0 bytes 0 accept
		udp sport 53 counter packets 0 bytes 0 accept
		udp sport 123 udp dport 123 counter packets 0 bytes 0 accept
		counter name "unexpected_blue_forward_udp"
		counter packets 0 bytes 0 log prefix "forward_blue_udp " drop comment "unexpected UDP drop at filter forward blue"
	}

	chain forward_blue_icmp {
		counter name "blue_forward_icmp"
		ip protocol icmp icmp type { destination-unreachable, router-advertisement, time-exceeded, parameter-problem } limit rate 100/second accept
		ip protocol icmp icmp type echo-request limit rate over 1/second counter packets 0 bytes 0 drop
		ip protocol icmp icmp type echo-request counter packets 0 bytes 0 accept
		ip6 nexthdr ipv6-icmp icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } limit rate 100/second accept
		ip6 nexthdr ipv6-icmp icmpv6 type echo-request limit rate over 1/second counter packets 0 bytes 0 drop
		ip6 nexthdr ipv6-icmp icmpv6 type echo-request counter packets 0 bytes 0 accept
		meta l4proto icmp counter packets 0 bytes 0 accept comment "Accept ICMP"
		ip6 nexthdr ipv6-icmp icmpv6 type destination-unreachable counter packets 0 bytes 0 accept
		ip6 nexthdr ipv6-icmp icmpv6 type packet-too-big counter packets 0 bytes 0 accept
		ip6 nexthdr ipv6-icmp icmpv6 type time-exceeded counter packets 0 bytes 0 accept
		ip6 nexthdr ipv6-icmp icmpv6 type parameter-problem counter packets 0 bytes 0 accept
		ip6 nexthdr ipv6-icmp icmpv6 type echo-reply counter packets 0 bytes 0 accept
		ip6 nexthdr ipv6-icmp icmpv6 type nd-router-advert counter packets 0 bytes 0 accept
		ip6 nexthdr ipv6-icmp icmpv6 type nd-neighbor-solicit counter packets 0 bytes 0 accept
		ip6 nexthdr ipv6-icmp icmpv6 type nd-neighbor-advert counter packets 0 bytes 0 accept
		ip protocol icmp icmp type echo-request counter packets 0 bytes 0 accept
		ip protocol icmp icmp type echo-request counter packets 0 bytes 0 accept
		ip protocol icmp icmp type echo-reply counter packets 0 bytes 0 accept
		ip protocol icmp icmp type destination-unreachable counter packets 0 bytes 0 accept
		ip protocol icmp icmp type router-advertisement counter packets 0 bytes 0 accept
		ip protocol icmp icmp type time-exceeded counter packets 0 bytes 0 accept
		ip protocol icmp icmp type parameter-problem counter packets 0 bytes 0 accept
		ip protocol icmp icmp type source-quench counter packets 0 bytes 0 drop
		ip protocol icmp icmp type redirect counter packets 0 bytes 0 drop
		ip protocol icmp icmp type router-solicitation counter packets 0 bytes 0 drop
		ip protocol icmp icmp type timestamp-request counter packets 0 bytes 0 drop
		ip protocol icmp icmp type timestamp-reply counter packets 0 bytes 0 drop
		ip protocol icmp icmp type info-request counter packets 0 bytes 0 drop
		ip protocol icmp icmp type info-reply counter packets 0 bytes 0 drop
		ip protocol icmp icmp type address-mask-request counter packets 0 bytes 0 drop
		ip protocol icmp icmp type address-mask-reply counter packets 0 bytes 0 drop
		counter name "unexpected_blue_forward_icmp"
		counter packets 0 bytes 0 log prefix "forward_blue_icmp_drop " drop comment "forward_blue_icmp_dropped"
		counter name "blue_forward_icmp"
		ip protocol icmp icmp type { destination-unreachable, router-advertisement, time-exceeded, parameter-problem } limit rate 100/second accept
		ip protocol icmp icmp type echo-request limit rate over 1/second counter packets 0 bytes 0 drop
		ip protocol icmp icmp type echo-request counter packets 0 bytes 0 accept
		ip6 nexthdr ipv6-icmp icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } limit rate 100/second accept
		ip6 nexthdr ipv6-icmp icmpv6 type echo-request limit rate over 1/second counter packets 0 bytes 0 drop
		ip6 nexthdr ipv6-icmp icmpv6 type echo-request counter packets 0 bytes 0 accept
		meta l4proto icmp counter packets 0 bytes 0 accept comment "Accept ICMP"
		ip6 nexthdr ipv6-icmp icmpv6 type destination-unreachable counter packets 0 bytes 0 accept
		ip6 nexthdr ipv6-icmp icmpv6 type packet-too-big counter packets 0 bytes 0 accept
		ip6 nexthdr ipv6-icmp icmpv6 type time-exceeded counter packets 0 bytes 0 accept
		ip6 nexthdr ipv6-icmp icmpv6 type parameter-problem counter packets 0 bytes 0 accept
		ip6 nexthdr ipv6-icmp icmpv6 type echo-reply counter packets 0 bytes 0 accept
		ip6 nexthdr ipv6-icmp icmpv6 type nd-router-advert counter packets 0 bytes 0 accept
		ip6 nexthdr ipv6-icmp icmpv6 type nd-neighbor-solicit counter packets 0 bytes 0 accept
		ip6 nexthdr ipv6-icmp icmpv6 type nd-neighbor-advert counter packets 0 bytes 0 accept
		ip protocol icmp icmp type echo-request counter packets 0 bytes 0 accept
		ip protocol icmp icmp type echo-request counter packets 0 bytes 0 accept
		ip protocol icmp icmp type echo-reply counter packets 0 bytes 0 accept
		ip protocol icmp icmp type destination-unreachable counter packets 0 bytes 0 accept
		ip protocol icmp icmp type router-advertisement counter packets 0 bytes 0 accept
		ip protocol icmp icmp type time-exceeded counter packets 0 bytes 0 accept
		ip protocol icmp icmp type parameter-problem counter packets 0 bytes 0 accept
		ip protocol icmp icmp type source-quench counter packets 0 bytes 0 drop
		ip protocol icmp icmp type redirect counter packets 0 bytes 0 drop
		ip protocol icmp icmp type router-solicitation counter packets 0 bytes 0 drop
		ip protocol icmp icmp type timestamp-request counter packets 0 bytes 0 drop
		ip protocol icmp icmp type timestamp-reply counter packets 0 bytes 0 drop
		ip protocol icmp icmp type info-request counter packets 0 bytes 0 drop
		ip protocol icmp icmp type info-reply counter packets 0 bytes 0 drop
		ip protocol icmp icmp type address-mask-request counter packets 0 bytes 0 drop
		ip protocol icmp icmp type address-mask-reply counter packets 0 bytes 0 drop
		counter name "unexpected_blue_forward_icmp"
		counter packets 0 bytes 0 log prefix "forward_blue_icmp_drop " drop comment "forward_blue_icmp_dropped"
	}

	chain forward_blue {
		counter packets 1982 bytes 147428
		counter name "blue_forward"
		ip daddr 127.0.0.0/8 counter packets 0 bytes 0 drop comment "drop invalid loopback traffic"
		ip6 daddr ::1 counter packets 0 bytes 0 drop comment "drop invalid loopback traffic"
		ip protocol tcp ct state new counter packets 0 bytes 0 jump forward_blue_tcp
		ip protocol udp ct state new counter packets 1982 bytes 147428 jump forward_blue_udp
		ip protocol icmp ct state new counter packets 0 bytes 0 jump forward_blue_icmp
		counter name "blue_forward_final"
		counter packets 0 bytes 0 log prefix "forward_blue" drop
		counter packets 0 bytes 0
		counter name "blue_forward"
		ip daddr 127.0.0.0/8 counter packets 0 bytes 0 drop comment "drop invalid loopback traffic"
		ip6 daddr ::1 counter packets 0 bytes 0 drop comment "drop invalid loopback traffic"
		ip protocol tcp ct state new counter packets 0 bytes 0 jump forward_blue_tcp
		ip protocol udp ct state new counter packets 0 bytes 0 jump forward_blue_udp
		ip protocol icmp ct state new counter packets 0 bytes 0 jump forward_blue_icmp
		counter name "blue_forward_final"
		counter packets 0 bytes 0 log prefix "forward_blue" drop
	}

	chain forward {
		type filter hook forward priority filter; policy accept;
		counter packets 42965 bytes 296038299
		counter name "filter_forward"
		ip daddr 255.255.255.255 counter packets 0 bytes 0 drop comment "really drop unsollicited IPv4 broadcast"
		ct state established,related counter packets 37879 bytes 295670302 accept
		ct state invalid counter packets 0 bytes 0 drop
		counter packets 5086 bytes 367997 jump bad_packets
		iif "wlp4s0" counter packets 3 bytes 216 jump forward_red
		iif "br0" counter packets 3101 bytes 220353 jump forward_green
		iif "virbr0" counter packets 1982 bytes 147428 jump forward_blue
		iif "lo" ip daddr 127.0.0.0/8 counter packets 0 bytes 0 log prefix "illegal loopback in filter-forward" drop
		counter name "unexpected_filter_forward"
		counter packets 0 bytes 0 log prefix "forward " drop comment "forward"
		counter packets 0 bytes 0
		counter name "filter_forward"
		ip daddr 255.255.255.255 counter packets 0 bytes 0 drop comment "really drop unsollicited IPv4 broadcast"
		ct state established,related counter packets 0 bytes 0 accept
		ct state invalid counter packets 0 bytes 0 drop
		counter packets 0 bytes 0 jump bad_packets
		iif "wlp4s0" counter packets 0 bytes 0 jump forward_red
		iif "br0" counter packets 0 bytes 0 jump forward_green
		iif "virbr0" counter packets 0 bytes 0 jump forward_blue
		iif "lo" ip daddr 127.0.0.0/8 counter packets 0 bytes 0 log prefix "illegal loopback in filter-forward" drop
		counter name "unexpected_filter_forward"
		counter packets 0 bytes 0 log prefix "forward " drop comment "forward"
	}
}
table ip NAT {
	counter ip_NAT {
		packets 21255 bytes 1418765
	}

	counter ip_NAT_final {
		packets 0 bytes 0
	}

	chain NAT_postrt {
		type nat hook postrouting priority srcnat; policy accept;
		counter packets 6179 bytes 410495
		counter name "ip_NAT"
		oifname "wlp4s0" ip saddr 192.168.132.0/24 counter packets 973 bytes 62311 masquerade
		oifname "wlp4s0" ip saddr 192.168.100.0/24 counter packets 178 bytes 11926 masquerade
		counter name "ip_NAT"
		counter packets 5028 bytes 336258
		counter packets 5024 bytes 336006
		counter name "ip_NAT"
		oifname "wlp4s0" ip saddr 192.168.132.0/24 counter packets 0 bytes 0 masquerade
		oifname "wlp4s0" ip saddr 192.168.100.0/24 counter packets 0 bytes 0 masquerade
		counter name "ip_NAT"
		counter packets 5024 bytes 336006
	}
}
```
