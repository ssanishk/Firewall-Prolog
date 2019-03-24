myip("192.168.1.106").

%Code for Error Handling

%A:- Adapter
%B:- VLAN ID
%C:- Ethernet Protocol
%D;- IP Source
%E:- IP Destination
%F:- Transportation Protocol(Datagram)
%G:- Source Port if 'F' is 'tcp' or 'udp' else Type if 'F' is 'icmp' or 'icmpv6'
%H:- Destination Port if is 'tcp' or 'udp' else Code if 'F' is 'icmp' or 'icmpv6'

% Checks whether the given parameters are within acceptable ranges
packet( invalid_input, A, B, C, D, E, F, G, H):-
	not(
		(	rangeAdapter(a,A,p),                                						%Checks validity of Adapter                                                        	 	rangeGen(1,B, 1001), 										%Checks validity of VLAN ID
            										
			[_|M]= [_, "arp", "aarp", "atalk", "ipx", "mpls","netbui", "pppoe", "rarp", "sna","xns"], 	
			member(C, M),											%Checks validity of Ethernet Protocol
			(myip(D) ; myip(E)),										%Checks whether one of the given IP's is the source IP 
			(  
				( (not(isIP(D)),rangeIP(0,D,255,0), rangeIP(0,D,255,1), rangeIP(0,D,255,2), 
                                    rangeIP(0,D,255,3)); 
					(isIP(D), rangeIP(0x0000,D,0xffff,0), rangeIP(0x0000,D,0xffff,1), rangeIP(0x0000,D,0xffff,2), 							
					rangeIP(0x0000,D,0xffff,3), rangeIP(0x0000,D,0xffff,4), rangeIP(0x0000,D,0xffff,5), 
                                        rangeIP(0x0000,D,0xffff,6), rangeIP(0x0000,D,0xffff,7))
			    	    
		        	),
 	
				(	
					(not(isIP(E)),rangeIP(0,E,255,0), rangeIP(0,E,255,1), rangeIP(0,E,255,2),		%If IP type is ipv4; checks validity of each field one by one  
				    rangeIP(0,E,255,3));  
			    	        (isIP(E), rangeIP(0x0000,E,0xffff,0), rangeIP(0x0000,E,0xffff,1), rangeIP(0x0000,E,0xffff,2), 							
					rangeIP(0x0000,E,0xffff,3), rangeIP(0x0000,E,0xffff,4), rangeIP(0x0000,E,0xffff,5), 		%If IP type is ipv6; checks validity of each field one by one 
					rangeIP(0x0000,E,0xffff,6), rangeIP(0x0000,E,0xffff,7))
				)
			),
		
			(
				(F = "tcp", rangeGen(0,G,65535), rangeGen(0,H,65535));					%If Datagram is 'tcp' checks validity of source and destination port
		        	(F = "udp", rangeGen(0,G,65535), rangeGen(0,H,65535)); 					%If Datagram is 'udp' checks validity of source and destination port
				(not(isIP(D)), F = "icmp", rangeGen(0,G,255), rangeGen(0,H,10)); 			%If Datagram is 'icmp' checks validity of Type and Code
				(isIP(D), F = "icmpv6", rangeGen(0,G,255), rangeGen(0,H,10));				%If Datagram is 'icmpv6' checks validity of Type and Code
				(rangeGen(0x00,F,0xff))									%If Datagram is a number, checks validity
			)
		)
		
		
	). 

%End of code for Error Handling

  
%%General tcp and port condition

packet(reject, A, B, C, D, E, F, G, H):-
    (rangeIP(0x64, D, 0x64, 0), rangeIP(0xff9b, D, 0xff9b, 1)).

packet(reject, A, B, C, D, E, F, G, H):-
	(F="tcp", 
	(([_|Q] = [_,19, 22, 23, 5900, 3389, 162], member(H, Q));
	rangeGen(200, G, 1023);
	rangeGen(200, H, 1023))).

%%General udp and port condition
packet(reject, A, B, C, D, E, F, G, H):-
	(F="udp",
    (([_|Q] = [_,19, 22, 23, 162, 1434, 3389, 41170], member(H, Q)));
	((G=:= 1434; G=:=41170);
	rangeGen(200, G, 1023);
	rangeGen(200, H, 1023))).

%%General icmp/icmpv6 conditions
packet(reject, A, B, C, D, E, F, G, H):-
	((F="icmp" ; F="icmpv6"),
	(G=:=8; G=:= 0; G=:= 11);
	(G=:=3, H=:=4);
	rangeGen(7, H, 10)).

%%computer is not allowed to send a packet to itself. 
packet(reject, A, B, C, D, E, F, G, H):-
	(myip(D), myip(E)).

%%IP ranges starting from 127, 224 - 254 are reserved
%%We cannot send a packet to those IP ranges
packet(reject, A, B, C, D, E, F, G, H):-
	(myip(D),
    (rangeIP(127, E, 127, 0);
    rangeIP(224, E, 254, 0))).


%%always block ipx, xns ethernet protocols and some VLAN id
packet(reject, A, B, C, D, E, F, G, H):-
	((C="ipx"; C="xns");
    (rangeGen(23, B, 37))).

%%Firewall blocks certain IP ranges of class C. 
packet(reject, A, B, C, D, E, F, G, H):-
    ((rangeIP(193, D, 223, 0), rangeIP(0, D, 30, 1));
    (rangeIP(193, E, 223, 0), rangeIP(0, E, 34, 1))).

packet(reject, A, B, C, D, E, F, G, H):-
    ((rangeIP(0x100, D, 0x100, 0); (rangeIP(0x100, E, 0x100, 0)));
    (rangeIP(0x2001, D, 0x2001, 0); (rangeIP(0x2001, E, 0x2001, 0)))).


%%We block request queries from some packets following certain ethernet protocols
packet(reject, A, B, C, D, E, F, G, H):-
	(myip(E),
	(C="atalk"; C="netbui")).

%%adapters c - d only work on icmp or icmpv6 and 
%%block all Class A IP addresses. 
packet(reject, A, B, C, D, E, F, G, H):-
	(rangeAdapter(c, A, d),
	((F="tcp"; F="udp");
	rangeIP(0,E,126,0);
    rangeIP(0,D,126,0))).

%%adapters e and f only work with ethernet protocols mpls/arp/aarp
packet(reject, A, B, C, D, E, F, G, H):-
	(rangeAdapter(e,A,f),
	not((C = "mpls"; C="arp"; C="aarp"))).

%%adapter k and l are completely blocked
packet(reject, A, B, C, D, E, F, G, H):-
	(rangeAdapter(k, A, l)).

%%the firewall drops all packets using ports between (5000-6000)
%%and certain VLAN Ids
packet(drop, A, B, C, D, E, F, G, H):-
	(((F="tcp"; F="upd");
    (rangeGen(5000, G, 6000);
    rangeGen(5000, G, 6000)));
   	rangeGen(40, B, 50)).

%%Working on adapters a and b, we drop any packet working on 
%%either udp or having an IP addresses from 128.00._._-170.50.0.0.
packet(drop, A, B, C, D, E, F, G, H):-
	(rangeAdapter(a, A, b),
    (F="udp";
    ((rangeIP(128, D, 170, 0), rangeIP(0, D, 10, 1));
    (rangeIP(128, E, 170, 0), rangeIP(0, E, 20, 1))))
    ).

%%adapters m - p are highly restricted, uses only mpls/rarp and only tcp.
%%they only allow only the first 200 ports for communication. 
%%This is done for highly classified message exchange.
%%Hence, the packet will be dropped if doesn't follow this.
packet(drop, A, B, C, D, E, F, G, H):-
	(rangeAdapter(m, A, p),
	(not((F="tcp"));
	not((C = "mpls"; C="arp"));
    rangeGen(201,G,65505);
    rangeGen(201,H,65505))).