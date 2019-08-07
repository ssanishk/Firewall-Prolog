# FIREWALL SYSTEM
Project Link : https://github.com/ssanishk/Firewall-Prolog
#### OBJECTIVE:-

   To check if a given valid input packet of data gets 'Rejected','Accepted' or 'Dropped' based on a modifiable Rule base.

#### DESCRIPTION:-

There are two main executable .pl files:
 
 1.Engine.pl    : This is the main executable file. It evaluates the status of the provided packet using the rule base        present in the 'Rulebase.pl' file. 

  2.RuleBase.pl  : This is the secondary file, which contains the rules for assigning the status of the input packet.

#### USAGE:-

  1. Load the file Engine.pl on Swi-Prolog after placing in root directory.
	?- ['Engine.pl']

  2. To check the status of the packet having the information {A,B,C,D,E,F,G,H} input the following
	?-determine(A,B,C,D,E,F,G,H)
```
	A:- Adapter 									(Character without quotes)
	B:- VLAN ID 									(Integer)
	C:- Ethernet Protocol ID						        (string within quotes)
	D;- IP Source Address								(IP within quotes)
	E:- IP Destination Address 							(IP within quotes)
	F:- Transportation Protocol-Datagram. 						(string within quotes or a number)
	G:- Source Port if 'F' is 'tcp' or 'udp' else Type if 'F' is 'icmp' or 'icmpv6' (Integer)
	H:- Destination Port if is 'tcp' or 'udp' else Code if 'F' is 'icmp' or 'icmpv6'(Integer)
	It is necessary for all the input to be in lower case letters
	Eg:-
	?- determine(j, 3, "mpls" , "192.168.1.106", "192.168.1.1", "tcp", 80, 4000).
```
NOTE: If the 'F' is a number instead of a string, then 'G' and 'H' are redundant and can be given any value

  3. Every packet will always be to or from our system, so every packet should have either the IP Source Address (D) or the 	IP Destination Address (E) same as the system's address                (present in myip function of Rulebase.pl). A 	     default value of myip is present in the rulebase ("192.168.1.106").
	
  4. Output depicts one of the three possible states: Accept, Reject and Drop.	
	?- Packet has been Dropped (for the example give above)
      If invalid input is given, the output is "Invalid Input".

#### MODIFYING THE RULE BASE:-

	The Rulebase.pl executable file is editable, and enables the user to add/remove packet conditions. For example a 	'Reject' packet condition looks like:
```	
	packet(reject, A, B, C, D, E, F, G, H):-	%can also specify 'drop', 'invalid_input' in the first argument
	(rangeAdapter(e,A,f),				%Specify user required conditions
	not((C = "mpls"; C="arp"; C="aarp"))).  
 ``` 

AUTHORS:-

Anishkumar SS        2017A7PS0069P
J Lakshmi Teja       2017A7PS0068P
Siddhant Kharbanda   2017A7PS0111P 
