%%Importing facts from RuleBase.pl file in the same directory.
:-include('Rulebase.pl').

%isIP is function that helps identify if given IP Y is type IPv4 or IPv6. It returns true for IPv6
isIP(Y):-
	split_string(Y,".","",L),   %Splits the string using '.' as a delimiter and returns a list 'L'
	length(L,1).		    %Checks if list 'L' has only one element			

%Code for range checkers

%Evaluates whether the given IP is IPv4 or IPv6 and accordingly check if the range of the 'Num' th place is between 'X' and 'Z'
%WARNING: ensure 'X' and 'Z' are in hexadecimal(like 0x0455) when checking for a IPv6 address
rangeIP(X,Y,Z,Num):-
	isIP(Y) ->
	split_string(Y,":","",L),
	length(L,8),	            
	nth0(Num,L,Elem),            %Gets the 'Num' th element of 'L' and assigns it to 'Elem'
	D="0x",
	string_concat(D,Elem,C),     %Concatenates 'D' and 'Elem' to give string 'C'	
	atom_number(C,A),	     %Converts string 'C' to a number 'A'
	A>X-1,
	A<Z+1;	

	split_string(Y,".","",L),
	length(L, 4),
	nth0(Num,L,Elem),
	atom_number(Elem,A),
	A>X-1,
	A<Z+1.

%Checks if the value 'Y' is between 'X' and 'Z'.
rangeGen(X,Y,Z):-
	write(Y),
	Y>X-1,
	Y<Z+1.
	
%Checks if the alphabet 'Y' is within the range of alphabets between 'X' and 'Z'
rangeAdapter(X,Y,Z):-
	char_code(X,A),  %To convert character 'X' to its ASCII value 'A'
	char_code(Y,B),
	char_code(Z,C),
	B>A-1, B<C+1.

%End of code for range checkers


%Code for Main Execution

% The main code evaluates in the order of 'Invalid Input' > 'Reject' > 'Drop' > 'Accept' 
% so as to enable the parameter with greater precedence to override the other in case of conflict



determine(Adapter,VlanID,EthProtocol,IPSource,IPDest,Datagram,Arg1,Arg2):-
	packet(invalid_input,Adapter,VlanID,EthProtocol,IPSource,IPDest,Datagram,Arg1,Arg2),
	write("Invalid Input").

determine(Adapter,VlanID,EthProtocol,IPSource,IPDest,Datagram,Arg1,Arg2):-
	packet(reject,Adapter,VlanID,EthProtocol,IPSource,IPDest,Datagram,Arg1,Arg2),
	write("Packet has been Rejected").

determine(Adapter,VlanID,EthProtocol,IPSource,IPDest,Datagram,Arg1,Arg2):-
	packet(drop,Adapter,VlanID,EthProtocol,IPSource,IPDest,Datagram,Arg1,Arg2),
	write("Packet has been Dropped").

determine(Adapter,VlanID,EthProtocol,IPSource,IPDest,Datagram,Arg1,Arg2):-
	write("Packet has been Accepted").

%End of code for Main Execution
