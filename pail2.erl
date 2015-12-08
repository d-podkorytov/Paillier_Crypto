-module(pail2).
-compile([export_all]).
log2(X) -> math:log(X) / 0.69314718055994529.

mpow(A,0) -> 1;
mpow(A,N) -> A*mpow(A,N-1).
mpow(A, 1, M) ->  A rem M;
mpow(A, 2, M) ->  A*A rem M;
mpow(A, B, M) ->  B1 = B div 2, B2 = B - B1, % B2 = B1 or B1+1
P = mpow(A, B1, M),
case B2 of
  B1 -> (P*P) rem M;
  _  -> (P*P*A) rem M
end.

generate_key(Bits) -> 
case Bits rem 2 of
        0 ->    P=gen_prime(Bits div 2), 
		Q=gen_prime(Bits div 2), 
		N=P*Q, 
		Pr={(P-1)*(Q-1),invmod((P-1)*(Q-1),P*Q)},
		Pub={N,N*N,N+1},
		Return = {Pr,Pub};
        _ -> "Bits should be divisible by 2"
end.

invmod(A,P) -> invmod(A,P,1000000).
invmod(A,P,0) -> "no inverse mod";
invmod(0,P,Iter) -> "0 has no inverse mod";
invmod(A,P,Iter) -> D=(P div A + 1) rem P, R=(D * A) rem P, invmod(A,P,Iter-1,D,R).
invmod(A,P,0,D,R) -> "no inverse mod";
invmod(0,P,Iter,D,R) -> "0 has no inverse mod";
invmod(A,P,Iter,D,1) -> D;
invmod(A,P,Iter,D,R) -> Dd=((P div R + 1)*D) rem P, Rr=(Dd * A) rem P, invmod(A,P,Iter-1,Dd,Rr).

encrypt(M,Pub) -> {N, Ns, G} = Pub, 
R=gen_prime(round(log2(N))),
case R<N of 
  true ->  % put(r,R), 
           R;
  _ -> encrypt(M,Pub)
end,
(mpow(G,M,Ns)*mpow(R,N,Ns)) rem Ns. 
%C - Encrypted Message (c = g^m * r^n mod n^2)

decrypt(C,{Pr,Pub}) -> {L,M} = Pr, 
                       {N, Ns, G} = Pub, 
                        Message=(((mpow(C,L,Ns)-1) div N) * M) rem N.

entext(T,Pub) when is_list(T) -> encrypt(lin:str2int(T),Pub);
entext(_,_) -> "wrong type".

detext(C,{Pr,Pub}) -> lin:int2str(decrypt(C,{Pr,Pub})).

ipow(A,B,N) ->   Aa=A rem N, T=rmm(1,B), ipow(A,B,N,T,Aa).
ipow(A,B,N,0,Rm) -> Rm;
ipow(A,B,N,T,Rm) when (T band B) == T -> 
                 Aa=((A*A) rem N * Rm) rem N, 
                 ipow(Aa,B,N,T bsr 1,[Rm]++[Aa]);
ipow(A,B,N,T,Rm) -> Aa=(A*A) rem N, 
                 L=lists:append(Rm,", "), 
                 ipow(Aa,B,N,T bsr 1,Rm++[Aa]).

rmm(T,B) when T<B  -> rmm(T bsl 1, B);
rmm(T,B) when T>B  -> T bsr 2;
rmm(T,B) when T==B -> T bsr 1.

rabin_miller_witness(Test,Possible) -> 
  lists:member(1,ipow(Test,Possible-1,Possible)).

is_pprime(1) -> true;
is_pprime(Possible) -> is_pprime(Possible,default_k(get_bits(Possible))).
is_pprime(P,0) -> true;
is_pprime(P,K) -> Test=random:uniform(P-1) bor 1, 
case rabin_miller_witness(Test,P) of  
  true -> is_pprime(P,K-1);
  false -> false 
end.

default_k(Bits) -> max(64,2*Bits).

get_bits(0) -> 0;
get_bits(N) -> get_bits(N,0).
get_bits(0,B) -> B;
get_bits(N,B) -> get_bits(N bsr 1, B+1).

gen_prime(Bits) -> gen_prime(Bits,default_k(Bits)).
gen_prime(Bits,K) -> P=mrand(mpow(2,Bits-1),
                     mpow(2,Bits)) bor 1, 
case primes:is_prime(P) of 
   true -> P;
   false -> gen_prime(Bits,K)
end.

mrand(M1,M2) -> Res=random:uniform(M2), case Res>M1 of
  true -> Res;
  _ -> mrand(M1,M2)
end.

gen_keys()-> Pid=spawn(?MODULE, generate_key, [1024] ), %link(Pid), 
receive
_ -> ok
end.
% {link(spawn(fun generate_key(128)),link(spawn(fun generate_key(256)),link(spawn(fun generate_key(512)),link(spawn(fun generate_key(1024))}.

add(A,B,{_, Ns, _})       ->  (A*B) rem Ns.
add_const(A,N,{N, Ns, G}) ->  (A*mpow(G,N,Ns)) rem Ns.
mul_const(A,N,{_, Ns, _})-> mpow(A,N,Ns).
