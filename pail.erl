-module(pail).
-compile([export_all]).
-define(log2denom, 0.69314718055994529).

log2(X) -> math:log(X) / ?log2denom.

mpow(A,0) -> 1;
mpow(A,N) -> A*mpow(A,N-1).
mpow(A, 1, M) -> A rem M;
mpow(A, 2, M) -> A*A rem M;
mpow(A, B, M) ->  B1 = B div 2, B2 = B - B1, % B2 = B1 or B1+1
P = mpow(A, B1, M),
case B2 of
  B1 -> (P*P) rem M;
  _  -> (P*P*A) rem M
end.

generate_key(Bits) -> 
case Bits rem 2 of
        0 -> P=gen_prime(Bits div 2), 
		Q=gen_prime(Bits div 2), 
		N=P*Q, put(bits,Bits),
		put(private,Pr={(P-1)*(Q-1),invmod((P-1)*(Q-1),P*Q)}),
		put(public,Pub={N,N*N,N+1}),
		Return = {P,Q,N,Pr,Pub};
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

encrypt(M) -> P=get(public), {N, Ns, G} = P, 
R=gen_prime(round(log2(N))),
case R<N of 
  true ->  put(r,R), R;
  _ -> encrypt(M)
end,
(mpow(G,M,Ns)*mpow(R,N,Ns)) rem Ns.   %C - Encrypted Message (c = g^m * r^n mod n^2)

decrypt(C) -> Pr=get(private),{L,M} = Pr, P=get(public), {N, Ns, G} = P, Message=(((mpow(C,L,Ns)-1) div N) * M) rem N.

entext(T) when is_list(T) -> encrypt(lin:str2int(T));
entext(T) -> "wrong type".

detext(C) -> lin:int2str(decrypt(C)).

ipow(A,B,N) -> Aa=A rem N, put(rm,[Aa]), put(a,Aa), T=rmm(1,B), ipow(A,B,N,T).
ipow(A,B,N,0) -> get(rm);
ipow(A,B,N,T) when (T band B) == T -> Aa=((A*A) rem N * get(a)) rem N, L=get(rm), put(rm,get(rm)++[Aa]), ipow(Aa,B,N,T bsr 1);
ipow(A,B,N,T) -> Aa=(A*A) rem N, L=lists:append(get(rm),", "), put(rm,get(rm)++[Aa]), put(t,T), ipow(Aa,B,N,T bsr 1).

rmm(T,B) when T<B -> rmm(T bsl 1, B);
rmm(T,B) when T>B -> T bsr 2;
rmm(T,B) when T==B -> T bsr 1.

rabin_miller_witness(Test,Possible) -> lists:member(1,ipow(Test,Possible-1,Possible)).

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
gen_prime(Bits,K) -> P=mrand(mpow(2,Bits-1),mpow(2,Bits)) bor 1, case primes:is_prime(P) of 
   true -> P;
   false -> gen_prime(Bits,K)
end.

mrand(M1,M2) -> Res=random:uniform(M2), case Res>M1 of
  true -> Res;
  _ -> mrand(M1,M2)
end.

add(A,B) -> P=get(public), {_, Ns, _} = P, (A*B) rem Ns.
add_const(A,N) -> P=get(public), {N, Ns, G} = P, (A*mpow(G,N,Ns)) rem Ns.

mul_const(A,N) -> P=get(public), {_, Ns, _} = P, mpow(A,N,Ns).
