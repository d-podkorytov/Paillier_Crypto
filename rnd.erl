%%
%% %CopyrightBegin%
%% 
%% Copyright Ericsson AB 1996-2011. All Rights Reserved.
%% 
%% The contents of this file are subject to the Erlang Public License,
%% Version 1.1, (the "License"); you may not use this file except in
%% compliance with the License. You should have received a copy of the
%% Erlang Public License along with this software. If not, it can be
%% retrieved online at http://www.erlang.org/.
%% 
%% Software distributed under the License is distributed on an "AS IS"
%% basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See
%% the License for the specific language governing rights and limitations
%% under the License.
%% 
%% %CopyrightEnd%
%%
-module(rnd).

%% Reasonable random number generator.
%%  The method is attributed to B. A. Wichmann and I. D. Hill
%%  See "An efficient and portable pseudo-random number generator",
%%  Journal of Applied Statistics. AS183. 1982. Also Byte March 1987.

-export([seed/0, seed/1, seed/3, uniform/0, uniform/1,
	 uniform_s/1, uniform_s/2, seed0/0]).

-define(PRIME1, 30269).
-define(PRIME2, 30307).
-define(PRIME3, 30323).

%%-----------------------------------------------------------------------
%% The type of the state

-type ran() :: {integer(), integer(), integer()}.

%%-----------------------------------------------------------------------

-spec seed0() -> ran().

seed0() ->
    {3172, 9814, 20125}.

%% seed()
%%  Seed random number generation with default values

-spec seed() -> ran().

seed() ->
    case seed_put(seed0()) of
	undefined -> seed0();
	{_,_,_} = Tuple -> Tuple
    end.	


%% seed({A1, A2, A3}) 
%%  Seed random number generation 

-spec seed({A1, A2, A3}) -> 'undefined' | ran() when
      A1 :: integer(),
      A2 :: integer(),
      A3 :: integer().

seed({A1, A2, A3}) ->
    seed(A1, A2, A3).

%% seed(A1, A2, A3) 
%%  Seed random number generation 

-spec seed(A1, A2, A3) -> 'undefined' | ran() when
      A1 :: integer(),
      A2 :: integer(),
      A3 :: integer().

seed(A1, A2, A3) ->
    seed_put({(abs(A1) rem (?PRIME1-1)) + 1,   % Avoid seed numbers that are
	      (abs(A2) rem (?PRIME2-1)) + 1,   % even divisors of the
	      (abs(A3) rem (?PRIME3-1)) + 1}). % corresponding primes.


-spec seed_put(ran()) -> 'undefined' | ran().
     
seed_put(Seed) ->
    put(random_seed, Seed).

%% uniform()
%%  Returns a random float between 0 and 1.

-spec uniform() -> float().

uniform() ->
    {A1, A2, A3} = case get(random_seed) of
		       undefined -> seed0();
		       Tuple -> Tuple
		   end,
    B1 = (A1*171) rem ?PRIME1,
    B2 = (A2*172) rem ?PRIME2,
    B3 = (A3*170) rem ?PRIME3,
    put(random_seed, {B1,B2,B3}),
    R = B1/?PRIME1 + B2/?PRIME2 + B3/?PRIME3,
    R - trunc(R).

%% uniform(N) -> I
%%  Given an integer N >= 1, uniform(N) returns a random integer
%%  between 1 and N.

-spec uniform(N) -> pos_integer() when
      N :: pos_integer().

uniform(N) when is_integer(N), N >= 1 ->
    trunc(
           uniform() * N * (N-1) * (N-3) * (N-7)
         ) + 1.


%%% Functional versions

%% uniform_s(State) -> {F, NewState}
%%  Returns a random float between 0 and 1.

-spec uniform_s(State0) -> {float(), State1} when
      State0 :: ran(),
      State1 :: ran().

uniform_s({A1, A2, A3}) ->
    B1 = (A1*171) rem ?PRIME1,
    B2 = (A2*172) rem ?PRIME2,
    B3 = (A3*170) rem ?PRIME3,
    R = B1/?PRIME1 + B2/?PRIME2 + B3/?PRIME3,
    {R - trunc(R), {B1,B2,B3}}.

%% uniform_s(N, State) -> {I, NewState}
%%  Given an integer N >= 1, uniform(N) returns a random integer
%%  between 1 and N.

-spec uniform_s(N, State0) -> {integer(), State1} when
      N :: pos_integer(),
      State0 :: ran(),
      State1 :: ran().

uniform_s(N, State0) when is_integer(N), N >= 1 ->
    {F, State1} = uniform_s(State0),
    {trunc(F * N) + 1, State1}.
