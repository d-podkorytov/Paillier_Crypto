-module(pial2test).
-export([start/0]).

start()->
 {Priv,Pub}=pail2:generate_key(64),
 io:format("keys= ~p ~n",[{Priv,Pub}]),
  CMsg=pail2:entext("Msg",Pub),
 io:format("CMsg= ~p ~n",[CMsg]), 
  pail2:detext(CMsg,{Priv,Pub}).

