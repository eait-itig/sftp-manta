%% Copyright (c) 2017-2018, Loïc Hoguin <essen@ninenines.eu>
%% Copyright 2019, The University of Queensland
%%
%% Permission to use, copy, modify, and/or distribute this software for any
%% purpose with or without fee is hereby granted, provided that the above
%% copyright notice and this permission notice appear in all copies.
%%
%% THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
%% WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
%% MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
%% ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
%% WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
%% ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
%% OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

-module(gun_data_h).
-behavior(gun_content_handler).

-export([init/5]).
-export([handle/3]).
-export([await_body/2, await_body/3]).

-record(state, {
    reply_to :: pid(),
    stream_ref :: reference()
}).

-spec init(pid(), reference(), _, _, _) -> {ok, #state{}}.
init(ReplyTo, StreamRef, _, _, _) ->
    {ok, #state{reply_to=ReplyTo, stream_ref=StreamRef}}.

-spec handle(fin | nofin, binary(), State) -> {done, State} when State::#state{}.
handle(IsFin, Data, State=#state{reply_to=ReplyTo, stream_ref=StreamRef}) ->
    Ref = erlang:make_ref(),
    MRef = monitor(process, ReplyTo),
    ReplyTo ! {gun_data, self(), StreamRef, IsFin, Data, Ref},
    receive
        {gun_data_ack, ReplyTo, StreamRef, Ref} -> ok;
        {'DOWN', MRef, process, _, Reason} -> ok
    end,
    demonitor(MRef),
    {done, State}.

await_body(ServerPid, StreamRef) ->
    MRef = monitor(process, ServerPid),
    Res = await_body(ServerPid, StreamRef, 5000, MRef, <<>>),
    demonitor(MRef, [flush]),
    Res.

await_body(ServerPid, StreamRef, MRef) when is_reference(MRef) ->
    await_body(ServerPid, StreamRef, 5000, MRef, <<>>);
await_body(ServerPid, StreamRef, Timeout) ->
    MRef = monitor(process, ServerPid),
    Res = await_body(ServerPid, StreamRef, Timeout, MRef, <<>>),
    demonitor(MRef, [flush]),
    Res.

await_body(ServerPid, StreamRef, Timeout, MRef) ->
    await_body(ServerPid, StreamRef, Timeout, MRef, <<>>).

await_body(ServerPid, StreamRef, Timeout, MRef, Acc) ->
    receive
        {gun_data, ServerPid, StreamRef, nofin, Data, Ref} ->
            ServerPid ! {gun_data_ack, self(), StreamRef, Ref},
            await_body(ServerPid, StreamRef, Timeout, MRef,
                << Acc/binary, Data/binary >>);
        {gun_data, ServerPid, StreamRef, fin, Data, Ref} ->
            ServerPid ! {gun_data_ack, self(), StreamRef, Ref},
            {ok, << Acc/binary, Data/binary >>};
        %% It's OK to return trailers here because the client
        %% specifically requested them.
        {gun_trailers, ServerPid, StreamRef, Trailers} ->
            {ok, Acc, Trailers};
        {gun_error, ServerPid, StreamRef, Reason} ->
            {error, Reason};
        {gun_error, ServerPid, Reason} ->
            {error, Reason};
        {'DOWN', MRef, process, ServerPid, Reason} ->
            {error, Reason}
    after Timeout ->
        {error, timeout}
    end.

