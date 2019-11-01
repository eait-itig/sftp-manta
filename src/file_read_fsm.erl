%%
%% sftp-manta bridge
%%
%% Copyright 2019 Alex Wilson <alex@uq.edu.au>
%% The University of Queensland
%%
%% Redistribution and use in source and binary forms, with or without
%% modification, are permitted provided that the following conditions
%% are met:
%% 1. Redistributions of source code must retain the above copyright
%%    notice, this list of conditions and the following disclaimer.
%% 2. Redistributions in binary form must reproduce the above copyright
%%    notice, this list of conditions and the following disclaimer in the
%%    documentation and/or other materials provided with the distribution.
%%
%% THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
%% IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
%% OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
%% IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
%% INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
%% NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
%% DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
%% THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
%% (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
%% THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
%%

-module(file_read_fsm).

-behaviour(gen_statem).

-include_lib("kernel/include/file.hrl").
-compile([{parse_transform, lager_transform}]).

-export([start_link/4]).
-export([init/1, callback_mode/0]).
-export([disconnected/3, ready/3, flowing/3, corked/3, skipping/3, ended/3, errored/3]).

start_link({Host, Port}, Path, AuthMode, SignerOrToken) ->
    gen_statem:start_link(?MODULE, [{Host, Port}, Path, AuthMode, SignerOrToken], []).

-record(state, {
    host,
    port,
    path,
    gun,
    amode,
    signer,
    token,
    rng,
    stream,
    len,
    hdrs,
    error,
    waiter = none,
    reader = none,
    mref,
    ackref = none,
    rpos = 0,
    spos = 0,
    buf = <<>>
    }).

-define(BUF_MAX, 128*1024).

callback_mode() -> [state_functions, state_enter].

request(Verb, Url, Hdrs0, #state{gun = Gun, signer = Signer, amode = signature}) ->
    Req = http_signature:sign(Signer, Verb, Url, Hdrs0),
    #{headers := Hdrs1} = Req,
    Method = case Verb of
        head -> "HEAD";
        get -> "GET";
        post -> "POST";
        put -> "PUT";
        delete -> "DELETE"
    end,
    Hdrs2 = maps:to_list(Hdrs1),
    gun:request(Gun, Method, Url, Hdrs2);
request(Verb, Url, Hdrs0, #state{gun = Gun, token = Token, amode = token}) ->
    Authz = iolist_to_binary([<<"Token ">>, Token]),
    Hdrs1 = Hdrs0#{<<"authorization">> => Authz},
    Method = case Verb of
        head -> "HEAD";
        get -> "GET";
        post -> "POST";
        put -> "PUT";
        delete -> "DELETE"
    end,
    Hdrs2 = maps:to_list(Hdrs1),
    gun:request(Gun, Method, Url, Hdrs2).

init([{Host, Port}, Path, signature, Signer]) ->
    S0 = #state{host = Host, port = Port, path = Path,
        amode = signature, signer = Signer},
    {ok, disconnected, S0};
init([{Host, Port}, Path, token, Token]) ->
    S0 = #state{host = Host, port = Port, path = Path,
        amode = token, token = Token},
    {ok, disconnected, S0}.

disconnected(enter, _, _S) ->
    keep_state_and_data;
disconnected({call, From}, connect, S0 = #state{host = Host, port = Port, path = Path}) ->
    {ok, Gun} = gun:open(Host, Port, #{
        transport_opts => [
            {recbuf, 128*1024}, {sndbuf, 128*1024}, {buffer, 256*1024},
            {keepalive, true}
        ],
        retry => 0
    }),
    {ok, _} = gun:await_up(Gun),
    MRef = monitor(process, Gun),
    S1 = S0#state{gun = Gun, mref = MRef},
    Stream = request(head, Path, #{}, S1),
    case gun:await(Gun, Stream, 30000) of
        {response, fin, Status, Headers} when (Status < 300) ->
            Hdrs = maps:from_list(Headers),
            #{<<"content-length">> := LenBin} = Hdrs,
            Len = binary_to_integer(LenBin),
            CanRange = case Hdrs of
                #{<<"accept-ranges">> := <<"none">>} -> false;
                #{<<"accept-ranges">> := _} -> true;
                _ -> false
            end,
            gen_statem:reply(From, ok),
            {next_state, ready, S1#state{rng = CanRange, len = Len}};
        _ ->
            gen_statem:reply(From, {error, enoent}),
            {stop, normal}
    end.

ready(enter, _, #state{}) ->
    keep_state_and_data;
ready({call, From}, {position, Offset}, S = #state{rng = true, gun = Gun}) ->
    Pos = case Offset of
        {bof, V} -> V;
        {cur, V} -> V;
        bof -> 0;
        cur -> 0
    end,
    PosBin = integer_to_binary(Pos),
    LenBin = integer_to_binary(S#state.len),
    RangeHeader = <<"bytes=", PosBin/binary, "-", LenBin/binary>>,
    InHdrs = #{<<"range">> => RangeHeader},
    Stream = request(get, S#state.path, InHdrs, S),
    S1 = S#state{buf = <<>>, rpos = Pos, spos = Pos, stream = Stream},
    gen_statem:reply(From, {ok, Pos}),
    case gun:await(Gun, Stream, 30000) of
        {response, fin, Status, _Headers} when (Status < 300) ->
            {next_state, ended, S1};
        {response, nofin, Status, Headers} when (Status < 300) ->
            Hdrs = maps:from_list(Headers),
            if
                (Pos > 0) -> lager:debug("using range req to skip to ~p", [Pos]);
                true -> ok
            end,
            {next_state, flowing, S1#state{hdrs = Hdrs}};
        {response, nofin, Status, Headers} ->
            Hdrs = maps:from_list(Headers),
            #{<<"content-type">> := ContentType} = Hdrs,
            {ok, Body} = gun_data_h:await_body(Gun, Stream, 30000),
            ErrInfo = case ContentType of
                <<"application/json">> -> {http, Status, jsx:decode(Body, [return_maps])};
                _ -> {http, Status, Body}
            end,
            case ErrInfo of
                {http, 416, #{<<"code">> := <<"RequestedRangeNotSatisfiableError">>}} ->
                    {next_state, ended, S1};
                _ ->
                    lager:debug("getobject returned ~p", [ErrInfo]),
                    {next_state, errored, S1#state{error = ErrInfo}}
            end;
        {response, fin, Status, _Headers} ->
            {next_state, errored, S1#state{error = {http, Status}}}
    end;
ready({call, From}, {position, Offset}, S = #state{rng = false, gun = Gun}) ->
    Pos = case Offset of
        {bof, V} -> V;
        {cur, V} -> V;
        bof -> 0;
        cur -> 0
    end,
    Stream = request(get, S#state.path, #{}, S),
    S1 = S#state{buf = <<>>, rpos = Pos, spos = 0, waiter = From, stream = Stream},
    case gun:await(Gun, Stream, 30000) of
        {response, fin, Status, _Headers} when (Status < 300) ->
            gen_statem:reply(From, {ok, Pos}),
            {next_state, ended, S1};
        {response, nofin, Status, Headers} when (Status < 300) ->
            Hdrs = maps:from_list(Headers),
            S2 = S1#state{hdrs = Hdrs},
            case Pos of
                0 ->
                    gen_statem:reply(From, {ok, Pos}),
                    {next_state, flowing, S2};
                _ ->
                    lager:debug("skipping ahead to ~p", [Pos]),
                    {next_state, skipping, S2}
            end;
        {response, nofin, Status, Headers} ->
            Hdrs = maps:from_list(Headers),
            #{<<"content-type">> := ContentType} = Hdrs,
            {ok, Body} = gun_data_h:await_body(Gun, Stream, 30000),
            ErrInfo = case ContentType of
                <<"application/json">> -> {http, Status, jsx:decode(Body, [return_maps])};
                _ -> {http, Status, Body}
            end,
            gen_statem:reply(From, {ok, Pos}),
            case ErrInfo of
                _ ->
                    lager:debug("getobject returned ~p", [ErrInfo]),
                    {next_state, errored, S1#state{error = ErrInfo}}
            end;
        {response, fin, Status, _Headers} ->
            gen_statem:reply(From, {ok, Pos}),
            {next_state, errored, S1#state{error = {http, Status}}}
    end;
ready({call, From}, {read, Len}, S = #state{gun = Gun}) ->
    Stream = request(get, S#state.path, #{}, S),
    S1 = S#state{buf = <<>>, rpos = 0, spos = 0, reader = {From, Len}, stream = Stream},
    case gun:await(Gun, Stream, 30000) of
        {response, fin, Status, _Headers} when (Status < 300) ->
            {next_state, ended, S1};
        {response, nofin, Status, Headers} when (Status < 300) ->
            Hdrs = maps:from_list(Headers),
            {next_state, flowing, S1#state{hdrs = Hdrs}};
        {response, nofin, Status, Headers} ->
            Hdrs = maps:from_list(Headers),
            #{<<"content-type">> := ContentType} = Hdrs,
            {ok, Body} = gun_data_h:await_body(Gun, Stream, 30000),
            ErrInfo = case ContentType of
                <<"application/json">> -> {http, Status, jsx:decode(Body, [return_maps])};
                _ -> {http, Status, Body}
            end,
            case ErrInfo of
                _ ->
                    lager:debug("getobject returned ~p", [ErrInfo]),
                    {next_state, errored, S1#state{error = ErrInfo}}
            end;
        {response, fin, Status, _Headers} ->
            {next_state, errored, S1#state{error = {http, Status}}}
    end;
ready({call, From}, {write, _Data}, #state{}) ->
    gen_statem:reply(From, {error, ebadf}),
    keep_state_and_data;
ready({call, From}, close, #state{gun = Gun}) ->
    gun:flush(Gun),
    gun:close(Gun),
    gen_statem:reply(From, ok),
    {stop, normal};
ready(info, {'DOWN', MRef, process, Gun, Reason}, S = #state{mref = MRef, gun = Gun}) ->
    {next_state, errored, S#state{error = {gun_down, Reason}}}.

ended(enter, _, S = #state{reader = {From, Len}, buf = Buf, ackref = none}) ->
    RealLen = if (Len > size(Buf)) -> size(Buf); true -> Len end,
    <<Chunk:RealLen/binary, NewBuf/binary>> = Buf,
    gen_statem:reply(From, {ok, Chunk}),
    S1 = S#state{buf = NewBuf, rpos = S#state.rpos + RealLen, reader = none},
    {keep_state, S1};
ended(enter, _, #state{ackref = none}) ->
    keep_state_and_data;
ended(enter, _, S = #state{gun = Gun, stream = Stream, ackref = AckRef}) ->
    Gun ! {gun_data_ack, self(), Stream, AckRef},
    {repeat_state, S#state{ackref = none}};
ended({call, From}, {position, Offset}, S = #state{rpos = RPos, spos = SPos}) ->
    RPos2 = case Offset of
        {bof, V} -> V;
        {cur, V} -> RPos + V;
        bof -> 0;
        cur -> RPos
    end,
    if
        (RPos2 == RPos) ->
            gen_statem:reply(From, {ok, RPos2}),
            keep_state_and_data;
        (RPos2 >= SPos) ->
            gen_statem:reply(From, {ok, RPos2}),
            {keep_state, S#state{rpos = RPos2}};
        true ->
            lager:debug("ended stream restarting, asked to seek to ~p", [RPos2]),
            {next_state, ready, S, postpone}
    end;
ended({call, From}, {read, Len}, S = #state{buf = Buf}) when (size(Buf) > 0) ->
    RealLen = if (Len > size(Buf)) -> size(Buf); true -> Len end,
    <<Chunk:RealLen/binary, NewBuf/binary>> = Buf,
    gen_statem:reply(From, {ok, Chunk}),
    S1 = S#state{buf = NewBuf, rpos = S#state.rpos + RealLen},
    {next_state, ended, S1};
ended({call, From}, {read, _Len}, S = #state{}) ->
    gen_statem:reply(From, eof),
    {next_state, ended, S};
ended({call, From}, {write, _Data}, #state{}) ->
    gen_statem:reply(From, {error, ebadf}),
    keep_state_and_data;
ended({call, From}, close, #state{gun = Gun}) ->
    gun:flush(Gun),
    gun:close(Gun),
    gen_statem:reply(From, ok),
    {stop, normal};
ended(info, {gun_error, Gun, Stream, _Why}, #state{gun = Gun, stream = Stream}) ->
    keep_state_and_data;
ended(info, {gun_error, Gun, _Why}, #state{gun = Gun}) ->
    keep_state_and_data.

errored(enter, _, S = #state{error = Err, waiter = Waiter, reader = Reader}) ->
    case Waiter of
        none -> ok;
        FromW -> gen_statem:reply(FromW, {error, Err})
    end,
    case Reader of
        none -> ok;
        {From, _Len} -> gen_statem:reply(From, {error, Err})
    end,
    {keep_state, S#state{waiter = none, reader = none}};
errored({call, From}, {position, _Offset}, #state{error = Err}) ->
    gen_statem:reply(From, {error, Err}),
    keep_state_and_data;
errored({call, From}, {read, _Len}, #state{error = Err}) ->
    gen_statem:reply(From, {error, Err}),
    keep_state_and_data;
errored({call, From}, {write, _Data}, #state{}) ->
    gen_statem:reply(From, {error, ebadf}),
    keep_state_and_data;
errored({call, From}, close, #state{gun = Gun}) ->
    gun:flush(Gun),
    gun:close(Gun),
    gen_statem:reply(From, ok),
    {stop, normal}.


maybe_reply_reader(S = #state{reader = {From, Len}, buf = Buf}) when (size(Buf) >= Len) ->
    <<Chunk:Len/binary, Rem/binary>> = Buf,
    RPos2 = S#state.rpos + Len,
    gen_statem:reply(From, {ok, Chunk}),
    S#state{buf = Rem, rpos = RPos2, reader = none};
maybe_reply_reader(S = #state{}) -> S.


skipping(enter, _, #state{ackref = none}) ->
    keep_state_and_data;
skipping(enter, _, S = #state{gun = Gun, stream = Stream, ackref = AckRef}) ->
    Gun ! {gun_data_ack, self(), Stream, AckRef},
    {keep_state, S#state{ackref = none}};
skipping({call, From}, {read, Len}, S = #state{}) ->
    {next_state, skipping, S#state{reader = {From, Len}}};
skipping({call, From}, {write, _Data}, #state{}) ->
    gen_statem:reply(From, {error, ebadf}),
    keep_state_and_data;
skipping(info, {gun_data, Gun, Stream, nofin, Data, AckRef}, S = #state{gun = Gun, stream = Stream}) ->
    #state{spos = SPos, rpos = RPos} = S,
    SPos2 = SPos + size(Data),
    if
        (SPos2 > RPos) ->
            S1 = case S of
                #state{waiter = none} -> S;
                #state{waiter = From} ->
                    gen_statem:reply(From, {ok, RPos}),
                    S#state{waiter = none}
            end,
            ToKeep = SPos2 - RPos,
            ToDiscard = size(Data) - ToKeep,
            <<_Dropped:ToDiscard/binary, Rem/binary>> = Data,
            S2 = S1#state{buf = Rem, spos = SPos2, ackref = AckRef},
            lager:debug("skip ended, bufsz = ~p, spos = ~p", [size(Rem), SPos2]),
            S3 = maybe_reply_reader(S2),
            {next_state, flowing, S3};
        true ->
            {repeat_state, S#state{spos = SPos2, ackref = AckRef}}
    end;
skipping(info, {gun_data, Gun, Stream, fin, Data, AckRef}, S = #state{gun = Gun, stream = Stream}) ->
    #state{spos = SPos, rpos = RPos} = S,
    SPos2 = SPos + size(Data),
    S1 = case S of
        #state{waiter = none} -> S;
        #state{waiter = From} ->
            gen_statem:reply(From, {ok, RPos}),
            S#state{waiter = none}
    end,
    if
        (SPos2 > RPos) ->
            ToDiscard = size(Data) - (SPos2 - RPos),
            <<_Dropped:ToDiscard/binary, Rem/binary>> = Data,
            S2 = S1#state{buf = Rem, spos = SPos2, ackref = AckRef},
            lager:debug("skip ended at eof, bufsz = ~p, spos = ~p", [size(Rem), SPos2]),
            S3 = maybe_reply_reader(S2),
            {next_state, ended, S3};
        true ->
            {next_state, ended, S1#state{spos = SPos2}}
    end;
skipping(info, {gun_error, Gun, Stream, Reason}, S = #state{gun = Gun, stream = Stream}) ->
    {next_state, errored, S#state{error = {gun_strm_error, Reason}}};
skipping(info, {gun_error, Gun, Reason}, S = #state{gun = Gun}) ->
    {next_state, errored, S#state{error = {gun_error, Reason}}};
skipping(info, {'DOWN', MRef, process, Gun, Reason}, S = #state{mref = MRef, gun = Gun}) ->
    {next_state, errored, S#state{error = {gun_down, Reason}}};

skipping({call, From}, close, S = #state{gun = Gun, stream = Stream}) ->
    gun:cancel(Gun, Stream),
    case S#state.ackref of
        none -> ok;
        AckRef -> Gun ! {gun_data_ack, self(), Stream, AckRef}
    end,
    gun:flush(Gun),
    gun:close(Gun),
    gen_statem:reply(From, ok),
    {stop, normal}.

flowing(enter, _, #state{ackref = none}) ->
    keep_state_and_data;
flowing(enter, _, S = #state{gun = Gun, stream = Stream, ackref = AckRef}) ->
    Gun ! {gun_data_ack, self(), Stream, AckRef},
    {keep_state, S#state{ackref = none}};

flowing({call, From}, {read, Len}, S = #state{buf = Buf}) when (size(Buf) >= Len) ->
    <<Chunk:Len/binary, NewBuf/binary>> = Buf,
    gen_statem:reply(From, {ok, Chunk}),
    Pos = S#state.rpos + Len,
    S1 = S#state{buf = NewBuf, reader = none, rpos = Pos},
    {next_state, flowing, S1};
flowing({call, From}, {read, Len}, S = #state{}) ->
    {next_state, flowing, S#state{reader = {From, Len}}};
flowing({call, From}, {write, _Data}, #state{}) ->
    gen_statem:reply(From, {error, ebadf}),
    keep_state_and_data;

flowing({call, From}, {position, Offset}, S = #state{rpos = RPos, spos = SPos}) ->
    RPos2 = case Offset of
        {bof, V} -> V;
        {cur, V} -> RPos + V;
        bof -> 0;
        cur -> RPos
    end,
    if
        (RPos2 == RPos) ->
            gen_statem:reply(From, {ok, RPos2}),
            {next_state, flowing, S};
        (RPos2 > SPos) ->
            S1 = S#state{buf = <<>>, rpos = RPos2, waiter = From},
            lager:debug("skipping ahead to ~p (at ~p)", [RPos2, RPos]),
            {next_state, skipping, S1};
        (RPos2 > RPos) ->
            Buf1 = S#state.buf,
            ToDrop = RPos2 - RPos,
            <<_Dropped:ToDrop/binary, Buf2/binary>> = Buf1,
            S1 = S#state{rpos = RPos2, buf = Buf2},
            gen_statem:reply(From, {ok, RPos2}),
            lager:debug("dropping ~p bytes to reach ~p (was at ~p)", [ToDrop,
                RPos2, RPos]),
            {next_state, flowing, S1};
        true ->
            lager:debug("seeking backwards to ~p from ~p", [RPos2, RPos]),
            #state{gun = Gun, stream = Stream} = S,
            gun:cancel(Gun, Stream),
            gun:flush(Gun),
            {next_state, ready, S, postpone}
    end;

flowing(info, {gun_data, Gun, Stream, fin, Data, AckRef}, S = #state{gun = Gun, stream = Stream}) ->
    #state{buf = Buf0, spos = SPos} = S,
    Buf1 = <<Buf0/binary, Data/binary>>,
    SPos2 = SPos + size(Data),
    S1 = S#state{spos = SPos2, buf = Buf1},
    S2 = maybe_reply_reader(S1),
    S3 = S2#state{ackref = AckRef},
    {next_state, ended, S3};
flowing(info, {gun_data, Gun, Stream, nofin, Data, AckRef}, S = #state{gun = Gun, stream = Stream}) ->
    #state{buf = Buf0, spos = SPos} = S,
    Buf1 = <<Buf0/binary, Data/binary>>,
    SPos2 = SPos + size(Data),
    S1 = S#state{spos = SPos2, buf = Buf1},
    S2 = maybe_reply_reader(S1),
    S3 = S2#state{ackref = AckRef},
    if
        (size(S3#state.buf) > ?BUF_MAX) -> {next_state, corked, S3};
        true -> {repeat_state, S3}
    end;

flowing(info, {gun_error, Gun, Stream, Reason}, S = #state{gun = Gun, stream = Stream}) ->
    {next_state, errored, S#state{error = {gun_strm_error, Reason}}};
flowing(info, {gun_error, Gun, Reason}, S = #state{gun = Gun}) ->
    {next_state, errored, S#state{error = {gun_error, Reason}}};
flowing(info, {'DOWN', MRef, process, Gun, Reason}, S = #state{mref = MRef, gun = Gun}) ->
    {next_state, errored, S#state{error = {gun_down, Reason}}};

flowing({call, From}, close, S = #state{gun = Gun, stream = Stream}) ->
    gun:cancel(Gun, Stream),
    case S#state.ackref of
        none -> ok;
        AckRef -> Gun ! {gun_data_ack, self(), Stream, AckRef}
    end,
    gun:flush(Gun),
    gun:close(Gun),
    gen_statem:reply(From, ok),
    {stop, normal}.

corked(enter, _, #state{}) ->
    keep_state_and_data;

corked({call, From}, {read, Len}, S = #state{buf = Buf}) when (size(Buf) >= Len) ->
    <<Chunk:Len/binary, NewBuf/binary>> = Buf,
    gen_statem:reply(From, {ok, Chunk}),
    Pos = S#state.rpos + Len,
    S2 = S#state{buf = NewBuf, rpos = Pos, reader = none},
    if
        (size(NewBuf) > ?BUF_MAX) -> {repeat_state, S2};
        true -> {next_state, flowing, S2}
    end;
corked({call, From}, {read, Len}, S = #state{}) ->
    {next_state, flowing, S#state{reader = {From, Len}}};

corked({call, _From}, {position, _Offset}, S = #state{}) ->
    {next_state, flowing, S, postpone};
corked({call, From}, {write, _Data}, #state{}) ->
    gen_statem:reply(From, {error, ebadf}),
    keep_state_and_data;

corked(info, {gun_data, Gun, Stream, nofin, Data, AckRef}, S = #state{gun = Gun, stream = Stream}) ->
    #state{buf = Buf0} = S,
    Buf1 = <<Buf0/binary, Data/binary>>,
    {keep_state, S#state{buf = Buf1, ackref = AckRef}};
corked(info, {gun_data, Gun, Stream, fin, Data, AckRef}, S = #state{gun = Gun, stream = Stream}) ->
    #state{buf = Buf0} = S,
    Buf1 = <<Buf0/binary, Data/binary>>,
    {next_state, ended, S#state{buf = Buf1, ackref = AckRef}};

corked(info, {gun_error, Gun, Stream, Reason}, S = #state{gun = Gun, stream = Stream}) ->
    {next_state, errored, S#state{error = {gun_strm_error, Reason}}};
corked(info, {gun_error, Gun, Reason}, S = #state{gun = Gun}) ->
    {next_state, errored, S#state{error = {gun_error, Reason}}};
corked(info, {'DOWN', MRef, process, Gun, Reason}, S = #state{mref = MRef, gun = Gun}) ->
    {next_state, errored, S#state{error = {gun_down, Reason}}};

corked({call, From}, close, S = #state{gun = Gun, stream = Stream}) ->
    gun:cancel(Gun, Stream),
    case S#state.ackref of
        none -> ok;
        AckRef -> Gun ! {gun_data_ack, self(), Stream, AckRef}
    end,
    gun:flush(Gun),
    gun:close(Gun),
    gen_statem:reply(From, ok),
    {stop, normal}.
