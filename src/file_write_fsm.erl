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

-module(file_write_fsm).

-behaviour(gen_statem).

-include_lib("kernel/include/file.hrl").
-compile([{parse_transform, lager_transform}]).

-export([start_link/4]).
-export([init/1, callback_mode/0]).
-export([disconnected/3, flowing/3, errored/3]).

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
    stream,
    error,
    waiter,
    mref,
    wpos = 0
    }).

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

fn_ext_to_mime(Fname) when is_list(Fname) ->
    fn_ext_to_mime(unicode:characters_to_binary(Fname, utf8));
fn_ext_to_mime(Fname) ->
    case lists:reverse(binary:split(Fname, [<<".">>], [global])) of
        [<<"txt">> | _] -> <<"text/plain">>;
        [<<"html">> | _] -> <<"text/html">>;
        [<<"htm">> | _] -> <<"text/html">>;
        [<<"js">> | _] -> <<"text/javascript">>;
        [<<"json">> | _] -> <<"application/json">>;
        [<<"jpg">> | _] -> <<"image/jpeg">>;
        [<<"jpeg">> | _] -> <<"image/jpeg">>;
        [<<"png">> | _] -> <<"image/png">>;
        [<<"gif">> | _] -> <<"image/gif">>;
        [<<"css">> | _] -> <<"text/css">>;
        [<<"mp3">> | _] -> <<"audio/mpeg">>;
        [<<"mpeg">> | _] -> <<"video/mpeg">>;
        [<<"mp4">> | _] -> <<"video/mp4">>;
        [<<"m4a">> | _] -> <<"audio/mp4">>;
        [<<"mov">> | _] -> <<"video/quicktime">>;
        [<<"avi">> | _] -> <<"video/x-msvideo">>;
        [<<"wmv">> | _] -> <<"video/x-ms-wmv">>;
        [<<"3gp">> | _] -> <<"video/3gpp">>;
        [<<"ts">> | _] -> <<"video/MP2T">>;
        [<<"flv">> | _] -> <<"video/x-flv">>;
        [<<"mpg">> | _] -> <<"video/mpeg">>;
        [<<"opus">> | _] -> <<"audio/opus">>;
        [<<"svg">> | _] -> <<"image/svg+xml">>;
        [<<"webm">> | _] -> <<"video/webm">>;
        _ -> <<"application/octet-stream">>
    end.

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
    Mime = fn_ext_to_mime(Path),
    InHdrs = #{
        <<"content-type">> => Mime,
        <<"expect">> => <<"100-continue">>
    },
    Stream = request(put, Path, InHdrs, S1),
    receive
        {gun_inform, Gun, Stream, 100, _} -> ok
    end,
    gen_statem:reply(From, ok),
    {next_state, flowing, S1#state{stream = Stream}}.

flowing(enter, _, #state{}) ->
    keep_state_and_data;

flowing({call, From}, {read, _Len}, #state{}) ->
    gen_statem:reply(From, {error, ebadf}),
    keep_state_and_data;

flowing({call, From}, {write, Data}, S = #state{gun = Gun, stream = Stream, wpos = WPos1}) ->
    WPos2 = WPos1 + byte_size(Data),
    {message_queue_len, N} = process_info(Gun, message_queue_len),
    if
        (N > 10) -> timer:sleep(10*N);
        true -> ok
    end,
    ok = gun:data(Gun, Stream, nofin, Data),
    gen_statem:reply(From, ok),
    {next_state, flowing, S#state{wpos = WPos2}};

flowing({call, From}, {position, Offset}, S = #state{wpos = WPos}) ->
    WPos2 = case Offset of
        {bof, V} -> V;
        {cur, V} -> WPos + V;
        bof -> 0;
        cur -> WPos
    end,
    if
        (WPos2 == WPos) ->
            gen_statem:reply(From, {ok, WPos2}),
            {next_state, flowing, S};
        (WPos2 > WPos) ->
            #state{gun = Gun, stream = Stream} = S,
            Zeros = WPos2 - WPos,
            ok = gun:data(Gun, Stream, nofin, <<0:Zeros/unit:8>>),
            gen_statem:reply(From, {ok, WPos2}),
            {next_state, flowing, S#state{wpos = WPos2}};
        true ->
            #state{gun = Gun, stream = Stream} = S,
            gun:cancel(Gun, Stream),
            gun:flush(Gun),
            gen_statem:reply(From, {error, rewind}),
            {next_state, errored, S#state{error = rewind}}
    end;
    
flowing(info, {gun_error, Gun, Stream, Reason}, S = #state{gun = Gun, stream = Stream}) ->
    {next_state, errored, S#state{error = {gun_strm_error, Reason}}};
flowing(info, {gun_error, Gun, Reason}, S = #state{gun = Gun}) ->
    {next_state, errored, S#state{error = {gun_error, Reason}}};
flowing(info, {'DOWN', MRef, process, Gun, Reason}, S = #state{mref = MRef, gun = Gun}) ->
    {next_state, errored, S#state{error = {gun_down, Reason}}};

flowing({call, From}, close, #state{gun = Gun, stream = Stream}) ->
    ok = gun:data(Gun, Stream, fin, <<>>),
    case gun:await(Gun, Stream, 30000) of
        {response, fin, Status, _Headers} when (Status < 300) ->
            gen_statem:reply(From, ok),
            {stop, normal};
        {response, fin, Status, _Headers} ->
            gen_statem:reply(From, {error, {http, Status}}),
            {stop, normal};
        {response, nofin, Status, Headers} when (Status >= 300) ->
            Hdrs = maps:from_list(Headers),
            {ok, Body} = gun_data_h:await_body(Gun, Stream, 30000),
            ErrInfo = case Hdrs of
                #{<<"content-type">> := <<"application/json">>} ->
                    {http, Status, jsx:decode(Body, [return_maps])};
                _ ->
                    {http, Status, Body}
            end,
            gen_statem:reply(From, {error, ErrInfo}),
            {stop, normal}
    end.

errored(enter, _, S = #state{error = Err, waiter = Waiter}) ->
    case Waiter of
        none -> ok;
        FromW -> gen_statem:reply(FromW, {error, Err})
    end,
    {keep_state, S#state{waiter = none}};
errored({call, From}, {position, _Offset}, #state{error = Err}) ->
    gen_statem:reply(From, {error, Err}),
    keep_state_and_data;
errored({call, From}, {read, _Len}, #state{}) ->
    gen_statem:reply(From, {error, ebadf}),
    keep_state_and_data;
errored({call, From}, {write, _Data}, #state{error = Err}) ->
    gen_statem:reply(From, {error, Err}),
    keep_state_and_data;
errored({call, From}, close, #state{gun = Gun}) ->
    gun:flush(Gun),
    gun:close(Gun),
    gen_statem:reply(From, ok),
    {stop, normal}.
