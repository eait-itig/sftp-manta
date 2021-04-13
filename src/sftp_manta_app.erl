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

-module(sftp_manta_app).

-include_lib("public_key/include/public_key.hrl").
-include_lib("kernel/include/file.hrl").
-include_lib("ssh/src/ssh_connect.hrl").
-compile([{parse_transform, lager_transform}]).

-behaviour(application).
-behaviour(ssh_server_key_api).
-behaviour(ssh_sftpd_file_api).

-export([start/2, stop/1]).
-export([host_key/2, is_auth_key/3]).
-export([login/2, logout/1, close/2, delete/2, del_dir/2, get_cwd/1, is_dir/2, list_dir/2, 
     make_dir/2, make_symlink/3, open/3, position/3, read/3,
     read_file_info/2, read_link/2, read_link_info/2, rename/3,
     write/3, write_file_info/3]).
-export([validate_pw/4]).

% for ssh_cli
-export([init/1, handle_ssh_msg/2, handle_msg/2, terminate/2]).

start(_StartType, _StartArgs) ->
    sftp_manta_sup:start_link().

stop(_State) ->
    ok.

host_key('ssh-rsa', _Opts) ->
    {ok, KeyPath} = application:get_env(sftp_manta, rsa_host_key_file),
    {ok, Pem} = file:read_file(KeyPath),
    [KeyEntry] = public_key:pem_decode(Pem),
    Key = #'RSAPrivateKey'{} = public_key:pem_entry_decode(KeyEntry),
    {ok, Key};
host_key('rsa-sha2-256', Opts) -> host_key('ssh-rsa', Opts);
host_key('rsa-sha2-512', Opts) -> host_key('ssh-rsa', Opts);
host_key('ecdsa-sha2-nistp256', _Opts) ->
    {ok, KeyPath} = application:get_env(sftp_manta, host_key_file),
    {ok, Pem} = file:read_file(KeyPath),
    [KeyEntry] = public_key:pem_decode(Pem),
    Key = #'ECPrivateKey'{} = public_key:pem_entry_decode(KeyEntry),
    {ok, Key};
host_key(Alg, _Opts) ->
    {error, {no_key_for_alg, Alg}}.

is_auth_key(PubKey, User, _Opts) ->
    sftp_manta_auth:is_auth_key(PubKey, User).

validate_pw(User, Pw, RemoteAddr, _State) ->
    sftp_manta_auth:validate_pw(User, Pw, RemoteAddr).

-record(state, {
    user,
    amode,
    cwd,
    signer,
    token,
    gun,
    mahi,
    host,
    port = 443,
    statcache = #{},
    fds = #{},
    next_fd = 10,
    peer
    }).

-record(scp_opts, {
    verbose = false,
    recursive = false,
    directory = false,
    mode = receiver,
    bad = false,
    target
}).

-record(scp_state, {
    state = #state{},
    buf = [],
    hadeof = false,
    pid,
    srvpid,
    cmd,
    chan,
    cm,
    cwdstack = []
}).


init(_) ->
    process_flag(trap_exit, true),
    {ok, #scp_state{pid = self()}}.

terminate(_Reason, #scp_state{state = SS}) ->
    case SS of
        #state{gun = undefined} -> ok;
        _ -> logout(SS)
    end.

handle_msg({write, Pid, Data}, S = #scp_state{cm = CM, chan = ChanId, srvpid = Pid}) ->
    ssh_connection:send(CM, ChanId, ?SSH_EXTENDED_DATA_DEFAULT, Data),
    {ok, S};
handle_msg({exit, Pid, ExSt}, S = #scp_state{cm = CM, chan = ChanId, srvpid = Pid}) ->
    ssh_connection:exit_status(CM, ChanId, ExSt),
    ssh_connection:send_eof(CM, ChanId),
    {stop, ChanId, S};
handle_msg({'EXIT', Pid, Reason}, S = #scp_state{cm = CM, chan = ChanId, srvpid = Pid}) ->
    ssh_connection:send(CM, ChanId, ?SSH_EXTENDED_DATA_DEFAULT,
        [<<2>>, io_lib:format("Error: ~999p\n", [Reason])]),
    ssh_connection:exit_status(CM, ChanId, -1),
    ssh_connection:send_eof(CM, ChanId),
    {stop, ChanId, S};
handle_msg(_Msg, S = #scp_state{}) ->
    {ok, S}.

handle_ssh_msg({ssh_cm, CM, {exec, ChanId, WantRep, Cmd}}, S = #scp_state{state = SS0}) ->
    MantaHostInfo = application:get_env(sftp_manta, manta, []),
    MantaHost = proplists:get_value(host, MantaHostInfo),
    MantaPort = proplists:get_value(port, MantaHostInfo, 443),
    {ok, Mode} = application:get_env(sftp_manta, auth_mode),
    SS1 = SS0#state{host = MantaHost, port = MantaPort, amode = Mode},
    [{user, User}] = ssh_connection_handler:connection_info(CM, [user]),
    SS2 = login(User, SS1),
    SS3 = SS2#state{cwd = "/" ++ User ++ "/stor"},
    S1 = S#scp_state{state = SS3},
    lager:debug("handling command ~p for ~p", [Cmd, User]),
    case list_to_binary(Cmd) of
        <<"scp ", Rem/binary>> ->
            case parse_scp_opts(#scp_opts{}, Rem) of
                Opts = #scp_opts{bad = false} ->
                    S2 = S1#scp_state{cmd = Cmd, chan = ChanId, cm = CM},
                    ScpServPid = spawn_link(fun() ->
                        scp_server_loop(Opts, S1)
                    end),
                    ssh_connection:reply_request(CM, WantRep, success, ChanId),
                    S3 = S2#scp_state{srvpid = ScpServPid},
                    {ok, S3};

                #scp_opts{bad = BadOpt} ->
                    ssh_connection:send(CM, ChanId, ?SSH_EXTENDED_DATA_DEFAULT,
                        [<<2>>, io_lib:format("Unsupported scp option: -~s\n",
                        [BadOpt])]),
                    ssh_connection:reply_request(CM, WantRep, success, ChanId),
                    ssh_connection:exit_status(CM, ChanId, -1),
                    ssh_connection:send_eof(CM, ChanId),
                    {stop, ChanId, S1#scp_state{cm = CM, chan = ChanId}}
            end;
        _ ->
            ssh_connection:send(CM, ChanId, ?SSH_EXTENDED_DATA_DEFAULT,
                io_lib:format("Unsupported command: ~99p\n", [Cmd])),
            ssh_connection:reply_request(CM, WantRep, success, ChanId),
            ssh_connection:exit_status(CM, ChanId, -1),
            ssh_connection:send_eof(CM, ChanId),
            {stop, ChanId, S1#scp_state{cm = CM, chan = ChanId}}
    end;

handle_ssh_msg({ssh_cm, CM, {shell, ChanId, WantRep}}, S = #scp_state{}) ->
    ssh_connection:reply_request(CM, WantRep, success, ChanId),
    ssh_connection:send(CM, ChanId, ?SSH_EXTENDED_DATA_DEFAULT,
        <<"Interactive shell not supported.\n">>),
    ssh_connection:exit_status(CM, ChanId, -1),
    ssh_connection:send_eof(CM, ChanId),
    {stop, ChanId, S#scp_state{cm = CM, chan = ChanId}};

handle_ssh_msg({ssh_cm, CM, {data, _ChanId, _Type, Data}}, S = #scp_state{cm = CM, pid = Me, srvpid = Pid}) ->
    Pid ! {data, Me, Data},
    {ok, S};

handle_ssh_msg({ssh_cm, CM, {eof, ChanId}}, S = #scp_state{cm = CM, pid = Me, srvpid = Pid}) ->
    Pid ! {eof, Me},
    {ok, S};

handle_ssh_msg(_Msg, S = #scp_state{}) ->
    {ok, S}.

parse_scp_opts(O, <<>>) -> O;
parse_scp_opts(O, <<" ", Rem/binary>>) -> parse_scp_opts(O, Rem);
parse_scp_opts(O, <<"\t", Rem/binary>>) -> parse_scp_opts(O, Rem);
parse_scp_opts(O, <<"-v ", Rem/binary>>) ->
    parse_scp_opts(O#scp_opts{verbose = true}, Rem);
parse_scp_opts(O, <<"-d ", Rem/binary>>) ->
    parse_scp_opts(O#scp_opts{directory = true}, Rem);
parse_scp_opts(O, <<"-r ", Rem/binary>>) ->
    parse_scp_opts(O#scp_opts{recursive = true}, Rem);
parse_scp_opts(O, <<"-f ", Target/binary>>) ->
    O#scp_opts{mode = sender, target = Target};
parse_scp_opts(O, <<"-t ", Target/binary>>) ->
    O#scp_opts{mode = receiver, target = Target};
parse_scp_opts(O, <<"-", Opt:1/binary, Rem/binary>>) ->
    O#scp_opts{bad = Opt}.

await_line(S = #scp_state{buf = [], hadeof = true}) ->
    {eof, S};
await_line(S = #scp_state{pid = C, buf = B0}) ->
    B1 = iolist_to_binary(B0),
    case binary:split(B1, [<<"\n">>]) of
        [L, B2] -> {L, S#scp_state{buf = [B2]}};
        [B2] when S#scp_state.hadeof -> {B2, S#scp_state{buf = []}};
        [B2] ->
            receive
                {data, C, Data} ->
                    B3 = <<B2/binary, Data/binary>>,
                    await_line(S#scp_state{buf = [B3]});
                {eof, C} ->
                    await_line(S#scp_state{hadeof = true})
            end
    end.

await_bytes(N, S = #scp_state{buf = [], hadeof = true}) ->
    {eof, S};
await_bytes(N, S = #scp_state{buf = [Chunk0 | B1]}) ->
    if
        (N < byte_size(Chunk0)) ->
            R = binary_part(Chunk0, 0, N),
            Chunk1 = binary_part(Chunk0, N, byte_size(Chunk0) - N),
            {R, S#scp_state{buf = [Chunk1 | B1]}};
        (N == byte_size(Chunk0)) ->
            {Chunk0, S#scp_state{buf = B1}};
        (N > byte_size(Chunk0)) ->
            {Rest, S2} = await_bytes(N, S#scp_state{buf = B1}),
            {<<Chunk0/binary, Rest/binary>>, S2}
    end;
await_bytes(N, S = #scp_state{pid = C, buf = []}) ->
    receive
        {data, C, Data} ->
            await_bytes(N, S#scp_state{buf = [Data]});
        {eof, C} ->
            await_bytes(N, S#scp_state{hadeof = true})
    end.

match_part(Patt, Str) when is_binary(Str) ->
    match_part(Patt, unicode:characters_to_list(Str, utf8));
match_part([question|Rest1], [_|Rest2]) ->
    match_part(Rest1, Rest2);
match_part([accept], _) ->
    true;
match_part([double_star], _) ->
    true;
match_part([star|Rest], File) ->
    do_star(Rest, File);
match_part([{one_of, Ordset}|Rest], [C|File]) ->
    gb_sets:is_element(C, Ordset) andalso match_part(Rest, File);
match_part([{alt, Alts}], File) ->
    do_alt(Alts, File);
match_part([C|Rest1], [C|Rest2]) when is_integer(C) ->
    match_part(Rest1, Rest2);
match_part([X|_], [Y|_]) when is_integer(X), is_integer(Y) ->
    false;
match_part([], []) ->
    true;
match_part([], [_|_]) ->
    false;
match_part([_|_], []) ->
    false.

do_star(Pattern, [_|Rest]=File) ->
    match_part(Pattern, File) orelse do_star(Pattern, Rest);
do_star(Pattern, []) ->
    match_part(Pattern, []).

do_alt([Alt|Rest], File) ->
    match_part(Alt, File) orelse do_alt(Rest, File);
do_alt([], _File) ->
    false.

scp_server_loop(Opts, {stop, #scp_state{pid = C}}) ->
    C ! {exit, self(), 0};
scp_server_loop(Opts, {error, Msg, #scp_state{pid = C}}) ->
    C ! {write, self(), <<2, Msg/binary, "\n">>},
    C ! {exit, self(), 1};
scp_server_loop(Opts = #scp_opts{mode = sender, target = T, recursive = false},
        S0 = #scp_state{state = St0, pid = C, buf = B}) ->
    TStr = unicode:characters_to_list(T, utf8),
    {compiled_wildcard, Patt} = filelib:compile_wildcard(TStr),
    {Files, S1} = case Patt of
        {{exists, [$., $/ | File]}, 2} ->
            #state{user = U} = St0,
            N = iolist_to_binary([$/, U, "/stor/", File]),
            case get_stat(N, St0) of
                {ok, #file_info{size = Sz}, St1} ->
                    {[{N, Sz}], S0#scp_state{state = St1}};
                _ ->
                    {[], S0}
            end;
        {[[$. | Dir], Rest], 2} ->
            #state{user = U, gun = Gun} = St0,
            N = iolist_to_binary([$/, U, "/stor", Dir]),
            case fetch_dir_lim(Gun, path_to_uri(N), none, St0) of
                {ok, Objs} ->
                    {[{iolist_to_binary([N, $/, FN]), Sz} ||
                        #{<<"name">> := FN, <<"size">> := Sz} <- Objs,
                        match_part(Rest, FN)], S0};
                _ ->
                    {[], S0}
            end;
        {[Prefix, Rest], 0} ->
            #state{gun = Gun} = St0,
            case fetch_dir_lim(Gun, path_to_uri(Prefix), none, St0) of
                {ok, Objs} ->
                    {[{iolist_to_binary([Prefix, $/, N]), Sz} ||
                        #{<<"name">> := N, <<"size">> := Sz} <- Objs,
                        match_part(Rest, N)], S0};
                _ ->
                    {[], S0}
            end
    end,
    lager:debug("scp sending files = ~p", [Files]),
    case Files of
        [] ->
            C ! {write, self(), <<2, "no objects found\n">>},
            C ! {exit, self(), 1};
        _ ->
            Snext = lists:foldl(fun ({Path, Sz}, SS0) ->
                SS1 = scp_read_file(Opts, Path, Sz, SS0),
                C ! {write, self(), <<0>>},
                SS1
            end, S0, Files),
            C ! {exit, self(), 0}
    end;
scp_server_loop(Opts = #scp_opts{mode = sender, target = T},
        S0 = #scp_state{pid = C, buf = B}) ->
    lager:debug("TODO: implement sender mode"),
    C ! {write, self(), <<2, "scp source mode not implemented\n">>},
    C ! {exit, self(), 1};
scp_server_loop(Opts = #scp_opts{mode = receiver, target = <<".">>},
        S0 = #scp_state{pid = C}) ->
    C ! {write, self(), <<0>>},
    {L, S1} = await_line(S0),
    SS = S1#scp_state.state,
    lager:debug("read line ~p", [L]),
    Snext = case L of
        <<"C", _/binary>> ->
            [<<"C", ModeBin:4/binary>>, Rest0] = binary:split(L, [<<" ">>]),
            [LenBin, PathBin] = binary:split(Rest0, [<<" ">>]),
            Mode = binary_to_integer(ModeBin, 8),
            Len = binary_to_integer(LenBin),
            lager:debug("scp writing file ~p (~p bytes)", [PathBin, Len]),
            C ! {write, self(), <<0>>},
            Path = SS#state.cwd ++ "/" ++
                unicode:characters_to_list(PathBin, utf8),
            S2 = scp_write_file(Opts, Path, Len, S1),
            {<<0>>, S3} = await_bytes(1, S2),
            S3;
        <<"D", _/binary>> when Opts#scp_opts.recursive ->
            [<<"D", ModeBin:4/binary>>, Rest0] = binary:split(L, [<<" ">>]),
            [LenBin, PathBin] = binary:split(Rest0, [<<" ">>]),
            NewCwd = SS#state.cwd ++ "/" ++
                unicode:characters_to_list(PathBin, utf8),
            Stack = [SS#state.cwd | S1#scp_state.cwdstack],
            SS1 = SS#state{cwd = NewCwd},
            case make_dir(NewCwd, SS1) of
                {ok, SS2} ->
                    S1#scp_state{cwdstack = Stack, state = SS2};
                {Error, SS2} ->
                    {error, iolist_to_binary(io_lib:format("~999p", [Error])),
                        S1#scp_state{state = SS2}}
            end;
        <<"E">> when Opts#scp_opts.recursive ->
            [OldCwd | Stack] = S1#scp_state.cwdstack,
            S1#scp_state{state = SS#state{cwd = OldCwd}, cwdstack = Stack};
        <<"T", _/binary>> ->
            S1;
        eof ->
            {stop, S1}
    end,
    scp_server_loop(Opts, Snext);
scp_server_loop(Opts = #scp_opts{mode = receiver, target = T}, S0 = #scp_state{}) ->
    SS0 = S0#scp_state.state,
    Cwd0 = SS0#state.cwd,
    Cwd1 = case T of
        <<"/", _/binary>> -> unicode:characters_to_list(T, utf8);
        <<"./", Rest/binary>> -> Cwd0 ++ "/" ++ unicode:characters_to_list(Rest, utf8);
        _ -> Cwd0 ++ "/" ++ unicode:characters_to_list(T, utf8)
    end,
    S1 = S0#scp_state{state = SS0#state{cwd = Cwd1}},
    scp_server_loop(Opts#scp_opts{target = <<".">>}, S1).

scp_write_file(Opts = #scp_opts{}, Path, Len, SC0 = #scp_state{state = S0, pid = C}) ->
    #state{host = Host, port = Port} = S0,
    {ok, Fsm} = case S0 of
        #state{amode = operator, signer = Signer} ->
            file_write_fsm:start_link({Host, Port}, path_to_uri(Path), signature, Signer);
        #state{amode = mahi_plus_token, token = Token} ->
            file_write_fsm:start_link({Host, Port}, path_to_uri(Path), token, Token)
    end,
    case gen_statem:call(Fsm, connect) of
        ok -> ok;
        {error, {http, 404, #{<<"code">> := <<"ResourceNotFound">>}}} ->
            ErrBin = iolist_to_binary(io_lib:format(
                "Parent directory for ~s does not exist\n", [Path])),
            C ! {write, self(), <<2, " ", ErrBin/binary>>},
            C ! {exit, self(), 2},
            exit(normal);
        {error, {http, _, #{<<"code">> := Code, <<"message">> := Msg}}} ->
            ErrBin = iolist_to_binary(io_lib:format("~p: ~s\n", [Code, Msg])),
            C ! {write, self(), <<2, " ", ErrBin/binary>>},
            C ! {exit, self(), 3},
            exit(normal);
        {error, {http, Code}} ->
            ErrBin = iolist_to_binary(io_lib:format(
                "manta returned HTTP ~p\n", [Code])),
            C ! {write, self(), <<2, " ", ErrBin/binary>>},
            C ! {exit, self(), 4},
            exit(normal);
        {error, Err} ->
            ErrBin = iolist_to_binary(io_lib:format("~999p\n", [Err])),
            C ! {write, self(), <<2, " ", ErrBin/binary>>},
            C ! {exit, self(), 5},
            exit(normal)
    end,
    SC1 = scp_write_next_chunk(Opts, Fsm, Len, SC0),
    ok = gen_statem:call(Fsm, close),
    SC1.

scp_read_file(Opts = #scp_opts{}, Path, Len, SC0 = #scp_state{state = S0, pid = C}) ->
    #state{host = Host, port = Port} = S0,
    {ok, Fsm} = case S0 of
        #state{amode = operator, signer = Signer} ->
            file_read_fsm:start_link({Host, Port}, path_to_uri(Path), signature, Signer);
        #state{amode = mahi_plus_token, token = Token} ->
            file_read_fsm:start_link({Host, Port}, path_to_uri(Path), token, Token)
    end,
    case gen_statem:call(Fsm, connect) of
        ok -> ok;
        {error, {http, 404, #{<<"code">> := <<"ResourceNotFound">>}}} ->
            ErrBin = iolist_to_binary(io_lib:format(
                "Parent directory for ~s does not exist\n", [Path])),
            C ! {write, self(), <<2, " ", ErrBin/binary>>},
            C ! {exit, self(), 2},
            exit(normal);
        {error, {http, _, #{<<"code">> := Code, <<"message">> := Msg}}} ->
            ErrBin = iolist_to_binary(io_lib:format("~p: ~s\n", [Code, Msg])),
            C ! {write, self(), <<2, " ", ErrBin/binary>>},
            C ! {exit, self(), 3},
            exit(normal);
        {error, {http, Code}} ->
            ErrBin = iolist_to_binary(io_lib:format(
                "manta returned HTTP ~p\n", [Code])),
            C ! {write, self(), <<2, " ", ErrBin/binary>>},
            C ! {exit, self(), 4},
            exit(normal);
        {error, Err} ->
            ErrBin = iolist_to_binary(io_lib:format("~999p\n", [Err])),
            C ! {write, self(), <<2, " ", ErrBin/binary>>},
            C ! {exit, self(), 5},
            exit(normal)
    end,
    PathParts = binary:split(Path, [<<"/">>], [global]),
    Fname = lists:last(PathParts),
    SzBin = integer_to_binary(Len),
    C ! {write, self(), <<"C0644 ", SzBin/binary, " ", Fname/binary, "\n">>},
    SC1 = scp_read_next_chunk(Opts, Fsm, Len, SC0),
    ok = gen_statem:call(Fsm, close),
    SC1.

scp_read_next_chunk(Opts, Fsm, 0, S0) -> S0;
scp_read_next_chunk(Opts, Fsm, RemLen, S0 = #scp_state{pid = C}) ->
    ToRead = if (RemLen > 131072) -> 131072; true -> RemLen end,
    {ok, Data} = gen_statem:call(Fsm, {read, ToRead}),
    RemLen2 = RemLen - byte_size(Data),
    C ! {write, self(), Data},
    erlang:garbage_collect(),
    scp_read_next_chunk(Opts, Fsm, RemLen2, S0).

scp_write_next_chunk(Opts, Fsm, 0, S0) -> S0;
scp_write_next_chunk(Opts, Fsm, RemLen, S0 = #scp_state{}) ->
    ToRead = if (RemLen > 131072) -> 131072; true -> RemLen end,
    {Data, S1} = await_bytes(ToRead, S0),
    RemLen2 = RemLen - byte_size(Data),
    ok = gen_statem:call(Fsm, {write, Data}),
    erlang:garbage_collect(),
    scp_write_next_chunk(Opts, Fsm, RemLen2, S1).

path_to_uri(Path) when is_list(Path) ->
    path_to_uri(unicode:characters_to_binary(Path, utf8));
path_to_uri(Path) when is_binary(Path) ->
    Dirs = binary:split(Path, [<<"/">>], [global]),
    DirEncs = [cow_uri:urlencode(C) || C <- Dirs],
    iolist_to_binary(lists:join("/", DirEncs)).

request(Verb, Url, Hdrs0, #state{gun = Gun, signer = Signer, amode = operator}) ->
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
request(Verb, Url, Hdrs0, #state{gun = Gun, token = Token, amode = mahi_plus_token}) ->
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

login(User, S = #state{amode = operator}) ->
    lager:debug("sftpd starting for user ~p", [User]),
    {ok, KeyPath} = application:get_env(sftp_manta, auth_key_file),
    {ok, Pem} = file:read_file(KeyPath),
    [KeyEntry] = public_key:pem_decode(Pem),
    Key = #'ECPrivateKey'{} = public_key:pem_entry_decode(KeyEntry),
    SigKey0 = http_signature_key:from_record(Key),
    Fp = http_signature_key:fingerprint(SigKey0),
    UserBin = unicode:characters_to_binary(User, utf8),
    SigKey1 = SigKey0#{
        id := <<"/", UserBin/binary, "/keys/", Fp/binary>>,
        module := http_signature_ecdsa_joyent
    },
    Signer = http_signature_signer:new(SigKey1, <<"ecdsa-sha256">>,
        [<<"date">>]),
    {ok, Conn} = gun:open(S#state.host, S#state.port),
    {ok, _} = gun:await_up(Conn, 30000),
    S#state{user = User, signer = Signer, gun = Conn};

login(User, S = #state{amode = mahi_plus_token}) ->
    lager:debug("sftpd starting for user ~p", [User]),
    MahiHostInfo = application:get_env(sftp_manta, mahi, []),
    MahiHost = proplists:get_value(host, MahiHostInfo),
    MahiPort = proplists:get_value(port, MahiHostInfo, 80),
    {ok, MahiGun} = gun:open(MahiHost, MahiPort),
    {ok, _} = gun:await_up(MahiGun, 15000),
    Qs = uri_string:compose_query([{"login", User}]),
    Uri = iolist_to_binary(["/accounts?", Qs]),
    InHdrs = [{<<"accept">>, <<"application/json">>}],
    Stream = gun:get(MahiGun, Uri, InHdrs),
    case gun:await(MahiGun, Stream, 10000) of
        {response, nofin, Status, Headers} when (Status < 300) ->
            Hdrs = maps:from_list(Headers),
            #{<<"content-type">> := <<"application/json">>} = Hdrs,
            {ok, Body} = gun_data_h:await_body(MahiGun, Stream, 10000),
            #{<<"account">> := Account, <<"roles">> := Roles} =
                jsx:decode(Body, [return_maps]),
            #{<<"uuid">> := Uuid} = Account,
            DefaultRoles = case Account of
                #{<<"defaultRoles">> := D} -> D;
                _ -> []
            end,
            TokenJson = jsx:encode(#{
                <<"v">> => 2,
                <<"p">> => #{
                    <<"account">> => #{
                        <<"uuid">> => Uuid
                    },
                    <<"user">> => null,
                    <<"roles">> => Roles
                },
                <<"c">> => #{
                    <<"activeRoles">> => DefaultRoles
                },
                <<"t">> => erlang:system_time(millisecond)
            }),
            TokenGzip = zlib:gzip(TokenJson),
            PadLen = 16 - (byte_size(TokenGzip) rem 16),
            Padding = << <<PadLen:8>> || _ <- lists:seq(1, PadLen) >>,
            TokenPadded = <<TokenGzip/binary, Padding/binary>>,

            TokenConfig = application:get_env(sftp_manta, token_auth, []),
            TokenKey = proplists:get_value(key, TokenConfig),
            TokenIV = proplists:get_value(iv, TokenConfig),

            TokenEnc = crypto:block_encrypt(aes_cbc128, <<TokenKey:128/big>>,
                <<TokenIV:128/big>>, TokenPadded),
            Token = base64:encode(TokenEnc),

            {ok, Gun} = gun:open(S#state.host, S#state.port, #{
                transport_opts => [
                    {recbuf, 128*1024}, {sndbuf, 128*1024}, {buffer, 256*1024},
                    {keepalive, true}
                ],
                retry => 0
            }),
            {ok, _} = gun:await_up(Gun, 30000),

            S#state{user = User, mahi = MahiGun, gun = Gun, token = Token}
    end.

logout(#state{mahi = undefined, gun = Gun, user = User}) ->
    lager:debug("~p closed connection", [User]),
    gun:close(Gun);
logout(S = #state{mahi = MahiGun}) ->
    gun:close(MahiGun),
    logout(S#state{mahi = undefined}).

get_cwd([]) ->
    MantaHostInfo = application:get_env(sftp_manta, manta, []),
    MantaHost = proplists:get_value(host, MantaHostInfo),
    MantaPort = proplists:get_value(port, MantaHostInfo, 443),
    {ok, Mode} = application:get_env(sftp_manta, auth_mode),
    {{ok, "/"}, #state{host = MantaHost, port = MantaPort, amode = Mode}};
get_cwd(S = #state{user = User, cwd = undefined}) ->
    NewCwd = "/" ++ User ++ "/stor",
    {{ok, NewCwd}, S#state{cwd = NewCwd}};
get_cwd(S = #state{cwd = Cwd}) ->
    {{ok, Cwd}, S}.

-define(S_IFMT, 8#00170000).
-define(S_IFLNK, 8#0120000).
-define(S_IFREG, 8#0100000).
-define(S_IFBLK, 8#0060000).
-define(S_IFDIR, 8#0040000).

headers_to_file_info(Path, Hdrs) when is_list(Path) ->
    headers_to_file_info(unicode:characters_to_binary(Path, utf8), Hdrs);
headers_to_file_info(Path, Hdrs) ->
    #{<<"content-type">> := ContentType} = Hdrs,
    ContentLength = case Hdrs of
        #{<<"content-length">> := Len} -> binary_to_integer(Len);
        _ -> 0
    end,
    FInfo0 = #file_info{
        size = ContentLength,
        uid = 0,
        gid = 0
    },
    FInfo1 = case ContentType of
        <<"application/x-json-stream; type=directory">> ->
            FInfo0#file_info{type = directory, size = 0};
        _ ->
            FInfo0#file_info{type = regular}
    end,
    FInfo2 = case binary:split(Path, [<<"/">>], [global]) of
        [<<"">>, _User, <<"public">> | _Rest] when FInfo1#file_info.type =:= directory ->
            FInfo1#file_info{mode = 8#775 bor ?S_IFDIR};
        [<<"">>, _User, <<"public">> | _Rest] ->
            FInfo1#file_info{mode = 8#664 bor ?S_IFREG};
        _ when FInfo1#file_info.type =:= directory ->
            FInfo1#file_info{mode = 8#770 bor ?S_IFDIR};
        _ ->
            FInfo1#file_info{mode = 8#660 bor ?S_IFREG}
    end,
    FInfo3 = case Hdrs of
        #{<<"last-modified">> := LastMod} ->
            Date = http_signature_date:parse_date(LastMod),
            Mtime = calendar:universal_time_to_local_time(Date),
            FInfo2#file_info{mtime = Mtime, atime = Mtime};
        _ ->
            FInfo2
    end,
    FInfo3.

isotime_to_datetime(Bin) ->
    <<YearBin:4/binary, "-", MonthBin:2/binary, "-", DayBin:2/binary, "T", TimeBin/binary>> = Bin,
    <<Hour:2/binary, ":", Min:2/binary, ":", Sec:2/binary, Rem/binary>> = TimeBin,
    case Rem of
        <<"Z">> -> ok;
        <<".", _:3/binary, "Z">> -> ok
    end,
    Date = {binary_to_integer(YearBin), binary_to_integer(MonthBin),
        binary_to_integer(DayBin)},
    Time = {binary_to_integer(Hour), binary_to_integer(Min),
        binary_to_integer(Sec)},
    {Date, Time}.

lsobj_to_file_info(Path, LsObj) when is_list(Path) ->
    lsobj_to_file_info(unicode:characters_to_binary(Path, utf8), LsObj);
lsobj_to_file_info(Path, LsObj) ->
    ContentLength = case LsObj of
        #{<<"size">> := Len} -> Len;
        _ -> 0
    end,
    FInfo0 = #file_info{
        size = ContentLength,
        uid = 0,
        gid = 0
    },
    #{<<"type">> := Type} = LsObj,
    FInfo1 = case Type of
        <<"directory">> -> FInfo0#file_info{type = directory, size = 0};
        <<"object">> -> FInfo0#file_info{type = regular}
    end,
    FInfo2 = case binary:split(Path, [<<"/">>], [global]) of
        [<<"">>, _User, <<"public">> | _Rest] when FInfo1#file_info.type =:= directory ->
            FInfo1#file_info{mode = 8#775 bor ?S_IFDIR};
        [<<"">>, _User, <<"public">> | _Rest] ->
            FInfo1#file_info{mode = 8#664 bor ?S_IFREG};
        _ when FInfo1#file_info.type =:= directory ->
            FInfo1#file_info{mode = 8#770 bor ?S_IFDIR};
        _ ->
            FInfo1#file_info{mode = 8#660 bor ?S_IFREG}
    end,
    FInfo3 = case LsObj of
        #{<<"mtime">> := LastMod} ->
            Date = isotime_to_datetime(LastMod),
            Mtime = calendar:universal_time_to_local_time(Date),
            FInfo2#file_info{mtime = Mtime, atime = Mtime};
        _ ->
            FInfo2
    end,
    FInfo3.

fake_new_file_info(Path) when is_list(Path) ->
    fake_new_file_info(unicode:characters_to_binary(Path, utf8));
fake_new_file_info(Path) ->
    #file_info{
        size = 0,
        uid = 0, gid = 0,
        mtime = calendar:local_time(),
        atime = calendar:local_time(),
        type = regular,
        mode = case binary:split(Path, [<<"/">>], [global]) of
            [<<"">>, _User, <<"public">> | _Rest] -> 8#664 bor ?S_IFREG;
            _ -> 8#660 bor ?S_IFREG
        end
    }.

get_stat(Path, S = #state{}) when is_list(Path) ->
    get_stat(unicode:characters_to_binary(Path, utf8), S);
get_stat(Path, S = #state{statcache = Cache, gun = Gun}) ->
    Now = erlang:system_time(millisecond),
    Limit = Now - 2000,
    case Cache of
        #{Path := #{ts := When, stat := Stat}} when (When > Limit) ->
            {ok, Stat, S};
        #{Path := #{ts := When, error := Why}} when (When > Limit) ->
            {error, Why, S};
        _ ->
            Stream = request(head, path_to_uri(Path), #{}, S),
            case gun:await(Gun, Stream, 15000) of
                {response, fin, Status, Headers} when (Status < 300) ->
                    Hdrs = maps:from_list(Headers),
                    Stat = headers_to_file_info(Path, Hdrs),
                    Cache2 = Cache#{Path => #{ts => Now, stat => Stat}},
                    {ok, Stat, S#state{statcache = Cache2}};
                {response, fin, 404, _} ->
                    Cache2 = Cache#{Path => #{ts => Now, error => enoent}},
                    {error, enoent, S#state{statcache = Cache2}};
                {response, fin, 403, _} ->
                    {error, eacces, S};
                {response, fin, 405, _} ->
                    {error, eacces, S};
                {response, fin, Status, _Headers} ->
                    lager:debug("stat on ~p returned http ~p", [Path, Status]),
                    {error, einval, S}
            end
    end.

is_dir(AbsPath, S = #state{}) ->
    case get_stat(AbsPath, S) of
        {ok, #file_info{type = directory}, S2} ->
            {true, S2};
        {ok, #file_info{}, S2} ->
            {false, S2};
        {error, _Why, S2} ->
            {false, S2}
    end.

fetch_dir_lim(Gun, BaseUri, Marker, S) ->
    InHdrs = #{
        <<"accept">> => <<"application/json; type=directory">>
    },
    Qs = [
        {"limit", "1000"}
        | case Marker of
            none -> [];
            _ -> [{"marker", unicode:characters_to_list(Marker, utf8)}]
        end],
    Uri = iolist_to_binary([BaseUri, "?", uri_string:compose_query(Qs)]),
    Stream = request(get, Uri, InHdrs, S),
    case gun:await(Gun, Stream, 30000) of
        {response, nofin, Status, Headers} when (Status < 300) ->
            Hdrs = maps:from_list(Headers),
            #{<<"content-type">> := ContentType} = Hdrs,
            <<"application/x-json-stream; type=directory">> = ContentType,

            {ok, Body} = gun_data_h:await_body(Gun, Stream, 30000),
            Lines = binary:split(Body, [<<"\n">>], [global, trim]),
            Objs = [jsx:decode(Line, [return_maps]) || Line <- Lines],
            case Objs of
                [] ->
                    {ok, Objs};
                [#{<<"name">> := Marker}] ->
                    {ok, []};
                _ ->
                    case Objs of
                        [#{<<"name">> := Marker} | Rest] -> ok;
                        Rest -> ok
                    end,
                    #{<<"name">> := Marker1} = lists:last(Objs),
                    case fetch_dir_lim(Gun, BaseUri, Marker1, S) of
                        {ok, RecurObjs} ->
                            {ok, Rest ++ RecurObjs};
                        Err ->
                            Err
                    end
            end;
        {response, nofin, Status, Headers} ->
            Hdrs = maps:from_list(Headers),
            ErrInfo = case Hdrs of
                #{<<"content-type">> := ContentType} ->
                    {ok, Body} = gun_data_h:await_body(Gun, Stream, 30000),
                    case ContentType of
                        <<"application/json">> -> {http, Status, jsx:decode(Body, [return_maps])};
                        _ -> {http, Status, Body}
                    end;
                _ ->
                    {http, Status, none}
            end,
            lager:debug("list_dir returned ~p", [ErrInfo]),
            {error, ErrInfo};
        {response, _Mode, _Status, _Headers} ->
            gun:cancel(Gun, Stream),
            gun:flush(Stream),
            {error, enotdir}
    end.

list_dir(AbsPath, S) when is_list(AbsPath) ->
    list_dir(unicode:characters_to_binary(AbsPath, utf8), S);
list_dir(AbsPath, S = #state{gun = Gun, statcache = Cache0}) ->
    case fetch_dir_lim(Gun, path_to_uri(AbsPath), none, S) of
        {ok, Objs} ->
            Now = erlang:system_time(millisecond),
            Cache1 = lists:foldl(fun (Obj, Acc) ->
                #{<<"name">> := Name} = Obj,
                Path = case binary:last(AbsPath) of
                    $/ -> <<AbsPath/binary, Name/binary>>;
                    _ -> <<AbsPath/binary, "/", Name/binary>>
                end,
                Stat = lsobj_to_file_info(Path, Obj),
                Acc#{ Path => #{ts => Now, stat => Stat} }
            end, Cache0, Objs),

            Names = [Name || #{ <<"name">> := Name } <- Objs],
            {{ok, Names}, S#state{statcache = Cache1}};

        Err = {error, _} ->
            {Err, S}
    end.

read_file_info(Path, S = #state{}) ->
    read_link_info(Path, S).

read_link_info(Path, S = #state{}) ->
    case get_stat(Path, S) of
        {ok, FInfo = #file_info{}, S2} ->
            {{ok, FInfo}, S2};
        {error, Why, S2} ->
            {{error, Why}, S2}
    end.

delete(Path, S = #state{gun = Gun}) ->
    Stream = request(delete, path_to_uri(Path), #{}, S),
    case gun:await(Gun, Stream, 30000) of
        {response, fin, Status, _Headers} when (Status < 300) ->
            #state{statcache = Cache} = S,
            PathBin = unicode:characters_to_binary(Path, utf8),
            Cache2 = Cache#{ PathBin => #{ ts => 0, error => enoent } },
            S2 = S#state{statcache = Cache2},
            {ok, S2};
        {response, fin, Status, _Headers} ->
            {{error, {http, Status}}, S};
        {response, nofin, Status, Headers} when (Status > 300) ->
            Hdrs = maps:from_list(Headers),
            #{<<"content-type">> := ContentType} = Hdrs,
            {ok, Body} = gun_data_h:await_body(Gun, Stream, 30000),
            ErrInfo = case ContentType of
                <<"application/json">> -> {http, Status, jsx:decode(Body, [return_maps])};
                _ -> {http, Status, Body}
            end,
            case ErrInfo of
                {http, 403, _} ->
                    {{error, eacces}, S};
                {http, 404, _} ->
                    {{error, enoent}, S};
                {http, 400, #{<<"code">> := <<"DirectoryNotEmpty">>}} ->
                    {{error, eexist}, S};
                _ ->
                    lager:debug("delete returned ~p", [ErrInfo]),
                    {{error, ErrInfo}, S}
            end
    end.

del_dir(Path, S = #state{}) ->
    delete(Path, S).
     
make_dir(Path, S = #state{gun = Gun}) ->
    case get_stat(Path, S) of
        {ok, #file_info{type = directory}, S2} ->
            {ok, S2};
        {ok, _, S2} ->
            {{error, eexist}, S2};
        {error, _, S2} ->
            InHdrs = #{
                <<"content-type">> => <<"application/json; type=directory">>,
                <<"content-length">> => <<"0">>
            },
            Stream = request(put, path_to_uri(Path), InHdrs, S2),
            case gun:await(Gun, Stream, 30000) of
                {response, fin, Status, _Headers} when (Status < 300) ->
                    #state{statcache = Cache} = S2,
                    PathBin = unicode:characters_to_binary(Path, utf8),
                    Cache2 = Cache#{ PathBin => #{ ts => 0, error => enoent } },
                    S3 = S2#state{statcache = Cache2},
                    {ok, S3};
                {response, fin, Status, _Headers} ->
                    {{error, {http, Status}}, S};
                {response, nofin, Status, Headers} when (Status > 300) ->
                    Hdrs = maps:from_list(Headers),
                    #{<<"content-type">> := ContentType} = Hdrs,
                    {ok, Body} = gun_data_h:await_body(Gun, Stream, 30000),
                    ErrInfo = case ContentType of
                        <<"application/json">> -> {http, Status, jsx:decode(Body, [return_maps])};
                        _ -> {http, Status, Body}
                    end,
                    case ErrInfo of
                        _ ->
                            lager:debug("mkdir returned ~p", [ErrInfo]),
                            {{error, ErrInfo}, S2}
                    end
            end
    end.
     
make_symlink(_Path2, _Path, S = #state{}) ->
    {{error, enotsup}, S}.

-record(fd_state, {path, fsm}).

open(Path, Flags, S = #state{host = Host, port = Port}) ->
    case {lists:member(read, Flags), lists:member(write, Flags)} of
        {true, false} ->
            case get_stat(Path, S) of
                {ok, #file_info{type = regular}, S2} ->
                    lager:debug("~p opening ~p for read", [S#state.user, Path]),
                    {ok, Fsm} = case S2 of
                        #state{amode = operator, signer = Signer} ->
                            file_read_fsm:start_link({Host, Port}, path_to_uri(Path), signature, Signer);
                        #state{amode = mahi_plus_token, token = Token} ->
                            file_read_fsm:start_link({Host, Port}, path_to_uri(Path), token, Token)
                    end,
                    ok = gen_statem:call(Fsm, connect),
                    Fd = S2#state.next_fd,
                    S3 = S2#state{next_fd = Fd + 1},
                    FdMap = S3#state.fds,
                    FS = #fd_state{path = Path, fsm = Fsm},
                    S4 = S3#state{fds = FdMap#{Fd => FS}},
                    {{ok, Fd}, S4};
                {ok, #file_info{type = directory}, S2} ->
                    {{error, eisdir}, S2};
                {error, Why, S2} ->
                    {{error, Why}, S2}
            end;
        {_, true} ->
            lager:debug("~p opening ~p for write (~p)", [S#state.user, Path, Flags]),
            {ok, Fsm} = case S of
                #state{amode = operator, signer = Signer} ->
                    file_write_fsm:start_link({Host, Port}, path_to_uri(Path), signature, Signer);
                #state{amode = mahi_plus_token, token = Token} ->
                    file_write_fsm:start_link({Host, Port}, path_to_uri(Path), token, Token)
            end,
            ok = gen_statem:call(Fsm, connect),
            Fd = S#state.next_fd,
            S2 = S#state{next_fd = Fd + 1},
            FdMap = S2#state.fds,
            FS = #fd_state{path = Path, fsm = Fsm},
            S3 = S2#state{fds = FdMap#{Fd => FS}},
            Cache = S3#state.statcache,
            Now = erlang:system_time(millisecond),
            PathBin = unicode:characters_to_binary(Path, utf8),
            Cache2 = Cache#{PathBin => #{ts => Now, stat => fake_new_file_info(Path)}},
            S4 = S3#state{statcache = Cache2},
            {{ok, Fd}, S4};
        _ ->
            lager:debug("~p tried to open ~p with unsupported flags: ~p", [S#state.user,
                Path, Flags]),
            {{error, eacces}, S}
    end.

close(Fd, S = #state{fds = Fds0}) ->
    case Fds0 of
        #{Fd := Fs = #fd_state{fsm = Fsm}} ->
            lager:debug("closing fd ~p, for ~p", [Fd, Fs#fd_state.path]),
            ok = gen_statem:call(Fsm, close),
            receive
                {'EXIT', Fsm, normal} -> ok
            end,
            lager:debug("closed ~p", [Fd]),
            Fds1 = maps:remove(Fd, Fds0),
            {ok, S#state{fds = Fds1}};
        _ ->
            {{error, ebadf}, S}
    end.
     
position(Fd, Offs, S = #state{fds = Fds}) ->
    case Fds of
        #{Fd := #fd_state{fsm = Fsm}} ->
            Res = gen_statem:call(Fsm, {position, Offs}),
            {Res, S};
        _ ->
            {{error, ebadf}, S}
    end.

read(Fd, Len, S = #state{fds = Fds}) ->
    case Fds of
        #{Fd := #fd_state{fsm = Fsm}} ->
            Res = gen_statem:call(Fsm, {read, Len}),
            {Res, S};
        _ ->
            {{error, ebadf}, S}
    end.
          
read_link(_Path, S = #state{}) ->
    {{error, einval}, S}.

rename(Path, Path2, S = #state{gun = Gun}) ->
    InHdrs = #{
        <<"accept">> => <<"application/json">>,
        <<"content-type">> => <<"application/json; type=link">>,
        <<"content-length">> => <<"0">>,
        <<"location">> => unicode:characters_to_binary(Path, utf8)
    },
    Stream = request(put, path_to_uri(Path2), InHdrs, S),
    case gun:await(Gun, Stream, 30000) of
        {response, fin, Status, _Headers} when (Status < 300) ->
            #state{statcache = Cache} = S,
            PathBin = unicode:characters_to_binary(Path, utf8),
            Path2Bin = unicode:characters_to_binary(Path2, utf8),
            Cache2 = Cache#{
                PathBin => #{ ts => 0, error => enoent },
                Path2Bin => #{ ts => 0, error => enoent }
            },
            S2 = S#state{statcache = Cache2},
            delete(Path, S2);
        {response, fin, Status, _Headers} ->
            lager:debug("putlink returned ~p", [{http, Status}]),
            {{error, {http, Status}}, S};
        {response, nofin, Status, Headers} when (Status > 300) ->
            Hdrs = maps:from_list(Headers),
            #{<<"content-type">> := ContentType} = Hdrs,
            {ok, Body} = gun_data_h:await_body(Gun, Stream, 30000),
            ErrInfo = case ContentType of
                <<"application/json">> -> {http, Status, jsx:decode(Body, [return_maps])};
                _ -> {http, Status, Body}
            end,
            case ErrInfo of
                {http, 400, #{<<"code">> := <<"LinkNotObject">>}} ->
                    {{error, enotdir}, S};
                {http, 403, _} ->
                    {{error, eacces}, S};
                {http, 404, #{<<"code">> := <<"SourceObjectNotFound">>}} ->
                    {{error, enoent}, S};
                _ ->
                    lager:debug("putlink returned ~p", [ErrInfo]),
                    {{error, ErrInfo}, S}
            end
    end.

write(Fd, Data, S = #state{fds = Fds}) ->
    case Fds of
        #{Fd := #fd_state{fsm = Fsm}} ->
            Res = gen_statem:call(Fsm, {write, Data}),
            {Res, S};
        _ ->
            {{error, ebadf}, S}
    end.
     
write_file_info(Path, _Info, S = #state{}) ->
    case get_stat(Path, S) of
        {ok, _, S2} -> {ok, S2};
        {error, Why, S2} -> {{error, Why}, S2}
    end.

%% internal functions
