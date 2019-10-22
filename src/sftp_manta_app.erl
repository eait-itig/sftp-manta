%%%-------------------------------------------------------------------
%% @doc mylib public API
%% @end
%%%-------------------------------------------------------------------

-module(sftp_manta_app).

-include_lib("public_key/include/public_key.hrl").
-include_lib("kernel/include/file.hrl").
-compile([{parse_transform, lager_transform}]).

-behaviour(application).
-behaviour(ssh_server_key_api).
-behaviour(ssh_sftpd_file_api).

-export([start/2, stop/1]).
-export([host_key/2, is_auth_key/3]).
-export([login/2, close/2, delete/2, del_dir/2, get_cwd/1, is_dir/2, list_dir/2, 
     make_dir/2, make_symlink/3, open/3, position/3, read/3,
     read_file_info/2, read_link/2, read_link_info/2, rename/3,
     write/3, write_file_info/3]).
-export([validate_pw/4]).

start(_StartType, _StartArgs) ->
    sftp_manta_sup:start_link().

stop(_State) ->
    ok.

host_key('ecdsa-sha2-nistp256', _Opts) ->
    [KeyEntry] = public_key:pem_decode(<<"
-----BEGIN EC PRIVATE KEY-----
MHgCAQEEIQDlnhegeIWq5/2XeX947UmiGbSnLiHYpnZOeJrcxvLxTqAKBggqhkjO
PQMBB6FEA0IABBkBzZvS0Qzxkfs7fPej0kaddUWzTgDAJOL0sMXRRmpDJPDceAW9
rJnbf6HwxvMsNIZbdD8Qm6PKZ3f1XPhQ21o=
-----END EC PRIVATE KEY-----
    ">>),
    Key = #'ECPrivateKey'{} = public_key:pem_entry_decode(KeyEntry),
    {ok, Key};
host_key(Alg, _Opts) ->
    {error, {no_key_for_alg, Alg}}.

is_auth_key(PubKey, User, _Opts) ->
    true.

validate_pw(User, Pw, RemoteAddr, State) ->
    io:format("~p in ~p\n", [State, self()]),
    true.

-record(state, {
    user,
    cwd,
    signer,
    token,
    gun,
    host = "stluc.manta.uqcloud.net",
    port = 443,
    statcache = #{},
    fds = #{},
    next_fd = 10
    }).

request(Verb, Url, Hdrs0, S = #state{gun = Gun, signer = Signer}) ->
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
    lager:debug("~p ~p (headers = ~p)", [Method, Url, Hdrs2]),
    gun:request(Gun, Method, Url, Hdrs2).

login(User, S = #state{}) ->
    lager:debug("sftpd starting for user ~p", [User]),
    [KeyEntry] = public_key:pem_decode(<<"
-----BEGIN EC PRIVATE KEY-----
MHgCAQEEIQDlnhegeIWq5/2XeX947UmiGbSnLiHYpnZOeJrcxvLxTqAKBggqhkjO
PQMBB6FEA0IABBkBzZvS0Qzxkfs7fPej0kaddUWzTgDAJOL0sMXRRmpDJPDceAW9
rJnbf6HwxvMsNIZbdD8Qm6PKZ3f1XPhQ21o=
-----END EC PRIVATE KEY-----
    ">>),
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
    {ok, _} = gun:await_up(Conn),
    S#state{user = User, signer = Signer, gun = Conn}.

get_cwd([]) ->
    {{ok, "/"}, #state{}};
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
    FInfo2 = case string:split(Path, "/") of
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
    end.

isotime_to_datetime(Bin) ->
    <<YearBin:4/binary, "-", MonthBin:2/binary, "-", DayBin:2/binary, "T", TimeBin/binary>> = Bin,
    <<Hour:2/binary, ":", Min:2/binary, ":", Sec:2/binary, Rem/binary>> = TimeBin,
    _MSec = case Rem of
        <<"Z">> -> 0;
        <<".", V:3/binary, "Z">> -> binary_to_integer(V)
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
    FInfo2 = case string:split(Path, "/") of
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
    end.

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
            Stream = request(head, Path, #{}, S),
            case gun:await(Gun, Stream, 15000) of
                {response, fin, Status, Headers} when (Status < 300) ->
                    Hdrs = maps:from_list(Headers),
                    Stat = headers_to_file_info(Path, Hdrs),
                    Cache2 = Cache#{Path => #{ts => Now, stat => Stat}},
                    {ok, Stat, S#state{statcache = Cache2}};
                {response, fin, Status, Headers} when (Status == 404) ->
                    Cache2 = Cache#{Path => #{ts => Now, error => enoent}},
                    {error, enoent, S#state{statcache = Cache2}};
                {response, fin, Status, Headers} when (Status == 403) ->
                    {error, eacces, S};
                {response, fin, Status, Headers} ->
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
        {error, Why, S2} ->
            {false, S2}
    end.

list_dir(AbsPath, S) when is_list(AbsPath) ->
    list_dir(unicode:characters_to_binary(AbsPath, utf8), S);
list_dir(AbsPath, S = #state{gun = Gun, statcache = Cache0}) ->
    Stream = request(get, AbsPath, #{}, S),
    case gun:await(Gun, Stream, 30000) of
        {response, nofin, Status, Headers} when (Status < 300) ->
            Hdrs = maps:from_list(Headers),
            #{<<"content-type">> := ContentType} = Hdrs,
            <<"application/x-json-stream; type=directory">> = ContentType,

            {ok, Body} = gun_data_h:await_body(Gun, Stream, 30000),
            Lines = binary:split(Body, [<<"\n">>], [global, trim]),
            Objs = [jsx:decode(Line, [return_maps]) || Line <- Lines],

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
        {response, _Mode, Status, Headers} ->
            gun:cancel(Gun, Stream),
            gun:flush(Stream),
            {{error, enotdir}, S}
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
    Stream = request(delete, Path, #{}, S),
    case gun:await(Gun, Stream, 30000) of
        {response, fin, Status, Headers} when (Status < 300) ->
            #state{statcache = Cache} = S,
            Cache2 = Cache#{ Path => #{ ts => 0, error => enoent } },
            S2 = S#state{statcache = Cache2},
            {ok, S2};
        {response, fin, Status, Headers} ->
            {{error, {http, Status}}, S};
        {response, nofin, Status, Headers} when (Status > 300) ->
            Hdrs = maps:from_list(Headers),
            #{<<"content-type">> := ContentType} = Hdrs,
            {ok, Body} = gun_data_h:await_body(Gun, Stream, 30000),
            ErrInfo = case ContentType of
                <<"application/json">> -> {http, Status, jsx:decode(Body, [return_maps])};
                _ -> {http, Status, Body}
            end,
            {{error, ErrInfo}, S}
    end.

del_dir(Path, S = #state{}) ->
    delete(Path, S).
     
make_dir(Path, S = #state{gun = Gun}) ->
    InHdrs = #{
        <<"content-type">> => <<"application/json; type=directory">>,
        <<"content-length">> => <<"0">>
    },
    Stream = request(put, Path, InHdrs, S),
    case gun:await(Gun, Stream, 30000) of
        {response, fin, Status, Headers} when (Status < 300) ->
            #state{statcache = Cache} = S,
            Cache2 = Cache#{ Path => #{ ts => 0, error => enoent } },
            S2 = S#state{statcache = Cache2},
            {ok, S2};
        {response, fin, Status, Headers} ->
            {{error, {http, Status}}, S};
        {response, nofin, Status, Headers} when (Status > 300) ->
            Hdrs = maps:from_list(Headers),
            #{<<"content-type">> := ContentType} = Hdrs,
            {ok, Body} = gun_data_h:await_body(Gun, Stream, 30000),
            ErrInfo = case ContentType of
                <<"application/json">> -> {http, Status, jsx:decode(Body, [return_maps])};
                _ -> {http, Status, Body}
            end,
            {{error, ErrInfo}, S}
    end.
     
make_symlink(Path2, Path, S = #state{}) ->
    {{error, enotsup}, S}.

-record(fd_state, {path, fsm}).

open(Path, Flags, S = #state{host = Host, port = Port, signer = Signer}) ->
    case lists:member(write, Flags) of
        false ->
            case get_stat(Path, S) of
                {ok, #file_info{type = regular}, S2} ->
                    {ok, Fsm} = file_read_fsm:start_link({Host, Port}, Path, Signer),
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
        true ->
            {ok, Fsm} = file_write_fsm:start_link({Host, Port}, Path, Signer),
            ok = gen_statem:call(Fsm, connect),
            Fd = S#state.next_fd,
            S2 = S#state{next_fd = Fd + 1},
            FdMap = S2#state.fds,
            FS = #fd_state{path = Path, fsm = Fsm},
            S3 = S2#state{fds = FdMap#{Fd => FS}},
            {{ok, Fd}, S3}
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
            lager:debug("{position,~p}", [Offs]),
            Res = gen_statem:call(Fsm, {position, Offs}),
            lager:debug("{position,~p} => ~p", [Offs, Res]),
            {Res, S};
        _ ->
            {{error, ebadf}, S}
    end.

read(Fd, Len, S = #state{fds = Fds}) ->
    case Fds of
        #{Fd := #fd_state{fsm = Fsm, path = Path}} ->
            lager:debug("{read,~p}", [Len]),
            Res = gen_statem:call(Fsm, {read, Len}),
            case Res of
                {ok, Buf} -> lager:debug("{read,~p} => ~p bytes", [Len, size(Buf)]);
                _ -> lager:debug("{read,~p} => ~p", [Len, Res])
            end,
            {Res, S};
        _ ->
            {{error, ebadf}, S}
    end.
          
read_link(Path, S = #state{}) ->
    {{error, einval}, S}.

rename(Path, Path2, S = #state{}) ->
    {{error, einval}, S}.

write(Fd, Data, S = #state{fds = Fds}) ->
    case Fds of
        #{Fd := #fd_state{fsm = Fsm, path = Path}} ->
            Len = byte_size(Data),
            lager:debug("{write,~p}", [Len]),
            Res = gen_statem:call(Fsm, {write, Data}),
            lager:debug("{write,~p} => ~p", [Len, Res]),
            {Res, S};
        _ ->
            {{error, ebadf}, S}
    end.
     
write_file_info(Path, Info, S = #state{}) ->
    lager:debug("{write_file_info, ~p, ~p}", [Path, Info]),
    {{error, einval}, S}.

%% internal functions
