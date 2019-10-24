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
-export([login/2, logout/1, close/2, delete/2, del_dir/2, get_cwd/1, is_dir/2, list_dir/2, 
     make_dir/2, make_symlink/3, open/3, position/3, read/3,
     read_file_info/2, read_link/2, read_link_info/2, rename/3,
     write/3, write_file_info/3]).
-export([validate_pw/4]).

start(_StartType, _StartArgs) ->
    sftp_manta_sup:start_link().

stop(_State) ->
    ok.

host_key('ecdsa-sha2-nistp256', _Opts) ->
    {ok, KeyPath} = application:get_env(sftp_manta, host_key_file),
    {ok, Pem} = file:read_file(KeyPath),
    [KeyEntry] = public_key:pem_decode(Pem),
    Key = #'ECPrivateKey'{} = public_key:pem_entry_decode(KeyEntry),
    {ok, Key};
host_key(Alg, _Opts) ->
    {error, {no_key_for_alg, Alg}}.

mahi_get_auth_user(User) ->
    MahiHostInfo = application:get_env(sftp_manta, mahi, []),
    MahiHost = proplists:get_value(host, MahiHostInfo),
    MahiPort = proplists:get_value(port, MahiHostInfo, 80),
    {ok, MahiGun} = gun:open(MahiHost, MahiPort),
    {ok, _} = gun:await_up(MahiGun, 15000),
    Qs = uri_string:compose_query([{"login", User}]),
    Uri = iolist_to_binary(["/users?", Qs]),
    InHdrs = [{<<"accept">>, <<"application/json">>}],
    Stream = gun:get(MahiGun, Uri, InHdrs),
    Ret = case gun:await(MahiGun, Stream, 10000) of
        {response, nofin, Status, Headers} when (Status < 300) ->
            Hdrs = maps:from_list(Headers),
            #{<<"content-type">> := <<"application/json">>} = Hdrs,
            {ok, Body} = gun_data_h:await_body(MahiGun, Stream, 10000),
            #{<<"account">> := Account} = jsx:decode(Body, [return_maps]),
            {ok, Account};
        {response, nofin, Status, Headers} ->
            Hdrs = maps:from_list(Headers),
            #{<<"content-type">> := ContentType} = Hdrs,
            {ok, Body} = gun_data_h:await_body(MahiGun, Stream, 30000),
            ErrInfo = case ContentType of
                <<"application/json">> -> {http, Status, jsx:decode(Body, [return_maps])};
                _ -> {http, Status, Body}
            end,
            {error, ErrInfo};
        {response, fin, Status, Headers} ->
            {error, {http, Status}}
    end,
    gun:close(MahiGun),
    Ret.

is_auth_key(PubKey, User, _Opts) ->
    HSKey = http_signature_key:from_record(PubKey),
    Fp = http_signature_key:fingerprint(HSKey),
    {ok, Mode} = application:get_env(sftp_manta, auth_mode),
    case Mode of
        operator -> false;
        mahi_plus_token ->
            case mahi_get_auth_user(User) of
                {ok, Account} ->
                    #{<<"keys">> := Keys} = Account,
                    case Keys of
                        #{Fp := MahiPem} ->
                            [Entry] = public_key:pem_decode(MahiPem),
                            MahiPubKey = public_key:pem_entry_decode(Entry),
                            case MahiPubKey of
                                PubKey ->
                                    lager:debug("authed ~p with key ~p", [User, Fp]),
                                    true;
                                _ ->
                                    lager:warn("key ~p for user ~p matched fp, but not key!", [Fp, User]),
                                    false
                            end;
                        _ -> false
                    end;
                {error, Err} ->
                    lager:debug("mahi returned error looking up user '~s': ~p",
                        [User, Err]),
                    false
            end
    end.

validate_pw(User, Pw, RemoteAddr, State) ->
    Krb5Config = application:get_env(sftp_manta, krb5, []),
    case proplists:get_value(realm, Krb5Config) of
        undefined ->
            lager:debug("~p trying to use password auth", [User]),
            false;
        Realm ->
            Opts = Krb5Config -- [{realm, Realm}],
            {ok, KrbClient} = krb_client:open(Realm, Opts),
            case krb_client:authenticate(KrbClient, User, Pw) of
                ok ->
                    case mahi_get_auth_user(User) of
                        {ok, _Account} -> true;
                        {error, Err} ->
                            lager:warn("mahi rejected user ~p which krb5 "
                                "accepted", [User]),
                            false
                    end;
                {error, Why} ->
                    lager:debug("krb5 auth failed for ~p: ~p", [User, Why]),
                    false
            end
    end.

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
    next_fd = 10
    }).

request(Verb, Url, Hdrs0, S = #state{gun = Gun, signer = Signer, amode = operator}) ->
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
request(Verb, Url, Hdrs0, S = #state{gun = Gun, token = Token, amode = mahi_plus_token}) ->
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
            #{<<"uuid">> := Uuid, <<"defaultRoles">> := DefaultRoles} = Account,
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
                {response, fin, 404, Headers} ->
                    Cache2 = Cache#{Path => #{ts => Now, error => enoent}},
                    {error, enoent, S#state{statcache = Cache2}};
                {response, fin, 403, Headers} ->
                    {error, eacces, S};
                {response, fin, 405, Headers} ->
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
    InHdrs = #{
        <<"accept">> => <<"application/json; type=directory">>
    },
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
                    lager:debug("list_dir returned ~p", [ErrInfo]),
                    {{error, ErrInfo}, S}
            end;
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
            case ErrInfo of
                _ ->
                    lager:debug("mkdir returned ~p", [ErrInfo]),
                    {{error, ErrInfo}, S}
            end
    end.
     
make_symlink(Path2, Path, S = #state{}) ->
    {{error, enotsup}, S}.

-record(fd_state, {path, fsm}).

open(Path, Flags, S = #state{host = Host, port = Port}) ->
    case lists:member(write, Flags) of
        false ->
            case get_stat(Path, S) of
                {ok, #file_info{type = regular}, S2} ->
                    lager:debug("~p opening ~p for read", [S#state.user, Path]),
                    {ok, Fsm} = case S2 of
                        #state{amode = operator, signer = Signer} ->
                            file_read_fsm:start_link({Host, Port}, Path, operator, Signer);
                        #state{amode = mahi_plus_token, token = Token} ->
                            file_read_fsm:start_link({Host, Port}, Path, mahi_plus_token, Token)
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
        true ->
            lager:debug("~p opening ~p for write", [S#state.user, Path]),
            {ok, Fsm} = case S of
                #state{amode = operator, signer = Signer} ->
                    file_write_fsm:start_link({Host, Port}, Path, operator, Signer);
                #state{amode = mahi_plus_token, token = Token} ->
                    file_write_fsm:start_link({Host, Port}, Path, mahi_plus_token, Token)
            end,
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
            Res = gen_statem:call(Fsm, {position, Offs}),
            {Res, S};
        _ ->
            {{error, ebadf}, S}
    end.

read(Fd, Len, S = #state{fds = Fds}) ->
    case Fds of
        #{Fd := #fd_state{fsm = Fsm, path = Path}} ->
            Res = gen_statem:call(Fsm, {read, Len}),
            {Res, S};
        _ ->
            {{error, ebadf}, S}
    end.
          
read_link(Path, S = #state{}) ->
    {{error, einval}, S}.

rename(Path, Path2, S = #state{gun = Gun}) ->
    InHdrs = #{
        <<"accept">> => <<"application/json">>,
        <<"content-type">> => <<"application/json; type=link">>,
        <<"content-length">> => <<"0">>,
        <<"location">> => unicode:characters_to_binary(Path, utf8)
    },
    Stream = request(put, Path2, InHdrs, S),
    case gun:await(Gun, Stream, 30000) of
        {response, fin, Status, Headers} when (Status < 300) ->
            #state{statcache = Cache} = S,
            Cache2 = Cache#{
                Path => #{ ts => 0, error => enoent },
                Path2 => #{ ts => 0, error => enoent }
            },
            S2 = S#state{statcache = Cache2},
            delete(Path, S2);
        {response, fin, Status, Headers} ->
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
        #{Fd := #fd_state{fsm = Fsm, path = Path}} ->
            Len = byte_size(Data),
            Res = gen_statem:call(Fsm, {write, Data}),
            {Res, S};
        _ ->
            {{error, ebadf}, S}
    end.
     
write_file_info(Path, Info, S = #state{}) ->
    {{error, einval}, S}.

%% internal functions
