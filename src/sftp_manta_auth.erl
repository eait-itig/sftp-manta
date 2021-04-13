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

-module(sftp_manta_auth).

-include_lib("kernel/include/file.hrl").
-include_lib("public_key/include/public_key.hrl").

-behaviour(gen_server).
-compile([{parse_transform, lager_transform}]).

-export([start_link/0, is_auth_key/2, validate_pw/3]).
-export([init/1, terminate/2, handle_call/3, handle_info/2]).

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

is_auth_key(PubKey, User) ->
    gen_server:call(?MODULE, {is_auth_key, PubKey, User}).

validate_pw(User, Pw, RemoteAddr) ->
    gen_server:call(?MODULE, {validate_pw, User, Pw, RemoteAddr}).

-record(?MODULE, {
    krb :: undefined | pid(),
    krbmon :: undefined | reference(),
    mahi :: undefined | pid(),
    mahimon :: undefined | reference(),
    mode :: operator | mahi_plus_token,
    keys :: undefined | [term()],
    keymtime :: undefined | calendar:datetime()
    }).

init([]) ->
    {ok, Mode} = application:get_env(sftp_manta, auth_mode),
    S0 = #?MODULE{mode = Mode},
    Krb5Config = application:get_env(sftp_manta, krb5, []),
    S1 = case proplists:get_value(realm, Krb5Config) of
        undefined ->
            S0;
        Realm ->
            Opts = Krb5Config -- [{realm, Realm}],
            {ok, KrbClient} = krb_client:open(Realm, Opts),
            KrbMRef = monitor(process, KrbClient),
            S0#?MODULE{krb = KrbClient, krbmon = KrbMRef}
    end,
    case Mode of
        operator ->
            S2 = check_update_keys(S1),
            {ok, S2};
        mahi_plus_token ->
            MahiHostInfo = application:get_env(sftp_manta, mahi, []),
            MahiHost = proplists:get_value(host, MahiHostInfo),
            MahiPort = proplists:get_value(port, MahiHostInfo, 80),
            {ok, MahiGun} = gun:open(MahiHost, MahiPort),
            {ok, _} = gun:await_up(MahiGun, 30000),
            MRef = monitor(process, MahiGun),
            S2 = S1#?MODULE{mahi = MahiGun, mahimon = MRef},
            {ok, S2}
    end.

terminate(Why, S0 = #?MODULE{mahi = MahiGun}) when is_pid(MahiGun) ->
    gun:close(MahiGun),
    terminate(Why, S0#?MODULE{mahi = undefined});
terminate(Why, S0 = #?MODULE{}) ->
    lager:debug("auth process dying: ~p", [Why]),
    ok.

check_update_keys(S0 = #?MODULE{keymtime = OldMTime}) ->
    case application:get_env(sftp_manta, authorized_keys_file) of
        {ok, Filename} ->
            case file:read_file_info(Filename) of
                {ok, #file_info{type = regular, mtime = NewMTime}}
                                                when (NewMTime =:= OldMTime) ->
                    S0;

                {ok, #file_info{type = regular, mtime = NewMTime}} ->
                    {ok, Data} = file:read_file(Filename),
                    Keys = public_key:ssh_decode(Data, auth_keys),
                    S0#?MODULE{keys = Keys, keymtime = NewMTime};

                {ok, #file_info{type = Other}} ->
                    lager:debug("authorized_keys file is a ~p, must be a "
                        "regular file", [Other]),
                    S0;

                Err ->
                    lager:debug("failed to read '~s': ~p", [Filename, Err]),
                    S0
            end;
        _ ->
            S0
    end.

mahi_get_auth_user(User, S0 = #?MODULE{mahi = MahiGun}) ->
    Qs = uri_string:compose_query([{"login", User}]),
    Uri = iolist_to_binary(["/users?", Qs]),
    InHdrs = [{<<"accept">>, <<"application/json">>}],
    Stream = gun:get(MahiGun, Uri, InHdrs),
    case gun:await(MahiGun, Stream, 30000) of
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
        {response, fin, Status, _Headers} ->
            {error, {http, Status}}
    end.

handle_call({is_auth_key, PubKey, User}, _From, S0 = #?MODULE{keys = Keys0})
                                                        when is_list(Keys0) ->
    S1 = #?MODULE{keys = Keys} = check_update_keys(S0),
    Matching = [Attrs || {Key, Attrs} <- Keys, Key =:= PubKey],
    Result = lists:any(fun (Attrs) ->
        Opts = proplists:get_value(options, Attrs, []),
        case Opts of
            [] -> true;
            _ -> lists:member("user=" ++ User, Opts)
        end
    end, Matching),
    {reply, Result, S1};

handle_call({is_auth_key, PubKey, User}, _From, S0 = #?MODULE{mahi = MahiGun}) 
                                                        when is_pid(MahiGun) ->
    HSKey = http_signature_key:from_record(PubKey),
    Fp = http_signature_key:fingerprint(HSKey),
    case mahi_get_auth_user(User, S0) of
        {ok, Account} ->
            #{<<"keys">> := Keys} = Account,
            case Keys of
                #{Fp := MahiPem} ->
                    [Entry] = public_key:pem_decode(MahiPem),
                    MahiPubKey = public_key:pem_entry_decode(Entry),
                    case MahiPubKey of
                        PubKey ->
                            lager:debug("authed ~p with key ~p", [User, Fp]),
                            {reply, true, S0};
                        _ ->
                            lager:warn("key ~p for user ~p matched fp, but "
                                "not key!", [Fp, User]),
                            {reply, false, S0}
                    end;
                _ ->
                    {reply, false, S0}
            end;
        {error, Err} ->
            lager:debug("mahi returned error looking up user '~s': ~p",
                [User, Err]),
            {reply, false, S0}
    end;

handle_call({is_auth_key, _PubKey, _User}, _From, S0 = #?MODULE{}) ->
    {reply, false, S0};

handle_call({validate_pw, User, Pw, _Ip}, _From,
        S0 = #?MODULE{krb = Krb, mode = mahi_plus_token}) when is_pid(Krb) ->
    case mahi_get_auth_user(User, S0) of
        {ok, _Account} ->
            case krb_client:authenticate(Krb, User, Pw) of
                ok ->
                    {reply, true, S0};
                {error, Why} ->
                    lager:debug("krb5 auth failed for ~p: ~p", [User, Why]),
                    {reply, false, S0}
            end;
        {error, Err} ->
            lager:warn("mahi rejected user ~p: ~p", [User, Err]),
            {reply, false, S0}
    end;

handle_call({validate_pw, User, Pw, _Ip}, _From,
                S0 = #?MODULE{krb = Krb, mode = operator}) when is_pid(Krb) ->
    case krb_client:authenticate(Krb, User, Pw) of
        ok ->
            {reply, true, S0};
        {error, Why} ->
            lager:debug("krb5 auth failed for ~p: ~p", [User, Why]),
            {reply, false, S0}
    end;

handle_call({validate_pw, _User, _Pw, _Ip}, _From, S0 = #?MODULE{}) ->
    {reply, false, S0}.


handle_info({'DOWN', MRef, process, _Pid, Why}, S0 = #?MODULE{krbmon = MRef}) ->
    lager:debug("krb client died with: ~p", [Why]),
    Krb5Config = application:get_env(sftp_manta, krb5, []),
    Realm = proplists:get_value(realm, Krb5Config),
    Opts = Krb5Config -- [{realm, Realm}],
    {ok, KrbClient} = krb_client:open(Realm, Opts),
    KrbMRef = monitor(process, KrbClient),
    S1 = S0#?MODULE{krb = KrbClient, krbmon = KrbMRef},
    {noreply, S1};

handle_info({'DOWN', MRef, process, _Pid, Why}, S0 = #?MODULE{mahimon = MRef}) ->
    lager:debug("mahi client died with: ~p", [Why]),
    MahiHostInfo = application:get_env(sftp_manta, mahi, []),
    MahiHost = proplists:get_value(host, MahiHostInfo),
    MahiPort = proplists:get_value(port, MahiHostInfo, 80),
    {ok, MahiGun} = gun:open(MahiHost, MahiPort),
    {ok, _} = gun:await_up(MahiGun, 30000),
    MRef = monitor(process, MahiGun),
    S1 = S0#?MODULE{mahi = MahiGun, mahimon = MRef},
    {ok, S1};

handle_info({gun_down, Pid, _Proto, _Reason, _}, S0 = #?MODULE{mahi = Pid}) ->
    {noreply, S0};
handle_info({gun_up, Pid, _Proto}, S0 = #?MODULE{mahi = Pid}) ->
    {noreply, S0};
handle_info({gun_error, Pid, _Reason}, S0 = #?MODULE{mahi = Pid}) ->
    {noreply, S0}.
