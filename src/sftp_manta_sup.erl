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

-module(sftp_manta_sup).

-behaviour(supervisor).

-export([start_link/0]).

-export([init/1]).

-define(SERVER, ?MODULE).

start_link() ->
    supervisor:start_link({local, ?SERVER}, ?MODULE, []).

%% sup_flags() = #{strategy => strategy(),         % optional
%%                 intensity => non_neg_integer(), % optional
%%                 period => pos_integer()}        % optional
%% child_spec() = #{id => child_id(),       % mandatory
%%                  start => mfargs(),      % mandatory
%%                  restart => restart(),   % optional
%%                  shutdown => shutdown(), % optional
%%                  type => worker(),       % optional
%%                  modules => modules()}   % optional
init([]) ->
    SupFlags = #{strategy => one_for_one,
        intensity => 5,
        period => 10},
    SFTPSpec = sftpd_manta:subsystem_spec([
        {file_handler, sftp_manta_app}
        ]),
    SSHOpts = [
        {subsystems, [SFTPSpec]},
        {ssh_cli, {sftp_manta_app, []}},
        {pwdfun, fun sftp_manta_app:validate_pw/4},
        {pk_check_user, true},
        {key_cb, {sftp_manta_app, []}},
        {preferred_algorithms, [
            {kex, ['ecdh-sha2-nistp384','ecdh-sha2-nistp521',
                   'ecdh-sha2-nistp256','diffie-hellman-group-exchange-sha256',
                   'diffie-hellman-group16-sha512',
                   'diffie-hellman-group18-sha512',
                   'diffie-hellman-group14-sha256',
                   'diffie-hellman-group-exchange-sha1',
                   'diffie-hellman-group14-sha1',
                   'diffie-hellman-group1-sha1'
                  ]},
            {public_key, ['ecdsa-sha2-nistp256', 'rsa-sha2-512', 'rsa-sha2-256', 'ssh-rsa']}
        ]},
        {recbuf, 128*1024},
        {sndbuf, 128*1024},
        {buffer, 256*1024},
        {keepalive, true},
        {max_sessions, 256},
        {max_channels, 8},
        {parallel_login, true},
        {negotiation_timeout, 10000}
    ],
    ListenPort = application:get_env(sftp_manta, listen_port, 2222),
    ChildSpecs = [
        #{id => sshd, start => {ssh, daemon, [ListenPort, SSHOpts]}},
        #{id => auth, start => {sftp_manta_auth, start_link, []}}
    ],
    {ok, {SupFlags, ChildSpecs}}.

%% internal functions
