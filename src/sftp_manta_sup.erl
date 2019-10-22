%%%-------------------------------------------------------------------
%% @doc mylib top level supervisor.
%% @end
%%%-------------------------------------------------------------------

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
    SupFlags = #{strategy => one_for_all,
        intensity => 0,
        period => 1},
    SFTPSpec = sftpd_manta:subsystem_spec([
        {file_handler, sftp_manta_app}
        ]),
    SSHOpts = [
        {subsystems, [SFTPSpec]},
        {shell, {sftp_manta_shell, start, []}},
        {pwdfun, fun sftp_manta_app:validate_pw/4},
        {key_cb, {sftp_manta_app, []}},
        {preferred_algorithms, [
            {public_key, ['ecdsa-sha2-nistp256']}
        ]}
    ],
    ChildSpecs = [
        #{id => sshd, start => {ssh, daemon, [2222, SSHOpts]}}
    ],
    {ok, {SupFlags, ChildSpecs}}.

%% internal functions
