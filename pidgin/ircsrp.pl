use strict;
use warnings;

use Purple;

# CPAN
use Algorithm::IRCSRP2::Alice;

our %PLUGIN_INFO = (
    'perl_api_version' => 2,
    'name'             => 'ircsrp',
    'version'          => '0.500',
    'summary'          => 'Peer encryption in channels over IRC',
    'description'      => 'Uses the IRCSRP version 2 to setup key exchange and message encryption/decryption',
    'author'           => 'Adam Flott adam@npjh.com',
    'url'              => 'https://github.com/aflott/ircsrp2',
    'load'             => 'plugin_load',
    'unload'           => 'plugin_unload',
);

# context data structure
#
# (
#     server name => {
#         channel name => { ... }
#     }
#     ...
# )
# e.g.
#
# (
#     'adam@irc.underworld.no' => {
#         '#secret' => { ... }
#     }
# )

my %contexts;
my %signals;

my $plugin_ref;
my $convs_handle_ref;

# -------- Purple --------
sub plugin_init {
    return %PLUGIN_INFO;
}

sub plugin_load {
    my $plugin = shift;

    # saving globals
    my $convs_handle = Purple::Conversations::get_handle();
    $convs_handle_ref = $convs_handle;
    $plugin_ref       = $plugin;

    # dave communication
    Purple::Cmd::register($plugin, 'ircsrp', 'ws', 1,
        Purple::Cmd::Flag::CHAT | Purple::Cmd::Flag::PRPL_ONLY | Purple::Cmd::Flag::ALLOW_WRONG_ARGS,
        'prpl-irc', \&ircsrp_state_control, 'ircsrp <enable|disable|reset> <encrypted-room-name> <dave-nick> <user> <password>');

    debug('loaded');

    return;
}

sub plugin_unload {
    my $plugin = shift;

    clear_contexts();
    clear_signals();

    debug('unloaded');

    return;
}

sub debug {
    my @msgs = @_;

    my @frame = caller(1);

    unshift(@msgs, ($frame[3] || '') . ': ');

    return Purple::Debug::info('ircsrp', join('', @msgs) . "\n");
}

# -------- context --------
sub get_context {
    my ($account, $channel_name) = @_;

    return $contexts{$account->get_username()}->{$channel_name};
}

sub set_context {
    my ($account, $channel_name, $context) = @_;

    debug('Setting new context ', $context->{'dave_nick'}, ' to ', $account->get_username());

    return $contexts{$account->get_username()}->{$channel_name} = $context;
}

sub del_context {
    my ($account, $channel_name) = @_;

    debug('Deleting context on ', $account->get_username());

    return delete($contexts{$account->get_username()}->{$channel_name});
}

sub clear_contexts {
    %contexts = ();
}

# -------- signals --------
sub add_signal {
    my ($name, $code_ref, $args) = @_;

    $signals{$name} = Purple::Signal::connect($convs_handle_ref, $name, $plugin_ref, $code_ref, $args);
    debug("adding signal: $name -> $signals{$name}");
}

sub del_signal {
    my ($name) = @_;

    eval {
        Purple::Signal::disconnect($convs_handle_ref, $name, $plugin_ref);
        debug("removed signal: $name");
    };

    if (my $e = $@) {
        debug("Signal disconnection eval returned $e");
    }
}

sub clear_signals {
    debug('clearing signals');
    foreach my $signal (keys(%signals)) {
        if ($signals{$signal}) {
            del_signal($signal);
        }
    }
}

# --------- exchange --------
sub ircsrp_state_control {
    my ($conversation, $plugin_name, $huh, $command, $args) = @_;

    if ($command =~ /^(enable|disable)$/) {
        clear_signals();
        del_context($conversation->get_account, $conversation->get_name());
    }

    if ($command eq 'enable') {

        debug('enabling ircsrp');

        my @args      = split(/\s+/, $args);
        my $encrypted_room_name = shift(@args);
        my $dave_nick = shift(@args);
        my $I         = shift(@args);
        my $P         = shift(@args);

        my $alice = Algorithm::IRCSRP2::Alice->new('debug_cb' => \&debug);

        $alice->I($I);
        $alice->P($P);

        $alice->init();

        my %context = (
            'enabled'            => 1,
            'dave_nick'          => $dave_nick,
            'dave_conversation', => undef,
            'alice'              => $alice
        );

        debug('New context enabled with ', $context{'dave_nick'});

        $context{'dave_conversation'} = start_dave_key_exchange(\%context, $conversation->get_account(), $dave_nick);

        set_context($conversation->get_account(), $encrypted_room_name, \%context);

        add_signal('receiving-im-msg', \&receiving_im_msg_cb, $encrypted_room_name);
        add_signal('sending-chat-msg', \&sending_chat_msg_cb);
        add_signal('receiving-chat-msg', \&receiving_chat_msg_cb);

        return Purple::Cmd::Return::OK;
    }
    elsif ($command eq 'disable') {

        debug('disabling ircsrp');

        return Purple::Cmd::Return::OK;
    }
    elsif ($command eq 'reset') {

        debug('resetting all contexts');

        clear_contexts();

        return Purple::Cmd::Return::OK;
    }

    return Purple::Cmd::Return::FAILED;
}

sub start_dave_key_exchange {
    my ($context, $account, $dave_nick) = @_;

    my $dave_conversation = Purple::Conversation->new(Purple::Conversation::Type::IM, $account, $dave_nick);
    $dave_conversation->get_im_data->send($context->{'alice'}->srpa0());

    $context->{'alice'}->state('srpa0');

    return $dave_conversation;
}

# -------- purple im event callbacks --------
sub receiving_im_msg_cb {
    my ($account, $who, $msg, $conversation, $flags, $channel_name) = @_;

    debug("$who sent $msg");

    my $context = get_context($account, $channel_name);

    if ($context->{'enabled'} && $context->{'dave_nick'} eq $who) {
        if ($msg =~ /\+srpa1/ && $context->{'alice'}->state() eq 'srpa0') {
            $msg =~ s/.*\+srpa1 //;
            debug("Got srpa1 message $msg");

            $context->{'dave_conversation'}->get_im_data->send($context->{'alice'}->verify_srpa1($msg));
        }
        elsif ($msg =~ /\+srpa3 / && $context->{'alice'}->state() eq 'srpa2') {
            $msg =~ s/.*\+srpa3 //;
            debug("Got srpa3 message $msg");

            if ($context->{'alice'}->verify_srpa3($msg)) {
                $conversation->get_im_data->write(
                    '',
                    "(from ircsrp) You are now authenticated with $who",
                    Purple::Conversation::Flags::SYSTEM | Purple::Conversation::Flags::NO_LOG, time()
                );
            }
        }
    }

    return;
}

# -------- purple chat event callbacks --------
sub sending_chat_msg_cb {
    my ($account, $msg, $id) = @_;

    my $conversation = Purple::Conversation::Chat::purple_find_chat($account->get_connection(), $id);

    my $context = get_context($account, $conversation->get_name());

    if ($context && $context->{'enabled'} && $context->{'alice'}->state() eq 'authenticated') {

        my $who = $context->{'alice'}->I();

        my $encrypted;

        eval { $encrypted = $context->{'alice'}->encrypt_message($who, $msg); };

        if (my $e = $@) {
            chomp($e);
            debug('WARNING: encrypting message "', $msg, '" failed with error: ', $e);
        }
        else {
            $_[1] = $encrypted;
            debug('sending encrypted message "', $encrypted, '"');
        }
    }

    return;
}

sub receiving_chat_msg_cb {
    my ($account, $who, $msg, $conversation, $flags) = @_;

    debug("$who sent $msg");

    my $context = get_context($account, $conversation->get_name());

    if ($context && $context->{'enabled'} && $context->{'alice'}->state() eq 'authenticated') {

        my $decrypted;

        eval { $decrypted = $context->{'alice'}->decrypt_message($msg); };

        if (my $e = $@) {
            chomp($e);

            $conversation->get_chat_data->write(
                '',
                qq((from ircsrp) WARNING UNENCRYPTED! $who: "$_[2]"),
                Purple::Conversation::Flags::SYSTEM | Purple::Conversation::Flags::NO_LOG, time()
            );

            debug('WARNING: decryption failed for "', $_[2], '"' . ' with error: ' . $e);
        }
        elsif ($decrypted) {
            $_[2] = $decrypted;
            debug('decrypted message: "', $decrypted, '" from "', $msg, '"');
        }
        else {

            # cancel display for rekeying messages
            return 1;
        }
    }

    return 0;
}

1;    # to keep perlcritic happy
