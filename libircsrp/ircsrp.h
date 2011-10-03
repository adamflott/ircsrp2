#include <stdlib.h>
#include <string.h>

#include <gmp.h>

#include "external/bstring/bstrlib.h"

// datatypes
enum auth_state { 
    IRC_SRP_STATE_NEW = 0;
    IRC_SRP_STATE_INIT = 1;
};

enum irc_srp_error {
    IRC_SRP_ERROR_NONE = 0;
};

typedef struct irc_srp_exchange_t {
    // I
    char *user;
    // P
    char *password;
    
    void *s;
    mpz_t v;
}

typedef struct irc_srp_users_t {
    
}

typedef struct irc_srp_alice_t {
    enum auth_state state;

    irc_srp_exchange *ex;
}

typedef struct irc_srp_dave_t {
    enum auth_state state;
    
    irc_srp_exchange *ex;
    
    irc_srp_users *users;
}

// functions

// alice
irc_srp_alice_t * irc_srp_new_alice(void);
irc_srp_error     irc_srp_delete_alice(irc_srp_alice_t *alice);

irc_srp_error     irc_srp_init_alice(irc_srp_alice_t *alice, char *user, char *password);

irc_srp_error irc_srp_alice_make_0(irc_srp_alice_t *alice, char *return_msg_buffer);

// dave
irc_srp_error irc_srp_dave_verify_0(irc_srp_dave_t *dave, char *msg, char *buffer);


// utility
mpz_t bytes2int(void *data, unsigned int length);

// constants
mpz_t const_N(mpz_t n);
mpz_t const_N_minus_1(mpz_t n);