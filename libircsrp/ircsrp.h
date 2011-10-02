#include <stdlib.h>
#include <string.h>

#include <gmp.h>

#include "external/bstring/bstrlib.h"

// datatypes
enum auth_state { INIT };

typedef struct irc_srp_alice_t {
    enum auth_state state;
    
    // I
    char *user;
    // P
    char *password;
    
    void *s;
    mpz_t v;
}

// functions

// alice
irc_srp_init_alice(char *user, char *password);

// utility
mpz_t bytes2int(void *data, unsigned int length);

// constants
mpz_t const_N(void);