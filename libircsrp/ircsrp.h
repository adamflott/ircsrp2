#include <stdlib.h>
#include <string.h>

#include <gmp.h>

#include "external/bstring/bstrlib.h"

#define const_g 2;

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
irc_srp_init_alice(char *, char *);

mpz_t const_N(void);