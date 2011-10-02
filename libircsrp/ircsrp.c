#include "ircsrp.h"

irc_srp_alice_t * irc_srp_init_alice(char *user, char *pass) {
    irc_srp_alice_t *alice;
    
    bstring bstr_user = bfromcstr(user);
    bstring bstr_pass = bfromcstr(pass);
    
    unsigned int random_data_read_amount = 32;
    
    gmp_randstate_t *state;
    
    gmp_randinit_default(state);

    alice = (irc_srp_alice_t *)malloc(sizeof irc_srp_alice_t);
    memset(alice, 0. sizeof irc_srp_alice_t);
    
    void *s;
    
    int fh = open("/dev/random", O_RDONLY);
    read(fh, s, random_data_read_amount);
    close(fh);
    
    unsigned int length = random_data_read_amount + blength(bstr_user) + blength(bstr_pass);
    
    bstring digest;
    bstring sip = blk2bstr(s, random_data_read_amount);
    
    bconcat(sip, bstr_user);
    bconcat(sip, bstr_pass);
    
    sha256(sip->data, length, digest);
    
    mpz_t x = bytes2int(digest, length);
    
    alice->s = s;
    
    alice->state = INIT;
    
    return alice;
}

mpz_t bytes2int(void *data, unsigned int length) {
    void *current = data;
    
    mpz_t n;
    
    mpz_init(n);

    for (int i = 0; i < length; i++) {
        
        mpz_mul_ui(n, n, 256);
        mpz_add_ui(n, n, (unsigned char)current);
        
        current++;
    }

    return n;
}

mpz_t const_N(void) {
    mpz_t n;

    mpz_init(n);

    mpz_set_str(n, 
                "32317006071311007300338913926423828248817941241140239112842009751400741706634354222619689417363569347117901737909704191754605873209195028853758986185622153212175412514901774520270235796078236248884246189477587641105928646099411723245426622522193230540919037680524235519125679715870117001058055877651038861847280257976054903569732561526167081339361799541336476559160368317896729073178384589680639671900977202194168647225871031411336429319536193471636533209717077448227988588565369208645296636077250268955505928362751121174096972998068410554359584866583291642136218231078990999448652468262416972035911852507045361090559",
                10);

    return n;
}
