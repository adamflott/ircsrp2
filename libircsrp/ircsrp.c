#include "ircsrp.h"

irc_srp_error irc_srp_dave_verify_0(irc_srp_dave_t *dave, char *msg, char *buffer) {
    // TODO get I, s, v from specific user
    //    ex = ctx.users.others[sender] = IRCSRPExchange()
    //    
    //    I = ex.I = arg
    //    s, v = ex.s, ex.v = ctx.users.get_details(I)
    
    bstring data;
    bstring bmsg = bfromcstr(msg);
    bstring prefix = bfromcstr("+srpa 0");
    bstring empty = bfromcstr("");
    
    bfindreplace(msg, prefix, empty, 0);
    
    mpz_t b;
    mpz_t B;
    mpz_t Nm1;
    
    mp_bitcnt_t n = 2;
    
    gmp_randstate_t *state;
    gmp_randinit_default(state);

    mpz_init(Nm1);

    // b = ex.b = randint(2, N-1)
    mpz_urandomm(b, state, mpz_t const_N_minus_1(Nm1));
    
    // B = ex.B = (3*v + pow(g, b, N)) % N
    //   3*v
    mpz_t vx3;
    mpz_t rvx3;

    mpz_init(vx3);
    mpz_init(rvx3);
    
    mpz_set(vx3, v);
    mpz_mul_ui(rvx3, vx3, 3);
    
    mpz_clear(vx3);
    
    //   pow(g, b, N)
    mpz_t g;
    mpz_t rg;
    mpz_t N;
    
    mpz_init(g);
    mpz_init(rg);
    mpz_init(N);

    mpz_set(g, 2);
    const_N(N);
    
    mpz_powm_ui(rg, g, b, N);
    
    mpz_clear(g);
    
    //   (3*v + pow(g, b, N))
    mpz_t r;
    mpz_t rr;
    
    mpz_init(r);
    mpz_init(rr);
    
    mpz_add_ui(r, rxv3, rg);
    mpz_mod(rr, r, N);
    
    mpz_set(B, rr);

    mpz_clear(r);
    mpz_clear(N);
    
    // return "+srpa1 " + b64(s + int2bytes(B))
    bstring ret bfromcstr("+srpa1 ");
    
    void *data = int2bytes(B);
    
    char *concat = (char *)malloc(strlen(s) + strlen(data) + 1);
    
    // TODO change to better base64 lib http://libb64.sourceforge.net/
    // int base64_encode_block(const char* plaintext_in, int length_in, char* code_out, base64_encodestate* state_in);
    
    bcatcstr(ret, concat);
    
    buffer = bstr2cstr(ret, '');
    
    return IRC_SRP_ERROR_NONE;
}

irc_srp_error irc_srp_alice_make_0(irc_srp_alice_t *alice, char *return_msg_buffer) {
    bstring prefix;
    
    prefix = bfromcstr("+srpa0 ");
    
    bstring msg = bcatcstr(prefix, alice->user);
    
    return_msg_buffer = bstr2cstr(msg, '');
    
    bdestroy(msg);
    
    return IRC_SRP_ERROR_NONE;
}

irc_srp_alice_t * irc_srp_new_alice(void) {
    
    irc_srp_alice_t *alice;
    irc_srp_exchange_t *ex;
    
    alice = (irc_srp_alice_t *)malloc(sizeof irc_srp_alice_t);
    memset(alice, 0. sizeof irc_srp_alice_t);

    ex = (irc_srp_exchange_t *)malloc(sizeof irc_srp_exchange_t);
    memset(ex, 0. sizeof irc_srp_exchange_t);
    
    alice->ex = ex;
    alice->state = IRC_SRP_STATE_NEW;
    
    return alice;
}

irc_srp_error irc_srp_delete_alice(irc_srp_alice_t *alice) {
    
}

irc_srp_error irc_srp_init_alice(irc_srp_alice_t *alice, char *user, char *password) {
    
    bstring bstr_user = bfromcstr(user);
    bstring bstr_pass = bfromcstr(password);
    
    unsigned int random_data_read_amount = 32;
    
    gmp_randstate_t *state;
    
    gmp_randinit_default(state);
    
    void *s;
    mpz_t v;
    
    // begin s
    int fh = open("/dev/random", O_RDONLY);
    read(fh, s, random_data_read_amount);
    close(fh);
    
    alice->s = s;
    
    // end s
    
    // begin v
    unsigned int length = random_data_read_amount + blength(bstr_user) + blength(bstr_pass);
    
    bstring digest;
    bstring sip = blk2bstr(s, random_data_read_amount);
    
    bconcat(sip, bstr_user);
    bconcat(sip, bstr_pass);
    
    sha256(sip->data, length, digest);
    
    mpz_t x = bytes2int(digest, length);

    mpz_t g;
    mpz_init(g);
    
    mpz_set_ui(g, 2);
    
    mpz_powm(v, g, x, const_N());
    
    alice->v = v;
    // end v
    
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

mpz_t const_N_minus_1(mpz_t Nm1) {
    const_N(Nm1);
    
    mpz_sub_ui(Nm1, Nm1, 1);
    
    return Nm1;
}

mpz_t const_N(mpz_t N) {
    mpz_set_str(n, 
                "32317006071311007300338913926423828248817941241140239112842009751400741706634354222619689417363569347117901737909704191754605873209195028853758986185622153212175412514901774520270235796078236248884246189477587641105928646099411723245426622522193230540919037680524235519125679715870117001058055877651038861847280257976054903569732561526167081339361799541336476559160368317896729073178384589680639671900977202194168647225871031411336429319536193471636533209717077448227988588565369208645296636077250268955505928362751121174096972998068410554359584866583291642136218231078990999448652468262416972035911852507045361090559",
                10);

    return n;
}