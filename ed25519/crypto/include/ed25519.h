// TODO add guards

int sign(unsigned char *signed_msg,unsigned long long *signed_msg_len,
    const unsigned char *msg,unsigned long long msg_len,
    const unsigned char *priv_pub_key);
int sign_ephemeral(unsigned char *signed_msg,unsigned long long *signed_msg_len,
    const unsigned char *msg,unsigned long long msg_len,
    const unsigned char *priv_pub_key);
int sign_unprotected(unsigned char *signed_msg,unsigned long long *signed_msg_len,
    const unsigned char *msg,unsigned long long msg_len,
    const unsigned char *priv_pub_key);
int verify(unsigned char *msg, unsigned long long *msg_len,
    const unsigned char *signed_msg, const unsigned long long signed_msg_len,
    const unsigned char *pub_key);
void hash_masked(unsigned char *output, const unsigned char *input, const unsigned long long inlen, unsigned char *helper_shake_share0, unsigned char *helper_shake_share1);
