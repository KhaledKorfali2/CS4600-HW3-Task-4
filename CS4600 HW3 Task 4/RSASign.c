#include <stdio.h>
#include <stdlib.h>
#include <openssl/bn.h>

/* Function to print a BIGNUM variable in hexadecimal format */
void printBN(const char* msg, BIGNUM* a)
{
    char* number_str = BN_bn2hex(a);
    printf("%s %s", msg, number_str);
    OPENSSL_free(number_str);
}


int main() {
    // Declare and initialize variables and context
    BIGNUM* n = BN_new(); // modulus n
    BIGNUM* e = BN_new(); // public exponent
    BIGNUM* d = BN_new(); // private exponent
    BIGNUM* m = BN_new(); // plaintext message
    BIGNUM* s = BN_new(); // signature
    BIGNUM* decrypted_m = BN_new(); // decrypted plaintext message
    BN_CTX* ctx = BN_CTX_new(); // context


    // Initialize known values for n, e, and d
    BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
    BN_hex2bn(&e, "010001");
    BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");

    // Set the plaintext message
    BN_hex2bn(&m, "49206f776520796f752024323030302e"); // "I owe you $2000."
    //BN_hex2bn(&m, "49206f776520796f752024333030302e"); // "I owe you $3000."



    // Calculate the signature
    BN_mod_exp(s, m, d, n, ctx); // s = m^d (mod n)

    // Verify the signature by calculating m^e (mod n) and comparing with k
    BN_mod_exp(decrypted_m, s, e, n, ctx); // decrypted_m = s^e (mod n)
    int verified = BN_cmp(m, decrypted_m) == 0;

    // Print the results
    printf("Plaintext message: \"I owe you $2000.\"\n");
    printBN("Signature:", s);
    printf("\n");
    printf("Signature verified: %s\n", verified ? "yes" : "no");


    // Free memory
    BN_free(n);
    BN_free(e);
    BN_free(d);
    BN_free(m);
    BN_free(s);
    BN_free(decrypted_m);
    BN_CTX_free(ctx);


    return 0;
}