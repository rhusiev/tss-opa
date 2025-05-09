// From https://github.com/andrewkiluk/RSA-Library

#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

char buffer[1024];
const int MAX_DIGITS = 50;
int i, j = 0;

struct public_key_class {
  long long modulus;
  long long exponent;
};

struct private_key_class {
  long long modulus;
  long long exponent;
};

// This should totally be in the math library.
long long gcd(long long a, long long b) {
  long long c;
  while (a != 0) {
    c = a;
    a = b % a;
    b = c;
  }
  return b;
}

long long ExtEuclid(long long a, long long b) {
  long long x = 0, y = 1, u = 1, v = 0, gcd = b, m, n, q, r;
  while (a != 0) {
    q = gcd / a;
    r = gcd % a;
    m = x - u * q;
    n = y - v * q;
    gcd = a;
    a = r;
    x = u;
    y = v;
    u = m;
    v = n;
  }
  return y;
}
static inline long long modmult(long long a, long long b, long long mod) {
  // this is necessary since we will be dividing by a
  if (a == 0) {
    return 0;
  }
  register long long product = a * b;
  // if multiplication does not overflow, we can use it
  if (product / a == b) {
    return product % mod;
  }
  // if a % 2 == 1 i. e. a >> 1 is not a / 2
  if (a & 1) {
    product = modmult((a >> 1), b, mod);
    if ((product << 1) > product) {
      return (((product << 1) % mod) + b) % mod;
    }
  }
  // implicit else
  product = modmult((a >> 1), b, mod);
  if ((product << 1) > product) {
    return (product << 1) % mod;
  }
  // implicit else: this is about 10x slower than the code above, but it will
  // not overflow
  long long sum;
  sum = 0;
  while (b > 0) {
    if (b & 1)
      sum = (sum + a) % mod;
    a = (2 * a) % mod;
    b >>= 1;
  }
  return sum;
}
long long rsa_modExp(long long b, long long e, long long m) {
  long long product;
  product = 1;
  if (b < 0 || e < 0 || m <= 0) {
    return -1;
  }
  b = b % m;
  while (e > 0) {
    if (e & 1) {
      product = modmult(product, b, m);
    }
    b = modmult(b, b, m);
    e >>= 1;
  }
  return product;
}
// Calling this function will generate a public and private key and store them
// in the pointers it is given.
void rsa_gen_keys(struct public_key_class *pub, struct private_key_class *priv,
                  char *PRIME_SOURCE_FILE) {
  FILE *primes_list;
  if (!(primes_list = fopen(PRIME_SOURCE_FILE, "r"))) {
    fprintf(stderr, "Problem reading %s\n", PRIME_SOURCE_FILE);
    exit(1);
  }

  // count number of primes in the list
  long long prime_count = 0;
  do {
    int bytes_read = fread(buffer, 1, sizeof(buffer) - 1, primes_list);
    buffer[bytes_read] = '\0';
    for (i = 0; buffer[i]; i++) {
      if (buffer[i] == '\n') {
        prime_count++;
      }
    }
  } while (feof(primes_list) == 0);

  // choose random primes from the list, store them as p,q

  long long p = 0;
  long long q = 0;

  // values of e should be sufficiently large to protect against naive attacks
  long long e = (2 << 16) + 1;
  long long d = 0;
  char prime_buffer[MAX_DIGITS];
  long long max = 0;
  long long phi_max = 0;

  srand(time(NULL));

  do {
    // a and b are the positions of p and q in the list
    int a = (double)rand() * (prime_count + 1) / (RAND_MAX + 1.0);
    int b = (double)rand() * (prime_count + 1) / (RAND_MAX + 1.0);

    // here we find the prime at position a, store it as p
    rewind(primes_list);
    for (i = 0; i < a + 1; i++) {
      //  for(j=0; j < MAX_DIGITS; j++){
      //	prime_buffer[j] = 0;
      //  }
      fgets(prime_buffer, sizeof(prime_buffer) - 1, primes_list);
    }
    p = atol(prime_buffer);

    // here we find the prime at position b, store it as q
    rewind(primes_list);
    for (i = 0; i < b + 1; i++) {
      for (j = 0; j < MAX_DIGITS; j++) {
        prime_buffer[j] = 0;
      }
      fgets(prime_buffer, sizeof(prime_buffer) - 1, primes_list);
    }
    q = atol(prime_buffer);

    max = p * q;
    phi_max = (p - 1) * (q - 1);
  } while (!(p && q) || (p == q) || (gcd(phi_max, e) != 1));

  // Next, we need to choose a,b, so that a*max+b*e = gcd(max,e). We actually
  // only need b here, and in keeping with the usual notation of RSA we'll call
  // it d. We'd also like to make sure we get a representation of d as positive,
  // hence the while loop.
  d = ExtEuclid(phi_max, e);
  while (d < 0) {
    d = d + phi_max;
  }

  // printf("primes are %lld and %lld\n",(long long)p, (long long )q);
  //  We now store the public / private keys in the appropriate structs
  pub->modulus = max;
  pub->exponent = e;

  priv->modulus = max;
  priv->exponent = d;
}

long long *rsa_encrypt(const char *message, const unsigned long message_size,
                       const struct public_key_class *pub) {
  long long *encrypted = malloc(sizeof(long long) * message_size);
  if (encrypted == NULL) {
    fprintf(stderr, "Error: Heap allocation failed.\n");
    return NULL;
  }
  long long i = 0;
  for (i = 0; i < message_size; i++) {
    if ((encrypted[i] = rsa_modExp(message[i], pub->exponent, pub->modulus)) ==
        -1)
      return NULL;
  }
  return encrypted;
}

char *rsa_decrypt(const long long *message, const unsigned long message_size,
                  const struct private_key_class *priv) {
  if (message_size % sizeof(long long) != 0) {
    fprintf(stderr,
            "Error: message_size is not divisible by %d, so cannot be output "
            "of rsa_encrypt\n",
            (int)sizeof(long long));
    return NULL;
  }
  // We allocate space to do the decryption (temp) and space for the output as a
  // char array (decrypted)
  char *decrypted = malloc(message_size / sizeof(long long));
  char *temp = malloc(message_size);
  if ((decrypted == NULL) || (temp == NULL)) {
    fprintf(stderr, "Error: Heap allocation failed.\n");
    return NULL;
  }
  // Now we go through each 8-byte chunk and decrypt it.
  long long i = 0;
  for (i = 0; i < message_size / 8; i++) {
    if ((temp[i] = rsa_modExp(message[i], priv->exponent, priv->modulus)) ==
        -1) {
      free(temp);
      return NULL;
    }
  }
  // The result should be a number in the char range, which gives back the
  // original byte. We put that into decrypted, then return.
  for (i = 0; i < message_size / 8; i++) {
    decrypted[i] = temp[i];
  }
  free(temp);
  return decrypted;
}
