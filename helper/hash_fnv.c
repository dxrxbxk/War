#include <stdio.h>
#include <stdint.h>

#define FNV_OFFSET_BASIS_64 0xcbf29ce484222325ULL
#define FNV_PRIME_64 0x100000001b3ULL

uint64_t fnv1a_hash_64(const char *data, size_t len) {
    uint64_t hash = FNV_OFFSET_BASIS_64;
    for (size_t i = 0; i < len; i++) {
        hash ^= (uint8_t)data[i];
        hash *= FNV_PRIME_64;
    }
    return hash;
}

// Convertit un hash 64-bit en une chaîne ASCII imprimable de 8 caractères
void hash_to_printable(uint64_t hash, char *output) {
    for (int i = 0; i < 8; i++) {
        output[i] = (hash % 95) + 32;  // Valeur entre 32 (espace) et 126 (~)
        hash /= 95;
    }
    output[8] = '\0'; // Null-terminate la string
}

int main(int argc, char *argv[]) {
    const char *test_string = argv[1];
    uint64_t hash_value = fnv1a_hash_64(test_string, 27);

    char printable_hash[9]; // 8 caractères + null terminator
    hash_to_printable(hash_value, printable_hash);

    printf("FNV-1a 64-bit hash: 0x%016llx\n", hash_value);
    printf("Printable hash: %s\n", printable_hash);

    return 0;
}

