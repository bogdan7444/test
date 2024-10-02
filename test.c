#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define BUFFER_SIZE 1024

// Функция для шифрования данных
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    // Создание и инициализация контекста
    if (!(ctx = EVP_CIPHER_CTX_new())) return -1;

    // Инициализация шифрования AES-256-CBC
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) return -1;

    // Шифрование данных
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) return -1;
    ciphertext_len = len;

    // Завершение шифрования
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) return -1;
    ciphertext_len += len;

    // Очистка контекста
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

// Функция для расшифровки данных
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;

    // Создание и инициализация контекста
    if (!(ctx = EVP_CIPHER_CTX_new())) return -1;

    // Инициализация расшифровки AES-256-CBC
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) return -1;

    // Расшифровка данных
    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) return -1;
    plaintext_len = len;

    // Завершение расшифровки
    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) return -1;
    plaintext_len += len;

    // Очистка контекста
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

// Генерация ключа на основе пароля
void generate_key_iv(const char *password, unsigned char *key, unsigned char *iv) {
    unsigned char salt[8] = {0}; // Использование нулевого соли для простоты
    PKCS5_PBKDF2_HMAC(password, strlen(password), salt, sizeof(salt), 10000, EVP_sha256(), 32, key); // Генерация ключа
    RAND_bytes(iv, 16); // Генерация случайного IV
}

// Запись данных в файл
void write_data(FILE *fout, unsigned char *data, int len) {
    fwrite(data, 1, len, fout);
}

// Чтение данных из файла
int read_data(FILE *fin, unsigned char *buffer, int maxlen) {
    return fread(buffer, 1, maxlen, fin);
}

int main(int argc, char *argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <encrypt|decrypt> <inputfile> <password>\n", argv[0]);
        return 1;
    }

    const char *operation = argv[1];
    const char *input_filename = argv[2];
    const char *password = argv[3];

    FILE *fin = fopen(input_filename, "rb");
    if (!fin) {
        fprintf(stderr, "Error: Could not open input file '%s'\n", input_filename);
        return 1;
    }

    char output_filename[256];

    if (strcmp(operation, "encrypt") == 0) {
        snprintf(output_filename, sizeof(output_filename), "%s.enc", input_filename);
    } else if (strcmp(operation, "decrypt") == 0) {
        size_t len = strlen(input_filename);
        if (len > 4 && strcmp(input_filename + len - 4, ".enc") == 0) {
            // Если файл имеет суффикс .enc, убираем его и добавляем .dec
            snprintf(output_filename, sizeof(output_filename), "%.*s.dec", (int)(len - 4), input_filename);
        } else {
            // Если файл не имеет суффикса .enc, просто добавляем .dec
            snprintf(output_filename, sizeof(output_filename), "%s.dec", input_filename);
        }
    } else {
        fprintf(stderr, "Invalid operation: %s\n", operation);
        fclose(fin);
        return 1;
    }

    FILE *fout = fopen(output_filename, "wb");
    if (!fout) {
        fprintf(stderr, "Error: Could not open output file '%s'\n", output_filename);
        fclose(fin);
        return 1;
    }

    unsigned char key[32]; // 256-битный ключ
    unsigned char iv[16];  // 128-битный IV
    generate_key_iv(password, key, iv);
unsigned char buffer[BUFFER_SIZE];
    unsigned char out_buffer[BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH];

    int len;
    if (strcmp(operation, "encrypt") == 0) {
        // Сначала записываем IV в файл
        write_data(fout, iv, sizeof(iv));

        // Шифруем данные из файла
        while ((len = read_data(fin, buffer, BUFFER_SIZE)) > 0) {
            int out_len = encrypt(buffer, len, key, iv, out_buffer);
            write_data(fout, out_buffer, out_len);
        }
    } else if (strcmp(operation, "decrypt") == 0) {
        // Читаем IV из файла
        if (read_data(fin, iv, sizeof(iv)) != sizeof(iv)) {
            fprintf(stderr, "Error: Could not read IV from input file\n");
            fclose(fin);
            fclose(fout);
            return 1;
        }

        // Расшифровываем данные из файла
        while ((len = read_data(fin, buffer, BUFFER_SIZE)) > 0) {
            int out_len = decrypt(buffer, len, key, iv, out_buffer);
            write_data(fout, out_buffer, out_len);
        }
    }

    fclose(fin);
    fclose(fout);

    printf("Operation '%s' completed successfully.\n", operation);
    return 0;
}