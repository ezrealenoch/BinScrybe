/**
 * Test sample for BinScrybe
 * 
 * This is a harmless sample program with a few capabilities
 * that should be detected by CAPA.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#endif

// Simple XOR encryption
void xor_encrypt(char *data, size_t size, char key) {
    for (size_t i = 0; i < size; i++) {
        data[i] = data[i] ^ key;
    }
}

// Registry access function (Windows only)
#ifdef _WIN32
void check_registry() {
    HKEY hKey;
    LONG result;
    
    // Try to open a registry key
    result = RegOpenKeyEx(
        HKEY_CURRENT_USER,
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        0,
        KEY_READ,
        &hKey
    );
    
    if (result == ERROR_SUCCESS) {
        printf("Successfully opened Run registry key\n");
        RegCloseKey(hKey);
    } else {
        printf("Failed to open registry key\n");
    }
}
#endif

// Create a file
void create_file() {
    FILE *f = fopen("test_output.txt", "w");
    if (f) {
        fprintf(f, "This is a test file created by the BinScrybe test sample.\n");
        fclose(f);
        printf("Created test_output.txt\n");
    } else {
        printf("Failed to create file\n");
    }
}

// Main function
int main(int argc, char *argv[]) {
    printf("BinScrybe Test Sample\n");
    printf("---------------------\n");
    
    // 1. Demonstrate some string encryption
    char message[] = "This message will be encrypted with XOR";
    size_t message_len = strlen(message);
    
    printf("Original message: %s\n", message);
    
    // XOR encrypt with key 0x41 ('A')
    xor_encrypt(message, message_len, 0x41);
    printf("Encrypted message: ");
    for (size_t i = 0; i < message_len; i++) {
        printf("%02X ", (unsigned char)message[i]);
    }
    printf("\n");
    
    // Decrypt
    xor_encrypt(message, message_len, 0x41);
    printf("Decrypted message: %s\n\n", message);
    
    // 2. Create a file
    create_file();
    
    // 3. Access registry (Windows only)
    #ifdef _WIN32
    check_registry();
    #endif
    
    // 4. Sleep for a moment
    printf("\nSleeping for 2 seconds...\n");
    #ifdef _WIN32
    Sleep(2000);
    #else
    sleep(2);
    #endif
    
    printf("\nExecution complete!\n");
    return 0;
} 