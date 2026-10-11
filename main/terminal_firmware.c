
#include <string.h>
#include <stdint.h>
#include "esp_log.h"
#include "esp_heap_caps.h"
#include "esp_random.h"
#include "esp_mac.h"
#include "driver/uart.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "psa/crypto.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/pk.h"
#include "mbedtls/platform_util.h"
#include "root_ca_cert.h"
#include "esp_hmac.h"
#include "nvs_flash.h"
#include "nvs.h"

static const char *TAG = "TERMINAL";

#define UART_PORT           UART_NUM_0
#define UART_BUF_SIZE       1024
#define NONCE_LEN           32
#define CHALLENGE_LEN       32
#define MAC_LEN             6
#define UART_TIMEOUT_MS     200
#define FAIL_THRESHOLD      3
#define BACKOFF_MS          60000
#define SCHEMA_PAYPROOF     0x01
#define SCHEMA_PAYPROOF_LEN 6

/* PSA ECDSA P-256 signature output size: 2 * 32 bytes raw r||s */
/* Fixed message HMAC'd by eFuse-bound HMAC_KEY4 to derive device root R (hardware-rooted, not extractable) */
static const uint8_t DEVICE_ROOT_HMAC_MESSAGE[] = "PayProof-Terminal-v2.3-DeviceRoot-R";

/* RAM-only fail counter — Blueprint v2.3: never written to NVS */
static volatile int fail_counter = 0;

/* READY marker: sent while idle so the gateway knows when to start */
static const uint8_t READY_MARKER[8] = { 0xA5, 'P', 'P', 'R', 'D', 'Y', 0x5A, 0x0A };

/* ── UART helpers ── */
static int uart_recv_exact(uint8_t *buf, int len, int timeout_ms)
{
    int received = 0;
    TickType_t deadline = xTaskGetTickCount() + pdMS_TO_TICKS(timeout_ms);
    while (received < len) {
        if (xTaskGetTickCount() > deadline) {
            ESP_LOGW(TAG, "UART timeout %d/%d", received, len);
            return -1;
        }
        int r = uart_read_bytes(UART_PORT, buf + received,
                                len - received, pdMS_TO_TICKS(5));
        if (r > 0) received += r;
    }
    return received;
}

static int uart_recv_length_prefixed(uint8_t *buf, int max_len, int timeout_ms)
{
    uint8_t lb[2];
    if (uart_recv_exact(lb, 2, timeout_ms) < 0) return -1;
    int n = ((int)lb[0] << 8) | lb[1];
    if (n <= 0 || n > max_len) {
        ESP_LOGE(TAG, "Bad length prefix: %d", n);
        return -1;
    }
    if (uart_recv_exact(buf, n, timeout_ms) < 0) return -1;
    return n;
}

static void uart_send_raw(const uint8_t *buf, int len)
{
    uart_write_bytes(UART_PORT, (const char *)buf, len);
}

static void uart_send_length_prefixed(const uint8_t *buf, int len)
{
    uint8_t prefix[2] = { (uint8_t)((len >> 8) & 0xFF), (uint8_t)(len & 0xFF) };
    uart_write_bytes(UART_PORT, (const char *)prefix, 2);
    uart_write_bytes(UART_PORT, (const char *)buf, len);
}

/* ── DISCARD protocol — Blueprint v2.3 ── */
static void discard(const char *reason,
                    uint8_t *b1, int l1,
                    uint8_t *b2, int l2)
{
    ESP_LOGW(TAG, "[DISCARD] %s", reason);
    uart_flush(UART_PORT);
    if (b1 && l1 > 0) mbedtls_platform_zeroize(b1, l1);
    if (b2 && l2 > 0) mbedtls_platform_zeroize(b2, l2);
    fail_counter++;
    ESP_LOGW(TAG, "[DISCARD] fail_counter=%d/%d", fail_counter, FAIL_THRESHOLD);
    if (fail_counter >= FAIL_THRESHOLD) {
        ESP_LOGE(TAG, "[SLEEP] Backoff %dms — RAM counter persists", BACKOFF_MS);
        vTaskDelay(pdMS_TO_TICKS(BACKOFF_MS));
    }
}

/* ── Main handshake ── */
static void run_handshake(void)
{
    psa_status_t psa_ret;
    int ret;

    static uint8_t cert_buf[512];
    static uint8_t gateway_nonce[NONCE_LEN];
    static uint8_t terminal_challenge[CHALLENGE_LEN];
    static uint8_t gw_sig_buf[128];
    static uint8_t record_buf[600];
    static uint8_t sig_buf[64];

    mbedtls_x509_crt gateway_cert;
    mbedtls_x509_crt root_cert;
    mbedtls_x509_crt_init(&gateway_cert);
    mbedtls_x509_crt_init(&root_cert);

    psa_key_id_t key_id = PSA_KEY_ID_NULL;

    /* ── Step 1: Receive cert (length-prefixed) + nonce (raw 32 bytes) ── */
    ESP_LOGI(TAG, "[STATE] IDLE -> waiting for cert+nonce");

    int cert_len = uart_recv_length_prefixed(cert_buf, sizeof(cert_buf),
                                              UART_TIMEOUT_MS * 20);
    if (cert_len <= 0) {
        discard("Timeout on certificate", gateway_nonce, NONCE_LEN, NULL, 0);
        goto cleanup;
    }
    if (uart_recv_exact(gateway_nonce, NONCE_LEN, UART_TIMEOUT_MS) < 0) {
        discard("Timeout on nonce", gateway_nonce, NONCE_LEN, NULL, 0);
        goto cleanup;
    }
    ESP_LOGI(TAG, "[RX] Cert=%d bytes nonce=32 bytes", cert_len);

    /* ── Step 2: Verify gateway certificate against Root CA ── */
    ret = mbedtls_x509_crt_parse_der(&root_cert, ROOT_CA_CERT, ROOT_CA_CERT_len);
    if (ret != 0) {
        discard("Root CA parse failed", gateway_nonce, NONCE_LEN, NULL, 0);
        goto cleanup;
    }
    ret = mbedtls_x509_crt_parse_der(&gateway_cert, cert_buf, cert_len);
    if (ret != 0) {
        ESP_LOGE(TAG, "Cert parse: -0x%04x", -ret);
        discard("Gateway cert parse failed", gateway_nonce, NONCE_LEN, NULL, 0);
        goto cleanup;
    }
    uint32_t verify_flags = 0;
    ret = mbedtls_x509_crt_verify(&gateway_cert, &root_cert,
                                   NULL, NULL, &verify_flags, NULL, NULL);
    if (ret != 0 || verify_flags != 0) {
        ESP_LOGE(TAG, "Cert verify FAILED: -0x%04x flags=0x%08x", -ret, verify_flags);
        discard("Gateway cert invalid", gateway_nonce, NONCE_LEN, NULL, 0);
        goto cleanup;
    }
    ESP_LOGI(TAG, "[CHECK] Gateway cert verified: OK");

    /* ── Step 3: Generate and send Terminal_Challenge ── */
    esp_fill_random(terminal_challenge, CHALLENGE_LEN);
    uart_send_raw(terminal_challenge, CHALLENGE_LEN);
    ESP_LOGI(TAG, "[TX] Terminal_Challenge sent");

    /* ── Step 4: Receive gateway signature ── */
    int gw_sig_len = uart_recv_length_prefixed(gw_sig_buf, sizeof(gw_sig_buf),
                                                UART_TIMEOUT_MS * 8);
    if (gw_sig_len <= 0) {
        discard("Timeout on gateway signature",
                gateway_nonce, NONCE_LEN, terminal_challenge, CHALLENGE_LEN);
        goto cleanup;
    }
    ESP_LOGI(TAG, "[RX] Gateway sig: %d bytes", gw_sig_len);

    /* ── Step 5: Verify gateway proof-of-possession ── */
    /* Hash the challenge via PSA */
    uint8_t challenge_hash[32];
    size_t  hash_len = 0;
    psa_ret = psa_hash_compute(PSA_ALG_SHA_256,
                                terminal_challenge, CHALLENGE_LEN,
                                challenge_hash, sizeof(challenge_hash),
                                &hash_len);
    if (psa_ret != PSA_SUCCESS) {
        discard("Challenge hash failed",
                gateway_nonce, NONCE_LEN, terminal_challenge, CHALLENGE_LEN);
        goto cleanup;
    }

    /* Verify using gateway cert public key via mbedtls pk */
    ret = mbedtls_pk_verify(&gateway_cert.pk, MBEDTLS_MD_SHA256,
                             challenge_hash, hash_len,
                             gw_sig_buf, gw_sig_len);
    mbedtls_platform_zeroize(challenge_hash, sizeof(challenge_hash));

    if (ret != 0) {
        ESP_LOGE(TAG, "Gateway sig verify FAILED: -0x%04x", -ret);
        discard("Gateway proof-of-possession failed",
                gateway_nonce, NONCE_LEN, terminal_challenge, CHALLENGE_LEN);
        goto cleanup;
    }
    ESP_LOGI(TAG, "[CHECK] Gateway proof-of-possession: OK");

    /* Free cert contexts immediately after use — Blueprint v2.3 mandatory */
    mbedtls_x509_crt_free(&gateway_cert);
    mbedtls_x509_crt_free(&root_cert);
    mbedtls_x509_crt_init(&gateway_cert);
    mbedtls_x509_crt_init(&root_cert);
    /* ── Step 6: Derive hardware-rooted device R via eFuse HMAC_KEY4 ── */
    /* ── Step 6: Import mock root R as PSA key ── */
    uint8_t device_root_r[32];
    esp_err_t hmac_ret = esp_hmac_calculate(HMAC_KEY4, DEVICE_ROOT_HMAC_MESSAGE, sizeof(DEVICE_ROOT_HMAC_MESSAGE) - 1, device_root_r);
    if (hmac_ret != ESP_OK) {
        ESP_LOGE(TAG, "eFuse HMAC calculation failed: %d", (int)hmac_ret);
        discard("Hardware root key derivation failed", gateway_nonce, NONCE_LEN, NULL, 0);
        goto cleanup;
    }

    psa_key_attributes_t key_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&key_attr,
                     PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&key_attr, 256);
    psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_SIGN_HASH);
    psa_set_key_algorithm(&key_attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));

    psa_ret = psa_import_key(&key_attr, device_root_r, 32, &key_id);
    mbedtls_platform_zeroize(device_root_r, 32);

    if (psa_ret != PSA_SUCCESS) {
        ESP_LOGE(TAG, "PSA key import failed: %d", (int)psa_ret);
        discard("Key import failed", gateway_nonce, NONCE_LEN, NULL, 0);
        goto cleanup;
    }
    ESP_LOGI(TAG, "[CRYPTO] Terminal key imported");

    /* ── Step 7: Build outer envelope ── */
    uint8_t terminal_id[MAC_LEN];
    esp_read_mac(terminal_id, ESP_MAC_WIFI_STA);

    uint32_t amount        = 5000;  /* KES 50.00 */
    uint8_t  currency      = 0x01;  /* KES */
    uint32_t efuse_counter = 1;
    nvs_handle_t nvs_h;
    if (nvs_open("payproof", NVS_READWRITE, &nvs_h) == ESP_OK) {
        esp_err_t gret = nvs_get_u32(nvs_h, "tx_counter", &efuse_counter);
        if (gret == ESP_ERR_NVS_NOT_FOUND) {
            efuse_counter = 1;
        }
        uint32_t next_counter = efuse_counter + 1;
        nvs_set_u32(nvs_h, "tx_counter", next_counter);
        nvs_commit(nvs_h);
        nvs_close(nvs_h);
        ESP_LOGI(TAG, "[COUNTER] tx_counter=%u (next=%u)", (unsigned)efuse_counter, (unsigned)next_counter);
    } else {
        ESP_LOGE(TAG, "[COUNTER] NVS open failed, using fallback counter");
    }
    uint64_t timestamp     = 0;     /* PoC: zero */

    uint8_t envelope[256];
    int     off = 0;

    memcpy(envelope + off, terminal_id, MAC_LEN);      off += MAC_LEN;
    memcpy(envelope + off, gateway_nonce, NONCE_LEN);  off += NONCE_LEN;
    envelope[off++] = (SCHEMA_PAYPROOF_LEN >> 8) & 0xFF;
    envelope[off++] = (SCHEMA_PAYPROOF_LEN)      & 0xFF;
    envelope[off++] = SCHEMA_PAYPROOF;
    envelope[off++] = (amount >> 24) & 0xFF;
    envelope[off++] = (amount >> 16) & 0xFF;
    envelope[off++] = (amount >>  8) & 0xFF;
    envelope[off++] = (amount)       & 0xFF;
    envelope[off++] = currency;
    envelope[off++] = (efuse_counter >> 24) & 0xFF;
    envelope[off++] = (efuse_counter >> 16) & 0xFF;
    envelope[off++] = (efuse_counter >>  8) & 0xFF;
    envelope[off++] = (efuse_counter)        & 0xFF;
    for (int i = 7; i >= 0; i--) {
        envelope[off++] = (uint8_t)((timestamp >> (i * 8)) & 0xFF);
    }
    int envelope_len = off;

    /* ── Step 8: Hash envelope via PSA ── */
    uint8_t env_hash[32];
    size_t  env_hash_len = 0;
    psa_ret = psa_hash_compute(PSA_ALG_SHA_256,
                                envelope, envelope_len,
                                env_hash, sizeof(env_hash),
                                &env_hash_len);
    if (psa_ret != PSA_SUCCESS) {
        psa_destroy_key(key_id);
        key_id = PSA_KEY_ID_NULL;
        discard("Envelope hash failed", gateway_nonce, NONCE_LEN, NULL, 0);
        goto cleanup;
    }

    /* ── Step 9: PSA ECDSA sign ── */
    size_t sig_len = 0;
    psa_ret = psa_sign_hash(key_id,
                             PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                             env_hash, env_hash_len,
                             sig_buf, sizeof(sig_buf),
                             &sig_len);
    mbedtls_platform_zeroize(env_hash, sizeof(env_hash));

    psa_destroy_key(key_id);
    key_id = PSA_KEY_ID_NULL;

    if (psa_ret != PSA_SUCCESS) {
        ESP_LOGE(TAG, "PSA sign failed: %d", (int)psa_ret);
        discard("Signing failed", gateway_nonce, NONCE_LEN, NULL, 0);
        goto cleanup;
    }
    ESP_LOGI(TAG, "[CRYPTO] Payload signed (%d bytes)", (int)sig_len);

    /* ── Step 10: Send sealed record = envelope || signature ── */
    int record_len = envelope_len + (int)sig_len;
    memcpy(record_buf, envelope, envelope_len);
    memcpy(record_buf + envelope_len, sig_buf, sig_len);

    uart_send_length_prefixed(record_buf, record_len);

    mbedtls_platform_zeroize(record_buf, record_len);
    mbedtls_platform_zeroize(gateway_nonce, NONCE_LEN);
    mbedtls_platform_zeroize(terminal_challenge, CHALLENGE_LEN);
    mbedtls_platform_zeroize(sig_buf, sig_len);

    fail_counter = 0;
    ESP_LOGI(TAG, "[RECORD_SENT] Sealed record sent. fail_counter reset.");

cleanup:
    mbedtls_x509_crt_free(&gateway_cert);
    mbedtls_x509_crt_free(&root_cert);
    if (key_id != PSA_KEY_ID_NULL) psa_destroy_key(key_id);
}

/* ── app_main ── */
void app_main(void)
{
    ESP_LOGI(TAG, "PayProof Terminal v2.3 PoC");
    ESP_LOGI(TAG, "Internal heap: %u bytes",
             (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL));

    esp_err_t nvs_ret = nvs_flash_init();
    if (nvs_ret == ESP_ERR_NVS_NO_FREE_PAGES || nvs_ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_LOGW(TAG, "NVS needs erase, reinitializing");
        ESP_ERROR_CHECK(nvs_flash_erase());
        nvs_ret = nvs_flash_init();
    }
    if (nvs_ret != ESP_OK) {
        ESP_LOGE(TAG, "NVS init failed: %d", (int)nvs_ret);
        return;
    }
    ESP_LOGI(TAG, "NVS ready");
    psa_status_t psa_ret = psa_crypto_init();
    if (psa_ret != PSA_SUCCESS) {
        ESP_LOGE(TAG, "psa_crypto_init failed: %d", (int)psa_ret);
        return;
    }
    ESP_LOGI(TAG, "PSA crypto ready");

    uart_config_t uart_cfg = {
        .baud_rate  = 115200,
        .data_bits  = UART_DATA_8_BITS,
        .parity     = UART_PARITY_DISABLE,
        .stop_bits  = UART_STOP_BITS_1,
        .flow_ctrl  = UART_HW_FLOWCTRL_DISABLE,
    };
    uart_driver_install(UART_PORT, UART_BUF_SIZE * 2, 0, 0, NULL, 0);
    uart_param_config(UART_PORT, &uart_cfg);
    uart_set_pin(UART_PORT, 43, 44, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE);
    ESP_LOGI(TAG, "UART0 ready at 115200. Waiting for gateway...");

    while (1) {
        uint8_t init_byte;
        uart_flush_input(UART_PORT);
        uart_write_bytes(UART_PORT, (const char *)READY_MARKER, sizeof(READY_MARKER));
        int r = uart_read_bytes(UART_PORT, &init_byte, 1, pdMS_TO_TICKS(2000));
        if (r > 0 && init_byte == 0x01) {
            ESP_LOGI(TAG, "Gateway initiation. Starting handshake.");
            run_handshake();
        }
    }
}
