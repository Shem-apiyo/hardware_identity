idf_component_register(SRCS "terminal_firmware.c"
                       INCLUDE_DIRS "."
                       REQUIRES driver esp_driver_uart esp_security nvs_flash mbedtls esp_hw_support)
