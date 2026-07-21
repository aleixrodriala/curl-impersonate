  {
    .target = "safari265_ios",
    .alias = "safari265_ios",
    .httpversion = CURL_HTTP_VERSION_2_0,
    .ssl_version = CURL_SSLVERSION_TLSv1_2 | CURL_SSLVERSION_MAX_DEFAULT,
    .ciphers =
      "TLS_AES_256_GCM_SHA384:"
      "TLS_CHACHA20_POLY1305_SHA256:"
      "TLS_AES_128_GCM_SHA256:"
      "ECDHE-ECDSA-AES256-GCM-SHA384:"
      "ECDHE-ECDSA-AES128-GCM-SHA256:"
      "ECDHE-ECDSA-CHACHA20-POLY1305:"
      "ECDHE-RSA-AES256-GCM-SHA384:"
      "ECDHE-RSA-AES128-GCM-SHA256:"
      "ECDHE-RSA-CHACHA20-POLY1305:"
      "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:"
      "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:"
      "ECDHE-RSA-AES256-SHA:"
      "ECDHE-RSA-AES128-SHA:"
      "AES256-GCM-SHA384:"
      "AES128-GCM-SHA256:"
      "AES256-SHA:"
      "AES128-SHA:"
      "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA:"
      "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:"
      "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    .curves = "X25519MLKEM768:X25519:P-256:P-384:P-521",
    .sig_hash_algs =
      "ecdsa_secp256r1_sha256:"
      "rsa_pss_rsae_sha256:"
      "rsa_pkcs1_sha256:"
      "ecdsa_secp384r1_sha384:"
      "rsa_pss_rsae_sha384:"
      "rsa_pss_rsae_sha384:"
      "rsa_pkcs1_sha384:"
      "rsa_pss_rsae_sha512:"
      "rsa_pkcs1_sha512:"
      "rsa_pkcs1_sha1",
    .npn = false,
    .alpn = true,
    .alps = false,
    .tls_permute_extensions = false,
    .tls_session_ticket = false,
    .cert_compression = "zlib",
    .http_headers = {
      "Sec-Fetch-Dest: document",
      "User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.5 Mobile/15E148 Safari/604.1",
      "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      "Sec-Fetch-Site: none",
      "Sec-Fetch-Mode: navigate",
      "Accept-Language: en-US,en;q=0.9",
      "Priority: u=0, i",
      "Accept-Encoding: gzip, deflate, br, zstd"
    },
    .http2_pseudo_headers_order = "msap",
    .http2_settings = "2:0;3:100;4:2097152;9:1",
    .http2_window_update = 10420225,
    .http2_stream_weight = 0,
    .http2_stream_exclusive = 0,
    .http2_no_priority = true,
    .ech = "false",
    .tls_extension_order = "0-23-65281-10-11-16-5-13-18-51-45-43-27",
    .tls_use_new_alps_codepoint = false,
    .tls_signed_cert_timestamps = true,
    .tls_grease = true,
    .split_cookies = true,
    .form_boundary = "webkit",
  },
