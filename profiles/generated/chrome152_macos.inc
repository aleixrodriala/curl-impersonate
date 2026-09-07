  {
    .target = "chrome152_macos",
    .alias = "chrome152_macos",
    .httpversion = CURL_HTTP_VERSION_2_0,
    .ssl_version = CURL_SSLVERSION_TLSv1_2 | CURL_SSLVERSION_MAX_DEFAULT,
    .ciphers =
      "TLS_AES_128_GCM_SHA256:"
      "TLS_AES_256_GCM_SHA384:"
      "TLS_CHACHA20_POLY1305_SHA256:"
      "ECDHE-ECDSA-AES128-GCM-SHA256:"
      "ECDHE-RSA-AES128-GCM-SHA256:"
      "ECDHE-ECDSA-AES256-GCM-SHA384:"
      "ECDHE-RSA-AES256-GCM-SHA384:"
      "ECDHE-ECDSA-CHACHA20-POLY1305:"
      "ECDHE-RSA-CHACHA20-POLY1305:"
      "ECDHE-RSA-AES128-SHA:"
      "ECDHE-RSA-AES256-SHA:"
      "AES128-GCM-SHA256:"
      "AES256-GCM-SHA384:"
      "AES128-SHA:"
      "AES256-SHA",
    .curves = "X25519MLKEM768:X25519:P-256:P-384",
    .sig_hash_algs =
      "GREASE:"
      "mldsa44:"
      "mldsa65:"
      "mldsa87:"
      "ecdsa_secp256r1_sha256:"
      "rsa_pss_rsae_sha256:"
      "rsa_pkcs1_sha256:"
      "ecdsa_secp384r1_sha384:"
      "rsa_pss_rsae_sha384:"
      "rsa_pkcs1_sha384:"
      "rsa_pss_rsae_sha512:"
      "rsa_pkcs1_sha512",
    .http3_sig_hash_algs =
      "ecdsa_secp256r1_sha256:"
      "rsa_pss_rsae_sha256:"
      "rsa_pkcs1_sha256:"
      "ecdsa_secp384r1_sha384:"
      "rsa_pss_rsae_sha384:"
      "rsa_pkcs1_sha384:"
      "rsa_pss_rsae_sha512:"
      "rsa_pkcs1_sha512:"
      "rsa_pkcs1_sha1",
    .npn = false,
    .alpn = true,
    .alps = true,
    .tls_permute_extensions = true,
    .tls_session_ticket = true,
    .cert_compression = "brotli",
    .http_headers = {
      "sec-ch-ua: \"Chromium\";v=\"152\", \"Not?A_Brand\";v=\"24\", \"Google Chrome\";v=\"152\"",
      "sec-ch-ua-mobile: ?0",
      "sec-ch-ua-platform: \"macOS\"",
      "Upgrade-Insecure-Requests: 1",
      "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36",
      "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
      "Sec-Fetch-Site: none",
      "Sec-Fetch-Mode: navigate",
      "Sec-Fetch-User: ?1",
      "Sec-Fetch-Dest: document",
      "Accept-Encoding: gzip, deflate, br, zstd",
      "Accept-Language: en-US,en;q=0.9",
      "Priority: u=0, i"
    },
    .http2_pseudo_headers_order = "masp",
    .http2_settings = "1:65536;2:0;4:6291456;6:262144",
    .http2_window_update = 15663105,
    .http2_stream_weight = 256,
    .http2_stream_exclusive = 1,
    .http3_settings = "1:65536;6:262144;7:100;51:1;GREASE",
    .http3_pseudo_headers_order = "masp",
    .quic_cid_length = "webkit",
    .quic_transport_parameters = "1:30000;3:1472;4:15728640;5:6291456;6:6291456;7:6291456;8:100;9:103;15:;17:1@1,GREASE;32:65536;12584:0x4f524947;GREASE",
    .http3_tls_extension_order = NULL,
    .ech = "true",
    .tls_extension_order = NULL,
    .tls_use_new_alps_codepoint = true,
    .tls_signed_cert_timestamps = true,
    .tls_trust_anchors = "11129.9.1,11129.9.10,11129.9.11,11129.9.12,11129.9.13,11129.9.14,11129.9.15,11129.9.2,11129.9.3,11129.9.4,11129.9.5,11129.9.6,11129.9.7,11129.9.8,11129.9.9,44947.2.1,44947.2.13,44947.2.14,44947.2.15,44947.2.18,44947.2.19,44947.2.20,44947.2.6,52580.200109.1.10,52580.200109.1.11,52580.200109.1.12,52580.200109.1.13,52580.200109.1.18,52580.200109.1.19,52580.200109.1.7,52580.200109.1.8,52580.200109.1.9",
    .http3_tls_trust_anchors = "11129.9.1,11129.9.10,11129.9.11,11129.9.12,11129.9.13,11129.9.14,11129.9.15,11129.9.2,11129.9.3,11129.9.4,11129.9.5,11129.9.6,11129.9.7,11129.9.8,11129.9.9,44947.2.1,44947.2.13,44947.2.14,44947.2.15,44947.2.18,44947.2.19,44947.2.20,44947.2.6,52580.200109.1.10,52580.200109.1.11,52580.200109.1.12,52580.200109.1.13,52580.200109.1.18,52580.200109.1.19,52580.200109.1.7,52580.200109.1.8,52580.200109.1.9",
    .http3_disable_tls_signed_cert_timestamps = true,
    .http3_disable_tls_status_request = true,
    .tls_grease = true,
    .split_cookies = true,
    .form_boundary = "webkit",
  },
