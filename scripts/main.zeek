# Use the SSL::ssl_extension() event to route raw bytes to parsing functions based on the extension's code.
# Parsing this way is likely a bad idea.

module SSL::EXTENSIONS;

export {

  global names: table [count] of string = {
    [0] = "server_name",
    [1] = "max_fragment_length",
    [2] = "client_certificate_url",
    [3] = "trusted_ca_keys",
    [4] = "truncated_hmac",
    [5] = "status_request",
    [6] = "user_mapping",
    [7] = "client_authz",
    [8] = "server_authz",
    [9] = "cert_type",
    [10] = "supported_groups",
    [11] = "ec_point_formats",
    [12] = "srp",
    [13] = "signature_algorithms",
    [14] = "use_srtp",
    [15] = "heartbeat",
    [16] = "application_layer_protocol_negotiation",
    [17] = "status_request_v2",
    [18] = "signed_certificate_timestamp",
    [19] = "client_certificate_type",
    [20] = "server_certificate_type",
    [21] = "padding",
    [22] = "encrypt_then_mac",
    [23] = "extended_master_secret",
    [24] = "token_binding",
    [25] = "cached_info",
    [26] = "tls_lts",
    [27] = "compress_certificate",
    [28] = "record_size_limit",
    [29] = "pwd_protect",
    [30] = "pwd_clear",
    [31] = "password_salt",
    [32] = "ticket_pinning",
    [33] = "tls_cert_with_extern_psk",
    [34] = "delegated_credential",
    [35] = "session_ticket",
    [36] = "TLMSP",
    [37] = "TLMSP_proxying",
    [38] = "TLMSP_delegate",
    [39] = "supported_ekt_ciphers",
    [40] = "key_share_reserved",
    [41] = "pre_shared_key",
    [42] = "early_data",
    [43] = "supported_versions",
    [44] = "cookie",
    [45] = "psk_key_exchange_modes",
    # 46 is reserved
    [47] = "certificate_authorities",
    [48] = "oid_filters",
    [49] = "post_handshake_auth",
    [50] = "signature_algorithms_cert",
    [51] = "key_share",
    [52] = "transparency_info",
    [53] = "connection_id_deprecated",
    [54] = "connection_id",
    [55] = "external_id_hash",
    [56] = "external_session_id",
    [57] = "quic_transport_parameters",
    [58] = "ticket_request",
    [59] = "dnssec_chain",
    [60] = "sequence_number_encryption_algorithms",
    [61] = "rrc",
    [2570] = "grease",
    [6682] = "grease",
    [10794] = "grease",
    [14906] = "grease",
    [19018] = "grease",
    [23130] = "grease",
    [27242] = "grease",
    [31354] = "grease",
    [35466] = "grease",
    [39578] = "grease",
    [43690] = "grease",
    [47802] = "grease",
    [51914] = "grease",
    [56026] = "grease",
    [60138] = "grease",
    [64250] = "grease",
    [64768] = "ech_outer_extensions",
    [65037] = "encrypted_client_hello",
    [65281] = "renegotiation_info"
  };
}

event ssl_extension(c: connection, is_client: bool, code: count, val: string) {
  if (code !in SSL::EXTENSIONS::names) {
    return;
  }
  local result: any;
  switch SSL::EXTENSIONS::names[code] {
    case "TLMSP":
      result = (parse_ssl_extension_TLMSP(val) as ParseResult_TLMSP);
      event SSL::EXTENSIONS::ssl_extension_TLMSP(c, is_client, result);
      break;
    case "TLMSP_delegate":
      result = (parse_ssl_extension_TLMSP_delegate(val) as ParseResult_TLMSP_delegate);
      event SSL::EXTENSIONS::ssl_extension_TLMSP_delegate(c, is_client, result);
      break;
    case "TLMSP_proxying":
      result = (parse_ssl_extension_TLMSP_proxying(val) as ParseResult_TLMSP_proxying);
      event SSL::EXTENSIONS::ssl_extension_TLMSP_proxying(c, is_client, result);
      break;
    case "application_layer_protocol_negotiation":
      result = (parse_ssl_extension_application_layer_protocol_negotiation(val) as ParseResult_application_layer_protocol_negotiation);
      event SSL::EXTENSIONS::ssl_extension_application_layer_protocol_negotiation(c, is_client, result);
      break;
    case "cached_info":
      result = (parse_ssl_extension_cached_info(val) as ParseResult_cached_info);
      event SSL::EXTENSIONS::ssl_extension_cached_info(c, is_client, result);
      break;
    case "cert_type":
      result = (parse_ssl_extension_cert_type(val) as ParseResult_cert_type);
      event SSL::EXTENSIONS::ssl_extension_cert_type(c, is_client, result);
      break;
    case "certificate_authorities":
      result = (parse_ssl_extension_certificate_authorities(val) as ParseResult_certificate_authorities);
      event SSL::EXTENSIONS::ssl_extension_certificate_authorities(c, is_client, result);
      break;
    case "client_authz":
      result = (parse_ssl_extension_client_authz(val) as ParseResult_client_authz);
      event SSL::EXTENSIONS::ssl_extension_client_authz(c, is_client, result);
      break;
    case "client_certificate_type":
      result = (parse_ssl_extension_client_certificate_type(val) as ParseResult_client_certificate_type);
      event SSL::EXTENSIONS::ssl_extension_client_certificate_type(c, is_client, result);
      break;
    case "client_certificate_url":
      result = (parse_ssl_extension_client_certificate_url(val) as ParseResult_client_certificate_url);
      event SSL::EXTENSIONS::ssl_extension_client_certificate_url(c, is_client, result);
      break;
    case "compress_certificate":
      result = (parse_ssl_extension_compress_certificate(val) as ParseResult_compress_certificate);
      event SSL::EXTENSIONS::ssl_extension_compress_certificate(c, is_client, result);
      break;
    case "connection_id":
      result = (parse_ssl_extension_connection_id(val) as ParseResult_connection_id);
      event SSL::EXTENSIONS::ssl_extension_connection_id(c, is_client, result);
      break;
    case "connection_id_deprecated":
      result = (parse_ssl_extension_connection_id_deprecated(val) as ParseResult_connection_id_deprecated);
      event SSL::EXTENSIONS::ssl_extension_connection_id_deprecated(c, is_client, result);
      break;
    case "cookie":
      result = (parse_ssl_extension_cookie(val) as ParseResult_cookie);
      event SSL::EXTENSIONS::ssl_extension_cookie(c, is_client, result);
      break;
    case "delegated_credential":
      result = (parse_ssl_extension_delegated_credential(val) as ParseResult_delegated_credential);
      event SSL::EXTENSIONS::ssl_extension_delegated_credential(c, is_client, result);
      break;
    case "dnssec_chain":
      result = (parse_ssl_extension_dnssec_chain(val) as ParseResult_dnssec_chain);
      event SSL::EXTENSIONS::ssl_extension_dnssec_chain(c, is_client, result);
      break;
    case "early_data":
      result = (parse_ssl_extension_early_data(val) as ParseResult_early_data);
      event SSL::EXTENSIONS::ssl_extension_early_data(c, is_client, result);
      break;
    case "ec_point_formats":
      result = (parse_ssl_extension_ec_point_formats(val) as ParseResult_ec_point_formats);
      event SSL::EXTENSIONS::ssl_extension_ec_point_formats(c, is_client, result);
      break;
    case "ech_outer_extensions":
      result = (parse_ssl_extension_ech_outer_extensions(val) as ParseResult_ech_outer_extensions);
      event SSL::EXTENSIONS::ssl_extension_ech_outer_extensions(c, is_client, result);
      break;
    case "encrypt_then_mac":
      result = (parse_ssl_extension_encrypt_then_mac(val) as ParseResult_encrypt_then_mac);
      event SSL::EXTENSIONS::ssl_extension_encrypt_then_mac(c, is_client, result);
      break;
    case "encrypted_client_hello":
      result = (parse_ssl_extension_encrypted_client_hello(val) as ParseResult_encrypted_client_hello);
      event SSL::EXTENSIONS::ssl_extension_encrypted_client_hello(c, is_client, result);
      break;
    case "extended_master_secret":
      result = (parse_ssl_extension_extended_master_secret(val) as ParseResult_extended_master_secret);
      event SSL::EXTENSIONS::ssl_extension_extended_master_secret(c, is_client, result);
      break;
    case "external_id_hash":
      result = (parse_ssl_extension_external_id_hash(val) as ParseResult_external_id_hash);
      event SSL::EXTENSIONS::ssl_extension_external_id_hash(c, is_client, result);
      break;
    case "external_session_id":
      result = (parse_ssl_extension_external_session_id(val) as ParseResult_external_session_id);
      event SSL::EXTENSIONS::ssl_extension_external_session_id(c, is_client, result);
      break;
    case "grease":
      result = (parse_ssl_extension_grease(val, code) as ParseResult_grease);
      event SSL::EXTENSIONS::ssl_extension_grease(c, is_client, result);
      break;
    case "heartbeat":
      result = (parse_ssl_extension_heartbeat(val) as ParseResult_heartbeat);
      event SSL::EXTENSIONS::ssl_extension_heartbeat(c, is_client, result);
      break;
    case "key_share":
      result = (parse_ssl_extension_key_share(val, is_client) as ParseResult_key_share);
      event SSL::EXTENSIONS::ssl_extension_key_share(c, is_client, result);
      break;
    case "key_share_reserved":
      result = (parse_ssl_extension_key_share(val, is_client) as ParseResult_key_share);
      event SSL::EXTENSIONS::ssl_extension_key_share_reserved(c, is_client, result);
      break;
    case "max_fragment_length":
      result = (parse_ssl_extension_max_fragment_length(val) as ParseResult_max_fragment_length);
      event SSL::EXTENSIONS::ssl_extension_max_fragment_length(c, is_client, result);
      break;
    case "oid_filters":
      result = (parse_ssl_extension_oid_filters(val) as ParseResult_oid_filters);
      event SSL::EXTENSIONS::ssl_extension_oid_filters(c, is_client, result);
      break;
    case "padding":
      result = (parse_ssl_extension_padding(val) as ParseResult_padding);
      event SSL::EXTENSIONS::ssl_extension_padding(c, is_client, result);
      break;
    case "password_salt":
      result = (parse_ssl_extension_password_salt(val) as ParseResult_password_salt);
      event SSL::EXTENSIONS::ssl_extension_password_salt(c, is_client, result);
      break;
    case "post_handshake_auth":
      result = (parse_ssl_extension_post_handshake_auth(val) as ParseResult_post_handshake_auth);
      event SSL::EXTENSIONS::ssl_extension_post_handshake_auth(c, is_client, result);
      break;
    case "pre_shared_key":
      result = (parse_ssl_extension_pre_shared_key(val, is_client) as ParseResult_pre_shared_key);
      event SSL::EXTENSIONS::ssl_extension_pre_shared_key(c, is_client, result);
      break;
    case "psk_key_exchange_modes":
      result = (parse_ssl_extension_psk_key_exchange_modes(val) as ParseResult_psk_key_exchange_modes);
      event SSL::EXTENSIONS::ssl_extension_psk_key_exchange_modes(c, is_client, result);
      break;
    case "pwd_clear":
      result = (parse_ssl_extension_pwd_clear(val) as ParseResult_pwd_clear);
      event SSL::EXTENSIONS::ssl_extension_pwd_clear(c, is_client, result);
      break;
    case "pwd_protect":
      result = (parse_ssl_extension_pwd_protect(val) as ParseResult_pwd_protect);
      event SSL::EXTENSIONS::ssl_extension_pwd_protect(c, is_client, result);
      break;
    case "quic_transport_parameters":
      result = (parse_ssl_extension_quic_transport_parameters(val) as ParseResult_quic_transport_parameters);
      event SSL::EXTENSIONS::ssl_extension_quic_transport_parameters(c, is_client, result);
      break;
    case "record_size_limit":
      result = (parse_ssl_extension_record_size_limit(val) as ParseResult_record_size_limit);
      event SSL::EXTENSIONS::ssl_extension_record_size_limit(c, is_client, result);
      break;
    case "renegotiation_info":
      result = (parse_ssl_extension_renegotiation_info(val) as ParseResult_renegotiation_info);
      event SSL::EXTENSIONS::ssl_extension_renegotiation_info(c, is_client, result);
      break;
    case "rrc":
      result = (parse_ssl_extension_rrc(val) as ParseResult_rrc);
      event SSL::EXTENSIONS::ssl_extension_rrc(c, is_client, result);
      break;
    case "sequence_number_encryption_algorithms":
      result = (parse_ssl_extension_sequence_number_encryption_algorithms(val) as ParseResult_sequence_number_encryption_algorithms);
      event SSL::EXTENSIONS::ssl_extension_sequence_number_encryption_algorithms(c, is_client, result);
      break;
    case "server_authz":
      result = (parse_ssl_extension_server_authz(val) as ParseResult_server_authz);
      event SSL::EXTENSIONS::ssl_extension_server_authz(c, is_client, result);
      break;
    case "server_certificate_type":
      result = (parse_ssl_extension_server_certificate_type(val) as ParseResult_server_certificate_type);
      event SSL::EXTENSIONS::ssl_extension_server_certificate_type(c, is_client, result);
      break;
    case "server_name":
      result = (parse_ssl_extension_server_name(val) as ParseResult_server_name);
      event SSL::EXTENSIONS::ssl_extension_server_name(c, is_client, result);
      break;
    case "session_ticket":
      result = (parse_ssl_extension_session_ticket(val) as ParseResult_session_ticket);
      event SSL::EXTENSIONS::ssl_extension_session_ticket(c, is_client, result);
      break;
    case "signature_algorithms":
      result = (parse_ssl_extension_signature_algorithms(val) as ParseResult_signature_algorithms);
      event SSL::EXTENSIONS::ssl_extension_signature_algorithms(c, is_client, result);
      break;
    case "signature_algorithms_cert":
      result = (parse_ssl_extension_signature_algorithms_cert(val) as ParseResult_signature_algorithms_cert);
      event SSL::EXTENSIONS::ssl_extension_signature_algorithms_cert(c, is_client, result);
      break;
    case "signed_certificate_timestamp":
      result = (parse_ssl_extension_signed_certificate_timestamp(val) as ParseResult_signed_certificate_timestamp);
      event SSL::EXTENSIONS::ssl_extension_signed_certificate_timestamp(c, is_client, result);
      break;
    case "srp":
      result = (parse_ssl_extension_srp(val) as ParseResult_srp);
      event SSL::EXTENSIONS::ssl_extension_srp(c, is_client, result);
      break;
    case "status_request":
      result = (parse_ssl_extension_status_request(val) as ParseResult_status_request);
      event SSL::EXTENSIONS::ssl_extension_status_request(c, is_client, result);
      break;
    case "status_request_v2":
      result = (parse_ssl_extension_status_request_v2(val) as ParseResult_status_request_v2);
      event SSL::EXTENSIONS::ssl_extension_status_request_v2(c, is_client, result);
      break;
    case "supported_ekt_ciphers":
      result = (parse_ssl_extension_supported_ekt_ciphers(val) as ParseResult_supported_ekt_ciphers);
      event SSL::EXTENSIONS::ssl_extension_supported_ekt_ciphers(c, is_client, result);
      break;
    case "supported_groups":
      result = (parse_ssl_extension_supported_groups(val) as ParseResult_supported_groups);
      event SSL::EXTENSIONS::ssl_extension_supported_groups(c, is_client, result);
      break;
    case "supported_versions":
      result = (parse_ssl_extension_supported_versions(val, is_client) as ParseResult_supported_versions);
      event SSL::EXTENSIONS::ssl_extension_supported_versions(c, is_client, result);
      break;
    case "ticket_pinning":
      result = (parse_ssl_extension_ticket_pinning(val) as ParseResult_ticket_pinning);
      event SSL::EXTENSIONS::ssl_extension_ticket_pinning(c, is_client, result);
      break;
    case "ticket_request":
      result = (parse_ssl_extension_ticket_request(val) as ParseResult_ticket_request);
      event SSL::EXTENSIONS::ssl_extension_ticket_request(c, is_client, result);
      break;
    case "tls_cert_with_extern_psk":
      result = (parse_ssl_extension_tls_cert_with_extern_psk(val) as ParseResult_tls_cert_with_extern_psk);
      event SSL::EXTENSIONS::ssl_extension_tls_cert_with_extern_psk(c, is_client, result);
      break;
    case "tls_lts":
      result = (parse_ssl_extension_tls_lts(val) as ParseResult_tls_lts);
      event SSL::EXTENSIONS::ssl_extension_tls_lts(c, is_client, result);
      break;
    case "token_binding":
      result = (parse_ssl_extension_token_binding(val) as ParseResult_token_binding);
      event SSL::EXTENSIONS::ssl_extension_token_binding(c, is_client, result);
      break;
    case "transparency_info":
      result = (parse_ssl_extension_transparency_info(val) as ParseResult_transparency_info);
      event SSL::EXTENSIONS::ssl_extension_transparency_info(c, is_client, result);
      break;
    case "truncated_hmac":
      result = (parse_ssl_extension_truncated_hmac(val) as ParseResult_truncated_hmac);
      event SSL::EXTENSIONS::ssl_extension_truncated_hmac(c, is_client, result);
      break;
    case "trusted_ca_keys":
      result = (parse_ssl_extension_trusted_ca_keys(val) as ParseResult_trusted_ca_keys);
      event SSL::EXTENSIONS::ssl_extension_trusted_ca_keys(c, is_client, result);
      break;
    case "use_srtp":
      result = (parse_ssl_extension_use_srtp(val) as ParseResult_use_srtp);
      event SSL::EXTENSIONS::ssl_extension_use_srtp(c, is_client, result);
      break;
    case "user_mapping":
      result = (parse_ssl_extension_user_mapping(val) as ParseResult_user_mapping);
      event SSL::EXTENSIONS::ssl_extension_user_mapping(c, is_client, result);
      break;
  }
}
