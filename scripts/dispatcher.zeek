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
    [36] = "tlmsp",
    [37] = "tlmsp_proxying",
    [38] = "tlmsp_delegate",
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

  switch SSL::EXTENSIONS::names[code] {
    case "tlmsp":
      event SSL::EXTENSIONS::tlmsp(c, is_client, parse_tlmsp(val));
      break;
    case "tlmsp_delegate":
      event SSL::EXTENSIONS::tlmsp_delegate(c, is_client, parse_tlmsp_delegate(val));
      break;
    case "tlmsp_proxying":
      event SSL::EXTENSIONS::tlmsp_proxying(c, is_client, parse_tlmsp_proxying(val));
      break;
    case "application_layer_protocol_negotiation":
      event SSL::EXTENSIONS::application_layer_protocol_negotiation(c, is_client, parse_application_layer_protocol_negotiation(val));
      break;
    case "cached_info":
      event SSL::EXTENSIONS::cached_info(c, is_client, parse_cached_info(val));
      break;
    case "cert_type":
      event SSL::EXTENSIONS::cert_type(c, is_client, parse_cert_type(val));
      break;
    case "certificate_authorities":
      event SSL::EXTENSIONS::certificate_authorities(c, is_client, parse_certificate_authorities(val));
      break;
    case "client_authz":
      event SSL::EXTENSIONS::client_authz(c, is_client, parse_client_authz(val));
      break;
    case "client_certificate_type":
      event SSL::EXTENSIONS::client_certificate_type(c, is_client, parse_client_certificate_type(val));
      break;
    case "client_certificate_url":
      event SSL::EXTENSIONS::client_certificate_url(c, is_client, parse_client_certificate_url(val));
      break;
    case "compress_certificate":
      event SSL::EXTENSIONS::compress_certificate(c, is_client, parse_compress_certificate(val));
      break;
    case "connection_id":
      event SSL::EXTENSIONS::connection_id(c, is_client, parse_connection_id(val));
      break;
    case "connection_id_deprecated":
      event SSL::EXTENSIONS::connection_id_deprecated(c, is_client, parse_connection_id_deprecated(val));
      break;
    case "cookie":
      event SSL::EXTENSIONS::cookie(c, is_client, parse_cookie(val));
      break;
    case "delegated_credential":
      event SSL::EXTENSIONS::delegated_credential(c, is_client, parse_delegated_credential(val));
      break;
    case "dnssec_chain":
      event SSL::EXTENSIONS::dnssec_chain(c, is_client, parse_dnssec_chain(val));
      break;
    case "early_data":
      event SSL::EXTENSIONS::early_data(c, is_client, parse_early_data(val));
      break;
    case "ec_point_formats":
      event SSL::EXTENSIONS::ec_point_formats(c, is_client, parse_ec_point_formats(val));
      break;
    case "ech_outer_extensions":
      event SSL::EXTENSIONS::ech_outer_extensions(c, is_client, parse_ech_outer_extensions(val));
      break;
    case "encrypt_then_mac":
      event SSL::EXTENSIONS::encrypt_then_mac(c, is_client, parse_encrypt_then_mac(val));
      break;
    case "encrypted_client_hello":
      event SSL::EXTENSIONS::encrypted_client_hello(c, is_client, parse_encrypted_client_hello(val));
      break;
    case "extended_master_secret":
      event SSL::EXTENSIONS::extended_master_secret(c, is_client, parse_extended_master_secret(val));
      break;
    case "external_id_hash":
      event SSL::EXTENSIONS::external_id_hash(c, is_client, parse_external_id_hash(val));
      break;
    case "external_session_id":
      event SSL::EXTENSIONS::external_session_id(c, is_client, parse_external_session_id(val));
      break;
    case "grease":
      event SSL::EXTENSIONS::grease(c, is_client, parse_grease(val, code));
      break;
    case "heartbeat":
      event SSL::EXTENSIONS::heartbeat(c, is_client, parse_heartbeat(val));
      break;
    case "key_share":
      event SSL::EXTENSIONS::key_share(c, is_client, parse_key_share(val, is_client));
      break;
    case "key_share_reserved":
      event SSL::EXTENSIONS::key_share_reserved(c, is_client, parse_key_share(val, is_client));
      break;
    case "max_fragment_length":
      event SSL::EXTENSIONS::max_fragment_length(c, is_client, parse_max_fragment_length(val));
      break;
    case "oid_filters":
      event SSL::EXTENSIONS::oid_filters(c, is_client, parse_oid_filters(val));
      break;
    case "padding":
      event SSL::EXTENSIONS::padding(c, is_client, parse_padding(val));
      break;
    case "password_salt":
      event SSL::EXTENSIONS::password_salt(c, is_client, parse_password_salt(val));
      break;
    case "post_handshake_auth":
      event SSL::EXTENSIONS::post_handshake_auth(c, is_client, parse_post_handshake_auth(val));
      break;
    case "pre_shared_key":
      event SSL::EXTENSIONS::pre_shared_key(c, is_client, parse_pre_shared_key(val, is_client));
      break;
    case "psk_key_exchange_modes":
      event SSL::EXTENSIONS::psk_key_exchange_modes(c, is_client, parse_psk_key_exchange_modes(val));
      break;
    case "pwd_clear":
      event SSL::EXTENSIONS::pwd_clear(c, is_client, parse_pwd_clear(val));
      break;
    case "pwd_protect":
      event SSL::EXTENSIONS::pwd_protect(c, is_client, parse_pwd_protect(val));
      break;
    case "quic_transport_parameters":
      event SSL::EXTENSIONS::quic_transport_parameters(c, is_client, parse_quic_transport_parameters(val));
      break;
    case "record_size_limit":
      event SSL::EXTENSIONS::record_size_limit(c, is_client, parse_record_size_limit(val));
      break;
    case "renegotiation_info":
      event SSL::EXTENSIONS::renegotiation_info(c, is_client, parse_renegotiation_info(val));
      break;
    case "rrc":
      event SSL::EXTENSIONS::rrc(c, is_client, parse_rrc(val));
      break;
    case "sequence_number_encryption_algorithms":
      event SSL::EXTENSIONS::sequence_number_encryption_algorithms(c, is_client, parse_sequence_number_encryption_algorithms(val));
      break;
    case "server_authz":
      event SSL::EXTENSIONS::server_authz(c, is_client, parse_server_authz(val));
      break;
    case "server_certificate_type":
      event SSL::EXTENSIONS::server_certificate_type(c, is_client, parse_server_certificate_type(val));
      break;
    case "server_name":
      event SSL::EXTENSIONS::server_name(c, is_client, parse_server_name(val));
      break;
    case "session_ticket":
      event SSL::EXTENSIONS::session_ticket(c, is_client, parse_session_ticket(val));
      break;
    case "signature_algorithms":
      event SSL::EXTENSIONS::signature_algorithms(c, is_client, parse_signature_algorithms(val));
      break;
    case "signature_algorithms_cert":
      event SSL::EXTENSIONS::signature_algorithms_cert(c, is_client, parse_signature_algorithms_cert(val));
      break;
    case "signed_certificate_timestamp":
      event SSL::EXTENSIONS::signed_certificate_timestamp(c, is_client, parse_signed_certificate_timestamp(val));
      break;
    case "srp":
      event SSL::EXTENSIONS::srp(c, is_client, parse_srp(val));
      break;
    case "status_request":
      event SSL::EXTENSIONS::status_request(c, is_client, parse_status_request(val));
      break;
    case "status_request_v2":
      event SSL::EXTENSIONS::status_request_v2(c, is_client, parse_status_request_v2(val));
      break;
    case "supported_ekt_ciphers":
      event SSL::EXTENSIONS::supported_ekt_ciphers(c, is_client, parse_supported_ekt_ciphers(val));
      break;
    case "supported_groups":
      event SSL::EXTENSIONS::supported_groups(c, is_client, parse_supported_groups(val));
      break;
    case "supported_versions":
      event SSL::EXTENSIONS::supported_versions(c, is_client, parse_supported_versions(val, is_client));
      break;
    case "ticket_pinning":
      event SSL::EXTENSIONS::ticket_pinning(c, is_client, parse_ticket_pinning(val));
      break;
    case "ticket_request":
      event SSL::EXTENSIONS::ticket_request(c, is_client, parse_ticket_request(val));
      break;
    case "tls_cert_with_extern_psk":
      event SSL::EXTENSIONS::tls_cert_with_extern_psk(c, is_client, parse_tls_cert_with_extern_psk(val));
      break;
    case "tls_lts":
      event SSL::EXTENSIONS::tls_lts(c, is_client, parse_tls_lts(val));
      break;
    case "token_binding":
      event SSL::EXTENSIONS::token_binding(c, is_client, parse_token_binding(val));
      break;
    case "transparency_info":
      event SSL::EXTENSIONS::transparency_info(c, is_client, parse_transparency_info(val));
      break;
    case "truncated_hmac":
      event SSL::EXTENSIONS::truncated_hmac(c, is_client, parse_truncated_hmac(val));
      break;
    case "trusted_ca_keys":
      event SSL::EXTENSIONS::trusted_ca_keys(c, is_client, parse_trusted_ca_keys(val));
      break;
    case "use_srtp":
      event SSL::EXTENSIONS::use_srtp(c, is_client, parse_use_srtp(val));
      break;
    case "user_mapping":
      event SSL::EXTENSIONS::user_mapping(c, is_client, parse_user_mapping(val));
      break;
  }
}
