module SSL::EXTENSIONS;

export {
  type ParseResult_TLMSP: record {};
  type ParseResult_TLMSP_delegate: record {};
  type ParseResult_TLMSP_proxying: record {};

  type ParseResult_application_layer_protocol_negotiation: record {
    len: count; 
    protocols: vector of string &optional;
  };

  type ParseResult_cached_info: record {};
  type ParseResult_cert_type: record {};
  type ParseResult_certificate_authorities: record {};
  type ParseResult_client_authz: record {};
  type ParseResult_client_certificate_type: record {};
  type ParseResult_client_certificate_url: record {};
  type ParseResult_compress_certificate: record {};
  type ParseResult_connection_id: record {};
  type ParseResult_connection_id_deprecated: record {};
  type ParseResult_cookie: record {};
  type ParseResult_delegated_credential: record {};
  type ParseResult_dnssec_chain: record {};
  type ParseResult_early_data: record {};

  type ParseResult_ec_point_formats: record {
    len: count;
    formats: vector of count &optional;
  };

  type ParseResult_ech_outer_extensions: record {};
  type ParseResult_encrypt_then_mac: record {};

  type ParseResult_encrypted_client_hello: record {
    client_hello_type: count;
    kdf_id: count;
    aead_id: count;
    config_id: count;
    enc_len: count;
    enc: string;
    payload_len: count;
    payload: string;
  };

  type ParseResult_extended_master_secret: record {};
  type ParseResult_external_id_hash: record {};
  type ParseResult_external_session_id: record {};

  type ParseResult_grease: record {
    code: count;
    content: string &default="";
  };

  type ParseResult_heartbeat: record {};

  type ParseResult_key_share: record {
    len: count;
    # group keys yield key_exchange values
    map: table[count] of string &optional;
  };

  type ParseResult_max_fragment_length: record {};
  type ParseResult_oid_filters: record {};

  type ParseResult_padding: record {
    len: count;
    padding: string &optional;
  };

  type ParseResult_password_salt: record {};
  type ParseResult_post_handshake_auth: record {};

  # This demonstrates why it's not a clean solution to use a single
  #  type for parsing of extensions from both the client and the server
  type ParseResult_pre_shared_key: record {
    len: count;
    obfuscated_ticket_age: count &optional; #client 
    identities: string &optional; #client
    binders: string &optional; #client
    selected_identity: count &optional; #server
  };

  type ParseResult_psk_key_exchange_modes: record {
    len: count;
    psk_key_exchange_modes: vector of count &optional;    
  };

  type ParseResult_pwd_clear: record {};
  type ParseResult_pwd_protect: record {};
  type ParseResult_quic_transport_parameters: record {};
  type ParseResult_record_size_limit: record {};
  type ParseResult_renegotiation_info: record {};
  type ParseResult_rrc: record {};
  type ParseResult_sequence_number_encryption_algorithms: record {};
  type ParseResult_server_authz: record {};
  type ParseResult_server_certificate_type: record {};
  type ParseResult_server_name: record {};

  type ParseResult_session_ticket: record {
    len: count;
    session_ticket: string &optional;
  };

  type ParseResult_signature_algorithms: record {
    len: count;
    sig_algo_hash_algo: vector of count &optional;    
  };

  type ParseResult_signature_algorithms_cert: record {};
  type ParseResult_signed_certificate_timestamp: record {};
  type ParseResult_srp: record {};
  type ParseResult_status_request: record {};
  type ParseResult_status_request_v2: record {};
  type ParseResult_supported_ekt_ciphers: record {};

  type ParseResult_supported_groups: record {
    len: count;
    supported_groups: vector of count &optional;
  };

  type ParseResult_supported_versions: record {
    len: count;
    supported_versions: vector of count &optional;    
  };

  type ParseResult_ticket_pinning: record {};
  type ParseResult_ticket_request: record {};
  type ParseResult_tls_cert_with_extern_psk: record {};
  type ParseResult_tls_lts: record {};
  type ParseResult_token_binding: record {};
  type ParseResult_transparency_info: record {};
  type ParseResult_truncated_hmac: record {};
  type ParseResult_trusted_ca_keys: record {};
  type ParseResult_use_srtp: record {};
  type ParseResult_user_mapping: record {};
}
