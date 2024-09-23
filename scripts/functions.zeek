# The functions which parse ssl extensions as strings
# Many of these share functionality and they likely could be reduced
#  For example, supported_groups and supported_versions is basically
#  the same function


module SSL::EXTENSIONS;

function parse_ssl_extension_ec_point_formats(val: string): ParseResult_ec_point_formats {
  # 1 byte length
  if (|val| == 0) {
    return [];
  }
  local len: count = bytestring_to_count(val[0]);
  val = val[1:];

  # the rest of the bytes, one at a time
  local formats: vector of count = vector();
  local idx: count = 0;
  for (char in val) {
    formats += bytestring_to_count(val[idx]);
    idx += 1;
  }

  return [$formats=formats];
}


function parse_ssl_extension_supported_groups(val: string): ParseResult_supported_groups {
  # 2 byte length
  if (|val| == 0) {
    return [];
  }
  local len: count = bytestring_to_count(val[0:2]);
  val = val[2:];

  # the rest of the bytes, two at a time
  local supported_groups: vector of count = vector();
  local idx: count = 0;
  while (|val| > 0) {
    supported_groups += bytestring_to_count(val[0:2]);
    val = val[2:];
  }

  return [$supported_groups=supported_groups];
}

function parse_ssl_extension_session_ticket(val: string): ParseResult_session_ticket {
  # 1 byte length
  if (|val| == 0) {
    return [];
  }
  local len: count = bytestring_to_count(val[0]);
  val = val[1:];

  # the rest of the bytes, as a string
  local session_ticket: string = val;

  return [$session_ticket=session_ticket];
}

function parse_ssl_extension_padding(val: string): ParseResult_padding {
  # 2 byte length
  if (|val| == 0) {
    return [];
  }
  local len: count = bytestring_to_count(val[0:2]);
  val = val[2:];

  # the rest of the bytes, as a string
  for (char in val) {
    if (char != "\x00") {
      # TODO - raise a weird or a notice as all bytes should be 0x00
      #  https://www.rfc-editor.org/rfc/rfc7685.html#section-5
      ;
    }
  }

  return [$padding=val];
}

function parse_ssl_extension_signature_algorithms(val: string): ParseResult_signature_algorithms { 
  # 2 byte length
  if (|val| == 0) {
    return [];
  }
  local len: count = bytestring_to_count(val[0:2]);
  val = val[2:];

  # the rest of the bytes, two at a time
  local sig_algo_hash_algo: vector of count = vector();
  local idx: count = 0;
  while (|val| > 0) {
    sig_algo_hash_algo += bytestring_to_count(val[0:2]);
    val = val[2:];
  }

  return [$signature_algorithms=sig_algo_hash_algo];
}

function parse_ssl_extension_encrypted_client_hello(val: string): ParseResult_encrypted_client_hello {
  # 1 byte
  local client_hello_type: count = bytestring_to_count(val[0:1]);
  val = val[1:];

  # 2 bytes
  local kdf_id: count = bytestring_to_count(val[0:2]);
  val = val[2:];

  # 2 bytes
  local aead_id: count = bytestring_to_count(val[0:2]);
  val = val[2:];

  # 1 byte
  local config_id: count = bytestring_to_count(val[0:1]);
  val = val[1:];

  # 2 bytes
  local enc_len: count = bytestring_to_count(val[0:2]);
  val = val[2:]; 

  # variable length string
  local enc: string = val[0:enc_len];
  val = val[enc_len:];

  # 2 byte
  local payload_len: count = bytestring_to_count(val[0:2]);
  val = val[2:];

  # the rest of the bytes, as as string
  local payload: string = val;

  return [
    $client_hello_type=client_hello_type,
    $kdf_id=kdf_id,
    $aead_id=aead_id,
    $config_id=config_id,
    $enc_len=enc_len,
    $enc=enc,
    $payload_len=payload_len,
    $payload=payload
  ];
}

function parse_ssl_extension_supported_versions(val: string, is_client: bool): ParseResult_supported_versions {
  local supported_versions: vector of count = vector();
  local idx: count = 0;

  if (is_client) {
    # 1 byte length
    if (|val| == 0) {
      return [];
    }
    local len: count = bytestring_to_count(val[0]);
    val = val[1:];

    # the rest of the bytes, two at a time
    while (|val| > 0) {
      supported_versions += bytestring_to_count(val[0:2]);
      val = val[2:];
    }

    return [$supported_versions=supported_versions];

  } else {
    # is_client == F

    # the rest of the bytes, two at a time
    while (|val| > 0) {
      supported_versions += bytestring_to_count(val[0:2]);
      val = val[2:];
    }

    return [$supported_versions=supported_versions];
  }
}

function parse_ssl_extension_psk_key_exchange_modes(val: string): ParseResult_psk_key_exchange_modes {
  # 1 byte length
  if (|val| == 0) {
    return [];
  }
  local len: count = bytestring_to_count(val[0]);
  val = val[1:];

  # the rest of the bytes, one at a time
  local modes: vector of count = vector();
  local idx: count = 0;
  for (char in val) {
    modes += bytestring_to_count(val[idx]);
    idx += 1;
  }

  return [$psk_key_exchange_modes=modes];
}

function parse_ssl_extension_key_share(val: string, is_client: bool): ParseResult_key_share {
  local len: count;
  if (is_client) {
    # 2 byte length
    if (|val| == 0) {
      return [];
    }
    len = bytestring_to_count(val[0:2]);
    val = val[2:];
  } else {
    len = |val|;
  }

  local map: table[count] of string &ordered;
  local group: count;
  local key_exchange_len: count;
  local key_exchange: string;
  while (|val| > 0) {
    # 2 bytes
    group = bytestring_to_count(val[0:2]);
    val = val[2:];

    # 2 bytes
    key_exchange_len = bytestring_to_count(val[0:2]);
    val = val[2:];

    # variable length string
    key_exchange = val[0:key_exchange_len];
    val = val[key_exchange_len:];

    map[group] = key_exchange;
  }

   return [$map=map];
}

function parse_ssl_extension_pre_shared_key(val: string, is_client: bool): ParseResult_pre_shared_key {
  if (!is_client) {
    # the server's response should always be 2 bytes
    return [
      $is_client=is_client,
      $selected_identity=bytestring_to_count(val)
    ];
  }

  # 2 byte length
  if (|val| == 0) {
    return [$is_client=is_client];
  }
  local len: count = bytestring_to_count(val[0:2]);
  val = val[2:];

  # 2 byte identity length
  local id_len: count = bytestring_to_count(val[0:2]);
  val = val[2:];

  # variable length identity list as a string of bytes
  local identities: string = val[0:id_len];
  val = val[id_len:];

  # 4 byte obfuscated ticket age
  local ota: count = bytestring_to_count(val[0:4]);
  val = val[4:];

  # 2 byte binders length
  local binders_len: count = bytestring_to_count(val[0:2]);
  val = val[2:];

  # variable length binders list as a string of bytes
  local binders: string = val[0:binders_len];
  val = val[binders_len:];

  # TODO - check to ensure |binders| == |identities| and raise notice/weird
  # TODO - check for obviously invalid binders in client such as 0x00, this could
  #        be indicative of an identity enumeration attack by the client

  return [
    $is_client=is_client,
    $obfuscated_ticket_age=ota,
    $identities=identities,
    $binders=binders
  ];
}

function parse_ssl_extension_application_layer_protocol_negotiation(val: string): ParseResult_application_layer_protocol_negotiation {
  # 2 byte length
  if (|val| == 0) {
    return [];
  }
  local len: count = bytestring_to_count(val[0:2]);
  val = val[2:];

  local protocols: vector of string = vector();
  local proto_len: count;
  while (|val| > 0) {
    # 1 byte length
    proto_len = bytestring_to_count(val[0]);
    val = val[1:];

    # variable length identity list as a string of bytes
    local proto: string = val[0:proto_len];
    val = val[proto_len:];

    protocols += proto;
  }
  return [$protocols=protocols];
}

function parse_ssl_extension_grease(val: string, code: count): ParseResult_grease {
  return [$code=code, $content=val];
}

function parse_ssl_extension_heartbeat(val: string): ParseResult_heartbeat {
  if (|val| == 0) {
    return [];
  }

  # the rest of the bytes, one at a time
  local modes: vector of count = vector();
  local idx: count = 0;
  for (char in val) {
    modes += bytestring_to_count(val[idx]);
    idx += 1;
  }

  return [$modes=modes];
}

function parse_ssl_extension_renegotiation_info(val: string): ParseResult_renegotiation_info {
  # 1 byte length
  if (|val| == 0) {
    return [];
  }
  local len: count = bytestring_to_count(val[0]);
  val = val[1:];

  # TODO - find an example to parse

  return [];
}

function parse_ssl_extension_server_name(val: string): ParseResult_server_name {
  # 2 byte length
  if (|val| == 0) {
    return [];
  }
  local len: count = bytestring_to_count(val[0:2]);
  val = val[2:];

  local types_: vector of count = vector();
  local names: vector of string = vector();
  while (|val| > 0) {
    # 1 byte type
    local type_: count = bytestring_to_count(val[0:1]);
    types_ += type_;
    val = val[1:];

    # 2 byte length
    local name_len: count = bytestring_to_count(val[0:2]);
    val = val[2:];

    # variable length string
    local name: string = val[0:name_len];
    names += name;
    val = val[name_len:];
  }
  return [$types_=types_, $names=names];
}


function parse_ssl_extension_status_request(val: string): ParseResult_status_request {
  if (|val| == 0) {
    return [];
  }

  # 1 byte type
  local type_: count = bytestring_to_count(val[0]);
  val = val[1:];

  if (type_ == 255) {
    # TODO - raise notice
    ;
  } else if (type_ == 1) {
    # TODO - https://www.rfc-editor.org/rfc/rfc6066.html#section-8
    ;
  } else {
    # TODO - raise notie
    ;
  }

  return [$type_=type_];
}

# this is the ecaxt same as parse_ssl_extension_signature_algorithms
function parse_ssl_extension_delegated_credential(val: string): ParseResult_delegated_credential {
  # 2 byte length
  if (|val| == 0) {
    return [];
  }
  local len: count = bytestring_to_count(val[0:2]);
  val = val[2:];

  # the rest of the bytes, two at a time
  local sig_algos: vector of count = vector();
  local idx: count = 0;
  while (|val| > 0) {
    sig_algos += bytestring_to_count(val[0:2]);
    val = val[2:];
  }

  return [$signature_algorithms=sig_algos];
}

function parse_ssl_extension_quic_transport_parameters(val: string): ParseResult_quic_transport_parameters { return []; }

function parse_ssl_extension_record_size_limit(val: string): ParseResult_record_size_limit {
  return [$record_size_limit=bytestring_to_count(val)];
}


function parse_ssl_extension_TLMSP(val: string): ParseResult_TLMSP { return []; }
function parse_ssl_extension_TLMSP_delegate(val: string): ParseResult_TLMSP_delegate { return []; }
function parse_ssl_extension_TLMSP_proxying(val: string): ParseResult_TLMSP_proxying { return []; }
function parse_ssl_extension_cached_info(val: string): ParseResult_cached_info { return []; }
function parse_ssl_extension_cert_type(val: string): ParseResult_cert_type { return []; }
function parse_ssl_extension_certificate_authorities(val: string): ParseResult_certificate_authorities { return []; }
function parse_ssl_extension_client_authz(val: string): ParseResult_client_authz { return []; }
function parse_ssl_extension_client_certificate_type(val: string): ParseResult_client_certificate_type { return []; }
function parse_ssl_extension_client_certificate_url(val: string): ParseResult_client_certificate_url { return []; }
function parse_ssl_extension_compress_certificate(val: string): ParseResult_compress_certificate { return []; }
function parse_ssl_extension_connection_id(val: string): ParseResult_connection_id { return []; }
function parse_ssl_extension_connection_id_deprecated(val: string): ParseResult_connection_id_deprecated { return []; }
function parse_ssl_extension_cookie(val: string): ParseResult_cookie { return []; }
function parse_ssl_extension_dnssec_chain(val: string): ParseResult_dnssec_chain { return []; }
function parse_ssl_extension_early_data(val: string): ParseResult_early_data { return []; }
function parse_ssl_extension_ech_outer_extensions(val: string): ParseResult_ech_outer_extensions { return []; }
function parse_ssl_extension_encrypt_then_mac(val: string): ParseResult_encrypt_then_mac { return []; }
function parse_ssl_extension_extended_master_secret(val: string): ParseResult_extended_master_secret { return []; }
function parse_ssl_extension_external_id_hash(val: string): ParseResult_external_id_hash { return []; }
function parse_ssl_extension_external_session_id(val: string): ParseResult_external_session_id { return []; }
function parse_ssl_extension_max_fragment_length(val: string): ParseResult_max_fragment_length { return []; }
function parse_ssl_extension_oid_filters(val: string): ParseResult_oid_filters { return []; }
function parse_ssl_extension_password_salt(val: string): ParseResult_password_salt { return []; }
function parse_ssl_extension_post_handshake_auth(val: string): ParseResult_post_handshake_auth { return []; }
function parse_ssl_extension_pwd_clear(val: string): ParseResult_pwd_clear { return []; }
function parse_ssl_extension_pwd_protect(val: string): ParseResult_pwd_protect { return []; }
function parse_ssl_extension_rrc(val: string): ParseResult_rrc { return []; }
function parse_ssl_extension_sequence_number_encryption_algorithms(val: string): ParseResult_sequence_number_encryption_algorithms { return []; }
function parse_ssl_extension_server_authz(val: string): ParseResult_server_authz { return []; }
function parse_ssl_extension_server_certificate_type(val: string): ParseResult_server_certificate_type { return []; }
function parse_ssl_extension_signature_algorithms_cert(val: string): ParseResult_signature_algorithms_cert { return []; }
function parse_ssl_extension_signed_certificate_timestamp(val: string): ParseResult_signed_certificate_timestamp { return []; }
function parse_ssl_extension_srp(val: string): ParseResult_srp { return []; }
function parse_ssl_extension_status_request_v2(val: string): ParseResult_status_request_v2 { return []; }
function parse_ssl_extension_supported_ekt_ciphers(val: string): ParseResult_supported_ekt_ciphers { return []; }
function parse_ssl_extension_ticket_pinning(val: string): ParseResult_ticket_pinning { return []; }
function parse_ssl_extension_ticket_request(val: string): ParseResult_ticket_request { return []; }
function parse_ssl_extension_tls_cert_with_extern_psk(val: string): ParseResult_tls_cert_with_extern_psk { return []; }
function parse_ssl_extension_tls_lts(val: string): ParseResult_tls_lts { return []; }
function parse_ssl_extension_token_binding(val: string): ParseResult_token_binding { return []; }
function parse_ssl_extension_transparency_info(val: string): ParseResult_transparency_info { return []; }
function parse_ssl_extension_truncated_hmac(val: string): ParseResult_truncated_hmac { return []; }
function parse_ssl_extension_trusted_ca_keys(val: string): ParseResult_trusted_ca_keys { return []; }
function parse_ssl_extension_use_srtp(val: string): ParseResult_use_srtp { return []; }
function parse_ssl_extension_user_mapping(val: string): ParseResult_user_mapping { return []; }
