# The functions which parse ssl extensions as strings

module SSL::EXTENSIONS;


function parse_ec_point_formats(val: string): ParseResult_ec_point_formats {
  # length guard
  if (|val| == 0) { return []; }

  # 1 byte length
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


function parse_supported_groups(val: string): ParseResult_supported_groups {
  # length guard
  if (|val| == 0) { return []; }

  # 2 byte length
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

function parse_session_ticket(val: string): ParseResult_session_ticket {
  # length guard
  if (|val| == 0) { return []; }

  # 1 byte length
  local len: count = bytestring_to_count(val[0]);
  val = val[1:];

  # the rest of the bytes, as a string
  local session_ticket: string = val;

  return [$session_ticket=session_ticket];
}

function parse_padding(val: string): ParseResult_padding {
  # length guard
  if (|val| == 0) { return []; }

  # 2 byte length
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

function parse_signature_algorithms(val: string): ParseResult_signature_algorithms { 
  # length guard
  if (|val| == 0) { return []; }

  # 2 byte length
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

function parse_encrypted_client_hello(val: string): ParseResult_encrypted_client_hello {
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

function parse_ech_outer_extensions(val: string): ParseResult_ech_outer_extensions {
  return [];
}

function parse_supported_versions(val: string, is_client: bool): ParseResult_supported_versions {
  local supported_versions: vector of count = vector();
  local idx: count = 0;

  if (is_client) {
    # length guard
    if (|val| == 0) { return []; }

    # 1 byte length
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

function parse_psk_key_exchange_modes(val: string): ParseResult_psk_key_exchange_modes {
  # length guard
  if (|val| == 0) { return []; }

  # 1 byte length
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

function parse_key_share(val: string, is_client: bool): ParseResult_key_share {
  local len: count;
  if (is_client) {
    # length guard
    if (|val| == 0) { return []; }

    # 2 byte length
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

function parse_pre_shared_key(val: string, is_client: bool): ParseResult_pre_shared_key {
  if (!is_client) {
    # TODO - add a length guard check
    #        the server's response should always be 2 bytes
    return [
      $selected_identity=bytestring_to_count(val)
    ];
  }

  # length guard
  if (|val| == 0) { return []; }

  # 2 byte length
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
    $obfuscated_ticket_age=ota,
    $identities=identities,
    $binders=binders
  ];
}

function parse_application_layer_protocol_negotiation(val: string): ParseResult_application_layer_protocol_negotiation {
  # length guard
  if (|val| == 0) { return []; }

  # 2 byte length
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

function parse_grease(val: string, code: count): ParseResult_grease {
  return [$code=code, $content=val];
}

function parse_heartbeat(val: string): ParseResult_heartbeat {
  # length guard
  if (|val| == 0) { return []; }

  # the rest of the bytes, one at a time
  local modes: vector of count = vector();
  local idx: count = 0;
  for (char in val) {
    modes += bytestring_to_count(val[idx]);
    idx += 1;
  }

  return [$modes=modes];
}

function parse_renegotiation_info(val: string): ParseResult_renegotiation_info {
  # length guard
  if (|val| == 0) { return []; }

  # 1 byte length
  local len: count = bytestring_to_count(val[0]);
  val = val[1:];

  # TODO - find an example to parse

  return [];
}

function parse_server_name(val: string): ParseResult_server_name {
  # length guard
  if (|val| == 0) { return []; }

  # 2 byte length
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


function parse_status_request(val: string): ParseResult_status_request {
  # length guard
  if (|val| == 0) { return []; }

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

function parse_delegated_credential(val: string): ParseResult_delegated_credential {
  # length guard
  if (|val| == 0) { return []; }

  # 2 byte length
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

function parse_quic_transport_parameters(val: string): ParseResult_quic_transport_parameters {

  return [];

  # TODO 

  local parameter_types: table[count] of string = {
    [0x00] = "original_destination_connection_id",
    [0x01] = "max_idle_timeout",
    [0x02] = "stateless_reset_token",
    [0x03] = "max_udp_payload_size",
    [0x04] = "initial_max_data",
    [0x05] = "initial_max_stream_data_bidi_local",
    [0x06] = "initial_max_stream_data_bidi_remote",
    [0x07] = "initial_max_stream_data_uni",
    [0x08] = "initial_max_streams_bidi",
    [0x09] = "initial_max_streams_uni",
    [0x0a] = "ack_delay_exponent",
    [0x0b] = "max_ack_delay",
    [0x0c] = "disable_active_migration",
    [0x0d] = "preferred_address",
    [0x0e] = "active_connection_id_limit",
    [0x0f] = "initial_source_connection_id",
    [0x10] = "retry_source_connection_id"
  } &default="GREASE";
  
  local params_types: vector of count = vector();
  local params_values: vector of count = vector();
  local idx: count = 0;
}

function parse_record_size_limit(val: string): ParseResult_record_size_limit {
  return [$record_size_limit=bytestring_to_count(val)];
}

function parse_connection_id(val: string): ParseResult_connection_id {
  # length guard
  if (|val| == 0) { return []; }

  # 1 byte length
  local len: count = bytestring_to_count(val[0]);
  val = val[1:];

  return [$connection_id=val];
}
function parse_cookie(val: string): ParseResult_cookie { 
  # length guard
  if (|val| == 0) { return []; }

  # 2 byte length
  local len: count = bytestring_to_count(val[0:2]);
  val = val[2:];

  return [$cookie=val];
}

function parse_compress_certificate(val: string): ParseResult_compress_certificate {
  # length guard
  if (|val| == 0) { return []; }

  # 1 byte length
  local len: count = bytestring_to_count(val[0]);
  val = val[1:];

  # the rest of the bytes, two at a time
  local algorithms: vector of count = vector();
  local idx: count = 0;
  while (|val| > 0) {
    algorithms += bytestring_to_count(val[0:2]);
    val = val[2:];
  }

  return [$algorithms=algorithms];
}

function parse_token_binding(val: string): ParseResult_token_binding {
  # length guard
  if (|val| == 0) { return []; }

  # 1 byte major
  local proto_major: count = bytestring_to_count(val[0]);
  val = val[1:];

  # 1 byte minor
  local proto_minor: count = bytestring_to_count(val[0]);
  val = val[1:];

  # 1 byte length
  local key_params_len: count = bytestring_to_count(val[0]);
  val = val[1:];

  # the rest of the bytes, one at a time
  local params: vector of count = vector();
  local idx: count = 0;
  for (char in val) {
    params += bytestring_to_count(val[idx]);
    idx += 1;
  }

  return [
    $proto_major=proto_major,
    $proto_minor=proto_minor,
    $parameters=params
  ];
}


function parse_use_srtp(val: string): ParseResult_use_srtp {
  # https://datatracker.ietf.org/doc/html/rfc5764#section-4.1.1

  # length guard
  if (|val| == 0) { return []; }

  # 2 byte length
  local profiles_len: count = bytestring_to_count(val[0:2]);
  val = val[2:];

  # variable length count
  local profile: count = bytestring_to_count(val[0:profiles_len]);
  val = val[profiles_len:];

  # 1 byte mki length
  local mki_len: count = bytestring_to_count(val[0]);
  val = val[1:];

  return [$profile=profile, $mki_len=mki_len];
}

function parse_tlmsp(val: string): ParseResult_tlmsp { return []; }
function parse_tlmsp_delegate(val: string): ParseResult_tlmsp_delegate { return []; }
function parse_tlmsp_proxying(val: string): ParseResult_tlmsp_proxying { return []; }
function parse_cached_info(val: string): ParseResult_cached_info { return []; }
function parse_cert_type(val: string): ParseResult_cert_type { return []; }
function parse_certificate_authorities(val: string): ParseResult_certificate_authorities { return []; }
function parse_client_authz(val: string): ParseResult_client_authz { return []; }
function parse_client_certificate_type(val: string): ParseResult_client_certificate_type { return []; }
function parse_client_certificate_url(val: string): ParseResult_client_certificate_url { return []; }
function parse_connection_id_deprecated(val: string): ParseResult_connection_id_deprecated { return []; }
function parse_dnssec_chain(val: string): ParseResult_dnssec_chain { return []; }
function parse_early_data(val: string): ParseResult_early_data { return []; }
function parse_encrypt_then_mac(val: string): ParseResult_encrypt_then_mac { return []; }
function parse_extended_master_secret(val: string): ParseResult_extended_master_secret { return []; }
function parse_external_id_hash(val: string): ParseResult_external_id_hash { return []; }
function parse_external_session_id(val: string): ParseResult_external_session_id { return []; }
function parse_max_fragment_length(val: string): ParseResult_max_fragment_length { return []; }
function parse_oid_filters(val: string): ParseResult_oid_filters { return []; }
function parse_password_salt(val: string): ParseResult_password_salt { return []; }
function parse_post_handshake_auth(val: string): ParseResult_post_handshake_auth { return []; }
function parse_pwd_clear(val: string): ParseResult_pwd_clear { return []; }
function parse_pwd_protect(val: string): ParseResult_pwd_protect { return []; }
function parse_rrc(val: string): ParseResult_rrc { return []; }
function parse_sequence_number_encryption_algorithms(val: string): ParseResult_sequence_number_encryption_algorithms { return []; }
function parse_server_authz(val: string): ParseResult_server_authz { return []; }
function parse_server_certificate_type(val: string): ParseResult_server_certificate_type { return []; }
function parse_signature_algorithms_cert(val: string): ParseResult_signature_algorithms_cert { return []; }
function parse_signed_certificate_timestamp(val: string): ParseResult_signed_certificate_timestamp { return []; }
function parse_srp(val: string): ParseResult_srp { return []; }
function parse_status_request_v2(val: string): ParseResult_status_request_v2 { return []; }
function parse_supported_ekt_ciphers(val: string): ParseResult_supported_ekt_ciphers { return []; }
function parse_ticket_pinning(val: string): ParseResult_ticket_pinning { return []; }
function parse_ticket_request(val: string): ParseResult_ticket_request { return []; }
function parse_tls_cert_with_extern_psk(val: string): ParseResult_tls_cert_with_extern_psk { return []; }
function parse_tls_lts(val: string): ParseResult_tls_lts { return []; }
function parse_transparency_info(val: string): ParseResult_transparency_info { return []; }
function parse_truncated_hmac(val: string): ParseResult_truncated_hmac { return []; }
function parse_trusted_ca_keys(val: string): ParseResult_trusted_ca_keys { return []; }
function parse_user_mapping(val: string): ParseResult_user_mapping { return []; }
