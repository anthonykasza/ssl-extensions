module SSL::EXTENSIONS;

event SSL::EXTENSIONS::ssl_extension_ec_point_formats(c: connection, is_client: bool, val: ParseResult_ec_point_formats) {
  print "ec_point_formats length: ", val$len;
  for (idx in val$formats) {
    print "ec_point_format: ", val$formats[idx];
  }
}

event SSL::EXTENSIONS::ssl_extension_supported_groups(c: connection, is_client: bool, val: ParseResult_supported_groups) {
  print "supported_groups length: ", val$len;
  for (idx in val$supported_groups) {
    print "supported_group: ", val$supported_groups[idx];
  }
}

event SSL::EXTENSIONS::ssl_extension_session_ticket(c: connection, is_client: bool, val: ParseResult_session_ticket) {
  print "session_ticket length: ", val$len;
  if (val?$session_ticket) {
    print "session_ticket: ", val$session_ticket;
  } else {
    print "session_ticket: ", "<EMPTY>";
  }
}

event SSL::EXTENSIONS::ssl_extension_padding(c: connection, is_client: bool, val: ParseResult_padding) {
  if (val?$padding) {
    print "padding length: ", |val$padding|;
    print "padding: ", val$padding;
  }
}


event SSL::EXTENSIONS::ssl_extension_signature_algorithms(c: connection, is_client: bool, val: ParseResult_signature_algorithms) {
  print "signature_algorithms length: ", val$len;
  if (val$len == 0) { return; }
  for (idx in val$sig_algo_hash_algo) {
    print "sign algo, hash algo: ", val$sig_algo_hash_algo[idx];
  }
}

event SSL::EXTENSIONS::ssl_extension_encrypted_client_hello(c: connection, is_client: bool, val: ParseResult_signature_algorithms) {
  print "encrypted_client_hello: ", val;
}

event SSL::EXTENSIONS::ssl_extension_supported_versions(c: connection, is_client: bool, val: ParseResult_supported_versions) {
  print "supported_versions length: ", val$len;
  for (idx in val$supported_versions) {
    print "supported_version: ", val$supported_versions[idx];
  }
}

event SSL::EXTENSIONS::ssl_extension_psk_key_exchange_modes(c: connection, is_client: bool, val: ParseResult_psk_key_exchange_modes) {
  print "psk_key_exchange_modes length: ", val$len;
  for (idx in val$psk_key_exchange_modes) {
    print "psk_key_exchange_mode: ", val$psk_key_exchange_modes[idx];
  }
}

event SSL::EXTENSIONS::ssl_extension_key_share(c: connection, is_client: bool, val: ParseResult_key_share) {
  print "key_share length: ", val$len;
  for (group, key_exchange in val$map) {
    print "key_share group: ", group;
    print "key_share key_exchange", key_exchange;
  }
}

event SSL::EXTENSIONS::ssl_extension_key_share_reserved(c: connection, is_client: bool, val: ParseResult_key_share) {
  local ep: string = "server";
  if (is_client) { ep = "client"; }

  print ep, "key_share_reserved length: ", val$len;
  for (group, key_exchange in val$map) {
    print ep, "key_share_reserved group: ", group;
    print ep, "key_share_reserved key_exchange: ", key_exchange;
  }
}

event SSL::EXTENSIONS::ssl_extension_pre_shared_key(c: connection, is_client: bool, val: ParseResult_signature_algorithms) {
  print "pre_shared_key: ", val;
}

event SSL::EXTENSIONS::ssl_extension_application_layer_protocol_negotiation(c: connection, is_client: bool, val: ParseResult_signature_algorithms) {
  print "application_layer_protocol_negotiation: ", val;
}

event SSL::EXTENSIONS::ssl_extension_grease(c: connection, is_client: bool, val: ParseResult_grease) {
  print "grease code: ", val$code;
  print "grease content: ", val$content;
}
