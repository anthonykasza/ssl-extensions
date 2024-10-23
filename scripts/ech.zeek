module SSL::EXTENSIONS::ECH;

export {
  option private_key: string = "PRIVATE";
  global decrypt_ech: function(encrypted_payload: string): string;

  type Info: record {
    ts: time &log;
    uid: string &log;
    id: conn_id &log;

    kdf: string &log;
    aead: string &log;
    config_id: count &log;
    enc: string &log;

    encrypted_payload: string &log;
    cleartext_payload: string &log;
  };

  # logging boilerplate
  global log_ech: event(rec: Info);
  redef enum Log::ID += { LOG };
  global log_policy: Log::PolicyHook;

  global key_derivation_functions: table[count] of string = {
    [0x0000] = "Reserved",
    [0x0001] = "HKDF-SHA256",
    [0x0002] = "HKDF-SHA384",
    [0x0003] = "HKDF-SHA512"
  } &default = "UNKNOWN";

  global aead_functions: table[count] of string = {
    [0x0000] = "Reserved",
    [0x0001] = "AES-128-GCM",
    [0x0002] = "AES-256-GCM",
    [0x0003] = "ChaCha20Poly1305",
    [0xffff] = "Export-only",
  } &default = "UNKNOWN";
}

event zeek_init() &priority=10 {
  Log::create_stream(SSL::EXTENSIONS::ECH::LOG, [
    $columns=Info,
    $ev=log_ech,
    $path="ssl_ech",
    $policy=log_policy
  ]);
}

function decrypt_ech(encrypted_payload: string): string {
  # TODO - decrypt using server's private key
  #        strip padding
  #        check for optional client compression
  return cat(encrypted_payload + "_DECRYPTED_" + private_key);
}

event SSL::EXTENSIONS::encrypted_client_hello(c: connection, is_client: bool, result: SSL::EXTENSIONS::ParseResult_encrypted_client_hello) {
  Log::write(SSL::EXTENSIONS::ECH::LOG, [
    $ts=network_time(),
    $uid=c$uid,
    $id=c$id,

    $kdf=key_derivation_functions[result$kdf_id],
    $aead=aead_functions[result$aead_id],
    $config_id=result$config_id,
    $enc=result$enc,

    $encrypted_payload=result$payload,
    $cleartext_payload=decrypt_ech(result$payload)
  ]);
}

# TODO - attempt to analyze the server response to determine acceptance
#        https://www.ietf.org/archive/id/draft-ietf-tls-esni-17.html#name-determining-ech-acceptance

# TODO - attempt to identify when clients are greasing this extension
#        https://www.ietf.org/archive/id/draft-ietf-tls-esni-17.html#section-6.2

# TODO - attempt to incorporate ECHConfig data from DNS records to better inform the config_id field
#        https://datatracker.ietf.org/doc/draft-ietf-tls-svcb-ech/
