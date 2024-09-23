# @TEST-EXEC: zeek -C -r /Traces/tls/tls1_1.pcap $PACKAGE %INPUT >> output 2>&1
# @TEST-EXEC: btest-diff output

global event_list: set[string] = set(
  "SSL::EXTENSIONS::ssl_extension_rrc",
  "SSL::EXTENSIONS::ssl_extension_srp",
  "SSL::EXTENSIONS::ssl_extension_TLMSP",
  "SSL::EXTENSIONS::ssl_extension_cookie",
  "SSL::EXTENSIONS::ssl_extension_grease",
  "SSL::EXTENSIONS::ssl_extension_padding",
  "SSL::EXTENSIONS::ssl_extension_tls_lts",
  "SSL::EXTENSIONS::ssl_extension_use_srtp",
  "SSL::EXTENSIONS::ssl_extension_cert_type",
  "SSL::EXTENSIONS::ssl_extension_heartbeat",
  "SSL::EXTENSIONS::ssl_extension_key_share",
  "SSL::EXTENSIONS::ssl_extension_pwd_clear",
  "SSL::EXTENSIONS::ssl_extension_early_data",
  "SSL::EXTENSIONS::ssl_extension_cached_info",
  "SSL::EXTENSIONS::ssl_extension_oid_filters",
  "SSL::EXTENSIONS::ssl_extension_pwd_protect",
  "SSL::EXTENSIONS::ssl_extension_server_name",
  "SSL::EXTENSIONS::ssl_extension_client_authz",
  "SSL::EXTENSIONS::ssl_extension_dnssec_chain",
  "SSL::EXTENSIONS::ssl_extension_server_authz",
  "SSL::EXTENSIONS::ssl_extension_user_mapping",
  "SSL::EXTENSIONS::ssl_extension_connection_id",
  "SSL::EXTENSIONS::ssl_extension_password_salt",
  "SSL::EXTENSIONS::ssl_extension_token_binding",
  "SSL::EXTENSIONS::ssl_extension_TLMSP_delegate",
  "SSL::EXTENSIONS::ssl_extension_TLMSP_proxying",
  "SSL::EXTENSIONS::ssl_extension_pre_shared_key",
  "SSL::EXTENSIONS::ssl_extension_session_ticket",
  "SSL::EXTENSIONS::ssl_extension_status_request",
  "SSL::EXTENSIONS::ssl_extension_ticket_pinning",
  "SSL::EXTENSIONS::ssl_extension_ticket_request",
  "SSL::EXTENSIONS::ssl_extension_truncated_hmac",
  "SSL::EXTENSIONS::ssl_extension_trusted_ca_keys",
  "SSL::EXTENSIONS::ssl_extension_ec_point_formats",
  "SSL::EXTENSIONS::ssl_extension_encrypt_then_mac",
  "SSL::EXTENSIONS::ssl_extension_external_id_hash",
  "SSL::EXTENSIONS::ssl_extension_supported_groups",
  "SSL::EXTENSIONS::ssl_extension_record_size_limit",
  "SSL::EXTENSIONS::ssl_extension_status_request_v2",
  "SSL::EXTENSIONS::ssl_extension_transparency_info",
  "SSL::EXTENSIONS::ssl_extension_key_share_reserved",
  "SSL::EXTENSIONS::ssl_extension_renegotiation_info",
  "SSL::EXTENSIONS::ssl_extension_supported_versions",
  "SSL::EXTENSIONS::ssl_extension_external_session_id",
  "SSL::EXTENSIONS::ssl_extension_max_fragment_length",
  "SSL::EXTENSIONS::ssl_extension_post_handshake_auth",
  "SSL::EXTENSIONS::ssl_extension_compress_certificate",
  "SSL::EXTENSIONS::ssl_extension_delegated_credential",
  "SSL::EXTENSIONS::ssl_extension_ech_outer_extensions",
  "SSL::EXTENSIONS::ssl_extension_signature_algorithms",
  "SSL::EXTENSIONS::ssl_extension_supported_ekt_ciphers",
  "SSL::EXTENSIONS::ssl_extension_client_certificate_url",
  "SSL::EXTENSIONS::ssl_extension_encrypted_client_hello",
  "SSL::EXTENSIONS::ssl_extension_extended_master_secret",
  "SSL::EXTENSIONS::ssl_extension_psk_key_exchange_modes",
  "SSL::EXTENSIONS::ssl_extension_certificate_authorities",
  "SSL::EXTENSIONS::ssl_extension_client_certificate_type",
  "SSL::EXTENSIONS::ssl_extension_server_certificate_type",
  "SSL::EXTENSIONS::ssl_extension_connection_id_deprecated",
  "SSL::EXTENSIONS::ssl_extension_tls_cert_with_extern_psk",
  "SSL::EXTENSIONS::ssl_extension_quic_transport_parameters",
  "SSL::EXTENSIONS::ssl_extension_signature_algorithms_cert",
  "SSL::EXTENSIONS::ssl_extension_signed_certificate_timestamp",
  "SSL::EXTENSIONS::ssl_extension_sequence_number_encryption_algorithms",
  "SSL::EXTENSIONS::ssl_extension_application_layer_protocol_negotiation"
);

event zeek_init()
	{
	generate_all_events();
	}

event new_event(name: string, params: call_argument_vector)
	{
	if ( name !in event_list )
		{
		return;
		}
	# c: connection, is_cleint: bool, val: any
	print fmt("%s:  %s;", name, params[2]$value);
	}
