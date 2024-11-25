# @TEST-EXEC: zeek -C -r /Traces/tls/ocsp-request-only.pcap $PACKAGE %INPUT >> output 2>&1
# @TEST-EXEC: btest-diff output



event zeek_init()
	{
	generate_all_events();
	}

event new_event(name: string, params: call_argument_vector)
	{
	if ( !starts_with(name, "SSL::EXTENSIONS::") )
		{
		return;
		}
	# c: connection, is_client: bool, val: any
	print fmt("%s:  %s;", name, params[2]$value);
	}
