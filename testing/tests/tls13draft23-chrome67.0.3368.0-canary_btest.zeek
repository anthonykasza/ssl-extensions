# @TEST-EXEC: zeek -C -r /Traces/tls/tls13draft23-chrome67.0.3368.0-canary.pcap $PACKAGE %INPUT >> output 2>&1
# @TEST-EXEC: btest-diff output

@load ../../tests/event-list

event zeek_init()
	{
	generate_all_events();
	}

event new_event(name: string, params: call_argument_vector)
	{
	if ( name !in SSL::EXTENSIONS::TESTS::event_list )
		{
		return;
		}
	# c: connection, is_cleint: bool, val: any
	print fmt("%s:  %s;", name, params[2]$value);
	}
