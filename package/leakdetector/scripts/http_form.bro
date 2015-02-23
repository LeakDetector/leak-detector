module http_form;

export {
    redef enum Log::ID += { LOG };

    type Info: record {
			ts:			time	&log;
			host:		string	&log; 
			uri:		string  &log;
			formdata:	string	&log &optional;
    };
	
}
event bro_init()
{
    Log::create_stream(LOG, [$columns=Info]);
}

event http_entity_data(c: connection, is_orig: bool, length: count, data: string ){
    if ( is_orig && c$http$method == "POST" )

		Log::write( http_form::LOG, [$ts=network_time(),
								  $host=c$http$host,
								  $uri=c$http$uri,
								  $formdata=data]);
}