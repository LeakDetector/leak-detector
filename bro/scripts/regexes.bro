module regexes;

global title_set: set[string];


export {
    redef enum Log::ID += { LOG };

    type Info: record {
		ts:			time	&log;
		tag:		string	&log;
		data:		string	&log;
        };
	
	type Regex: record {
		tag:		string;
		regex:		pattern;
	};
    }


event bro_init()
    {
    Log::create_stream(LOG, [$columns=Info]);
    }
 
event http_entity_data(c: connection, is_orig: bool, length: count, data: string)
    {

		local patterns: vector of Regex = vector(
			[$tag="email", $regex=/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,4}/],
			[$tag="phone", $regex=/\(?[0-9]{3}\)?[-. ][0-9]{3}[-. ][0-9]{4}/],
			[$tag="welcome", $regex=/[Ww]elcome[,:]? [a-zA-Z0-9@]+/],
			[$tag="hi", $regex=/[Hh]i[,:]? [a-zA-Z0-9@]+/]
		);
                

		for (i in patterns) {
			local match_result:PatternMatchResult = match_pattern(data, patterns[i]$regex);

        	if ( match_result$matched ) {

				Log::write( regexes::LOG, [$ts=network_time(),
										   $tag=patterns[i]$tag,
										  $data=match_result$str] );
        	}

		}
    }
