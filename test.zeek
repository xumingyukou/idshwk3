global maap : table[addr] of set[string] = table();
event http_header (c: connection, is_orig: bool,name: string,value: string)
{
	if(name=="USER-AGENT")
	{
		if(c$id$orig_h in maap)
		{
			if(!(to_lower(value) in maap[c$id$orig_h]))
			{
				add maap[c$id$orig_h][to_lower(value)];
			}
		}
		else
		{
			maap[c$id$orig_h]=set(to_lower(value));
		}
	}
}
event zeek_done()
{
	for (Addr, Set in maap)
	{
		if(|Set|>=3)
		{
			print fmt("%s i a proxy",Addr);
		}
	}
}
