global agentTable: table[addr] of set[string] = table();
event agent_count(c: connection, is_orig: bool, name: string, value: string)
{
  	local ip :addr = c$id$orig_h;
	if(name=="USER-AGENT")
	{
	if(ip !in agentTable)
		agentTable[ip]=set(to_lower(value));
	else
		add agentTable[ip][to_lower(value)];
	}
}

event zeek_done()
{
	for(ip in agentTable)
	{
		if(|agentTable[ip]|>=3)
		print fmt("%s is a proxy",ip);
	}
} 