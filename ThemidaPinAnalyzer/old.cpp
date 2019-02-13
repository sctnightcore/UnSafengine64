
	if (addr >= main_txt_saddr && addr < main_txt_eaddr)
	{
		// find OEP and then near OEP
		// Debugger stops when HWBP is set on OEP
		// but HWBP on near OEP works well
		if (oep == 0) {
			set_meblock(addr);
			if (get_mwblock(addr) && get_meblock(addr) == 1)
			{
				if (oep == 0)
				{
					oep = addr;
					*fout << "OEP:" << toHex(oep - main_img_saddr) << endl;
					
					PIN_SemaphoreSet(&sem_oep_found);					
					LOG("Main Thread: Waiting sem_unpack_finished\n");					
					PIN_SemaphoreWait(&sem_unpack_finished);
					LOG("Main Thread: Waiting sem_dump_finished\n");
					PIN_SemaphoreWait(&sem_dump_finished);
				}
			}
		}
		// near OEP is the address of the first call instruction 
		else {
			if (isCheckAPIStart || isCheckAPIRunning || isCheckAPIEnd) return;
			for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
				for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {
					ADDRINT taddr = INS_Address(ins);
					if (taddr < main_txt_saddr || taddr > main_txt_eaddr) continue;
					if (INS_IsCall(ins)) {
						// oep = INS_Address(ins);
						oep = BBL_Address(bbl);
						*fout << "NEAR OEP:" << toHex(oep - main_img_saddr) << endl;						
						return;
					}
				}
			}
		}
		return;
	}