/**
 * Copyright (C) 2012 Malwasm Developers.
 * This file is part of Malwasm - https://code.google.com/p/malwasm/
 * See the file LICENSE for copying permission.
 *                  _                             
 *  _ __ ___   __ _| |_      ____ _ ___ _ __ ___  
 * | '_ ` _ \ / _` | \ \ /\ / / _` / __| '_ ` _ \
 * | | | | | | (_| | |\ V  V / (_| \__ \ | | | | |
 * |_| |_| |_|\__,_|_| \_/\_/ \__,_|___/_| |_| |_|
 */
#include "pin.H"
#include "instlib.H"
#include "portability.H"

#ifdef _WIN32
	#include <direct.h> // _mkdir windows
namespace W{
	#include <windows.h>
}
#else
	#include <sys/stat.h>
	#include <sys/types.h>
#endif

#include <iostream>
#include <iomanip>
#include <fstream>
#include <sstream>

using namespace INSTLIB;

/* ===================================================================== */
/* Commandline Switches */
/* ===================================================================== */
KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
		    "o", "malwpin.xml", "trace file");
KNOB<string> KnobAdrStart(KNOB_MODE_WRITEONCE, "pintool",
		    "adr-start", "0", "trace file");
KNOB<string> KnobAdrStop(KNOB_MODE_WRITEONCE, "pintool",
		    "adr-stop", "0", "trace file");
KNOB<string> KnobOutputDirStack(KNOB_MODE_WRITEONCE, "pintool",
		    "s", "memory\\", "Folder for dump");
KNOB<string> KnobNinstruct(KNOB_MODE_WRITEONCE, "pintool",
		    "n", "0", "Number of instruction to trace (default all)");


typedef struct {
	unsigned long cpt;

	ADDRINT dump_adr_write; // Flag that we need to dump on a write
	ADDRINT dump_adr_read;  // Flag that we need to dump on a read
	ADDRINT stack_end;  // Flag that we need to dump on a read
	ADDRINT is_jmp;         // if dif from 0 resolve the name

	bool dump_all;
	bool run;
}s_thread_data;

typedef struct {
        ADDRINT start;
        ADDRINT end;
        ADDRINT cur;
        INT32 type;
}s_mem_track;

typedef struct {
	string name;
	ADDRINT start;
	ADDRINT end;
} s_img;


/* ===================================================================== */
/* Global Variables */
/* ===================================================================== */
LOCALVAR std::ofstream out;
LOCALVAR FILTER filter;
LOCALVAR ICOUNT icount;
LOCALVAR int first = 0;

// Used to start/stop for an address
LOCALVAR ADDRINT adr_start = 0;
LOCALVAR ADDRINT adr_stop = 0;

// N instruction
LOCALVAR unsigned int max_ins = 0;

LOCALVAR INT32 numThreads = 0;
LOCALVAR const INT32 MaxNumThreads = 10000;
LOCALVAR s_thread_data td[MaxNumThreads];

LOCALVAR INT32 numMem = 0;
LOCALVAR const INT32 MaxNumMem = 10000;
LOCALVAR s_mem_track  mt[MaxNumMem];

LOCALVAR INT32 numImg = 0;
LOCALVAR const INT32 MaxNumImg = 10000;
LOCALVAR s_img  imgs[MaxNumImg];

LOCALVAR bool true_start;

PIN_LOCK lock;


INT32 Usage(){
    cerr << "malwasm pintool" << endl;
    cerr << KNOB_BASE::StringKnobSummary();
    cerr << endl;
    return -1;
}

void save_dump(unsigned int id, 
			unsigned int thread_id, 
			s_mem_track *mem, 
            string dump)
{
	string type = "data";
	
	GetLock(&lock, thread_id);

	out << "<" << type << ">"
		<< "<id>" << setbase(10) << id << "</id>"
		<< "<thread>" <<  setbase(10) << thread_id << "</thread>" 
		<< "<start>" << mem->start << "</start>"
		<< "<end>" << mem->end << "</end>"
		<< "<cur>" << mem->cur << "</cur>"
		<< "</" << type <<  ">" << endl;
	
	ReleaseLock(&lock);

	std::ofstream fp;
	std::stringstream str_filename;
	str_filename << KnobOutputDirStack.Value() << type  << "_" 
		<< id << "_" << thread_id << "_" << mem->start  << ".dmp";

	std::string filename =  str_filename.str();

	fp.open(filename.c_str(), ios::out | ios::binary);
	fp.write(dump.c_str(), dump.length());
	fp.close();
}

s_mem_track *get_mem(ADDRINT addr)
{
	INT32 i = 0;
	for(i=0; i < numMem; ++i){
		if(mt[i].start <= addr && addr <= mt[i].end)
			return (s_mem_track *)&mt[i];
	}
	return NULL;
}

s_img *get_img(ADDRINT addr)
{
	INT32 i = 1;
	for(i=1; i < numMem; ++i){
		if(imgs[i].start <= addr && addr < imgs[i].end)
			return (s_img *)&imgs[i];
	}
	return NULL;
}

void img_load(IMG img, VOID *v)
{
	ASSERT(numImg < MaxNumImg, "Maximum number of images exceeded\n");

	imgs[numImg].name = IMG_Name(img);
	imgs[numImg].start = IMG_StartAddress(img);
	imgs[numImg].end = IMG_HighAddress(img);
	numImg++;

/*	
    out << "<imgload>" << hex
		<< "<name>" << IMG_Name(img) << "</name>"
		<< "<start>" << IMG_StartAddress(img) << "</start>"
		<< "<end>" << IMG_HighAddress(img)  << "</end>"
		<< "</imgload>" << endl << dec;
*/	
}

void img_unload(IMG img, VOID *v)
{
	//out << "<imgunload>" << IMG_Name(img) << "</imgunload>" << endl;
}


s_mem_track *insert_mem(ADDRINT addr)
{
	ASSERT(numMem < MaxNumMem, "Maximum number of memory tracked exceeded\n");
	char value[4];
	ADDRINT cur = addr;
	size_t r;

	PIN_LockClient();
	RTN rtn = RTN_FindByAddress(addr);
	PIN_UnlockClient();

	if (RTN_Valid(rtn)){
		IMG_TYPE t = IMG_Type(SEC_Img(RTN_Sec(rtn)));
		if(t ==  LEVEL_CORE::IMG_TYPE_SHAREDLIB) return NULL;
	}
	if(get_img(addr) != NULL){
		return NULL;
	}

	W::MEMORY_BASIC_INFORMATION mbi;
	W::VirtualQuery((VOID*)addr, &mbi, sizeof(mbi));

	//if(mbi.Type != MEM_IMAGE){
		//return NULL;
	//}

	// Guess the beginning
	mt[numMem].start = (ADDRINT)mbi.BaseAddress;

	// Guess the end
	mt[numMem].end = mt[numMem].start + mbi.RegionSize;

	if(mt[numMem].start == 0){
		cout << "mem_dump error is 0" << endl;
		return NULL;
	}


/*	
	out << "<memtrack>" << hex 
		<< "<ask>" << addr << "</ask>"
		<< "<start>" << mt[numMem].start << "</start>" 
		<< "<end>" << mt[numMem].end <<  "</end>" 
		<< "<type>" << mt[numMem].type << "</type>"
		<< "</memtrack>" << endl << dec;
*/	
	

	numMem++;

	return (s_mem_track *)&mt[numMem-1];
}

#define DUMP_CHUNK 1024

void dump_mem(unsigned long id, INT32 thread_id, s_mem_track *mem){
	ADDRINT i;
	char value[DUMP_CHUNK];
	size_t r = 0;
	stringstream s(ios_base::out|ios_base::in|ios_base::binary);

	for(i=mem->start; i<mem->end; i += DUMP_CHUNK){
		EXCEPTION_INFO ExceptInfo;
		r = PIN_SafeCopyEx(&value, (VOID*)i, DUMP_CHUNK, &ExceptInfo);
		if(r == 0){
			cout << "error during dump ";
				break;
		}
		s.write(value, r);
	}
	save_dump(id, thread_id, mem, s.str());
}



bool has_to_run(THREADID threadid, ADDRINT addr = 0)
{
	if(addr != 0){
		if (adr_start == addr){
			td[threadid].run = true;
		}

		// Include the adr_stop	
		if (adr_stop == addr){
			td[threadid].run = false;
		}
	}
	return td[threadid].run;
}


VOID thread_start(THREADID threadid, CONTEXT *ctxt, INT32 flags, VOID *v)
{
	GetLock(&lock, threadid+1);
	numThreads++;
	ReleaseLock(&lock);


	if(adr_start != 0){
		td[threadid].run = false; 
	}else{
		td[threadid].run = true; 
	}

	td[threadid].cpt = 0;
	td[threadid].dump_adr_write = 0;
	td[threadid].dump_adr_read = 0;
	td[threadid].stack_end = 0;
	td[threadid].is_jmp = 0;
	td[threadid].dump_all = false;

	ASSERT(numThreads <= MaxNumThreads, "Maximum number of threads exceeded\n");
}


/**
* Given a fully qualified path to a file, this function extracts the raw
* filename and gets rid of the path.
* source: https://github.com/zynamics/pin-tools/blob/master/shellcode.cpp
**/
string extract_filename(const string& filename)
{
#ifdef _WIN32
	int lastBackslash = filename.rfind("\\"); // WINDOWS case
#else
	int lastBackslash = filename.rfind("/"); // linux case
#endif

	if (lastBackslash == -1){
		return filename;
	}else{
		return filename.substr(lastBackslash + 1);
	}
}

string format_address(RTN rtn, ADDRINT eip)
{
	string s;
    if (RTN_Valid(rtn)){
        s = extract_filename(IMG_Name(SEC_Img(RTN_Sec(rtn)))) + ":";
        s += RTN_Name(rtn);

        ADDRINT delta = eip - RTN_Address(rtn);
        if (delta != 0){
            s += "+" + hexstr(delta, 4);
        }
    }
    return s;
}

VOID printreg(THREADID threadid,
		INS ins, TRACE trace, string *name, 
		string *inst, string *comment,
		ADDRINT eip, ADDRINT eax, ADDRINT ebx, 
		ADDRINT ecx, ADDRINT edx, ADDRINT edi, 
		ADDRINT esi, ADDRINT ebp, ADDRINT esp,
		ADDRINT eflags)
{
	if(td[threadid].dump_all){
		if(td[threadid].dump_adr_read){
			s_mem_track *m = get_mem(td[threadid].dump_adr_read);
			if (m == NULL){
				m = insert_mem(td[threadid].dump_adr_read);
			}
		}

		if(td[threadid].dump_adr_write){
			s_mem_track *m = get_mem(td[threadid].dump_adr_write);
			if (m == NULL){
				m = insert_mem(td[threadid].dump_adr_write);
			}
		}

		if(has_to_run(threadid, eip)) {
			INT32 i = 0;
			for(i=0; i < numMem; ++i){
				dump_mem(td[threadid].cpt, threadid, &mt[i]);
			}
		}
		td[threadid].dump_all = false;
		td[threadid].dump_adr_read = 0;
		td[threadid].dump_adr_write = 0;
	}

	// Dump check part
	if(td[threadid].dump_adr_read){
		s_mem_track *m = get_mem(td[threadid].dump_adr_read);
		if (m == NULL){
			m = insert_mem(td[threadid].dump_adr_read);
			if( m != NULL){
				m->cur = td[threadid].dump_adr_read;
				if(has_to_run(threadid, eip)) 
					dump_mem(td[threadid].cpt, threadid, m);
			}
		}
	}

	if(td[threadid].dump_adr_write){
		s_mem_track *m = get_mem(td[threadid].dump_adr_write);
		if (m == NULL){
			m = insert_mem(td[threadid].dump_adr_write);
			if( m == NULL){
				cout << "error!" << endl;
			}
		}
		if(m && has_to_run(threadid, eip)){
			m->cur = td[threadid].dump_adr_write;
			dump_mem(td[threadid].cpt, threadid, m);
		}
	}

	td[threadid].dump_adr_read = 0;
	td[threadid].dump_adr_write = 0;
	
	if(!has_to_run(threadid, eip)) return;

	// Fix comment for IAT  
	string comment2;

	if (td[threadid].is_jmp){
		PIN_LockClient();
		comment2 = format_address(RTN_FindByAddress(td[threadid].is_jmp), td[threadid].is_jmp);
		td[threadid].is_jmp = 0;
		PIN_UnlockClient();
	}else{
		comment2 = *comment;
	}
	
	GetLock(&lock, threadid);

	//out << setbase(10)
	out << "<ins>" 
		<< "<id>" << td[threadid].cpt << "</id>"
		<< "<thread>" << threadid << "</thread>" 
		<< "<asm>" << *inst << "</asm>" 
		<< "<name>" << *name << "</name>" 
		<< "<comment>" << comment2 << "</comment>"
		<< "<reg>" 
		<< "<eax>" << eax << "</eax>" 
		<< "<ebx>" << ebx << "</ebx>" 
		<< "<ecx>" << ecx << "</ecx>" 
		<< "<edx>" << edx << "</edx>" 
		<< "<edi>" << edi << "</edi>" 
		<< "<esi>" << esi << "</esi>" 
		<< "<ebp>" << ebp << "</ebp>" 
		<< "<esp>" << esp << "</esp>" 
		<< "<eflags>" << eflags << "</eflags>" 
		<< "<eip>" << eip << "</eip>" 
		<< "</reg>" 
		<< "</ins>" << endl;
	
	ReleaseLock(&lock);

	++td[threadid].cpt;
}

void emit_jmp(THREADID threadid, VOID * ea)
{
	PIN_SafeCopy(&td[threadid].is_jmp, static_cast<UINT32*>(ea), 4);
}

void emit_memory_write(THREADID threadid, ADDRINT adr)
{
	td[threadid].dump_adr_write = adr;
}

void emit_memory_read(THREADID threadid, ADDRINT adr)
{
	td[threadid].dump_adr_read = adr;
}

void emit_jmp_reg(THREADID threadid, CONTEXT *ctxt, ADDRINT adr)
{
	td[threadid].is_jmp  = adr;
}

void emit_memory_api(THREADID threadid, ADDRINT adr)
{
	bool isMain = (imgs[0].start <= adr && adr < imgs[0].end);
	s_mem_track *m = get_mem(adr);

	if (m == NULL){
		if (isMain){
			m = insert_mem(adr);
			if( m == NULL){
				cout << "error!" << endl;
			}
		}
	}else{
		td[threadid].dump_all  = true;
	}
}

string call_trace(TRACE trace, INS ins)
{
    string s = "";

    if (INS_IsCall(ins) && !INS_IsDirectBranchOrCall(ins)){
        // Indirect call
		if(INS_MaxNumRRegs(ins)){
			REG r = INS_RegR(ins, 0);
			INS_InsertPredicatedCall(ins, IPOINT_BEFORE, 
					AFUNPTR(emit_jmp_reg), IARG_THREAD_ID, IARG_CONTEXT,
					IARG_REG_VALUE, r, IARG_END);
		}else{
			s = "call " + format_address(INS_Rtn(ins), INS_Address(ins));
		}
    }
    else if (INS_IsDirectBranchOrCall(ins)){
        // Is this a tail call?
        RTN sourceRtn = INS_Rtn(ins);
        RTN destRtn = RTN_FindByAddress(INS_DirectBranchOrCallTargetAddress(ins));

        if (INS_IsCall(ins) || sourceRtn != destRtn ){
		   	// conventional call or tail call
            BOOL tailcall = !INS_IsCall(ins);
            
            if (tailcall) {
                s += "tailcall ";
            }else 
			{
                if( INS_IsProcedureCall(ins) )
					s += "call ";
                else {
                    s += "pcMaterialization ";
                    tailcall=1;
                }
                
            }
			ADDRINT target = INS_DirectBranchOrCallTargetAddress(ins);    
			s += format_address(RTN_FindByAddress(target), target); 
        }else // is jmp
		{
            ADDRINT target = INS_DirectBranchOrCallTargetAddress(ins);
			s = "jmp " + format_address(RTN_FindByAddress(target), target); 
		}
	}else if (INS_IsRet(ins))
    {
        RTN rtn =  INS_Rtn(ins);
        
#if defined(TARGET_LINUX) && defined(TARGET_IA32)
        if( RTN_Valid(rtn) && RTN_Name(rtn) ==  "_dl_runtime_resolve") 
			return s;
#endif
		s = "return " + format_address(rtn, INS_Address(ins));
    }
    else if (INS_IsBranchOrCall(ins)){
		if (INS_IsMemoryRead(ins)){
			INS_InsertPredicatedCall(ins, IPOINT_BEFORE, 
				AFUNPTR(emit_jmp), IARG_THREAD_ID, 
				IARG_MEMORYREAD_EA, IARG_END);
		}else if(INS_MaxNumRRegs(ins)){
			REG r = INS_RegR(ins, 0);
			INS_InsertPredicatedCall(ins, IPOINT_BEFORE, 
					AFUNPTR(emit_jmp_reg), IARG_THREAD_ID, IARG_CONTEXT,
					IARG_REG_VALUE, r, IARG_END);
		}
		
	}
	return s;
}


void instruction_trace(TRACE trace, INS ins)
{
    ADDRINT addr = INS_Address(ins);
    ASSERTX(addr);
	
	if (!filter.SelectTrace(trace))
		return;
  	
	string name = "";
	string comment = "";
	IMG im = IMG_FindByAddress(INS_Address(ins));
	int inMain = IMG_Valid(im) ? IMG_IsMainExecutable(im) : 0;

	if (inMain){
		name = format_address(INS_Rtn(ins), INS_Address(ins));
		comment = call_trace(trace, ins);
	}

	string inst = INS_Disassemble(ins);

    if (INS_HasFallThrough(ins)){
        INS_InsertCall(ins, 
			IPOINT_AFTER,
			(AFUNPTR)printreg,
			IARG_THREAD_ID,
			IARG_PTR, ins,
			IARG_PTR, trace,
			IARG_PTR, new string(name),
			IARG_PTR, new string(inst),
			IARG_PTR, new string(comment),
			IARG_UINT32, INS_Address(ins), // EIP
			IARG_REG_VALUE, REG_EAX,
			IARG_REG_VALUE, REG_EBX,
			IARG_REG_VALUE, REG_ECX,
			IARG_REG_VALUE, REG_EDX,
			IARG_REG_VALUE, REG_EDI,
			IARG_REG_VALUE, REG_ESI,
			IARG_REG_VALUE, REG_EBP,
			IARG_REG_VALUE, REG_ESP,
			IARG_REG_VALUE, REG_EFLAGS,
			IARG_END
		);
    }

    if (INS_IsBranchOrCall(ins)){
		INS_InsertCall(ins, 
			IPOINT_TAKEN_BRANCH,
			(AFUNPTR)printreg,
			IARG_THREAD_ID,
			IARG_PTR, ins,
			IARG_PTR, trace,
			IARG_PTR, new string(name),
			IARG_PTR, new string(inst),
			IARG_PTR, new string(comment),
			IARG_UINT32, INS_Address(ins), // EIP
			IARG_REG_VALUE, REG_EAX,
			IARG_REG_VALUE, REG_EBX,
			IARG_REG_VALUE, REG_ECX,
			IARG_REG_VALUE, REG_EDX,
			IARG_REG_VALUE, REG_EDI,
			IARG_REG_VALUE, REG_ESI,
			IARG_REG_VALUE, REG_EBP,
			IARG_REG_VALUE, REG_ESP,
			IARG_REG_VALUE, REG_EFLAGS,
			IARG_END
		);
    }
    
	if (INS_IsMemoryWrite(ins)){
        INS_InsertCall(ins, 
				IPOINT_BEFORE, 
				AFUNPTR(emit_memory_write), 
				IARG_THREAD_ID,
				IARG_MEMORYWRITE_EA, 
				IARG_END);
	}
	if (INS_IsMemoryRead(ins)){
        INS_InsertCall(ins, 
				IPOINT_BEFORE, 
				AFUNPTR(emit_memory_read), 
				IARG_THREAD_ID,
				IARG_MEMORYREAD_EA, 
				IARG_END);
	}
}

void instruction_trace_api(TRACE trace, INS ins)
{
    ADDRINT addr = INS_Address(ins);
    ASSERTX(addr);
	
	if (!filter.SelectTrace(trace))
		return;

	if (INS_IsMemoryWrite(ins)){
        INS_InsertCall(ins, 
				IPOINT_BEFORE, 
				AFUNPTR(emit_memory_api), 
				IARG_THREAD_ID,
				IARG_MEMORYWRITE_EA, 
				IARG_END);
	}

	if (INS_IsMemoryRead(ins)){
        INS_InsertCall(ins, 
				IPOINT_BEFORE, 
				AFUNPTR(emit_memory_api), 
				IARG_THREAD_ID,
				IARG_MEMORYREAD_EA, 
				IARG_END);
	}
}

void trace(TRACE trace, VOID *v)
{
	for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)){
		for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)){

			IMG im = IMG_FindByAddress(INS_Address(ins));
			int inMain = IMG_Valid(im) ? IMG_IsMainExecutable(im) : 0;
			s_mem_track *mem = get_mem(INS_Address(ins));

			//if(true_start == false){
				//if(inMain){
					//out << "<run/>" << endl;
					//true_start = true;
				//}else{
					//return;
				//}
			//}

			// If is not a instruction in the main executable or
			// not a tracked mem
			if(!inMain && mem == NULL){
				instruction_trace_api(trace, ins);
			}else{
				instruction_trace(trace, ins);
			}
		}
	}
}


void fini(INT32 code, VOID *v)
{
    //out << "</info>" <<  endl;
    out.close();
}

int main(int argc, char *argv[]){
	PIN_InitSymbols();

    if( PIN_Init(argc,argv) ){
        return Usage();
    }

	InitLock(&lock);

	true_start = false;

	stringstream ss, ss2;
	ss << hex << KnobAdrStart.Value();
	ss >> adr_start;
	ss2 << hex << KnobAdrStop.Value();
	ss2 >> adr_stop;

	istringstream (KnobNinstruct.Value() ) >> max_ins;

	string dir =  KnobOutputDirStack.Value();
#ifdef _WIN32
	_mkdir(dir.c_str());
#else
	umask(0);
	mkdir(dir.c_str(), 0755);
#endif

	string filename =  KnobOutputFile.Value();
	out.open(filename.c_str());
    out << dec << right;	// format settings
	out << "<info>" <<  endl;
    out.setf(ios::showbase);

    IMG_AddInstrumentFunction(img_load, 0);
    IMG_AddUnloadFunction(img_unload, 0);

	TRACE_AddInstrumentFunction(trace, 0);
	PIN_AddFiniFunction(fini, 0);
	
	PIN_AddThreadStartFunction(thread_start, 0);

    
	filter.Activate();
    icount.Activate();

	PIN_StartProgram();
}

