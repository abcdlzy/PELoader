#include "stdafx.h"  
#include <iostream>
#include <fstream> 
#include "windows.h"
#include	"stdio.h"
#include	"stdlib.h"
#include	"math.h"
#include	"string.h"
#include	"conio.h"
#include	"time.h"
#include <vector>


#include "filters.h"
#include "bench.h"
#include "osrng.h"
#include "hex.h"
#include "modes.h"
#include "files.h"
#include "base64.h"
using namespace CryptoPP;
#pragma comment(lib, "cryptopp\\lib\\cryptlib.lib") 


using namespace std;
typedef IMAGE_SECTION_HEADER (*PIMAGE_SECTION_HEADERS)[1];   
  
// 计算对齐后的大小   
unsigned long GetAlignedSize(unsigned long Origin, unsigned long Alignment)   
{   
    return (Origin + Alignment - 1) / Alignment * Alignment;   
}   
  
// 计算加载pe并对齐需要占用多少内存   
// 未直接使用OptionalHeader.SizeOfImage作为结果是因为据说有的编译器生成的exe这个值会填0   
unsigned long CalcTotalImageSize(PIMAGE_DOS_HEADER MzH   
                                 , unsigned long FileLen   
                                 , PIMAGE_NT_HEADERS peH   
                                 , PIMAGE_SECTION_HEADERS peSecH)   
{   
    unsigned long res;   
    // 计算pe头的大小   
    res = GetAlignedSize( peH->OptionalHeader.SizeOfHeaders   
        , peH->OptionalHeader.SectionAlignment   
        );   
  
    // 计算所有节的大小   
    for( int i = 0; i < peH->FileHeader.NumberOfSections; ++i)   
    {   
        // 超出文件范围   
        if(peSecH[i]->PointerToRawData + peSecH[i]->SizeOfRawData > FileLen)   
            return 0;   
        else if(peSecH[i]->VirtualAddress)//计算对齐后某节的大小   
        {   
            if(peSecH[i]->Misc.VirtualSize)   
            {   
                res = GetAlignedSize( peSecH[i]->VirtualAddress + peSecH[i]->Misc.VirtualSize   
                    , peH->OptionalHeader.SectionAlignment   
                    );   
            }   
            else  
            {   
                res = GetAlignedSize( peSecH[i]->VirtualAddress + peSecH[i]->SizeOfRawData   
                    , peH->OptionalHeader.SectionAlignment   
                    );   
            }   
        }   
        else if( peSecH[i]->Misc.VirtualSize < peSecH[i]->SizeOfRawData )   
        {   
            res += GetAlignedSize( peSecH[i]->SizeOfRawData   
                , peH->OptionalHeader.SectionAlignment   
                );   
        }   
        else  
        {   
            res += GetAlignedSize( peSecH[i]->Misc.VirtualSize   
                , peH->OptionalHeader.SectionAlignment   
                );   
        }// if_else   
    }// for   
       
    return res;   
}   
  
  
  
  
// 加载pe到内存并对齐所有节   
BOOL AlignPEToMem( void *Buf   
                  , long Len   
                  , PIMAGE_NT_HEADERS &peH   
                  , PIMAGE_SECTION_HEADERS &peSecH   
                  , void *&Mem   
                  , unsigned long &ImageSize)   
{   
    PIMAGE_DOS_HEADER SrcMz;// DOS头   
    PIMAGE_NT_HEADERS SrcPeH;// PE头   
    PIMAGE_SECTION_HEADERS SrcPeSecH;// 节表   
       
    SrcMz = (PIMAGE_DOS_HEADER)Buf;   
  
    if( Len < sizeof(IMAGE_DOS_HEADER) )    
        return FALSE;   
       
    if( SrcMz->e_magic != IMAGE_DOS_SIGNATURE )   
        return FALSE;   
       
    if( Len < SrcMz->e_lfanew + (long)sizeof(IMAGE_NT_HEADERS) )   
        return FALSE;   
  
    SrcPeH = (PIMAGE_NT_HEADERS)((int)SrcMz + SrcMz->e_lfanew);   
    if( SrcPeH->Signature != IMAGE_NT_SIGNATURE )   
        return FALSE;   
  
    if( (SrcPeH->FileHeader.Characteristics & IMAGE_FILE_DLL) ||   
        (SrcPeH->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE == 0) ||   
        (SrcPeH->FileHeader.SizeOfOptionalHeader != sizeof(IMAGE_OPTIONAL_HEADER)) )   
    {   
        return FALSE;   
    }   
  
  
    SrcPeSecH = (PIMAGE_SECTION_HEADERS)((int)SrcPeH + sizeof(IMAGE_NT_HEADERS));   
    ImageSize = CalcTotalImageSize( SrcMz, Len, SrcPeH, SrcPeSecH);   
  
    if( ImageSize == 0 )   
        return FALSE;   
       
    Mem = VirtualAlloc( NULL, ImageSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE); // 分配内存   
    if( Mem != NULL )   
    {   
        // 计算需要复制的PE头字节数   
        unsigned long l = SrcPeH->OptionalHeader.SizeOfHeaders;   
        for( int i = 0; i < SrcPeH->FileHeader.NumberOfSections; ++i)   
        {   
            if( (SrcPeSecH[i]->PointerToRawData) &&   
                (SrcPeSecH[i]->PointerToRawData < l) )   
            {   
                l = SrcPeSecH[i]->PointerToRawData;   
            }   
        }   
        memmove( Mem, SrcMz, l);   
        peH = (PIMAGE_NT_HEADERS)((int)Mem + ((PIMAGE_DOS_HEADER)Mem)->e_lfanew);   
        peSecH = (PIMAGE_SECTION_HEADERS)((int)peH + sizeof(IMAGE_NT_HEADERS));   
  
        void *Pt = (void *)((unsigned long)Mem    
            + GetAlignedSize( peH->OptionalHeader.SizeOfHeaders   
            , peH->OptionalHeader.SectionAlignment)   
            );   
  int i;
        for(i = 0; i < peH->FileHeader.NumberOfSections; ++i)   
        {   
            // 定位该节在内存中的位置   
            if(peSecH[i]->VirtualAddress)   
                Pt = (void *)((unsigned long)Mem + peSecH[i]->VirtualAddress);   
  
            if(peSecH[i]->SizeOfRawData)   
            {   
                // 复制数据到内存   
                memmove(Pt, (const void *)((unsigned long)(SrcMz) + peSecH[i]->PointerToRawData), peSecH[i]->SizeOfRawData);   
                if(peSecH[i]->Misc.VirtualSize < peSecH[i]->SizeOfRawData)   
                    Pt = (void *)((unsigned long)Pt + GetAlignedSize(peSecH[i]->SizeOfRawData, peH->OptionalHeader.SectionAlignment));   
                else // pt 定位到下一节开始位置   
                    Pt = (void *)((unsigned long)Pt + GetAlignedSize(peSecH[i]->Misc.VirtualSize, peH->OptionalHeader.SectionAlignment));   
            }   
            else  
            {   
                Pt = (void *)((unsigned long)Pt + GetAlignedSize(peSecH[i]->Misc.VirtualSize, peH->OptionalHeader.SectionAlignment));   
            }   
        }   
    }   
    return TRUE;   
}   
  
  
  
typedef void *(__stdcall *pfVirtualAllocEx)(unsigned long, void *, unsigned long, unsigned long, unsigned long);   
pfVirtualAllocEx MyVirtualAllocEx = NULL;   
  
BOOL IsNT()   
{   
    return MyVirtualAllocEx!=NULL;   
}   
  
// 生成外壳程序命令行   
char *PrepareShellExe(char *CmdParam, unsigned long BaseAddr, unsigned long ImageSize)   
{   
    if(IsNT())   
    {   
        char *Buf = new char[256];   
        memset(Buf, 0, 256);   
        GetModuleFileName(0, Buf, 256);   
        strcat(Buf, CmdParam);   
        return Buf; // 请记得释放内存;-)   
    }   
    else  
    {   
        // Win98下的处理请参考原文;-)   
        // http://community.csdn.net/Expert/topic/4416/4416252.xml?temp=8.709133E-03   
        return NULL;   
    }   
}   
  
// 是否包含可重定向列表   
BOOL HasRelocationTable(PIMAGE_NT_HEADERS peH)   
{   
    return (peH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress)   
        && (peH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);   
}   
  
  
  
  
#pragma pack(push, 1)   
typedef struct{   
    unsigned long VirtualAddress;   
    unsigned long SizeOfBlock;   
} *PImageBaseRelocation;   
#pragma pack(pop)   
  
// 重定向PE用到的地址   
void DoRelocation(PIMAGE_NT_HEADERS peH, void *OldBase, void *NewBase)   
{   
    unsigned long Delta = (unsigned long)NewBase - peH->OptionalHeader.ImageBase;   
    PImageBaseRelocation p = (PImageBaseRelocation)((unsigned long)OldBase    
        + peH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);   
    while(p->VirtualAddress + p->SizeOfBlock)   
    {   
        unsigned short *pw = (unsigned short *)((int)p + sizeof(*p));   
        for(unsigned int i=1; i <= (p->SizeOfBlock - sizeof(*p)) / 2; ++i)   
        {   
            if((*pw) & 0xF000 == 0x3000){   
                unsigned long *t = (unsigned long *)((unsigned long)(OldBase) + p->VirtualAddress + ((*pw) & 0x0FFF));   
                *t += Delta;   
            }   
            ++pw;   
        }   
        p = (PImageBaseRelocation)pw;   
    }   
}   
  
// 卸载原外壳占用内存   
BOOL UnloadShell(HANDLE ProcHnd, unsigned long BaseAddr)   
{   
    typedef unsigned long (__stdcall *pfZwUnmapViewOfSection)(unsigned long, unsigned long);   
    pfZwUnmapViewOfSection ZwUnmapViewOfSection = NULL;   
    BOOL res = FALSE;   
    HMODULE m = LoadLibrary("ntdll.dll");   
    if(m){   
        ZwUnmapViewOfSection = (pfZwUnmapViewOfSection)GetProcAddress(m, "ZwUnmapViewOfSection");   
        if(ZwUnmapViewOfSection)   
            res = (ZwUnmapViewOfSection((unsigned long)ProcHnd, BaseAddr) == 0);   
        FreeLibrary(m);   
    }   
    return res;   
}   
  
// 创建外壳进程并获取其基址、大小和当前运行状态   
BOOL CreateChild(char *Cmd, CONTEXT &Ctx, HANDLE &ProcHnd, HANDLE &ThrdHnd,    
                 unsigned long &ProcId, unsigned long &BaseAddr, unsigned long &ImageSize)   
{   
    STARTUPINFOA si;   
    PROCESS_INFORMATION pi;   
    unsigned long old;   
    MEMORY_BASIC_INFORMATION MemInfo;   
    memset(&si, 0, sizeof(si));   
    memset(&pi, 0, sizeof(pi));   
    si.cb = sizeof(si);   
       
    BOOL res = CreateProcess(NULL, Cmd, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi); // 以挂起方式运行进程;   
    if(res){   
        ProcHnd = pi.hProcess;   
        ThrdHnd = pi.hThread;   
        ProcId = pi.dwProcessId;   
        // 获取外壳进程运行状态，[ctx.Ebx+8]内存处存的是外壳进程的加载基址，ctx.Eax存放有外壳进程的入口地址   
        Ctx.ContextFlags = CONTEXT_FULL;   
        GetThreadContext(ThrdHnd, &Ctx);   
        ReadProcessMemory(ProcHnd, (void *)(Ctx.Ebx+8), &BaseAddr, sizeof(unsigned long), &old); // 读取加载基址   
        void *p = (void *)BaseAddr;   
        // 计算外壳进程占有的内存   
        while(VirtualQueryEx(ProcHnd, p, &MemInfo, sizeof(MemInfo)))   
        {   
            if(MemInfo.State = MEM_FREE) break;   
            p = (void *)((unsigned long)p + MemInfo.RegionSize);   
        }   
        ImageSize = (unsigned long)p - (unsigned long)BaseAddr;   
    }   
    return res;   
}   
  
// 创建外壳进程并用目标进程替换它然后执行   
HANDLE AttachPE(char *CmdParam, PIMAGE_NT_HEADERS peH, PIMAGE_SECTION_HEADERS peSecH,    
                void *Ptr, unsigned long ImageSize, unsigned long &ProcId)   
{   
    HANDLE res = INVALID_HANDLE_VALUE;   
    CONTEXT Ctx;   
    HANDLE Thrd;   
    unsigned long Addr, Size;   
    char *s = PrepareShellExe(CmdParam, peH->OptionalHeader.ImageBase, ImageSize);   
    if(s==NULL) return res;   
    if(CreateChild(s, Ctx, res, Thrd, ProcId, Addr, Size)){   
        void *p = NULL;   
        unsigned long old;   
        if((peH->OptionalHeader.ImageBase == Addr) && (Size >= ImageSize)){// 外壳进程可以容纳目标进程并且加载地址一致   
            p = (void *)Addr;   
            VirtualProtectEx(res, p, Size, PAGE_EXECUTE_READWRITE, &old);   
        }   
        else if(IsNT()){   
            if(UnloadShell(res, Addr)){// 卸载外壳进程占有内存   
                p = MyVirtualAllocEx((unsigned long)res, (void *)peH->OptionalHeader.ImageBase, ImageSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);   
            }   
            if((p == NULL) && HasRelocationTable(peH)){// 分配内存失败并且目标进程支持重定向   
                p = MyVirtualAllocEx((unsigned long)res, NULL, ImageSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);   
                if(p) DoRelocation(peH, Ptr, p); // 重定向   
            }   
        }   
        if(p){   
            WriteProcessMemory(res, (void *)(Ctx.Ebx+8), &p, sizeof(DWORD), &old); // 重置目标进程运行环境中的基址   
            peH->OptionalHeader.ImageBase = (unsigned long)p;   
            if(WriteProcessMemory(res, p, Ptr, ImageSize, &old)){// 复制PE数据到目标进程   
                Ctx.ContextFlags = CONTEXT_FULL;   
                if((unsigned long)p == Addr)   
                    Ctx.Eax = peH->OptionalHeader.ImageBase + peH->OptionalHeader.AddressOfEntryPoint; // 重置运行环境中的入口地址   
                else  
                    Ctx.Eax = (unsigned long)p + peH->OptionalHeader.AddressOfEntryPoint;   
                SetThreadContext(Thrd, &Ctx);// 更新运行环境   
                ResumeThread(Thrd);// 执行   
                CloseHandle(Thrd);   
            }   
            else{// 加载失败,杀掉外壳进程   
                TerminateProcess(res, 0);   
                CloseHandle(Thrd);   
                CloseHandle(res);   
                res = INVALID_HANDLE_VALUE;   
            }   
        }   
        else{// 加载失败,杀掉外壳进程   
            TerminateProcess(res, 0);   
            CloseHandle(Thrd);   
            CloseHandle(res);   
            res = INVALID_HANDLE_VALUE;   
        }   
    }   
    delete[] s;   
    return res;   
}   
  
  
  
  
 /**//*******************************************************\  
{ ******************************************************* }  
{ *                 从内存中加载并运行exe               * }  
{ ******************************************************* }  
{ * 参数：                                                }  
{ * Buffer: 内存中的exe地址                               }  
{ * Len: 内存中exe占用长度                                }  
{ * CmdParam: 命令行参数(不包含exe文件名的剩余命令行参数）}  
{ * ProcessId: 返回的进程Id                               }  
{ * 返回值： 如果成功则返回进程的Handle(ProcessHandle),   }  
{            如果失败则返回INVALID_HANDLE_VALUE           }  
{ ******************************************************* }  
 \*******************************************************/  
HANDLE MemExecute(void *ABuffer, long Len, char *CmdParam, unsigned long *ProcessId)   
{   
    HANDLE res = INVALID_HANDLE_VALUE;   
    PIMAGE_NT_HEADERS peH;   
    PIMAGE_SECTION_HEADERS peSecH;   
    void *Ptr;   
    unsigned long peSz;   
    if(AlignPEToMem(ABuffer, Len, peH, peSecH, Ptr, peSz))   
    {   
        res = AttachPE(CmdParam, peH, peSecH, Ptr, peSz, *ProcessId);   
        VirtualFree(Ptr, peSz, MEM_DECOMMIT);   
    }   
    return res;   
}   
  
// 初始化   
class CInit   
{   
public:   
    CInit()   
    {   
        MyVirtualAllocEx = (pfVirtualAllocEx)GetProcAddress(GetModuleHandle("Kernel32.dll"), "VirtualAllocEx");   
    }   
}Init;   



void getcpuidex(unsigned int CPUInfo[4], unsigned int InfoType, unsigned int ECXValue)
{
#if defined(__GNUC__)    // GCC
    __cpuid_count(InfoType, ECXValue, CPUInfo[0],CPUInfo[1],CPUInfo[2],CPUInfo[3]);
#elif defined(_MSC_VER)    // MSVC
    #if defined(_WIN64) || _MSC_VER>=1600    // 64位下不支持内联汇编. 1600: VS2010, 据说VC2008 SP1之后才支持__cpuidex.
        __cpuidex((int*)(void*)CPUInfo, (int)InfoType, (int)ECXValue);
    #else
        if (NULL==CPUInfo)    return;
        _asm{
            // load. 读取参数到寄存器.
            mov edi, CPUInfo;    // 准备用edi寻址CPUInfo
            mov eax, InfoType;
            mov ecx, ECXValue;
            // CPUID
            cpuid;
            // save. 将寄存器保存到CPUInfo
            mov    [edi], eax;
            mov    [edi+4], ebx;
            mov    [edi+8], ecx;
            mov    [edi+12], edx;
        }
    #endif
#endif    // #if defined(__GNUC__)
}

void getcpuid(unsigned int CPUInfo[4], unsigned int InfoType)
{
#if defined(__GNUC__)    // GCC
    __cpuid(InfoType, CPUInfo[0],CPUInfo[1],CPUInfo[2],CPUInfo[3]);
#elif defined(_MSC_VER)    // MSVC
    #if _MSC_VER>=1400    // VC2005才支持__cpuid
        __cpuid((int*)(void*)CPUInfo, (int)InfoType);
    #else
        getcpuidex(CPUInfo, InfoType, 0);
    #endif
#endif    // #if defined(__GNUC__)
}

char* join(char *s1, char *s2)  
{  
    char *result = (char*)malloc(strlen(s1)+strlen(s2)+1);//+1 for the zero-terminator  
    //in real code you would check for errors in malloc here  
    if (result == NULL) exit (1);  
  
    strcpy(result, s1);  
    strcat(result, s2);  
  
    return result;  
}    



SecByteBlock HexDecodeString(const char *hex) {
	StringSource ss(hex, true, new HexDecoder);
	SecByteBlock result((size_t)ss.MaxRetrievable());
	ss.Get(result, result.size());
	return result;
}

void AES_CTR_Encrypt(unsigned char *hexKey,int keysize, unsigned char *hexIV, const char *infile, const char *outfile) {
	//SecByteBlock key = HexDecodeString(hexKey);
	//SecByteBlock iv = HexDecodeString(hexIV);

	//CTR_Mode<AES>::Encryption aes(key, key.size(), iv);
CTR_Mode<AES>::Encryption aes(hexKey, keysize, hexIV);

	FileSource(infile, true, new StreamTransformationFilter(aes, new FileSink(outfile)));
}

void AES_CTR_Decrypt(unsigned char *hexKey,int keysize, unsigned char *hexIV, const char *infile, const char *outfile) {
	//SecByteBlock key = HexDecodeString(hexKey);
	//SecByteBlock iv = HexDecodeString(hexIV);

	CTR_Mode<AES>::Decryption aes(hexKey, keysize, hexIV);

	FileSource(infile, true, new StreamTransformationFilter(aes, new FileSink(outfile)));
	
}



  


std::string encrypt(const std::string& str_in, const std::string& key, const std::string& iv)
{

    std::string str_out;
    CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption encryption((byte*)key.c_str(),    key.length(), (byte*)iv.c_str());
    CryptoPP::StringSource encryptor(str_in, true,
        new CryptoPP::StreamTransformationFilter(encryption,
            new CryptoPP::Base64Encoder(
                new CryptoPP::StringSink(str_out),
                false // do not append a newline
            )
        )
    );
    return str_out;
}


std::string decrypt(const std::string& str_in, const std::string& key, const std::string& iv)
{

    std::string str_out;    
    CryptoPP::CFB_Mode<CryptoPP::AES>::Decryption decryption((byte*)key.c_str(), key.length(), (byte*)iv.c_str());

    CryptoPP::StringSource decryptor(str_in, true,
        new CryptoPP::Base64Decoder(
            new CryptoPP::StreamTransformationFilter(decryption,
                new CryptoPP::StringSink(str_out)
            )
        )
    );
    return str_out;
}


int split(const string& str, vector<string>& ret_, string sep = "|")
{
    if (str.empty())
    {
        return 0;
    }

    string tmp;
    string::size_type pos_begin = str.find_first_not_of(sep);
    string::size_type comma_pos = 0;

    while (pos_begin != string::npos)
    {
        comma_pos = str.find(sep, pos_begin);
        if (comma_pos != string::npos)
        {
            tmp = str.substr(pos_begin, comma_pos - pos_begin);
            pos_begin = comma_pos + sep.length();
        }
        else
        {
            tmp = str.substr(pos_begin);
            pos_begin = comma_pos;
        }

        if (!tmp.empty())
        {
            ret_.push_back(tmp);
            tmp.clear();
        }
    }
    return 0;
}

int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,LPSTR     lpCmdLine,int       nCmdShow)   
{  
	/*
	//获取cpu id

	unsigned int dwBuf[4];
	getcpuid(dwBuf, 0);
	char s[80];
	char s1[80];
	char s2[80];
	char* result;
	itoa(dwBuf[1],s,16);
	itoa(dwBuf[2],s1,16);
	itoa(dwBuf[3],s2,16);
	result=join(s,s1);
	result=join(result,s2);
	string resultstr=result;



	//获取当前系统时间
	time_t rawtime;
	time ( &rawtime );

	//asctime (timeinfo)
	char nowtime[80];
	ltoa(rawtime,nowtime,10);

	string nowtimestr=nowtime;

	string authkey="123456789abcdef";
	string authiv="123456789abcdef";

	//认证
	char authbuffer[65535];  
   ifstream in("auth");  
   if (! in.is_open())  
   { 
		//没有找到认证文件
	   string tempmsg="请把程序安装目录下的reg发送给注册提供方或截图当前界面\ncode:  "+resultstr;
	   MessageBox(NULL, tempmsg.c_str(),"没有发现注册信息",0);
	   ofstream out("reg");  
		if (out.is_open())   
		{  
		 out <<result;  
		 out.close();  
		}  
		return 0;

   }
   else
   {

	   while (!in.eof() )  
	   {  
		   in.getline (authbuffer,4096);  
		   cout << authbuffer << endl;  
	   }  
   }
string authbufferStr=authbuffer;
string deAuthStr=decrypt(authbufferStr,authkey,authiv);

if(deAuthStr.length()!=0){
	vector<string> vt;
    split(deAuthStr, vt);

	if(vt[0]!="auth"){
		MessageBox(NULL, "认证信息异常","",0);
		return 0;
	}
	if(vt[1]!=resultstr){
		MessageBox(NULL, "认证信息不能用于此计算机,认证失败","",0);
		return 0;
	}
	if(atoi(vt[2].c_str())<atoi(nowtime)){
		MessageBox(NULL, "超过使用期限","",0);
		return 0;
	}
}
else
{
	MessageBox(NULL, "解析失败","",0);
	return 0;
}



//get temp dir
char sztempdirectory[MAX_PATH];
 int i = GetTempPath(MAX_PATH - 1, sztempdirectory);
 if (sztempdirectory[i - 1] != '\\')
  {
   lstrcat(sztempdirectory, "\\");
  }
char *tempfile=join(sztempdirectory,"temp.file");
*/
unsigned char key[]	= {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	0x00,0x00, 0x00,0x00,0x00,0x00,0x00,0x00};//AES::DEFAULT_KEYLENGTH
	unsigned char iv[]	= {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, 0x00,0x00, 0x00,0x00,0x00,0x00,0x00,0x00};


AES_CTR_Encrypt(key,16,iv,"firefox.exe","encexe");
/*
AES_CTR_Decrypt(key,16,iv,"encexe",tempfile);


//MessageBox(NULL, "","",0);
	
    filebuf *pbuf;  
  ifstream filestr;  
  long size;  
  char * buffer;  
  // 要读入整个文件，必须采用二进制打开   
  filestr.open (tempfile, ios::binary);  
  // 获取filestr对应buffer对象的指针   
  pbuf=filestr.rdbuf();  
    
  // 调用buffer对象方法获取文件大小  
  size=pbuf->pubseekoff (0,ios::end,ios::in);  
  pbuf->pubseekpos (0,ios::in);  
     
  // 分配内存空间  
  buffer=new char[size];  
     
  // 获取文件内容  
  pbuf->sgetn (buffer,size);  
    
  filestr.close();  


FILE *pFile = fopen(tempfile, //打开文件的名称
                    "w"); // 文件打开方式 如果原来有内容也会销毁
//向文件写数据
fwrite ("start", //要输入的文字
         1,//文字每一项的大小 以为这里是字符型的 就设置为1 如果是汉字就设置为4
         5, //单元个数 我们也可以直接写5
         pFile //我们刚刚获得到的地址
         );

fflush(pFile); //数据刷新 数据立即更新 
fclose(pFile); //告诉系统我们文件写完了数据更新，但是我们要要重新打开才能在写

// 输出到标准输出  
    unsigned long ulProcessId = 0;   
    MemExecute( buffer, size, "", &ulProcessId);   
  delete []buffer;  

*/
  return 0; 
        
}   