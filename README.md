# f5_ssl_cipher_report
Python script that generates list of VIPs, associated profiles, and cipher string/list for SSL profiles in use

Usage:

python3 f5_ssl_scan.py --host *host* --username *username* --password *password* [--csv *output_filename.csv*] [--fullciphers] [--verbose]

Sample output:

```
Found Client SSL profile: clientssl
 -> Ciphers: DEFAULT
 -> Retreiving complete cipher list
Found Client SSL profile: clientssl-insecure-compatible
 -> Ciphers: !SSLv2:ALL:!DH:!ADH:!EDH:@SPEED
 -> Retreiving complete cipher list
Found Client SSL profile: clientssl-secure
 -> Ciphers: ecdhe:rsa:!sslv3:!rc4:!exp:!des
 -> Retreiving complete cipher list
Found Client SSL profile: crypto-server-default-clientssl
 -> Ciphers: DHE-RSA-AES256-GCM-SHA384
 -> Retreiving complete cipher list
Found Client SSL profile: greg_example_1
 -> Ciphers: !TLSv1:ECDHE
 -> Retreiving complete cipher list
Found Client SSL profile: greg_example_2
 -> Ciphers: !EDH:RSA
 -> Retreiving complete cipher list
Found Client SSL profile: wom-default-clientssl
 -> Ciphers: DEFAULT
 -> Retreiving complete cipher list
Found Server SSL profile: apm-default-serverssl
 -> Ciphers: DEFAULT
 -> Retreiving complete cipher list
Found Server SSL profile: crypto-client-default-serverssl
 -> Ciphers: DHE-RSA-AES256-GCM-SHA384
 -> Retreiving complete cipher list
Found Server SSL profile: greg_example_4
 -> Ciphers: ECDHE:!RSA
 -> Retreiving complete cipher list
Found Server SSL profile: pcoip-default-serverssl
 -> Ciphers: DEFAULT
 -> Retreiving complete cipher list
Found Server SSL profile: serverssl
 -> Ciphers: DEFAULT
 -> Retreiving complete cipher list
Found Server SSL profile: serverssl-insecure-compatible
 -> Ciphers: !SSLv2:!EXPORT:!DH:RSA+RC4:RSA+AES:RSA+DES:RSA+3DES:ECDHE+AES:ECDHE+3DES:@SPEED
 -> Retreiving complete cipher list
Found Server SSL profile: wom-default-serverssl
 -> Ciphers: DEFAULT
 -> Retreiving complete cipher list
************************************************************************************************************************
Virtual server found: greg_example_1
************************************************************************************************************************
 -> Profile found: greg_example_1 (Context: clientside)
   -> Cipher string: !TLSv1:ECDHE
   -> Complete cipher list: 
       ID  SUITE                            BITS PROT    METHOD  CIPHER    MAC     KEYX
 0: 49200  ECDHE-RSA-AES256-GCM-SHA384      256  TLS1.2  Native  AES-GCM   SHA384  ECDHE_RSA 
 1: 49192  ECDHE-RSA-AES256-SHA384          256  TLS1.2  Native  AES       SHA384  ECDHE_RSA 
 2: 49172  ECDHE-RSA-AES256-CBC-SHA         256  TLS1.1  Native  AES       SHA     ECDHE_RSA 
 3: 49172  ECDHE-RSA-AES256-CBC-SHA         256  TLS1.2  Native  AES       SHA     ECDHE_RSA 
 4: 49170  ECDHE-RSA-DES-CBC3-SHA           168  TLS1.1  Native  DES       SHA     ECDHE_RSA 
 5: 49170  ECDHE-RSA-DES-CBC3-SHA           168  TLS1.2  Native  DES       SHA     ECDHE_RSA 
 6: 49199  ECDHE-RSA-AES128-GCM-SHA256      128  TLS1.2  Native  AES-GCM   SHA256  ECDHE_RSA 
 7: 49191  ECDHE-RSA-AES128-SHA256          128  TLS1.2  Native  AES       SHA256  ECDHE_RSA 
 8: 49171  ECDHE-RSA-AES128-CBC-SHA         128  TLS1.1  Native  AES       SHA     ECDHE_RSA 
 9: 49171  ECDHE-RSA-AES128-CBC-SHA         128  TLS1.2  Native  AES       SHA     ECDHE_RSA 

 -> Profile found: tcp (Context: all)
   -> Non-SSL Profile
*************************
* END OF VIRTUAL SERVER *
*************************
************************************************************************************************************************
Virtual server found: greg_example_2
************************************************************************************************************************
 -> Profile found: greg_example_2 (Context: clientside)
   -> Cipher string: !EDH:RSA
   -> Complete cipher list: 
       ID  SUITE                            BITS PROT    METHOD  CIPHER    MAC     KEYX
 0:   157  AES256-GCM-SHA384                256  TLS1.2  Native  AES-GCM   SHA384  RSA       
 1:    61  AES256-SHA256                    256  TLS1.2  Native  AES       SHA256  RSA       
 2:    53  AES256-SHA                       256  SSL3    Native  AES       SHA     RSA       
 3:    53  AES256-SHA                       256  TLS1    Native  AES       SHA     RSA       
 4:    53  AES256-SHA                       256  TLS1.1  Native  AES       SHA     RSA       
 5:    53  AES256-SHA                       256  TLS1.2  Native  AES       SHA     RSA       
 6:    53  AES256-SHA                       256  DTLS1   Native  AES       SHA     RSA       
 7:    10  DES-CBC3-SHA                     168  SSL3    Native  DES       SHA     RSA       
 8:    10  DES-CBC3-SHA                     168  TLS1    Native  DES       SHA     RSA       
 9:    10  DES-CBC3-SHA                     168  TLS1.1  Native  DES       SHA     RSA       
10:    10  DES-CBC3-SHA                     168  TLS1.2  Native  DES       SHA     RSA       
11:    10  DES-CBC3-SHA                     168  DTLS1   Native  DES       SHA     RSA       
12:   156  AES128-GCM-SHA256                128  TLS1.2  Native  AES-GCM   SHA256  RSA       
13:    60  AES128-SHA256                    128  TLS1.2  Native  AES       SHA256  RSA       
14:    47  AES128-SHA                       128  SSL3    Native  AES       SHA     RSA       
15:    47  AES128-SHA                       128  TLS1    Native  AES       SHA     RSA       
16:    47  AES128-SHA                       128  TLS1.1  Native  AES       SHA     RSA       
17:    47  AES128-SHA                       128  TLS1.2  Native  AES       SHA     RSA       
18:    47  AES128-SHA                       128  DTLS1   Native  AES       SHA     RSA       
19:     5  RC4-SHA                          128  SSL3    Native  RC4       SHA     RSA       
20:     5  RC4-SHA                          128  TLS1    Native  RC4       SHA     RSA       
21:     5  RC4-SHA                          128  TLS1.1  Native  RC4       SHA     RSA       
22:     5  RC4-SHA                          128  TLS1.2  Native  RC4       SHA     RSA       
23:     4  RC4-MD5                          128  SSL3    Native  RC4       MD5     RSA       
24:     4  RC4-MD5                          128  TLS1    Native  RC4       MD5     RSA       
25:     4  RC4-MD5                          128  TLS1.1  Native  RC4       MD5     RSA       
26:     4  RC4-MD5                          128  TLS1.2  Native  RC4       MD5     RSA       
27:     9  DES-CBC-SHA                       64  SSL3    Native  DES       SHA     RSA       
28:     9  DES-CBC-SHA                       64  TLS1    Native  DES       SHA     RSA       
29:     9  DES-CBC-SHA                       64  TLS1.1  Native  DES       SHA     RSA       
30:     9  DES-CBC-SHA                       64  DTLS1   Native  DES       SHA     RSA       
31:    98  EXP1024-DES-CBC-SHA               56  SSL3    Native  DES       SHA     RSA       
32:    98  EXP1024-DES-CBC-SHA               56  TLS1    Native  DES       SHA     RSA       
33:    98  EXP1024-DES-CBC-SHA               56  DTLS1   Native  DES       SHA     RSA       
34:   100  EXP1024-RC4-SHA                   56  SSL3    Native  RC4       SHA     RSA       
35:   100  EXP1024-RC4-SHA                   56  TLS1    Native  RC4       SHA     RSA       
36:     8  EXP-DES-CBC-SHA                   40  SSL3    Native  DES       SHA     RSA       
37:     8  EXP-DES-CBC-SHA                   40  TLS1    Native  DES       SHA     RSA       
38:     8  EXP-DES-CBC-SHA                   40  DTLS1   Native  DES       SHA     RSA       
39:     3  EXP-RC4-MD5                       40  SSL3    Native  RC4       MD5     RSA       
40:     3  EXP-RC4-MD5                       40  TLS1    Native  RC4       MD5     RSA       
41:   132  CAMELLIA256-SHA                  256  TLS1    Native  CAMELLIA  SHA     RSA       
42:   132  CAMELLIA256-SHA                  256  TLS1.1  Native  CAMELLIA  SHA     RSA       
43:   132  CAMELLIA256-SHA                  256  TLS1.2  Native  CAMELLIA  SHA     RSA       
44:    65  CAMELLIA128-SHA                  128  TLS1    Native  CAMELLIA  SHA     RSA       
45:    65  CAMELLIA128-SHA                  128  TLS1.1  Native  CAMELLIA  SHA     RSA       
46:    65  CAMELLIA128-SHA                  128  TLS1.2  Native  CAMELLIA  SHA     RSA       

 -> Profile found: http (Context: all)
   -> Non-SSL Profile
 -> Profile found: oneconnect (Context: all)
   -> Non-SSL Profile
 -> Profile found: tcp (Context: all)
   -> Non-SSL Profile
*************************
* END OF VIRTUAL SERVER *
*************************
************************************************************************************************************************
Virtual server found: greg_example_3
************************************************************************************************************************
 -> Profile found: clientssl-secure (Context: clientside)
   -> Cipher string: ecdhe:rsa:!sslv3:!rc4:!exp:!des
   -> Complete cipher list: 
       ID  SUITE                            BITS PROT    METHOD  CIPHER    MAC     KEYX
 0: 49200  ECDHE-RSA-AES256-GCM-SHA384      256  TLS1.2  Native  AES-GCM   SHA384  ECDHE_RSA 
 1: 49192  ECDHE-RSA-AES256-SHA384          256  TLS1.2  Native  AES       SHA384  ECDHE_RSA 
 2: 49172  ECDHE-RSA-AES256-CBC-SHA         256  TLS1    Native  AES       SHA     ECDHE_RSA 
 3: 49172  ECDHE-RSA-AES256-CBC-SHA         256  TLS1.1  Native  AES       SHA     ECDHE_RSA 
 4: 49172  ECDHE-RSA-AES256-CBC-SHA         256  TLS1.2  Native  AES       SHA     ECDHE_RSA 
 5: 49170  ECDHE-RSA-DES-CBC3-SHA           168  TLS1    Native  DES       SHA     ECDHE_RSA 
 6: 49170  ECDHE-RSA-DES-CBC3-SHA           168  TLS1.1  Native  DES       SHA     ECDHE_RSA 
 7: 49170  ECDHE-RSA-DES-CBC3-SHA           168  TLS1.2  Native  DES       SHA     ECDHE_RSA 
 8: 49199  ECDHE-RSA-AES128-GCM-SHA256      128  TLS1.2  Native  AES-GCM   SHA256  ECDHE_RSA 
 9: 49191  ECDHE-RSA-AES128-SHA256          128  TLS1.2  Native  AES       SHA256  ECDHE_RSA 
10: 49171  ECDHE-RSA-AES128-CBC-SHA         128  TLS1    Native  AES       SHA     ECDHE_RSA 
11: 49171  ECDHE-RSA-AES128-CBC-SHA         128  TLS1.1  Native  AES       SHA     ECDHE_RSA 
12: 49171  ECDHE-RSA-AES128-CBC-SHA         128  TLS1.2  Native  AES       SHA     ECDHE_RSA 
13:   157  AES256-GCM-SHA384                256  TLS1.2  Native  AES-GCM   SHA384  RSA       
14:    61  AES256-SHA256                    256  TLS1.2  Native  AES       SHA256  RSA       
15:    53  AES256-SHA                       256  TLS1    Native  AES       SHA     RSA       
16:    53  AES256-SHA                       256  TLS1.1  Native  AES       SHA     RSA       
17:    53  AES256-SHA                       256  TLS1.2  Native  AES       SHA     RSA       
18:    53  AES256-SHA                       256  DTLS1   Native  AES       SHA     RSA       
19:    10  DES-CBC3-SHA                     168  TLS1    Native  DES       SHA     RSA       
20:    10  DES-CBC3-SHA                     168  TLS1.1  Native  DES       SHA     RSA       
21:    10  DES-CBC3-SHA                     168  TLS1.2  Native  DES       SHA     RSA       
22:    10  DES-CBC3-SHA                     168  DTLS1   Native  DES       SHA     RSA       
23:   156  AES128-GCM-SHA256                128  TLS1.2  Native  AES-GCM   SHA256  RSA       
24:    60  AES128-SHA256                    128  TLS1.2  Native  AES       SHA256  RSA       
25:    47  AES128-SHA                       128  TLS1    Native  AES       SHA     RSA       
26:    47  AES128-SHA                       128  TLS1.1  Native  AES       SHA     RSA       
27:    47  AES128-SHA                       128  TLS1.2  Native  AES       SHA     RSA       
28:    47  AES128-SHA                       128  DTLS1   Native  AES       SHA     RSA       
29:   132  CAMELLIA256-SHA                  256  TLS1    Native  CAMELLIA  SHA     RSA       
30:   132  CAMELLIA256-SHA                  256  TLS1.1  Native  CAMELLIA  SHA     RSA       
31:   132  CAMELLIA256-SHA                  256  TLS1.2  Native  CAMELLIA  SHA     RSA       
32:    65  CAMELLIA128-SHA                  128  TLS1    Native  CAMELLIA  SHA     RSA       
33:    65  CAMELLIA128-SHA                  128  TLS1.1  Native  CAMELLIA  SHA     RSA       
34:    65  CAMELLIA128-SHA                  128  TLS1.2  Native  CAMELLIA  SHA     RSA       

 -> Profile found: tcp (Context: all)
   -> Non-SSL Profile
*************************
* END OF VIRTUAL SERVER *
*************************
************************************************************************************************************************
Virtual server found: greg_example_4
************************************************************************************************************************
 -> Profile found: greg_example_4 (Context: serverside)
   -> Cipher string: ECDHE:!RSA
   -> Complete cipher list: 
       ID  SUITE                            BITS PROT    METHOD  CIPHER    MAC     KEYX
 0: 49200  ECDHE-RSA-AES256-GCM-SHA384      256  TLS1.2  Native  AES-GCM   SHA384  ECDHE_RSA 
 1: 49192  ECDHE-RSA-AES256-SHA384          256  TLS1.2  Native  AES       SHA384  ECDHE_RSA 
 2: 49172  ECDHE-RSA-AES256-CBC-SHA         256  TLS1    Native  AES       SHA     ECDHE_RSA 
 3: 49172  ECDHE-RSA-AES256-CBC-SHA         256  TLS1.1  Native  AES       SHA     ECDHE_RSA 
 4: 49172  ECDHE-RSA-AES256-CBC-SHA         256  TLS1.2  Native  AES       SHA     ECDHE_RSA 
 5: 49170  ECDHE-RSA-DES-CBC3-SHA           168  TLS1    Native  DES       SHA     ECDHE_RSA 
 6: 49170  ECDHE-RSA-DES-CBC3-SHA           168  TLS1.1  Native  DES       SHA     ECDHE_RSA 
 7: 49170  ECDHE-RSA-DES-CBC3-SHA           168  TLS1.2  Native  DES       SHA     ECDHE_RSA 
 8: 49199  ECDHE-RSA-AES128-GCM-SHA256      128  TLS1.2  Native  AES-GCM   SHA256  ECDHE_RSA 
 9: 49191  ECDHE-RSA-AES128-SHA256          128  TLS1.2  Native  AES       SHA256  ECDHE_RSA 
10: 49171  ECDHE-RSA-AES128-CBC-SHA         128  TLS1    Native  AES       SHA     ECDHE_RSA 
11: 49171  ECDHE-RSA-AES128-CBC-SHA         128  TLS1.1  Native  AES       SHA     ECDHE_RSA 
12: 49171  ECDHE-RSA-AES128-CBC-SHA         128  TLS1.2  Native  AES       SHA     ECDHE_RSA

 -> Profile found: tcp (Context: all)
   -> Non-SSL Profile
*************************
* END OF VIRTUAL SERVER *
*************************
```
