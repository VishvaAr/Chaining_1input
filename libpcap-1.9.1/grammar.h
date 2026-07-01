/* A Bison parser, made by GNU Bison 3.8.2.  */

/* Bison interface for Yacc-like parsers in C

   Copyright (C) 1984, 1989-1990, 2000-2015, 2018-2021 Free Software Foundation,
   Inc.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.

   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */

/* DO NOT RELY ON FEATURES THAT ARE NOT DOCUMENTED in the manual,
   especially those whose name start with YY_ or yy_.  They are
   private implementation details that can be changed or removed.  */

#ifndef YY_PCAP_GRAMMAR_H_INCLUDED
# define YY_PCAP_GRAMMAR_H_INCLUDED
/* Debug traces.  */
#ifndef YYDEBUG
# define YYDEBUG 0
#endif
#if YYDEBUG
extern int pcap_debug;
#endif

/* Token kinds.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
  enum yytokentype
  {
    YYEMPTY = -2,
    YYEOF = 0,                     /* "end of file"  */
    YYerror = 256,                 /* error  */
    YYUNDEF = 257,                 /* "invalid token"  */
    DST = 258,                     /* DST  */
    SRC = 259,                     /* SRC  */
    HOST = 260,                    /* HOST  */
    GATEWAY = 261,                 /* GATEWAY  */
    NET = 262,                     /* NET  */
    NETMASK = 263,                 /* NETMASK  */
    PORT = 264,                    /* PORT  */
    PORTRANGE = 265,               /* PORTRANGE  */
    LESS = 266,                    /* LESS  */
    GREATER = 267,                 /* GREATER  */
    PROTO = 268,                   /* PROTO  */
    PROTOCHAIN = 269,              /* PROTOCHAIN  */
    CBYTE = 270,                   /* CBYTE  */
    ARP = 271,                     /* ARP  */
    RARP = 272,                    /* RARP  */
    IP = 273,                      /* IP  */
    SCTP = 274,                    /* SCTP  */
    TCP = 275,                     /* TCP  */
    UDP = 276,                     /* UDP  */
    ICMP = 277,                    /* ICMP  */
    IGMP = 278,                    /* IGMP  */
    IGRP = 279,                    /* IGRP  */
    PIM = 280,                     /* PIM  */
    VRRP = 281,                    /* VRRP  */
    CARP = 282,                    /* CARP  */
    ATALK = 283,                   /* ATALK  */
    AARP = 284,                    /* AARP  */
    DECNET = 285,                  /* DECNET  */
    LAT = 286,                     /* LAT  */
    SCA = 287,                     /* SCA  */
    MOPRC = 288,                   /* MOPRC  */
    MOPDL = 289,                   /* MOPDL  */
    TK_BROADCAST = 290,            /* TK_BROADCAST  */
    TK_MULTICAST = 291,            /* TK_MULTICAST  */
    NUM = 292,                     /* NUM  */
    INBOUND = 293,                 /* INBOUND  */
    OUTBOUND = 294,                /* OUTBOUND  */
    PF_IFNAME = 295,               /* PF_IFNAME  */
    PF_RSET = 296,                 /* PF_RSET  */
    PF_RNR = 297,                  /* PF_RNR  */
    PF_SRNR = 298,                 /* PF_SRNR  */
    PF_REASON = 299,               /* PF_REASON  */
    PF_ACTION = 300,               /* PF_ACTION  */
    TYPE = 301,                    /* TYPE  */
    SUBTYPE = 302,                 /* SUBTYPE  */
    DIR = 303,                     /* DIR  */
    ADDR1 = 304,                   /* ADDR1  */
    ADDR2 = 305,                   /* ADDR2  */
    ADDR3 = 306,                   /* ADDR3  */
    ADDR4 = 307,                   /* ADDR4  */
    RA = 308,                      /* RA  */
    TA = 309,                      /* TA  */
    LINK = 310,                    /* LINK  */
    GEQ = 311,                     /* GEQ  */
    LEQ = 312,                     /* LEQ  */
    NEQ = 313,                     /* NEQ  */
    ID = 314,                      /* ID  */
    EID = 315,                     /* EID  */
    HID = 316,                     /* HID  */
    HID6 = 317,                    /* HID6  */
    AID = 318,                     /* AID  */
    LSH = 319,                     /* LSH  */
    RSH = 320,                     /* RSH  */
    LEN = 321,                     /* LEN  */
    IPV6 = 322,                    /* IPV6  */
    ICMPV6 = 323,                  /* ICMPV6  */
    AH = 324,                      /* AH  */
    ESP = 325,                     /* ESP  */
    VLAN = 326,                    /* VLAN  */
    MPLS = 327,                    /* MPLS  */
    PPPOED = 328,                  /* PPPOED  */
    PPPOES = 329,                  /* PPPOES  */
    GENEVE = 330,                  /* GENEVE  */
    ISO = 331,                     /* ISO  */
    ESIS = 332,                    /* ESIS  */
    CLNP = 333,                    /* CLNP  */
    ISIS = 334,                    /* ISIS  */
    L1 = 335,                      /* L1  */
    L2 = 336,                      /* L2  */
    IIH = 337,                     /* IIH  */
    LSP = 338,                     /* LSP  */
    SNP = 339,                     /* SNP  */
    CSNP = 340,                    /* CSNP  */
    PSNP = 341,                    /* PSNP  */
    STP = 342,                     /* STP  */
    IPX = 343,                     /* IPX  */
    NETBEUI = 344,                 /* NETBEUI  */
    LANE = 345,                    /* LANE  */
    LLC = 346,                     /* LLC  */
    METAC = 347,                   /* METAC  */
    BCC = 348,                     /* BCC  */
    SC = 349,                      /* SC  */
    ILMIC = 350,                   /* ILMIC  */
    OAMF4EC = 351,                 /* OAMF4EC  */
    OAMF4SC = 352,                 /* OAMF4SC  */
    OAM = 353,                     /* OAM  */
    OAMF4 = 354,                   /* OAMF4  */
    CONNECTMSG = 355,              /* CONNECTMSG  */
    METACONNECT = 356,             /* METACONNECT  */
    VPI = 357,                     /* VPI  */
    VCI = 358,                     /* VCI  */
    RADIO = 359,                   /* RADIO  */
    FISU = 360,                    /* FISU  */
    LSSU = 361,                    /* LSSU  */
    MSU = 362,                     /* MSU  */
    HFISU = 363,                   /* HFISU  */
    HLSSU = 364,                   /* HLSSU  */
    HMSU = 365,                    /* HMSU  */
    SIO = 366,                     /* SIO  */
    OPC = 367,                     /* OPC  */
    DPC = 368,                     /* DPC  */
    SLS = 369,                     /* SLS  */
    HSIO = 370,                    /* HSIO  */
    HOPC = 371,                    /* HOPC  */
    HDPC = 372,                    /* HDPC  */
    HSLS = 373,                    /* HSLS  */
    LEX_ERROR = 374,               /* LEX_ERROR  */
    OR = 375,                      /* OR  */
    AND = 376,                     /* AND  */
    UMINUS = 377                   /* UMINUS  */
  };
  typedef enum yytokentype yytoken_kind_t;
#endif
/* Token kinds.  */
#define YYEMPTY -2
#define YYEOF 0
#define YYerror 256
#define YYUNDEF 257
#define DST 258
#define SRC 259
#define HOST 260
#define GATEWAY 261
#define NET 262
#define NETMASK 263
#define PORT 264
#define PORTRANGE 265
#define LESS 266
#define GREATER 267
#define PROTO 268
#define PROTOCHAIN 269
#define CBYTE 270
#define ARP 271
#define RARP 272
#define IP 273
#define SCTP 274
#define TCP 275
#define UDP 276
#define ICMP 277
#define IGMP 278
#define IGRP 279
#define PIM 280
#define VRRP 281
#define CARP 282
#define ATALK 283
#define AARP 284
#define DECNET 285
#define LAT 286
#define SCA 287
#define MOPRC 288
#define MOPDL 289
#define TK_BROADCAST 290
#define TK_MULTICAST 291
#define NUM 292
#define INBOUND 293
#define OUTBOUND 294
#define PF_IFNAME 295
#define PF_RSET 296
#define PF_RNR 297
#define PF_SRNR 298
#define PF_REASON 299
#define PF_ACTION 300
#define TYPE 301
#define SUBTYPE 302
#define DIR 303
#define ADDR1 304
#define ADDR2 305
#define ADDR3 306
#define ADDR4 307
#define RA 308
#define TA 309
#define LINK 310
#define GEQ 311
#define LEQ 312
#define NEQ 313
#define ID 314
#define EID 315
#define HID 316
#define HID6 317
#define AID 318
#define LSH 319
#define RSH 320
#define LEN 321
#define IPV6 322
#define ICMPV6 323
#define AH 324
#define ESP 325
#define VLAN 326
#define MPLS 327
#define PPPOED 328
#define PPPOES 329
#define GENEVE 330
#define ISO 331
#define ESIS 332
#define CLNP 333
#define ISIS 334
#define L1 335
#define L2 336
#define IIH 337
#define LSP 338
#define SNP 339
#define CSNP 340
#define PSNP 341
#define STP 342
#define IPX 343
#define NETBEUI 344
#define LANE 345
#define LLC 346
#define METAC 347
#define BCC 348
#define SC 349
#define ILMIC 350
#define OAMF4EC 351
#define OAMF4SC 352
#define OAM 353
#define OAMF4 354
#define CONNECTMSG 355
#define METACONNECT 356
#define VPI 357
#define VCI 358
#define RADIO 359
#define FISU 360
#define LSSU 361
#define MSU 362
#define HFISU 363
#define HLSSU 364
#define HMSU 365
#define SIO 366
#define OPC 367
#define DPC 368
#define SLS 369
#define HSIO 370
#define HOPC 371
#define HDPC 372
#define HSLS 373
#define LEX_ERROR 374
#define OR 375
#define AND 376
#define UMINUS 377

/* Value type.  */
#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
union YYSTYPE
{
#line 291 "grammar.y"

	int i;
	bpf_u_int32 h;
	char *s;
	struct stmt *stmt;
	struct arth *a;
	struct {
		struct qual q;
		int atmfieldtype;
		int mtp3fieldtype;
		struct block *b;
	} blk;
	struct block *rblk;

#line 326 "grammar.h"

};
typedef union YYSTYPE YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define YYSTYPE_IS_DECLARED 1
#endif




int pcap_parse (void *yyscanner, compiler_state_t *cstate);


#endif /* !YY_PCAP_GRAMMAR_H_INCLUDED  */
