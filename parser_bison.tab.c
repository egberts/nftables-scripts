/* A Bison parser, made by GNU Bison 3.8.2.  */

/* Bison implementation for Yacc-like parsers in C

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

/* C LALR(1) parser skeleton written by Richard Stallman, by
   simplifying the original so-called "semantic" parser.  */

/* DO NOT RELY ON FEATURES THAT ARE NOT DOCUMENTED in the manual,
   especially those whose name start with YY_ or yy_.  They are
   private implementation details that can be changed or removed.  */

/* All symbols defined below should begin with yy or YY, to avoid
   infringing on user name space.  This should be done even for local
   variables, as they might otherwise be expanded by user macros.
   There are some unavoidable exceptions within include files to
   define necessary library symbols; they are noted "INFRINGES ON
   USER NAME SPACE" below.  */

/* Identify Bison output, and Bison version.  */
#define YYBISON 30802

/* Bison version string.  */
#define YYBISON_VERSION "3.8.2"

/* Skeleton name.  */
#define YYSKELETON_NAME "yacc.c"

/* Pure parsers.  */
#define YYPURE 1

/* Push parsers.  */
#define YYPUSH 0

/* Pull parsers.  */
#define YYPULL 1

/* Substitute the type names.  */
#define YYSTYPE         NFT_STYPE
#define YYLTYPE         NFT_LTYPE
/* Substitute the variable and function names.  */
#define yyparse         nft_parse
#define yylex           nft_lex
#define yyerror         nft_error
#define yydebug         nft_debug
#define yynerrs         nft_nerrs

/* First part of user prologue.  */
#line 11 "../../nft/nftables/src/parser_bison.y"


#include <ctype.h>
#include <stddef.h>
#include <stdio.h>
#include <inttypes.h>
#include <syslog.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter/nf_conntrack_tuple_common.h>
#include <linux/netfilter/nf_nat.h>
#include <linux/netfilter/nf_log.h>
#include <linux/netfilter/nfnetlink_osf.h>
#include <linux/netfilter/nf_synproxy.h>
#include <linux/xfrm.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <libnftnl/common.h>
#include <libnftnl/set.h>
#include <libnftnl/udata.h>

#include <rule.h>
#include <statement.h>
#include <expression.h>
#include <headers.h>
#include <utils.h>
#include <parser.h>
#include <erec.h>
#include <sctp_chunk.h>

#include "parser_bison.h"

void parser_init(struct nft_ctx *nft, struct parser_state *state,
		 struct list_head *msgs, struct list_head *cmds,
		 struct scope *top_scope)
{
	memset(state, 0, sizeof(*state));
	state->msgs = msgs;
	state->cmds = cmds;
	state->scopes[0] = scope_init(top_scope, NULL);
	init_list_head(&state->indesc_list);
}

static void yyerror(struct location *loc, struct nft_ctx *nft, void *scanner,
		    struct parser_state *state, const char *s)
{
	erec_queue(error(loc, "%s", s), state->msgs);
}

static struct scope *current_scope(const struct parser_state *state)
{
	return state->scopes[state->scope];
}

static int open_scope(struct parser_state *state, struct scope *scope)
{
	if (state->scope >= array_size(state->scopes) - 1) {
		state->scope_err = true;
		return -1;
	}

	scope_init(scope, current_scope(state));
	state->scopes[++state->scope] = scope;

	return 0;
}

static void close_scope(struct parser_state *state)
{
	if (state->scope_err) {
		state->scope_err = false;
		return;
	}

	assert(state->scope > 0);
	state->scope--;
}

static void location_init(void *scanner, struct parser_state *state,
			  struct location *loc)
{
	memset(loc, 0, sizeof(*loc));
	loc->indesc = state->indesc;
}

static void location_update(struct location *loc, struct location *rhs, int n)
{
	if (n) {
		loc->indesc       = rhs[n].indesc;
		loc->token_offset = rhs[1].token_offset;
		loc->line_offset  = rhs[1].line_offset;
		loc->first_line   = rhs[1].first_line;
		loc->first_column = rhs[1].first_column;
		loc->last_line    = rhs[n].last_line;
		loc->last_column  = rhs[n].last_column;
	} else {
		loc->indesc       = rhs[0].indesc;
		loc->token_offset = rhs[0].token_offset;
		loc->line_offset  = rhs[0].line_offset;
		loc->first_line   = loc->last_line   = rhs[0].last_line;
		loc->first_column = loc->last_column = rhs[0].last_column;
	}
}

static struct expr *handle_concat_expr(const struct location *loc,
					 struct expr *expr,
					 struct expr *expr_l, struct expr *expr_r,
					 struct location loc_rhs[3])
{
	if (expr->etype != EXPR_CONCAT) {
		expr = concat_expr_alloc(loc);
		compound_expr_add(expr, expr_l);
	} else {
		location_update(&expr_r->location, loc_rhs, 2);

		expr = expr_l;
		expr->location = *loc;
	}

	compound_expr_add(expr, expr_r);
	return expr;
}

static bool already_set(const void *attr, const struct location *loc,
			struct parser_state *state)
{
	if (!attr)
		return false;

	erec_queue(error(loc, "You can only specify this once. This statement is duplicated."),
		   state->msgs);
	return true;
}

#define YYLLOC_DEFAULT(Current, Rhs, N)	location_update(&Current, Rhs, N)

#define symbol_value(loc, str) \
	symbol_expr_alloc(loc, SYMBOL_VALUE, current_scope(state), str)

/* Declare those here to avoid compiler warnings */
void nft_set_debug(int, void *);
int nft_lex(void *, void *, void *);

#line 225 "parser_bison.tab.c"

# ifndef YY_CAST
#  ifdef __cplusplus
#   define YY_CAST(Type, Val) static_cast<Type> (Val)
#   define YY_REINTERPRET_CAST(Type, Val) reinterpret_cast<Type> (Val)
#  else
#   define YY_CAST(Type, Val) ((Type) (Val))
#   define YY_REINTERPRET_CAST(Type, Val) ((Type) (Val))
#  endif
# endif
# ifndef YY_NULLPTR
#  if defined __cplusplus
#   if 201103L <= __cplusplus
#    define YY_NULLPTR nullptr
#   else
#    define YY_NULLPTR 0
#   endif
#  else
#   define YY_NULLPTR ((void*)0)
#  endif
# endif


/* Debug traces.  */
#ifndef NFT_DEBUG
# if defined YYDEBUG
#if YYDEBUG
#   define NFT_DEBUG 1
#  else
#   define NFT_DEBUG 0
#  endif
# else /* ! defined YYDEBUG */
#  define NFT_DEBUG 1
# endif /* ! defined YYDEBUG */
#endif  /* ! defined NFT_DEBUG */
#if NFT_DEBUG
extern int nft_debug;
#endif

/* Token kinds.  */
#ifndef NFT_TOKENTYPE
# define NFT_TOKENTYPE
  enum nft_tokentype
  {
    NFT_EMPTY = -2,
    TOKEN_EOF = 0,                 /* "end of file"  */
    NFT_error = 256,               /* error  */
    NFT_UNDEF = 257,               /* "invalid token"  */
    JUNK = 258,                    /* "junk"  */
    NEWLINE = 259,                 /* "newline"  */
    COLON = 260,                   /* "colon"  */
    SEMICOLON = 261,               /* "semicolon"  */
    COMMA = 262,                   /* "comma"  */
    DOT = 263,                     /* "."  */
    EQ = 264,                      /* "=="  */
    NEQ = 265,                     /* "!="  */
    LT = 266,                      /* "<"  */
    GT = 267,                      /* ">"  */
    GTE = 268,                     /* ">="  */
    LTE = 269,                     /* "<="  */
    LSHIFT = 270,                  /* "<<"  */
    RSHIFT = 271,                  /* ">>"  */
    AMPERSAND = 272,               /* "&"  */
    CARET = 273,                   /* "^"  */
    NOT = 274,                     /* "!"  */
    SLASH = 275,                   /* "/"  */
    ASTERISK = 276,                /* "*"  */
    DASH = 277,                    /* "-"  */
    AT = 278,                      /* "@"  */
    VMAP = 279,                    /* "vmap"  */
    PLUS = 280,                    /* "+"  */
    INCLUDE = 281,                 /* "include"  */
    DEFINE = 282,                  /* "define"  */
    REDEFINE = 283,                /* "redefine"  */
    UNDEFINE = 284,                /* "undefine"  */
    FIB = 285,                     /* "fib"  */
    SOCKET = 286,                  /* "socket"  */
    TRANSPARENT = 287,             /* "transparent"  */
    WILDCARD = 288,                /* "wildcard"  */
    CGROUPV2 = 289,                /* "cgroupv2"  */
    TPROXY = 290,                  /* "tproxy"  */
    OSF = 291,                     /* "osf"  */
    SYNPROXY = 292,                /* "synproxy"  */
    MSS = 293,                     /* "mss"  */
    WSCALE = 294,                  /* "wscale"  */
    TYPEOF = 295,                  /* "typeof"  */
    HOOK = 296,                    /* "hook"  */
    HOOKS = 297,                   /* "hooks"  */
    DEVICE = 298,                  /* "device"  */
    DEVICES = 299,                 /* "devices"  */
    TABLE = 300,                   /* "table"  */
    TABLES = 301,                  /* "tables"  */
    CHAIN = 302,                   /* "chain"  */
    CHAINS = 303,                  /* "chains"  */
    RULE = 304,                    /* "rule"  */
    RULES = 305,                   /* "rules"  */
    SETS = 306,                    /* "sets"  */
    SET = 307,                     /* "set"  */
    ELEMENT = 308,                 /* "element"  */
    MAP = 309,                     /* "map"  */
    MAPS = 310,                    /* "maps"  */
    FLOWTABLE = 311,               /* "flowtable"  */
    HANDLE = 312,                  /* "handle"  */
    RULESET = 313,                 /* "ruleset"  */
    TRACE = 314,                   /* "trace"  */
    INET = 315,                    /* "inet"  */
    NETDEV = 316,                  /* "netdev"  */
    ADD = 317,                     /* "add"  */
    UPDATE = 318,                  /* "update"  */
    REPLACE = 319,                 /* "replace"  */
    CREATE = 320,                  /* "create"  */
    INSERT = 321,                  /* "insert"  */
    DELETE = 322,                  /* "delete"  */
    GET = 323,                     /* "get"  */
    LIST = 324,                    /* "list"  */
    RESET = 325,                   /* "reset"  */
    FLUSH = 326,                   /* "flush"  */
    RENAME = 327,                  /* "rename"  */
    DESCRIBE = 328,                /* "describe"  */
    IMPORT = 329,                  /* "import"  */
    EXPORT = 330,                  /* "export"  */
    MONITOR = 331,                 /* "monitor"  */
    ALL = 332,                     /* "all"  */
    ACCEPT = 333,                  /* "accept"  */
    DROP = 334,                    /* "drop"  */
    CONTINUE = 335,                /* "continue"  */
    JUMP = 336,                    /* "jump"  */
    GOTO = 337,                    /* "goto"  */
    RETURN = 338,                  /* "return"  */
    TO = 339,                      /* "to"  */
    CONSTANT = 340,                /* "constant"  */
    INTERVAL = 341,                /* "interval"  */
    DYNAMIC = 342,                 /* "dynamic"  */
    AUTOMERGE = 343,               /* "auto-merge"  */
    TIMEOUT = 344,                 /* "timeout"  */
    GC_INTERVAL = 345,             /* "gc-interval"  */
    ELEMENTS = 346,                /* "elements"  */
    EXPIRES = 347,                 /* "expires"  */
    POLICY = 348,                  /* "policy"  */
    MEMORY = 349,                  /* "memory"  */
    PERFORMANCE = 350,             /* "performance"  */
    SIZE = 351,                    /* "size"  */
    FLOW = 352,                    /* "flow"  */
    OFFLOAD = 353,                 /* "offload"  */
    METER = 354,                   /* "meter"  */
    METERS = 355,                  /* "meters"  */
    FLOWTABLES = 356,              /* "flowtables"  */
    NUM = 357,                     /* "number"  */
    STRING = 358,                  /* "string"  */
    QUOTED_STRING = 359,           /* "quoted string"  */
    ASTERISK_STRING = 360,         /* "string with a trailing asterisk"  */
    LL_HDR = 361,                  /* "ll"  */
    NETWORK_HDR = 362,             /* "nh"  */
    TRANSPORT_HDR = 363,           /* "th"  */
    BRIDGE = 364,                  /* "bridge"  */
    ETHER = 365,                   /* "ether"  */
    SADDR = 366,                   /* "saddr"  */
    DADDR = 367,                   /* "daddr"  */
    TYPE = 368,                    /* "type"  */
    VLAN = 369,                    /* "vlan"  */
    ID = 370,                      /* "id"  */
    CFI = 371,                     /* "cfi"  */
    DEI = 372,                     /* "dei"  */
    PCP = 373,                     /* "pcp"  */
    ARP = 374,                     /* "arp"  */
    HTYPE = 375,                   /* "htype"  */
    PTYPE = 376,                   /* "ptype"  */
    HLEN = 377,                    /* "hlen"  */
    PLEN = 378,                    /* "plen"  */
    OPERATION = 379,               /* "operation"  */
    IP = 380,                      /* "ip"  */
    HDRVERSION = 381,              /* "version"  */
    HDRLENGTH = 382,               /* "hdrlength"  */
    DSCP = 383,                    /* "dscp"  */
    ECN = 384,                     /* "ecn"  */
    LENGTH = 385,                  /* "length"  */
    FRAG_OFF = 386,                /* "frag-off"  */
    TTL = 387,                     /* "ttl"  */
    PROTOCOL = 388,                /* "protocol"  */
    CHECKSUM = 389,                /* "checksum"  */
    PTR = 390,                     /* "ptr"  */
    VALUE = 391,                   /* "value"  */
    LSRR = 392,                    /* "lsrr"  */
    RR = 393,                      /* "rr"  */
    SSRR = 394,                    /* "ssrr"  */
    RA = 395,                      /* "ra"  */
    ICMP = 396,                    /* "icmp"  */
    CODE = 397,                    /* "code"  */
    SEQUENCE = 398,                /* "seq"  */
    GATEWAY = 399,                 /* "gateway"  */
    MTU = 400,                     /* "mtu"  */
    IGMP = 401,                    /* "igmp"  */
    MRT = 402,                     /* "mrt"  */
    OPTIONS = 403,                 /* "options"  */
    IP6 = 404,                     /* "ip6"  */
    PRIORITY = 405,                /* "priority"  */
    FLOWLABEL = 406,               /* "flowlabel"  */
    NEXTHDR = 407,                 /* "nexthdr"  */
    HOPLIMIT = 408,                /* "hoplimit"  */
    ICMP6 = 409,                   /* "icmpv6"  */
    PPTR = 410,                    /* "param-problem"  */
    MAXDELAY = 411,                /* "max-delay"  */
    AH = 412,                      /* "ah"  */
    RESERVED = 413,                /* "reserved"  */
    SPI = 414,                     /* "spi"  */
    ESP = 415,                     /* "esp"  */
    COMP = 416,                    /* "comp"  */
    FLAGS = 417,                   /* "flags"  */
    CPI = 418,                     /* "cpi"  */
    PORT = 419,                    /* "port"  */
    UDP = 420,                     /* "udp"  */
    SPORT = 421,                   /* "sport"  */
    DPORT = 422,                   /* "dport"  */
    UDPLITE = 423,                 /* "udplite"  */
    CSUMCOV = 424,                 /* "csumcov"  */
    TCP = 425,                     /* "tcp"  */
    ACKSEQ = 426,                  /* "ackseq"  */
    DOFF = 427,                    /* "doff"  */
    WINDOW = 428,                  /* "window"  */
    URGPTR = 429,                  /* "urgptr"  */
    OPTION = 430,                  /* "option"  */
    ECHO = 431,                    /* "echo"  */
    EOL = 432,                     /* "eol"  */
    MPTCP = 433,                   /* "mptcp"  */
    NOP = 434,                     /* "nop"  */
    SACK = 435,                    /* "sack"  */
    SACK0 = 436,                   /* "sack0"  */
    SACK1 = 437,                   /* "sack1"  */
    SACK2 = 438,                   /* "sack2"  */
    SACK3 = 439,                   /* "sack3"  */
    SACK_PERM = 440,               /* "sack-permitted"  */
    FASTOPEN = 441,                /* "fastopen"  */
    MD5SIG = 442,                  /* "md5sig"  */
    TIMESTAMP = 443,               /* "timestamp"  */
    COUNT = 444,                   /* "count"  */
    LEFT = 445,                    /* "left"  */
    RIGHT = 446,                   /* "right"  */
    TSVAL = 447,                   /* "tsval"  */
    TSECR = 448,                   /* "tsecr"  */
    SUBTYPE = 449,                 /* "subtype"  */
    DCCP = 450,                    /* "dccp"  */
    SCTP = 451,                    /* "sctp"  */
    CHUNK = 452,                   /* "chunk"  */
    DATA = 453,                    /* "data"  */
    INIT = 454,                    /* "init"  */
    INIT_ACK = 455,                /* "init-ack"  */
    HEARTBEAT = 456,               /* "heartbeat"  */
    HEARTBEAT_ACK = 457,           /* "heartbeat-ack"  */
    ABORT = 458,                   /* "abort"  */
    SHUTDOWN = 459,                /* "shutdown"  */
    SHUTDOWN_ACK = 460,            /* "shutdown-ack"  */
    ERROR = 461,                   /* "error"  */
    COOKIE_ECHO = 462,             /* "cookie-echo"  */
    COOKIE_ACK = 463,              /* "cookie-ack"  */
    ECNE = 464,                    /* "ecne"  */
    CWR = 465,                     /* "cwr"  */
    SHUTDOWN_COMPLETE = 466,       /* "shutdown-complete"  */
    ASCONF_ACK = 467,              /* "asconf-ack"  */
    FORWARD_TSN = 468,             /* "forward-tsn"  */
    ASCONF = 469,                  /* "asconf"  */
    TSN = 470,                     /* "tsn"  */
    STREAM = 471,                  /* "stream"  */
    SSN = 472,                     /* "ssn"  */
    PPID = 473,                    /* "ppid"  */
    INIT_TAG = 474,                /* "init-tag"  */
    A_RWND = 475,                  /* "a-rwnd"  */
    NUM_OSTREAMS = 476,            /* "num-outbound-streams"  */
    NUM_ISTREAMS = 477,            /* "num-inbound-streams"  */
    INIT_TSN = 478,                /* "initial-tsn"  */
    CUM_TSN_ACK = 479,             /* "cum-tsn-ack"  */
    NUM_GACK_BLOCKS = 480,         /* "num-gap-ack-blocks"  */
    NUM_DUP_TSNS = 481,            /* "num-dup-tsns"  */
    LOWEST_TSN = 482,              /* "lowest-tsn"  */
    SEQNO = 483,                   /* "seqno"  */
    NEW_CUM_TSN = 484,             /* "new-cum-tsn"  */
    VTAG = 485,                    /* "vtag"  */
    RT = 486,                      /* "rt"  */
    RT0 = 487,                     /* "rt0"  */
    RT2 = 488,                     /* "rt2"  */
    RT4 = 489,                     /* "srh"  */
    SEG_LEFT = 490,                /* "seg-left"  */
    ADDR = 491,                    /* "addr"  */
    LAST_ENT = 492,                /* "last-entry"  */
    TAG = 493,                     /* "tag"  */
    SID = 494,                     /* "sid"  */
    HBH = 495,                     /* "hbh"  */
    FRAG = 496,                    /* "frag"  */
    RESERVED2 = 497,               /* "reserved2"  */
    MORE_FRAGMENTS = 498,          /* "more-fragments"  */
    DST = 499,                     /* "dst"  */
    MH = 500,                      /* "mh"  */
    META = 501,                    /* "meta"  */
    MARK = 502,                    /* "mark"  */
    IIF = 503,                     /* "iif"  */
    IIFNAME = 504,                 /* "iifname"  */
    IIFTYPE = 505,                 /* "iiftype"  */
    OIF = 506,                     /* "oif"  */
    OIFNAME = 507,                 /* "oifname"  */
    OIFTYPE = 508,                 /* "oiftype"  */
    SKUID = 509,                   /* "skuid"  */
    SKGID = 510,                   /* "skgid"  */
    NFTRACE = 511,                 /* "nftrace"  */
    RTCLASSID = 512,               /* "rtclassid"  */
    IBRIPORT = 513,                /* "ibriport"  */
    OBRIPORT = 514,                /* "obriport"  */
    IBRIDGENAME = 515,             /* "ibrname"  */
    OBRIDGENAME = 516,             /* "obrname"  */
    PKTTYPE = 517,                 /* "pkttype"  */
    CPU = 518,                     /* "cpu"  */
    IIFGROUP = 519,                /* "iifgroup"  */
    OIFGROUP = 520,                /* "oifgroup"  */
    CGROUP = 521,                  /* "cgroup"  */
    TIME = 522,                    /* "time"  */
    CLASSID = 523,                 /* "classid"  */
    NEXTHOP = 524,                 /* "nexthop"  */
    CT = 525,                      /* "ct"  */
    L3PROTOCOL = 526,              /* "l3proto"  */
    PROTO_SRC = 527,               /* "proto-src"  */
    PROTO_DST = 528,               /* "proto-dst"  */
    ZONE = 529,                    /* "zone"  */
    DIRECTION = 530,               /* "direction"  */
    EVENT = 531,                   /* "event"  */
    EXPECTATION = 532,             /* "expectation"  */
    EXPIRATION = 533,              /* "expiration"  */
    HELPER = 534,                  /* "helper"  */
    LABEL = 535,                   /* "label"  */
    STATE = 536,                   /* "state"  */
    STATUS = 537,                  /* "status"  */
    ORIGINAL = 538,                /* "original"  */
    REPLY = 539,                   /* "reply"  */
    COUNTER = 540,                 /* "counter"  */
    NAME = 541,                    /* "name"  */
    PACKETS = 542,                 /* "packets"  */
    BYTES = 543,                   /* "bytes"  */
    AVGPKT = 544,                  /* "avgpkt"  */
    COUNTERS = 545,                /* "counters"  */
    QUOTAS = 546,                  /* "quotas"  */
    LIMITS = 547,                  /* "limits"  */
    SYNPROXYS = 548,               /* "synproxys"  */
    HELPERS = 549,                 /* "helpers"  */
    LOG = 550,                     /* "log"  */
    PREFIX = 551,                  /* "prefix"  */
    GROUP = 552,                   /* "group"  */
    SNAPLEN = 553,                 /* "snaplen"  */
    QUEUE_THRESHOLD = 554,         /* "queue-threshold"  */
    LEVEL = 555,                   /* "level"  */
    LIMIT = 556,                   /* "limit"  */
    RATE = 557,                    /* "rate"  */
    BURST = 558,                   /* "burst"  */
    OVER = 559,                    /* "over"  */
    UNTIL = 560,                   /* "until"  */
    QUOTA = 561,                   /* "quota"  */
    USED = 562,                    /* "used"  */
    SECMARK = 563,                 /* "secmark"  */
    SECMARKS = 564,                /* "secmarks"  */
    SECOND = 565,                  /* "second"  */
    MINUTE = 566,                  /* "minute"  */
    HOUR = 567,                    /* "hour"  */
    DAY = 568,                     /* "day"  */
    WEEK = 569,                    /* "week"  */
    _REJECT = 570,                 /* "reject"  */
    WITH = 571,                    /* "with"  */
    ICMPX = 572,                   /* "icmpx"  */
    SNAT = 573,                    /* "snat"  */
    DNAT = 574,                    /* "dnat"  */
    MASQUERADE = 575,              /* "masquerade"  */
    REDIRECT = 576,                /* "redirect"  */
    RANDOM = 577,                  /* "random"  */
    FULLY_RANDOM = 578,            /* "fully-random"  */
    PERSISTENT = 579,              /* "persistent"  */
    QUEUE = 580,                   /* "queue"  */
    QUEUENUM = 581,                /* "num"  */
    BYPASS = 582,                  /* "bypass"  */
    FANOUT = 583,                  /* "fanout"  */
    DUP = 584,                     /* "dup"  */
    FWD = 585,                     /* "fwd"  */
    NUMGEN = 586,                  /* "numgen"  */
    INC = 587,                     /* "inc"  */
    MOD = 588,                     /* "mod"  */
    OFFSET = 589,                  /* "offset"  */
    JHASH = 590,                   /* "jhash"  */
    SYMHASH = 591,                 /* "symhash"  */
    SEED = 592,                    /* "seed"  */
    POSITION = 593,                /* "position"  */
    INDEX = 594,                   /* "index"  */
    COMMENT = 595,                 /* "comment"  */
    XML = 596,                     /* "xml"  */
    JSON = 597,                    /* "json"  */
    VM = 598,                      /* "vm"  */
    NOTRACK = 599,                 /* "notrack"  */
    EXISTS = 600,                  /* "exists"  */
    MISSING = 601,                 /* "missing"  */
    EXTHDR = 602,                  /* "exthdr"  */
    IPSEC = 603,                   /* "ipsec"  */
    REQID = 604,                   /* "reqid"  */
    SPNUM = 605,                   /* "spnum"  */
    IN = 606,                      /* "in"  */
    OUT = 607,                     /* "out"  */
    XT = 608                       /* "xt"  */
  };
  typedef enum nft_tokentype nft_token_kind_t;
#endif

/* Value type.  */
#if ! defined NFT_STYPE && ! defined NFT_STYPE_IS_DECLARED
union NFT_STYPE
{
#line 178 "../../nft/nftables/src/parser_bison.y"

	uint64_t		val;
	uint32_t		val32;
	uint8_t			val8;
	const char *		string;

	struct list_head	*list;
	struct cmd		*cmd;
	struct handle		handle;
	struct table		*table;
	struct chain		*chain;
	struct rule		*rule;
	struct stmt		*stmt;
	struct expr		*expr;
	struct set		*set;
	struct obj		*obj;
	struct flowtable	*flowtable;
	struct ct		*ct;
	const struct datatype	*datatype;
	struct handle_spec	handle_spec;
	struct position_spec	position_spec;
	struct prio_spec	prio_spec;
	struct limit_rate	limit_rate;
	struct tcp_kind_field {
		uint16_t kind; /* must allow > 255 for SACK1, 2.. hack */
		uint8_t field;
	} tcp_kind_field;

#line 662 "parser_bison.tab.c"

};
typedef union NFT_STYPE NFT_STYPE;
# define NFT_STYPE_IS_TRIVIAL 1
# define NFT_STYPE_IS_DECLARED 1
#endif

/* Location type.  */
#if ! defined NFT_LTYPE && ! defined NFT_LTYPE_IS_DECLARED
typedef struct NFT_LTYPE NFT_LTYPE;
struct NFT_LTYPE
{
  int first_line;
  int first_column;
  int last_line;
  int last_column;
};
# define NFT_LTYPE_IS_DECLARED 1
# define NFT_LTYPE_IS_TRIVIAL 1
#endif




int nft_parse (struct nft_ctx *nft, void *scanner, struct parser_state *state);



/* Symbol kind.  */
enum yysymbol_kind_t
{
  YYSYMBOL_YYEMPTY = -2,
  YYSYMBOL_YYEOF = 0,                      /* "end of file"  */
  YYSYMBOL_YYerror = 1,                    /* error  */
  YYSYMBOL_YYUNDEF = 2,                    /* "invalid token"  */
  YYSYMBOL_JUNK = 3,                       /* "junk"  */
  YYSYMBOL_NEWLINE = 4,                    /* "newline"  */
  YYSYMBOL_COLON = 5,                      /* "colon"  */
  YYSYMBOL_SEMICOLON = 6,                  /* "semicolon"  */
  YYSYMBOL_COMMA = 7,                      /* "comma"  */
  YYSYMBOL_DOT = 8,                        /* "."  */
  YYSYMBOL_EQ = 9,                         /* "=="  */
  YYSYMBOL_NEQ = 10,                       /* "!="  */
  YYSYMBOL_LT = 11,                        /* "<"  */
  YYSYMBOL_GT = 12,                        /* ">"  */
  YYSYMBOL_GTE = 13,                       /* ">="  */
  YYSYMBOL_LTE = 14,                       /* "<="  */
  YYSYMBOL_LSHIFT = 15,                    /* "<<"  */
  YYSYMBOL_RSHIFT = 16,                    /* ">>"  */
  YYSYMBOL_AMPERSAND = 17,                 /* "&"  */
  YYSYMBOL_CARET = 18,                     /* "^"  */
  YYSYMBOL_NOT = 19,                       /* "!"  */
  YYSYMBOL_SLASH = 20,                     /* "/"  */
  YYSYMBOL_ASTERISK = 21,                  /* "*"  */
  YYSYMBOL_DASH = 22,                      /* "-"  */
  YYSYMBOL_AT = 23,                        /* "@"  */
  YYSYMBOL_VMAP = 24,                      /* "vmap"  */
  YYSYMBOL_PLUS = 25,                      /* "+"  */
  YYSYMBOL_INCLUDE = 26,                   /* "include"  */
  YYSYMBOL_DEFINE = 27,                    /* "define"  */
  YYSYMBOL_REDEFINE = 28,                  /* "redefine"  */
  YYSYMBOL_UNDEFINE = 29,                  /* "undefine"  */
  YYSYMBOL_FIB = 30,                       /* "fib"  */
  YYSYMBOL_SOCKET = 31,                    /* "socket"  */
  YYSYMBOL_TRANSPARENT = 32,               /* "transparent"  */
  YYSYMBOL_WILDCARD = 33,                  /* "wildcard"  */
  YYSYMBOL_CGROUPV2 = 34,                  /* "cgroupv2"  */
  YYSYMBOL_TPROXY = 35,                    /* "tproxy"  */
  YYSYMBOL_OSF = 36,                       /* "osf"  */
  YYSYMBOL_SYNPROXY = 37,                  /* "synproxy"  */
  YYSYMBOL_MSS = 38,                       /* "mss"  */
  YYSYMBOL_WSCALE = 39,                    /* "wscale"  */
  YYSYMBOL_TYPEOF = 40,                    /* "typeof"  */
  YYSYMBOL_HOOK = 41,                      /* "hook"  */
  YYSYMBOL_HOOKS = 42,                     /* "hooks"  */
  YYSYMBOL_DEVICE = 43,                    /* "device"  */
  YYSYMBOL_DEVICES = 44,                   /* "devices"  */
  YYSYMBOL_TABLE = 45,                     /* "table"  */
  YYSYMBOL_TABLES = 46,                    /* "tables"  */
  YYSYMBOL_CHAIN = 47,                     /* "chain"  */
  YYSYMBOL_CHAINS = 48,                    /* "chains"  */
  YYSYMBOL_RULE = 49,                      /* "rule"  */
  YYSYMBOL_RULES = 50,                     /* "rules"  */
  YYSYMBOL_SETS = 51,                      /* "sets"  */
  YYSYMBOL_SET = 52,                       /* "set"  */
  YYSYMBOL_ELEMENT = 53,                   /* "element"  */
  YYSYMBOL_MAP = 54,                       /* "map"  */
  YYSYMBOL_MAPS = 55,                      /* "maps"  */
  YYSYMBOL_FLOWTABLE = 56,                 /* "flowtable"  */
  YYSYMBOL_HANDLE = 57,                    /* "handle"  */
  YYSYMBOL_RULESET = 58,                   /* "ruleset"  */
  YYSYMBOL_TRACE = 59,                     /* "trace"  */
  YYSYMBOL_INET = 60,                      /* "inet"  */
  YYSYMBOL_NETDEV = 61,                    /* "netdev"  */
  YYSYMBOL_ADD = 62,                       /* "add"  */
  YYSYMBOL_UPDATE = 63,                    /* "update"  */
  YYSYMBOL_REPLACE = 64,                   /* "replace"  */
  YYSYMBOL_CREATE = 65,                    /* "create"  */
  YYSYMBOL_INSERT = 66,                    /* "insert"  */
  YYSYMBOL_DELETE = 67,                    /* "delete"  */
  YYSYMBOL_GET = 68,                       /* "get"  */
  YYSYMBOL_LIST = 69,                      /* "list"  */
  YYSYMBOL_RESET = 70,                     /* "reset"  */
  YYSYMBOL_FLUSH = 71,                     /* "flush"  */
  YYSYMBOL_RENAME = 72,                    /* "rename"  */
  YYSYMBOL_DESCRIBE = 73,                  /* "describe"  */
  YYSYMBOL_IMPORT = 74,                    /* "import"  */
  YYSYMBOL_EXPORT = 75,                    /* "export"  */
  YYSYMBOL_MONITOR = 76,                   /* "monitor"  */
  YYSYMBOL_ALL = 77,                       /* "all"  */
  YYSYMBOL_ACCEPT = 78,                    /* "accept"  */
  YYSYMBOL_DROP = 79,                      /* "drop"  */
  YYSYMBOL_CONTINUE = 80,                  /* "continue"  */
  YYSYMBOL_JUMP = 81,                      /* "jump"  */
  YYSYMBOL_GOTO = 82,                      /* "goto"  */
  YYSYMBOL_RETURN = 83,                    /* "return"  */
  YYSYMBOL_TO = 84,                        /* "to"  */
  YYSYMBOL_CONSTANT = 85,                  /* "constant"  */
  YYSYMBOL_INTERVAL = 86,                  /* "interval"  */
  YYSYMBOL_DYNAMIC = 87,                   /* "dynamic"  */
  YYSYMBOL_AUTOMERGE = 88,                 /* "auto-merge"  */
  YYSYMBOL_TIMEOUT = 89,                   /* "timeout"  */
  YYSYMBOL_GC_INTERVAL = 90,               /* "gc-interval"  */
  YYSYMBOL_ELEMENTS = 91,                  /* "elements"  */
  YYSYMBOL_EXPIRES = 92,                   /* "expires"  */
  YYSYMBOL_POLICY = 93,                    /* "policy"  */
  YYSYMBOL_MEMORY = 94,                    /* "memory"  */
  YYSYMBOL_PERFORMANCE = 95,               /* "performance"  */
  YYSYMBOL_SIZE = 96,                      /* "size"  */
  YYSYMBOL_FLOW = 97,                      /* "flow"  */
  YYSYMBOL_OFFLOAD = 98,                   /* "offload"  */
  YYSYMBOL_METER = 99,                     /* "meter"  */
  YYSYMBOL_METERS = 100,                   /* "meters"  */
  YYSYMBOL_FLOWTABLES = 101,               /* "flowtables"  */
  YYSYMBOL_NUM = 102,                      /* "number"  */
  YYSYMBOL_STRING = 103,                   /* "string"  */
  YYSYMBOL_QUOTED_STRING = 104,            /* "quoted string"  */
  YYSYMBOL_ASTERISK_STRING = 105,          /* "string with a trailing asterisk"  */
  YYSYMBOL_LL_HDR = 106,                   /* "ll"  */
  YYSYMBOL_NETWORK_HDR = 107,              /* "nh"  */
  YYSYMBOL_TRANSPORT_HDR = 108,            /* "th"  */
  YYSYMBOL_BRIDGE = 109,                   /* "bridge"  */
  YYSYMBOL_ETHER = 110,                    /* "ether"  */
  YYSYMBOL_SADDR = 111,                    /* "saddr"  */
  YYSYMBOL_DADDR = 112,                    /* "daddr"  */
  YYSYMBOL_TYPE = 113,                     /* "type"  */
  YYSYMBOL_VLAN = 114,                     /* "vlan"  */
  YYSYMBOL_ID = 115,                       /* "id"  */
  YYSYMBOL_CFI = 116,                      /* "cfi"  */
  YYSYMBOL_DEI = 117,                      /* "dei"  */
  YYSYMBOL_PCP = 118,                      /* "pcp"  */
  YYSYMBOL_ARP = 119,                      /* "arp"  */
  YYSYMBOL_HTYPE = 120,                    /* "htype"  */
  YYSYMBOL_PTYPE = 121,                    /* "ptype"  */
  YYSYMBOL_HLEN = 122,                     /* "hlen"  */
  YYSYMBOL_PLEN = 123,                     /* "plen"  */
  YYSYMBOL_OPERATION = 124,                /* "operation"  */
  YYSYMBOL_IP = 125,                       /* "ip"  */
  YYSYMBOL_HDRVERSION = 126,               /* "version"  */
  YYSYMBOL_HDRLENGTH = 127,                /* "hdrlength"  */
  YYSYMBOL_DSCP = 128,                     /* "dscp"  */
  YYSYMBOL_ECN = 129,                      /* "ecn"  */
  YYSYMBOL_LENGTH = 130,                   /* "length"  */
  YYSYMBOL_FRAG_OFF = 131,                 /* "frag-off"  */
  YYSYMBOL_TTL = 132,                      /* "ttl"  */
  YYSYMBOL_PROTOCOL = 133,                 /* "protocol"  */
  YYSYMBOL_CHECKSUM = 134,                 /* "checksum"  */
  YYSYMBOL_PTR = 135,                      /* "ptr"  */
  YYSYMBOL_VALUE = 136,                    /* "value"  */
  YYSYMBOL_LSRR = 137,                     /* "lsrr"  */
  YYSYMBOL_RR = 138,                       /* "rr"  */
  YYSYMBOL_SSRR = 139,                     /* "ssrr"  */
  YYSYMBOL_RA = 140,                       /* "ra"  */
  YYSYMBOL_ICMP = 141,                     /* "icmp"  */
  YYSYMBOL_CODE = 142,                     /* "code"  */
  YYSYMBOL_SEQUENCE = 143,                 /* "seq"  */
  YYSYMBOL_GATEWAY = 144,                  /* "gateway"  */
  YYSYMBOL_MTU = 145,                      /* "mtu"  */
  YYSYMBOL_IGMP = 146,                     /* "igmp"  */
  YYSYMBOL_MRT = 147,                      /* "mrt"  */
  YYSYMBOL_OPTIONS = 148,                  /* "options"  */
  YYSYMBOL_IP6 = 149,                      /* "ip6"  */
  YYSYMBOL_PRIORITY = 150,                 /* "priority"  */
  YYSYMBOL_FLOWLABEL = 151,                /* "flowlabel"  */
  YYSYMBOL_NEXTHDR = 152,                  /* "nexthdr"  */
  YYSYMBOL_HOPLIMIT = 153,                 /* "hoplimit"  */
  YYSYMBOL_ICMP6 = 154,                    /* "icmpv6"  */
  YYSYMBOL_PPTR = 155,                     /* "param-problem"  */
  YYSYMBOL_MAXDELAY = 156,                 /* "max-delay"  */
  YYSYMBOL_AH = 157,                       /* "ah"  */
  YYSYMBOL_RESERVED = 158,                 /* "reserved"  */
  YYSYMBOL_SPI = 159,                      /* "spi"  */
  YYSYMBOL_ESP = 160,                      /* "esp"  */
  YYSYMBOL_COMP = 161,                     /* "comp"  */
  YYSYMBOL_FLAGS = 162,                    /* "flags"  */
  YYSYMBOL_CPI = 163,                      /* "cpi"  */
  YYSYMBOL_PORT = 164,                     /* "port"  */
  YYSYMBOL_UDP = 165,                      /* "udp"  */
  YYSYMBOL_SPORT = 166,                    /* "sport"  */
  YYSYMBOL_DPORT = 167,                    /* "dport"  */
  YYSYMBOL_UDPLITE = 168,                  /* "udplite"  */
  YYSYMBOL_CSUMCOV = 169,                  /* "csumcov"  */
  YYSYMBOL_TCP = 170,                      /* "tcp"  */
  YYSYMBOL_ACKSEQ = 171,                   /* "ackseq"  */
  YYSYMBOL_DOFF = 172,                     /* "doff"  */
  YYSYMBOL_WINDOW = 173,                   /* "window"  */
  YYSYMBOL_URGPTR = 174,                   /* "urgptr"  */
  YYSYMBOL_OPTION = 175,                   /* "option"  */
  YYSYMBOL_ECHO = 176,                     /* "echo"  */
  YYSYMBOL_EOL = 177,                      /* "eol"  */
  YYSYMBOL_MPTCP = 178,                    /* "mptcp"  */
  YYSYMBOL_NOP = 179,                      /* "nop"  */
  YYSYMBOL_SACK = 180,                     /* "sack"  */
  YYSYMBOL_SACK0 = 181,                    /* "sack0"  */
  YYSYMBOL_SACK1 = 182,                    /* "sack1"  */
  YYSYMBOL_SACK2 = 183,                    /* "sack2"  */
  YYSYMBOL_SACK3 = 184,                    /* "sack3"  */
  YYSYMBOL_SACK_PERM = 185,                /* "sack-permitted"  */
  YYSYMBOL_FASTOPEN = 186,                 /* "fastopen"  */
  YYSYMBOL_MD5SIG = 187,                   /* "md5sig"  */
  YYSYMBOL_TIMESTAMP = 188,                /* "timestamp"  */
  YYSYMBOL_COUNT = 189,                    /* "count"  */
  YYSYMBOL_LEFT = 190,                     /* "left"  */
  YYSYMBOL_RIGHT = 191,                    /* "right"  */
  YYSYMBOL_TSVAL = 192,                    /* "tsval"  */
  YYSYMBOL_TSECR = 193,                    /* "tsecr"  */
  YYSYMBOL_SUBTYPE = 194,                  /* "subtype"  */
  YYSYMBOL_DCCP = 195,                     /* "dccp"  */
  YYSYMBOL_SCTP = 196,                     /* "sctp"  */
  YYSYMBOL_CHUNK = 197,                    /* "chunk"  */
  YYSYMBOL_DATA = 198,                     /* "data"  */
  YYSYMBOL_INIT = 199,                     /* "init"  */
  YYSYMBOL_INIT_ACK = 200,                 /* "init-ack"  */
  YYSYMBOL_HEARTBEAT = 201,                /* "heartbeat"  */
  YYSYMBOL_HEARTBEAT_ACK = 202,            /* "heartbeat-ack"  */
  YYSYMBOL_ABORT = 203,                    /* "abort"  */
  YYSYMBOL_SHUTDOWN = 204,                 /* "shutdown"  */
  YYSYMBOL_SHUTDOWN_ACK = 205,             /* "shutdown-ack"  */
  YYSYMBOL_ERROR = 206,                    /* "error"  */
  YYSYMBOL_COOKIE_ECHO = 207,              /* "cookie-echo"  */
  YYSYMBOL_COOKIE_ACK = 208,               /* "cookie-ack"  */
  YYSYMBOL_ECNE = 209,                     /* "ecne"  */
  YYSYMBOL_CWR = 210,                      /* "cwr"  */
  YYSYMBOL_SHUTDOWN_COMPLETE = 211,        /* "shutdown-complete"  */
  YYSYMBOL_ASCONF_ACK = 212,               /* "asconf-ack"  */
  YYSYMBOL_FORWARD_TSN = 213,              /* "forward-tsn"  */
  YYSYMBOL_ASCONF = 214,                   /* "asconf"  */
  YYSYMBOL_TSN = 215,                      /* "tsn"  */
  YYSYMBOL_STREAM = 216,                   /* "stream"  */
  YYSYMBOL_SSN = 217,                      /* "ssn"  */
  YYSYMBOL_PPID = 218,                     /* "ppid"  */
  YYSYMBOL_INIT_TAG = 219,                 /* "init-tag"  */
  YYSYMBOL_A_RWND = 220,                   /* "a-rwnd"  */
  YYSYMBOL_NUM_OSTREAMS = 221,             /* "num-outbound-streams"  */
  YYSYMBOL_NUM_ISTREAMS = 222,             /* "num-inbound-streams"  */
  YYSYMBOL_INIT_TSN = 223,                 /* "initial-tsn"  */
  YYSYMBOL_CUM_TSN_ACK = 224,              /* "cum-tsn-ack"  */
  YYSYMBOL_NUM_GACK_BLOCKS = 225,          /* "num-gap-ack-blocks"  */
  YYSYMBOL_NUM_DUP_TSNS = 226,             /* "num-dup-tsns"  */
  YYSYMBOL_LOWEST_TSN = 227,               /* "lowest-tsn"  */
  YYSYMBOL_SEQNO = 228,                    /* "seqno"  */
  YYSYMBOL_NEW_CUM_TSN = 229,              /* "new-cum-tsn"  */
  YYSYMBOL_VTAG = 230,                     /* "vtag"  */
  YYSYMBOL_RT = 231,                       /* "rt"  */
  YYSYMBOL_RT0 = 232,                      /* "rt0"  */
  YYSYMBOL_RT2 = 233,                      /* "rt2"  */
  YYSYMBOL_RT4 = 234,                      /* "srh"  */
  YYSYMBOL_SEG_LEFT = 235,                 /* "seg-left"  */
  YYSYMBOL_ADDR = 236,                     /* "addr"  */
  YYSYMBOL_LAST_ENT = 237,                 /* "last-entry"  */
  YYSYMBOL_TAG = 238,                      /* "tag"  */
  YYSYMBOL_SID = 239,                      /* "sid"  */
  YYSYMBOL_HBH = 240,                      /* "hbh"  */
  YYSYMBOL_FRAG = 241,                     /* "frag"  */
  YYSYMBOL_RESERVED2 = 242,                /* "reserved2"  */
  YYSYMBOL_MORE_FRAGMENTS = 243,           /* "more-fragments"  */
  YYSYMBOL_DST = 244,                      /* "dst"  */
  YYSYMBOL_MH = 245,                       /* "mh"  */
  YYSYMBOL_META = 246,                     /* "meta"  */
  YYSYMBOL_MARK = 247,                     /* "mark"  */
  YYSYMBOL_IIF = 248,                      /* "iif"  */
  YYSYMBOL_IIFNAME = 249,                  /* "iifname"  */
  YYSYMBOL_IIFTYPE = 250,                  /* "iiftype"  */
  YYSYMBOL_OIF = 251,                      /* "oif"  */
  YYSYMBOL_OIFNAME = 252,                  /* "oifname"  */
  YYSYMBOL_OIFTYPE = 253,                  /* "oiftype"  */
  YYSYMBOL_SKUID = 254,                    /* "skuid"  */
  YYSYMBOL_SKGID = 255,                    /* "skgid"  */
  YYSYMBOL_NFTRACE = 256,                  /* "nftrace"  */
  YYSYMBOL_RTCLASSID = 257,                /* "rtclassid"  */
  YYSYMBOL_IBRIPORT = 258,                 /* "ibriport"  */
  YYSYMBOL_OBRIPORT = 259,                 /* "obriport"  */
  YYSYMBOL_IBRIDGENAME = 260,              /* "ibrname"  */
  YYSYMBOL_OBRIDGENAME = 261,              /* "obrname"  */
  YYSYMBOL_PKTTYPE = 262,                  /* "pkttype"  */
  YYSYMBOL_CPU = 263,                      /* "cpu"  */
  YYSYMBOL_IIFGROUP = 264,                 /* "iifgroup"  */
  YYSYMBOL_OIFGROUP = 265,                 /* "oifgroup"  */
  YYSYMBOL_CGROUP = 266,                   /* "cgroup"  */
  YYSYMBOL_TIME = 267,                     /* "time"  */
  YYSYMBOL_CLASSID = 268,                  /* "classid"  */
  YYSYMBOL_NEXTHOP = 269,                  /* "nexthop"  */
  YYSYMBOL_CT = 270,                       /* "ct"  */
  YYSYMBOL_L3PROTOCOL = 271,               /* "l3proto"  */
  YYSYMBOL_PROTO_SRC = 272,                /* "proto-src"  */
  YYSYMBOL_PROTO_DST = 273,                /* "proto-dst"  */
  YYSYMBOL_ZONE = 274,                     /* "zone"  */
  YYSYMBOL_DIRECTION = 275,                /* "direction"  */
  YYSYMBOL_EVENT = 276,                    /* "event"  */
  YYSYMBOL_EXPECTATION = 277,              /* "expectation"  */
  YYSYMBOL_EXPIRATION = 278,               /* "expiration"  */
  YYSYMBOL_HELPER = 279,                   /* "helper"  */
  YYSYMBOL_LABEL = 280,                    /* "label"  */
  YYSYMBOL_STATE = 281,                    /* "state"  */
  YYSYMBOL_STATUS = 282,                   /* "status"  */
  YYSYMBOL_ORIGINAL = 283,                 /* "original"  */
  YYSYMBOL_REPLY = 284,                    /* "reply"  */
  YYSYMBOL_COUNTER = 285,                  /* "counter"  */
  YYSYMBOL_NAME = 286,                     /* "name"  */
  YYSYMBOL_PACKETS = 287,                  /* "packets"  */
  YYSYMBOL_BYTES = 288,                    /* "bytes"  */
  YYSYMBOL_AVGPKT = 289,                   /* "avgpkt"  */
  YYSYMBOL_COUNTERS = 290,                 /* "counters"  */
  YYSYMBOL_QUOTAS = 291,                   /* "quotas"  */
  YYSYMBOL_LIMITS = 292,                   /* "limits"  */
  YYSYMBOL_SYNPROXYS = 293,                /* "synproxys"  */
  YYSYMBOL_HELPERS = 294,                  /* "helpers"  */
  YYSYMBOL_LOG = 295,                      /* "log"  */
  YYSYMBOL_PREFIX = 296,                   /* "prefix"  */
  YYSYMBOL_GROUP = 297,                    /* "group"  */
  YYSYMBOL_SNAPLEN = 298,                  /* "snaplen"  */
  YYSYMBOL_QUEUE_THRESHOLD = 299,          /* "queue-threshold"  */
  YYSYMBOL_LEVEL = 300,                    /* "level"  */
  YYSYMBOL_LIMIT = 301,                    /* "limit"  */
  YYSYMBOL_RATE = 302,                     /* "rate"  */
  YYSYMBOL_BURST = 303,                    /* "burst"  */
  YYSYMBOL_OVER = 304,                     /* "over"  */
  YYSYMBOL_UNTIL = 305,                    /* "until"  */
  YYSYMBOL_QUOTA = 306,                    /* "quota"  */
  YYSYMBOL_USED = 307,                     /* "used"  */
  YYSYMBOL_SECMARK = 308,                  /* "secmark"  */
  YYSYMBOL_SECMARKS = 309,                 /* "secmarks"  */
  YYSYMBOL_SECOND = 310,                   /* "second"  */
  YYSYMBOL_MINUTE = 311,                   /* "minute"  */
  YYSYMBOL_HOUR = 312,                     /* "hour"  */
  YYSYMBOL_DAY = 313,                      /* "day"  */
  YYSYMBOL_WEEK = 314,                     /* "week"  */
  YYSYMBOL__REJECT = 315,                  /* "reject"  */
  YYSYMBOL_WITH = 316,                     /* "with"  */
  YYSYMBOL_ICMPX = 317,                    /* "icmpx"  */
  YYSYMBOL_SNAT = 318,                     /* "snat"  */
  YYSYMBOL_DNAT = 319,                     /* "dnat"  */
  YYSYMBOL_MASQUERADE = 320,               /* "masquerade"  */
  YYSYMBOL_REDIRECT = 321,                 /* "redirect"  */
  YYSYMBOL_RANDOM = 322,                   /* "random"  */
  YYSYMBOL_FULLY_RANDOM = 323,             /* "fully-random"  */
  YYSYMBOL_PERSISTENT = 324,               /* "persistent"  */
  YYSYMBOL_QUEUE = 325,                    /* "queue"  */
  YYSYMBOL_QUEUENUM = 326,                 /* "num"  */
  YYSYMBOL_BYPASS = 327,                   /* "bypass"  */
  YYSYMBOL_FANOUT = 328,                   /* "fanout"  */
  YYSYMBOL_DUP = 329,                      /* "dup"  */
  YYSYMBOL_FWD = 330,                      /* "fwd"  */
  YYSYMBOL_NUMGEN = 331,                   /* "numgen"  */
  YYSYMBOL_INC = 332,                      /* "inc"  */
  YYSYMBOL_MOD = 333,                      /* "mod"  */
  YYSYMBOL_OFFSET = 334,                   /* "offset"  */
  YYSYMBOL_JHASH = 335,                    /* "jhash"  */
  YYSYMBOL_SYMHASH = 336,                  /* "symhash"  */
  YYSYMBOL_SEED = 337,                     /* "seed"  */
  YYSYMBOL_POSITION = 338,                 /* "position"  */
  YYSYMBOL_INDEX = 339,                    /* "index"  */
  YYSYMBOL_COMMENT = 340,                  /* "comment"  */
  YYSYMBOL_XML = 341,                      /* "xml"  */
  YYSYMBOL_JSON = 342,                     /* "json"  */
  YYSYMBOL_VM = 343,                       /* "vm"  */
  YYSYMBOL_NOTRACK = 344,                  /* "notrack"  */
  YYSYMBOL_EXISTS = 345,                   /* "exists"  */
  YYSYMBOL_MISSING = 346,                  /* "missing"  */
  YYSYMBOL_EXTHDR = 347,                   /* "exthdr"  */
  YYSYMBOL_IPSEC = 348,                    /* "ipsec"  */
  YYSYMBOL_REQID = 349,                    /* "reqid"  */
  YYSYMBOL_SPNUM = 350,                    /* "spnum"  */
  YYSYMBOL_IN = 351,                       /* "in"  */
  YYSYMBOL_OUT = 352,                      /* "out"  */
  YYSYMBOL_XT = 353,                       /* "xt"  */
  YYSYMBOL_354_ = 354,                     /* '='  */
  YYSYMBOL_355_ = 355,                     /* '{'  */
  YYSYMBOL_356_ = 356,                     /* '}'  */
  YYSYMBOL_357_ = 357,                     /* '('  */
  YYSYMBOL_358_ = 358,                     /* ')'  */
  YYSYMBOL_359_ = 359,                     /* '|'  */
  YYSYMBOL_360_ = 360,                     /* '$'  */
  YYSYMBOL_361_ = 361,                     /* '['  */
  YYSYMBOL_362_ = 362,                     /* ']'  */
  YYSYMBOL_YYACCEPT = 363,                 /* $accept  */
  YYSYMBOL_input = 364,                    /* input  */
  YYSYMBOL_stmt_separator = 365,           /* stmt_separator  */
  YYSYMBOL_opt_newline = 366,              /* opt_newline  */
  YYSYMBOL_close_scope_ah = 367,           /* close_scope_ah  */
  YYSYMBOL_close_scope_arp = 368,          /* close_scope_arp  */
  YYSYMBOL_close_scope_at = 369,           /* close_scope_at  */
  YYSYMBOL_close_scope_comp = 370,         /* close_scope_comp  */
  YYSYMBOL_close_scope_ct = 371,           /* close_scope_ct  */
  YYSYMBOL_close_scope_counter = 372,      /* close_scope_counter  */
  YYSYMBOL_close_scope_dccp = 373,         /* close_scope_dccp  */
  YYSYMBOL_close_scope_dst = 374,          /* close_scope_dst  */
  YYSYMBOL_close_scope_dup = 375,          /* close_scope_dup  */
  YYSYMBOL_close_scope_esp = 376,          /* close_scope_esp  */
  YYSYMBOL_close_scope_eth = 377,          /* close_scope_eth  */
  YYSYMBOL_close_scope_export = 378,       /* close_scope_export  */
  YYSYMBOL_close_scope_fib = 379,          /* close_scope_fib  */
  YYSYMBOL_close_scope_frag = 380,         /* close_scope_frag  */
  YYSYMBOL_close_scope_fwd = 381,          /* close_scope_fwd  */
  YYSYMBOL_close_scope_hash = 382,         /* close_scope_hash  */
  YYSYMBOL_close_scope_hbh = 383,          /* close_scope_hbh  */
  YYSYMBOL_close_scope_ip = 384,           /* close_scope_ip  */
  YYSYMBOL_close_scope_ip6 = 385,          /* close_scope_ip6  */
  YYSYMBOL_close_scope_vlan = 386,         /* close_scope_vlan  */
  YYSYMBOL_close_scope_icmp = 387,         /* close_scope_icmp  */
  YYSYMBOL_close_scope_igmp = 388,         /* close_scope_igmp  */
  YYSYMBOL_close_scope_import = 389,       /* close_scope_import  */
  YYSYMBOL_close_scope_ipsec = 390,        /* close_scope_ipsec  */
  YYSYMBOL_close_scope_list = 391,         /* close_scope_list  */
  YYSYMBOL_close_scope_limit = 392,        /* close_scope_limit  */
  YYSYMBOL_close_scope_meta = 393,         /* close_scope_meta  */
  YYSYMBOL_close_scope_mh = 394,           /* close_scope_mh  */
  YYSYMBOL_close_scope_monitor = 395,      /* close_scope_monitor  */
  YYSYMBOL_close_scope_nat = 396,          /* close_scope_nat  */
  YYSYMBOL_close_scope_numgen = 397,       /* close_scope_numgen  */
  YYSYMBOL_close_scope_osf = 398,          /* close_scope_osf  */
  YYSYMBOL_close_scope_policy = 399,       /* close_scope_policy  */
  YYSYMBOL_close_scope_quota = 400,        /* close_scope_quota  */
  YYSYMBOL_close_scope_queue = 401,        /* close_scope_queue  */
  YYSYMBOL_close_scope_reject = 402,       /* close_scope_reject  */
  YYSYMBOL_close_scope_reset = 403,        /* close_scope_reset  */
  YYSYMBOL_close_scope_rt = 404,           /* close_scope_rt  */
  YYSYMBOL_close_scope_sctp = 405,         /* close_scope_sctp  */
  YYSYMBOL_close_scope_sctp_chunk = 406,   /* close_scope_sctp_chunk  */
  YYSYMBOL_close_scope_secmark = 407,      /* close_scope_secmark  */
  YYSYMBOL_close_scope_socket = 408,       /* close_scope_socket  */
  YYSYMBOL_close_scope_tcp = 409,          /* close_scope_tcp  */
  YYSYMBOL_close_scope_tproxy = 410,       /* close_scope_tproxy  */
  YYSYMBOL_close_scope_type = 411,         /* close_scope_type  */
  YYSYMBOL_close_scope_th = 412,           /* close_scope_th  */
  YYSYMBOL_close_scope_udp = 413,          /* close_scope_udp  */
  YYSYMBOL_close_scope_udplite = 414,      /* close_scope_udplite  */
  YYSYMBOL_close_scope_log = 415,          /* close_scope_log  */
  YYSYMBOL_close_scope_synproxy = 416,     /* close_scope_synproxy  */
  YYSYMBOL_close_scope_xt = 417,           /* close_scope_xt  */
  YYSYMBOL_common_block = 418,             /* common_block  */
  YYSYMBOL_line = 419,                     /* line  */
  YYSYMBOL_base_cmd = 420,                 /* base_cmd  */
  YYSYMBOL_add_cmd = 421,                  /* add_cmd  */
  YYSYMBOL_replace_cmd = 422,              /* replace_cmd  */
  YYSYMBOL_create_cmd = 423,               /* create_cmd  */
  YYSYMBOL_insert_cmd = 424,               /* insert_cmd  */
  YYSYMBOL_table_or_id_spec = 425,         /* table_or_id_spec  */
  YYSYMBOL_chain_or_id_spec = 426,         /* chain_or_id_spec  */
  YYSYMBOL_set_or_id_spec = 427,           /* set_or_id_spec  */
  YYSYMBOL_obj_or_id_spec = 428,           /* obj_or_id_spec  */
  YYSYMBOL_delete_cmd = 429,               /* delete_cmd  */
  YYSYMBOL_get_cmd = 430,                  /* get_cmd  */
  YYSYMBOL_list_cmd = 431,                 /* list_cmd  */
  YYSYMBOL_basehook_device_name = 432,     /* basehook_device_name  */
  YYSYMBOL_basehook_spec = 433,            /* basehook_spec  */
  YYSYMBOL_reset_cmd = 434,                /* reset_cmd  */
  YYSYMBOL_flush_cmd = 435,                /* flush_cmd  */
  YYSYMBOL_rename_cmd = 436,               /* rename_cmd  */
  YYSYMBOL_import_cmd = 437,               /* import_cmd  */
  YYSYMBOL_export_cmd = 438,               /* export_cmd  */
  YYSYMBOL_monitor_cmd = 439,              /* monitor_cmd  */
  YYSYMBOL_monitor_event = 440,            /* monitor_event  */
  YYSYMBOL_monitor_object = 441,           /* monitor_object  */
  YYSYMBOL_monitor_format = 442,           /* monitor_format  */
  YYSYMBOL_markup_format = 443,            /* markup_format  */
  YYSYMBOL_describe_cmd = 444,             /* describe_cmd  */
  YYSYMBOL_table_block_alloc = 445,        /* table_block_alloc  */
  YYSYMBOL_table_options = 446,            /* table_options  */
  YYSYMBOL_table_block = 447,              /* table_block  */
  YYSYMBOL_chain_block_alloc = 448,        /* chain_block_alloc  */
  YYSYMBOL_chain_block = 449,              /* chain_block  */
  YYSYMBOL_subchain_block = 450,           /* subchain_block  */
  YYSYMBOL_typeof_data_expr = 451,         /* typeof_data_expr  */
  YYSYMBOL_typeof_expr = 452,              /* typeof_expr  */
  YYSYMBOL_set_block_alloc = 453,          /* set_block_alloc  */
  YYSYMBOL_set_block = 454,                /* set_block  */
  YYSYMBOL_set_block_expr = 455,           /* set_block_expr  */
  YYSYMBOL_set_flag_list = 456,            /* set_flag_list  */
  YYSYMBOL_set_flag = 457,                 /* set_flag  */
  YYSYMBOL_map_block_alloc = 458,          /* map_block_alloc  */
  YYSYMBOL_map_block_obj_type = 459,       /* map_block_obj_type  */
  YYSYMBOL_map_block = 460,                /* map_block  */
  YYSYMBOL_set_mechanism = 461,            /* set_mechanism  */
  YYSYMBOL_set_policy_spec = 462,          /* set_policy_spec  */
  YYSYMBOL_flowtable_block_alloc = 463,    /* flowtable_block_alloc  */
  YYSYMBOL_flowtable_block = 464,          /* flowtable_block  */
  YYSYMBOL_flowtable_expr = 465,           /* flowtable_expr  */
  YYSYMBOL_flowtable_list_expr = 466,      /* flowtable_list_expr  */
  YYSYMBOL_flowtable_expr_member = 467,    /* flowtable_expr_member  */
  YYSYMBOL_data_type_atom_expr = 468,      /* data_type_atom_expr  */
  YYSYMBOL_data_type_expr = 469,           /* data_type_expr  */
  YYSYMBOL_obj_block_alloc = 470,          /* obj_block_alloc  */
  YYSYMBOL_counter_block = 471,            /* counter_block  */
  YYSYMBOL_quota_block = 472,              /* quota_block  */
  YYSYMBOL_ct_helper_block = 473,          /* ct_helper_block  */
  YYSYMBOL_ct_timeout_block = 474,         /* ct_timeout_block  */
  YYSYMBOL_ct_expect_block = 475,          /* ct_expect_block  */
  YYSYMBOL_limit_block = 476,              /* limit_block  */
  YYSYMBOL_secmark_block = 477,            /* secmark_block  */
  YYSYMBOL_synproxy_block = 478,           /* synproxy_block  */
  YYSYMBOL_type_identifier = 479,          /* type_identifier  */
  YYSYMBOL_hook_spec = 480,                /* hook_spec  */
  YYSYMBOL_prio_spec = 481,                /* prio_spec  */
  YYSYMBOL_extended_prio_name = 482,       /* extended_prio_name  */
  YYSYMBOL_extended_prio_spec = 483,       /* extended_prio_spec  */
  YYSYMBOL_int_num = 484,                  /* int_num  */
  YYSYMBOL_dev_spec = 485,                 /* dev_spec  */
  YYSYMBOL_flags_spec = 486,               /* flags_spec  */
  YYSYMBOL_policy_spec = 487,              /* policy_spec  */
  YYSYMBOL_policy_expr = 488,              /* policy_expr  */
  YYSYMBOL_chain_policy = 489,             /* chain_policy  */
  YYSYMBOL_identifier = 490,               /* identifier  */
  YYSYMBOL_string = 491,                   /* string  */
  YYSYMBOL_time_spec = 492,                /* time_spec  */
  YYSYMBOL_family_spec = 493,              /* family_spec  */
  YYSYMBOL_family_spec_explicit = 494,     /* family_spec_explicit  */
  YYSYMBOL_table_spec = 495,               /* table_spec  */
  YYSYMBOL_tableid_spec = 496,             /* tableid_spec  */
  YYSYMBOL_chain_spec = 497,               /* chain_spec  */
  YYSYMBOL_chainid_spec = 498,             /* chainid_spec  */
  YYSYMBOL_chain_identifier = 499,         /* chain_identifier  */
  YYSYMBOL_set_spec = 500,                 /* set_spec  */
  YYSYMBOL_setid_spec = 501,               /* setid_spec  */
  YYSYMBOL_set_identifier = 502,           /* set_identifier  */
  YYSYMBOL_flowtable_spec = 503,           /* flowtable_spec  */
  YYSYMBOL_flowtableid_spec = 504,         /* flowtableid_spec  */
  YYSYMBOL_flowtable_identifier = 505,     /* flowtable_identifier  */
  YYSYMBOL_obj_spec = 506,                 /* obj_spec  */
  YYSYMBOL_objid_spec = 507,               /* objid_spec  */
  YYSYMBOL_obj_identifier = 508,           /* obj_identifier  */
  YYSYMBOL_handle_spec = 509,              /* handle_spec  */
  YYSYMBOL_position_spec = 510,            /* position_spec  */
  YYSYMBOL_index_spec = 511,               /* index_spec  */
  YYSYMBOL_rule_position = 512,            /* rule_position  */
  YYSYMBOL_ruleid_spec = 513,              /* ruleid_spec  */
  YYSYMBOL_comment_spec = 514,             /* comment_spec  */
  YYSYMBOL_ruleset_spec = 515,             /* ruleset_spec  */
  YYSYMBOL_rule = 516,                     /* rule  */
  YYSYMBOL_rule_alloc = 517,               /* rule_alloc  */
  YYSYMBOL_stmt_list = 518,                /* stmt_list  */
  YYSYMBOL_stateful_stmt_list = 519,       /* stateful_stmt_list  */
  YYSYMBOL_stateful_stmt = 520,            /* stateful_stmt  */
  YYSYMBOL_stmt = 521,                     /* stmt  */
  YYSYMBOL_xt_stmt = 522,                  /* xt_stmt  */
  YYSYMBOL_chain_stmt_type = 523,          /* chain_stmt_type  */
  YYSYMBOL_chain_stmt = 524,               /* chain_stmt  */
  YYSYMBOL_verdict_stmt = 525,             /* verdict_stmt  */
  YYSYMBOL_verdict_map_stmt = 526,         /* verdict_map_stmt  */
  YYSYMBOL_verdict_map_expr = 527,         /* verdict_map_expr  */
  YYSYMBOL_verdict_map_list_expr = 528,    /* verdict_map_list_expr  */
  YYSYMBOL_verdict_map_list_member_expr = 529, /* verdict_map_list_member_expr  */
  YYSYMBOL_connlimit_stmt = 530,           /* connlimit_stmt  */
  YYSYMBOL_counter_stmt = 531,             /* counter_stmt  */
  YYSYMBOL_counter_stmt_alloc = 532,       /* counter_stmt_alloc  */
  YYSYMBOL_counter_args = 533,             /* counter_args  */
  YYSYMBOL_counter_arg = 534,              /* counter_arg  */
  YYSYMBOL_log_stmt = 535,                 /* log_stmt  */
  YYSYMBOL_log_stmt_alloc = 536,           /* log_stmt_alloc  */
  YYSYMBOL_log_args = 537,                 /* log_args  */
  YYSYMBOL_log_arg = 538,                  /* log_arg  */
  YYSYMBOL_level_type = 539,               /* level_type  */
  YYSYMBOL_log_flags = 540,                /* log_flags  */
  YYSYMBOL_log_flags_tcp = 541,            /* log_flags_tcp  */
  YYSYMBOL_log_flag_tcp = 542,             /* log_flag_tcp  */
  YYSYMBOL_limit_stmt = 543,               /* limit_stmt  */
  YYSYMBOL_quota_mode = 544,               /* quota_mode  */
  YYSYMBOL_quota_unit = 545,               /* quota_unit  */
  YYSYMBOL_quota_used = 546,               /* quota_used  */
  YYSYMBOL_quota_stmt = 547,               /* quota_stmt  */
  YYSYMBOL_limit_mode = 548,               /* limit_mode  */
  YYSYMBOL_limit_burst_pkts = 549,         /* limit_burst_pkts  */
  YYSYMBOL_limit_rate_pkts = 550,          /* limit_rate_pkts  */
  YYSYMBOL_limit_burst_bytes = 551,        /* limit_burst_bytes  */
  YYSYMBOL_limit_rate_bytes = 552,         /* limit_rate_bytes  */
  YYSYMBOL_limit_bytes = 553,              /* limit_bytes  */
  YYSYMBOL_time_unit = 554,                /* time_unit  */
  YYSYMBOL_reject_stmt = 555,              /* reject_stmt  */
  YYSYMBOL_reject_stmt_alloc = 556,        /* reject_stmt_alloc  */
  YYSYMBOL_reject_with_expr = 557,         /* reject_with_expr  */
  YYSYMBOL_reject_opts = 558,              /* reject_opts  */
  YYSYMBOL_nat_stmt = 559,                 /* nat_stmt  */
  YYSYMBOL_nat_stmt_alloc = 560,           /* nat_stmt_alloc  */
  YYSYMBOL_tproxy_stmt = 561,              /* tproxy_stmt  */
  YYSYMBOL_synproxy_stmt = 562,            /* synproxy_stmt  */
  YYSYMBOL_synproxy_stmt_alloc = 563,      /* synproxy_stmt_alloc  */
  YYSYMBOL_synproxy_args = 564,            /* synproxy_args  */
  YYSYMBOL_synproxy_arg = 565,             /* synproxy_arg  */
  YYSYMBOL_synproxy_config = 566,          /* synproxy_config  */
  YYSYMBOL_synproxy_obj = 567,             /* synproxy_obj  */
  YYSYMBOL_synproxy_ts = 568,              /* synproxy_ts  */
  YYSYMBOL_synproxy_sack = 569,            /* synproxy_sack  */
  YYSYMBOL_primary_stmt_expr = 570,        /* primary_stmt_expr  */
  YYSYMBOL_shift_stmt_expr = 571,          /* shift_stmt_expr  */
  YYSYMBOL_and_stmt_expr = 572,            /* and_stmt_expr  */
  YYSYMBOL_exclusive_or_stmt_expr = 573,   /* exclusive_or_stmt_expr  */
  YYSYMBOL_inclusive_or_stmt_expr = 574,   /* inclusive_or_stmt_expr  */
  YYSYMBOL_basic_stmt_expr = 575,          /* basic_stmt_expr  */
  YYSYMBOL_concat_stmt_expr = 576,         /* concat_stmt_expr  */
  YYSYMBOL_map_stmt_expr_set = 577,        /* map_stmt_expr_set  */
  YYSYMBOL_map_stmt_expr = 578,            /* map_stmt_expr  */
  YYSYMBOL_prefix_stmt_expr = 579,         /* prefix_stmt_expr  */
  YYSYMBOL_range_stmt_expr = 580,          /* range_stmt_expr  */
  YYSYMBOL_multiton_stmt_expr = 581,       /* multiton_stmt_expr  */
  YYSYMBOL_stmt_expr = 582,                /* stmt_expr  */
  YYSYMBOL_nat_stmt_args = 583,            /* nat_stmt_args  */
  YYSYMBOL_masq_stmt = 584,                /* masq_stmt  */
  YYSYMBOL_masq_stmt_alloc = 585,          /* masq_stmt_alloc  */
  YYSYMBOL_masq_stmt_args = 586,           /* masq_stmt_args  */
  YYSYMBOL_redir_stmt = 587,               /* redir_stmt  */
  YYSYMBOL_redir_stmt_alloc = 588,         /* redir_stmt_alloc  */
  YYSYMBOL_redir_stmt_arg = 589,           /* redir_stmt_arg  */
  YYSYMBOL_dup_stmt = 590,                 /* dup_stmt  */
  YYSYMBOL_fwd_stmt = 591,                 /* fwd_stmt  */
  YYSYMBOL_nf_nat_flags = 592,             /* nf_nat_flags  */
  YYSYMBOL_nf_nat_flag = 593,              /* nf_nat_flag  */
  YYSYMBOL_queue_stmt = 594,               /* queue_stmt  */
  YYSYMBOL_queue_stmt_compat = 595,        /* queue_stmt_compat  */
  YYSYMBOL_queue_stmt_alloc = 596,         /* queue_stmt_alloc  */
  YYSYMBOL_queue_stmt_args = 597,          /* queue_stmt_args  */
  YYSYMBOL_queue_stmt_arg = 598,           /* queue_stmt_arg  */
  YYSYMBOL_queue_expr = 599,               /* queue_expr  */
  YYSYMBOL_queue_stmt_expr_simple = 600,   /* queue_stmt_expr_simple  */
  YYSYMBOL_queue_stmt_expr = 601,          /* queue_stmt_expr  */
  YYSYMBOL_queue_stmt_flags = 602,         /* queue_stmt_flags  */
  YYSYMBOL_queue_stmt_flag = 603,          /* queue_stmt_flag  */
  YYSYMBOL_set_elem_expr_stmt = 604,       /* set_elem_expr_stmt  */
  YYSYMBOL_set_elem_expr_stmt_alloc = 605, /* set_elem_expr_stmt_alloc  */
  YYSYMBOL_set_stmt = 606,                 /* set_stmt  */
  YYSYMBOL_set_stmt_op = 607,              /* set_stmt_op  */
  YYSYMBOL_map_stmt = 608,                 /* map_stmt  */
  YYSYMBOL_meter_stmt = 609,               /* meter_stmt  */
  YYSYMBOL_flow_stmt_legacy_alloc = 610,   /* flow_stmt_legacy_alloc  */
  YYSYMBOL_flow_stmt_opts = 611,           /* flow_stmt_opts  */
  YYSYMBOL_flow_stmt_opt = 612,            /* flow_stmt_opt  */
  YYSYMBOL_meter_stmt_alloc = 613,         /* meter_stmt_alloc  */
  YYSYMBOL_match_stmt = 614,               /* match_stmt  */
  YYSYMBOL_variable_expr = 615,            /* variable_expr  */
  YYSYMBOL_symbol_expr = 616,              /* symbol_expr  */
  YYSYMBOL_set_ref_expr = 617,             /* set_ref_expr  */
  YYSYMBOL_set_ref_symbol_expr = 618,      /* set_ref_symbol_expr  */
  YYSYMBOL_integer_expr = 619,             /* integer_expr  */
  YYSYMBOL_primary_expr = 620,             /* primary_expr  */
  YYSYMBOL_fib_expr = 621,                 /* fib_expr  */
  YYSYMBOL_fib_result = 622,               /* fib_result  */
  YYSYMBOL_fib_flag = 623,                 /* fib_flag  */
  YYSYMBOL_fib_tuple = 624,                /* fib_tuple  */
  YYSYMBOL_osf_expr = 625,                 /* osf_expr  */
  YYSYMBOL_osf_ttl = 626,                  /* osf_ttl  */
  YYSYMBOL_shift_expr = 627,               /* shift_expr  */
  YYSYMBOL_and_expr = 628,                 /* and_expr  */
  YYSYMBOL_exclusive_or_expr = 629,        /* exclusive_or_expr  */
  YYSYMBOL_inclusive_or_expr = 630,        /* inclusive_or_expr  */
  YYSYMBOL_basic_expr = 631,               /* basic_expr  */
  YYSYMBOL_concat_expr = 632,              /* concat_expr  */
  YYSYMBOL_prefix_rhs_expr = 633,          /* prefix_rhs_expr  */
  YYSYMBOL_range_rhs_expr = 634,           /* range_rhs_expr  */
  YYSYMBOL_multiton_rhs_expr = 635,        /* multiton_rhs_expr  */
  YYSYMBOL_map_expr = 636,                 /* map_expr  */
  YYSYMBOL_expr = 637,                     /* expr  */
  YYSYMBOL_set_expr = 638,                 /* set_expr  */
  YYSYMBOL_set_list_expr = 639,            /* set_list_expr  */
  YYSYMBOL_set_list_member_expr = 640,     /* set_list_member_expr  */
  YYSYMBOL_meter_key_expr = 641,           /* meter_key_expr  */
  YYSYMBOL_meter_key_expr_alloc = 642,     /* meter_key_expr_alloc  */
  YYSYMBOL_set_elem_expr = 643,            /* set_elem_expr  */
  YYSYMBOL_set_elem_key_expr = 644,        /* set_elem_key_expr  */
  YYSYMBOL_set_elem_expr_alloc = 645,      /* set_elem_expr_alloc  */
  YYSYMBOL_set_elem_options = 646,         /* set_elem_options  */
  YYSYMBOL_set_elem_option = 647,          /* set_elem_option  */
  YYSYMBOL_set_elem_expr_options = 648,    /* set_elem_expr_options  */
  YYSYMBOL_set_elem_stmt_list = 649,       /* set_elem_stmt_list  */
  YYSYMBOL_set_elem_stmt = 650,            /* set_elem_stmt  */
  YYSYMBOL_set_elem_expr_option = 651,     /* set_elem_expr_option  */
  YYSYMBOL_set_lhs_expr = 652,             /* set_lhs_expr  */
  YYSYMBOL_set_rhs_expr = 653,             /* set_rhs_expr  */
  YYSYMBOL_initializer_expr = 654,         /* initializer_expr  */
  YYSYMBOL_counter_config = 655,           /* counter_config  */
  YYSYMBOL_counter_obj = 656,              /* counter_obj  */
  YYSYMBOL_quota_config = 657,             /* quota_config  */
  YYSYMBOL_quota_obj = 658,                /* quota_obj  */
  YYSYMBOL_secmark_config = 659,           /* secmark_config  */
  YYSYMBOL_secmark_obj = 660,              /* secmark_obj  */
  YYSYMBOL_ct_obj_type = 661,              /* ct_obj_type  */
  YYSYMBOL_ct_cmd_type = 662,              /* ct_cmd_type  */
  YYSYMBOL_ct_l4protoname = 663,           /* ct_l4protoname  */
  YYSYMBOL_ct_helper_config = 664,         /* ct_helper_config  */
  YYSYMBOL_timeout_states = 665,           /* timeout_states  */
  YYSYMBOL_timeout_state = 666,            /* timeout_state  */
  YYSYMBOL_ct_timeout_config = 667,        /* ct_timeout_config  */
  YYSYMBOL_ct_expect_config = 668,         /* ct_expect_config  */
  YYSYMBOL_ct_obj_alloc = 669,             /* ct_obj_alloc  */
  YYSYMBOL_limit_config = 670,             /* limit_config  */
  YYSYMBOL_limit_obj = 671,                /* limit_obj  */
  YYSYMBOL_relational_expr = 672,          /* relational_expr  */
  YYSYMBOL_list_rhs_expr = 673,            /* list_rhs_expr  */
  YYSYMBOL_rhs_expr = 674,                 /* rhs_expr  */
  YYSYMBOL_shift_rhs_expr = 675,           /* shift_rhs_expr  */
  YYSYMBOL_and_rhs_expr = 676,             /* and_rhs_expr  */
  YYSYMBOL_exclusive_or_rhs_expr = 677,    /* exclusive_or_rhs_expr  */
  YYSYMBOL_inclusive_or_rhs_expr = 678,    /* inclusive_or_rhs_expr  */
  YYSYMBOL_basic_rhs_expr = 679,           /* basic_rhs_expr  */
  YYSYMBOL_concat_rhs_expr = 680,          /* concat_rhs_expr  */
  YYSYMBOL_boolean_keys = 681,             /* boolean_keys  */
  YYSYMBOL_boolean_expr = 682,             /* boolean_expr  */
  YYSYMBOL_keyword_expr = 683,             /* keyword_expr  */
  YYSYMBOL_primary_rhs_expr = 684,         /* primary_rhs_expr  */
  YYSYMBOL_relational_op = 685,            /* relational_op  */
  YYSYMBOL_verdict_expr = 686,             /* verdict_expr  */
  YYSYMBOL_chain_expr = 687,               /* chain_expr  */
  YYSYMBOL_meta_expr = 688,                /* meta_expr  */
  YYSYMBOL_meta_key = 689,                 /* meta_key  */
  YYSYMBOL_meta_key_qualified = 690,       /* meta_key_qualified  */
  YYSYMBOL_meta_key_unqualified = 691,     /* meta_key_unqualified  */
  YYSYMBOL_meta_stmt = 692,                /* meta_stmt  */
  YYSYMBOL_socket_expr = 693,              /* socket_expr  */
  YYSYMBOL_socket_key = 694,               /* socket_key  */
  YYSYMBOL_offset_opt = 695,               /* offset_opt  */
  YYSYMBOL_numgen_type = 696,              /* numgen_type  */
  YYSYMBOL_numgen_expr = 697,              /* numgen_expr  */
  YYSYMBOL_xfrm_spnum = 698,               /* xfrm_spnum  */
  YYSYMBOL_xfrm_dir = 699,                 /* xfrm_dir  */
  YYSYMBOL_xfrm_state_key = 700,           /* xfrm_state_key  */
  YYSYMBOL_xfrm_state_proto_key = 701,     /* xfrm_state_proto_key  */
  YYSYMBOL_xfrm_expr = 702,                /* xfrm_expr  */
  YYSYMBOL_hash_expr = 703,                /* hash_expr  */
  YYSYMBOL_nf_key_proto = 704,             /* nf_key_proto  */
  YYSYMBOL_rt_expr = 705,                  /* rt_expr  */
  YYSYMBOL_rt_key = 706,                   /* rt_key  */
  YYSYMBOL_ct_expr = 707,                  /* ct_expr  */
  YYSYMBOL_ct_dir = 708,                   /* ct_dir  */
  YYSYMBOL_ct_key = 709,                   /* ct_key  */
  YYSYMBOL_ct_key_dir = 710,               /* ct_key_dir  */
  YYSYMBOL_ct_key_proto_field = 711,       /* ct_key_proto_field  */
  YYSYMBOL_ct_key_dir_optional = 712,      /* ct_key_dir_optional  */
  YYSYMBOL_symbol_stmt_expr = 713,         /* symbol_stmt_expr  */
  YYSYMBOL_list_stmt_expr = 714,           /* list_stmt_expr  */
  YYSYMBOL_ct_stmt = 715,                  /* ct_stmt  */
  YYSYMBOL_payload_stmt = 716,             /* payload_stmt  */
  YYSYMBOL_payload_expr = 717,             /* payload_expr  */
  YYSYMBOL_payload_raw_expr = 718,         /* payload_raw_expr  */
  YYSYMBOL_payload_base_spec = 719,        /* payload_base_spec  */
  YYSYMBOL_eth_hdr_expr = 720,             /* eth_hdr_expr  */
  YYSYMBOL_eth_hdr_field = 721,            /* eth_hdr_field  */
  YYSYMBOL_vlan_hdr_expr = 722,            /* vlan_hdr_expr  */
  YYSYMBOL_vlan_hdr_field = 723,           /* vlan_hdr_field  */
  YYSYMBOL_arp_hdr_expr = 724,             /* arp_hdr_expr  */
  YYSYMBOL_arp_hdr_field = 725,            /* arp_hdr_field  */
  YYSYMBOL_ip_hdr_expr = 726,              /* ip_hdr_expr  */
  YYSYMBOL_ip_hdr_field = 727,             /* ip_hdr_field  */
  YYSYMBOL_ip_option_type = 728,           /* ip_option_type  */
  YYSYMBOL_ip_option_field = 729,          /* ip_option_field  */
  YYSYMBOL_icmp_hdr_expr = 730,            /* icmp_hdr_expr  */
  YYSYMBOL_icmp_hdr_field = 731,           /* icmp_hdr_field  */
  YYSYMBOL_igmp_hdr_expr = 732,            /* igmp_hdr_expr  */
  YYSYMBOL_igmp_hdr_field = 733,           /* igmp_hdr_field  */
  YYSYMBOL_ip6_hdr_expr = 734,             /* ip6_hdr_expr  */
  YYSYMBOL_ip6_hdr_field = 735,            /* ip6_hdr_field  */
  YYSYMBOL_icmp6_hdr_expr = 736,           /* icmp6_hdr_expr  */
  YYSYMBOL_icmp6_hdr_field = 737,          /* icmp6_hdr_field  */
  YYSYMBOL_auth_hdr_expr = 738,            /* auth_hdr_expr  */
  YYSYMBOL_auth_hdr_field = 739,           /* auth_hdr_field  */
  YYSYMBOL_esp_hdr_expr = 740,             /* esp_hdr_expr  */
  YYSYMBOL_esp_hdr_field = 741,            /* esp_hdr_field  */
  YYSYMBOL_comp_hdr_expr = 742,            /* comp_hdr_expr  */
  YYSYMBOL_comp_hdr_field = 743,           /* comp_hdr_field  */
  YYSYMBOL_udp_hdr_expr = 744,             /* udp_hdr_expr  */
  YYSYMBOL_udp_hdr_field = 745,            /* udp_hdr_field  */
  YYSYMBOL_udplite_hdr_expr = 746,         /* udplite_hdr_expr  */
  YYSYMBOL_udplite_hdr_field = 747,        /* udplite_hdr_field  */
  YYSYMBOL_tcp_hdr_expr = 748,             /* tcp_hdr_expr  */
  YYSYMBOL_optstrip_stmt = 749,            /* optstrip_stmt  */
  YYSYMBOL_tcp_hdr_field = 750,            /* tcp_hdr_field  */
  YYSYMBOL_tcp_hdr_option_kind_and_field = 751, /* tcp_hdr_option_kind_and_field  */
  YYSYMBOL_tcp_hdr_option_sack = 752,      /* tcp_hdr_option_sack  */
  YYSYMBOL_tcp_hdr_option_type = 753,      /* tcp_hdr_option_type  */
  YYSYMBOL_tcpopt_field_sack = 754,        /* tcpopt_field_sack  */
  YYSYMBOL_tcpopt_field_window = 755,      /* tcpopt_field_window  */
  YYSYMBOL_tcpopt_field_tsopt = 756,       /* tcpopt_field_tsopt  */
  YYSYMBOL_tcpopt_field_maxseg = 757,      /* tcpopt_field_maxseg  */
  YYSYMBOL_tcpopt_field_mptcp = 758,       /* tcpopt_field_mptcp  */
  YYSYMBOL_dccp_hdr_expr = 759,            /* dccp_hdr_expr  */
  YYSYMBOL_dccp_hdr_field = 760,           /* dccp_hdr_field  */
  YYSYMBOL_sctp_chunk_type = 761,          /* sctp_chunk_type  */
  YYSYMBOL_sctp_chunk_common_field = 762,  /* sctp_chunk_common_field  */
  YYSYMBOL_sctp_chunk_data_field = 763,    /* sctp_chunk_data_field  */
  YYSYMBOL_sctp_chunk_init_field = 764,    /* sctp_chunk_init_field  */
  YYSYMBOL_sctp_chunk_sack_field = 765,    /* sctp_chunk_sack_field  */
  YYSYMBOL_sctp_chunk_alloc = 766,         /* sctp_chunk_alloc  */
  YYSYMBOL_sctp_hdr_expr = 767,            /* sctp_hdr_expr  */
  YYSYMBOL_sctp_hdr_field = 768,           /* sctp_hdr_field  */
  YYSYMBOL_th_hdr_expr = 769,              /* th_hdr_expr  */
  YYSYMBOL_th_hdr_field = 770,             /* th_hdr_field  */
  YYSYMBOL_exthdr_expr = 771,              /* exthdr_expr  */
  YYSYMBOL_hbh_hdr_expr = 772,             /* hbh_hdr_expr  */
  YYSYMBOL_hbh_hdr_field = 773,            /* hbh_hdr_field  */
  YYSYMBOL_rt_hdr_expr = 774,              /* rt_hdr_expr  */
  YYSYMBOL_rt_hdr_field = 775,             /* rt_hdr_field  */
  YYSYMBOL_rt0_hdr_expr = 776,             /* rt0_hdr_expr  */
  YYSYMBOL_rt0_hdr_field = 777,            /* rt0_hdr_field  */
  YYSYMBOL_rt2_hdr_expr = 778,             /* rt2_hdr_expr  */
  YYSYMBOL_rt2_hdr_field = 779,            /* rt2_hdr_field  */
  YYSYMBOL_rt4_hdr_expr = 780,             /* rt4_hdr_expr  */
  YYSYMBOL_rt4_hdr_field = 781,            /* rt4_hdr_field  */
  YYSYMBOL_frag_hdr_expr = 782,            /* frag_hdr_expr  */
  YYSYMBOL_frag_hdr_field = 783,           /* frag_hdr_field  */
  YYSYMBOL_dst_hdr_expr = 784,             /* dst_hdr_expr  */
  YYSYMBOL_dst_hdr_field = 785,            /* dst_hdr_field  */
  YYSYMBOL_mh_hdr_expr = 786,              /* mh_hdr_expr  */
  YYSYMBOL_mh_hdr_field = 787,             /* mh_hdr_field  */
  YYSYMBOL_exthdr_exists_expr = 788,       /* exthdr_exists_expr  */
  YYSYMBOL_exthdr_key = 789                /* exthdr_key  */
};
typedef enum yysymbol_kind_t yysymbol_kind_t;




#ifdef short
# undef short
#endif

/* On compilers that do not define __PTRDIFF_MAX__ etc., make sure
   <limits.h> and (if available) <stdint.h> are included
   so that the code can choose integer types of a good width.  */

#ifndef __PTRDIFF_MAX__
# include <limits.h> /* INFRINGES ON USER NAME SPACE */
# if defined __STDC_VERSION__ && 199901 <= __STDC_VERSION__
#  include <stdint.h> /* INFRINGES ON USER NAME SPACE */
#  define YY_STDINT_H
# endif
#endif

/* Narrow types that promote to a signed type and that can represent a
   signed or unsigned integer of at least N bits.  In tables they can
   save space and decrease cache pressure.  Promoting to a signed type
   helps avoid bugs in integer arithmetic.  */

#ifdef __INT_LEAST8_MAX__
typedef __INT_LEAST8_TYPE__ yytype_int8;
#elif defined YY_STDINT_H
typedef int_least8_t yytype_int8;
#else
typedef signed char yytype_int8;
#endif

#ifdef __INT_LEAST16_MAX__
typedef __INT_LEAST16_TYPE__ yytype_int16;
#elif defined YY_STDINT_H
typedef int_least16_t yytype_int16;
#else
typedef short yytype_int16;
#endif

/* Work around bug in HP-UX 11.23, which defines these macros
   incorrectly for preprocessor constants.  This workaround can likely
   be removed in 2023, as HPE has promised support for HP-UX 11.23
   (aka HP-UX 11i v2) only through the end of 2022; see Table 2 of
   <https://h20195.www2.hpe.com/V2/getpdf.aspx/4AA4-7673ENW.pdf>.  */
#ifdef __hpux
# undef UINT_LEAST8_MAX
# undef UINT_LEAST16_MAX
# define UINT_LEAST8_MAX 255
# define UINT_LEAST16_MAX 65535
#endif

#if defined __UINT_LEAST8_MAX__ && __UINT_LEAST8_MAX__ <= __INT_MAX__
typedef __UINT_LEAST8_TYPE__ yytype_uint8;
#elif (!defined __UINT_LEAST8_MAX__ && defined YY_STDINT_H \
       && UINT_LEAST8_MAX <= INT_MAX)
typedef uint_least8_t yytype_uint8;
#elif !defined __UINT_LEAST8_MAX__ && UCHAR_MAX <= INT_MAX
typedef unsigned char yytype_uint8;
#else
typedef short yytype_uint8;
#endif

#if defined __UINT_LEAST16_MAX__ && __UINT_LEAST16_MAX__ <= __INT_MAX__
typedef __UINT_LEAST16_TYPE__ yytype_uint16;
#elif (!defined __UINT_LEAST16_MAX__ && defined YY_STDINT_H \
       && UINT_LEAST16_MAX <= INT_MAX)
typedef uint_least16_t yytype_uint16;
#elif !defined __UINT_LEAST16_MAX__ && USHRT_MAX <= INT_MAX
typedef unsigned short yytype_uint16;
#else
typedef int yytype_uint16;
#endif

#ifndef YYPTRDIFF_T
# if defined __PTRDIFF_TYPE__ && defined __PTRDIFF_MAX__
#  define YYPTRDIFF_T __PTRDIFF_TYPE__
#  define YYPTRDIFF_MAXIMUM __PTRDIFF_MAX__
# elif defined PTRDIFF_MAX
#  ifndef ptrdiff_t
#   include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  endif
#  define YYPTRDIFF_T ptrdiff_t
#  define YYPTRDIFF_MAXIMUM PTRDIFF_MAX
# else
#  define YYPTRDIFF_T long
#  define YYPTRDIFF_MAXIMUM LONG_MAX
# endif
#endif

#ifndef YYSIZE_T
# ifdef __SIZE_TYPE__
#  define YYSIZE_T __SIZE_TYPE__
# elif defined size_t
#  define YYSIZE_T size_t
# elif defined __STDC_VERSION__ && 199901 <= __STDC_VERSION__
#  include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  define YYSIZE_T size_t
# else
#  define YYSIZE_T unsigned
# endif
#endif

#define YYSIZE_MAXIMUM                                  \
  YY_CAST (YYPTRDIFF_T,                                 \
           (YYPTRDIFF_MAXIMUM < YY_CAST (YYSIZE_T, -1)  \
            ? YYPTRDIFF_MAXIMUM                         \
            : YY_CAST (YYSIZE_T, -1)))

#define YYSIZEOF(X) YY_CAST (YYPTRDIFF_T, sizeof (X))


/* Stored state numbers (used for stacks). */
typedef yytype_int16 yy_state_t;

/* State numbers in computations.  */
typedef int yy_state_fast_t;

#ifndef YY_
# if defined YYENABLE_NLS && YYENABLE_NLS
#  if ENABLE_NLS
#   include <libintl.h> /* INFRINGES ON USER NAME SPACE */
#   define YY_(Msgid) dgettext ("bison-runtime", Msgid)
#  endif
# endif
# ifndef YY_
#  define YY_(Msgid) Msgid
# endif
#endif


#ifndef YY_ATTRIBUTE_PURE
# if defined __GNUC__ && 2 < __GNUC__ + (96 <= __GNUC_MINOR__)
#  define YY_ATTRIBUTE_PURE __attribute__ ((__pure__))
# else
#  define YY_ATTRIBUTE_PURE
# endif
#endif

#ifndef YY_ATTRIBUTE_UNUSED
# if defined __GNUC__ && 2 < __GNUC__ + (7 <= __GNUC_MINOR__)
#  define YY_ATTRIBUTE_UNUSED __attribute__ ((__unused__))
# else
#  define YY_ATTRIBUTE_UNUSED
# endif
#endif

/* Suppress unused-variable warnings by "using" E.  */
#if ! defined lint || defined __GNUC__
# define YY_USE(E) ((void) (E))
#else
# define YY_USE(E) /* empty */
#endif

/* Suppress an incorrect diagnostic about yylval being uninitialized.  */
#if defined __GNUC__ && ! defined __ICC && 406 <= __GNUC__ * 100 + __GNUC_MINOR__
# if __GNUC__ * 100 + __GNUC_MINOR__ < 407
#  define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN                           \
    _Pragma ("GCC diagnostic push")                                     \
    _Pragma ("GCC diagnostic ignored \"-Wuninitialized\"")
# else
#  define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN                           \
    _Pragma ("GCC diagnostic push")                                     \
    _Pragma ("GCC diagnostic ignored \"-Wuninitialized\"")              \
    _Pragma ("GCC diagnostic ignored \"-Wmaybe-uninitialized\"")
# endif
# define YY_IGNORE_MAYBE_UNINITIALIZED_END      \
    _Pragma ("GCC diagnostic pop")
#else
# define YY_INITIAL_VALUE(Value) Value
#endif
#ifndef YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
# define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
# define YY_IGNORE_MAYBE_UNINITIALIZED_END
#endif
#ifndef YY_INITIAL_VALUE
# define YY_INITIAL_VALUE(Value) /* Nothing. */
#endif

#if defined __cplusplus && defined __GNUC__ && ! defined __ICC && 6 <= __GNUC__
# define YY_IGNORE_USELESS_CAST_BEGIN                          \
    _Pragma ("GCC diagnostic push")                            \
    _Pragma ("GCC diagnostic ignored \"-Wuseless-cast\"")
# define YY_IGNORE_USELESS_CAST_END            \
    _Pragma ("GCC diagnostic pop")
#endif
#ifndef YY_IGNORE_USELESS_CAST_BEGIN
# define YY_IGNORE_USELESS_CAST_BEGIN
# define YY_IGNORE_USELESS_CAST_END
#endif


#define YY_ASSERT(E) ((void) (0 && (E)))

#if 1

/* The parser invokes alloca or malloc; define the necessary symbols.  */

# ifdef YYSTACK_USE_ALLOCA
#  if YYSTACK_USE_ALLOCA
#   ifdef __GNUC__
#    define YYSTACK_ALLOC __builtin_alloca
#   elif defined __BUILTIN_VA_ARG_INCR
#    include <alloca.h> /* INFRINGES ON USER NAME SPACE */
#   elif defined _AIX
#    define YYSTACK_ALLOC __alloca
#   elif defined _MSC_VER
#    include <malloc.h> /* INFRINGES ON USER NAME SPACE */
#    define alloca _alloca
#   else
#    define YYSTACK_ALLOC alloca
#    if ! defined _ALLOCA_H && ! defined EXIT_SUCCESS
#     include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
      /* Use EXIT_SUCCESS as a witness for stdlib.h.  */
#     ifndef EXIT_SUCCESS
#      define EXIT_SUCCESS 0
#     endif
#    endif
#   endif
#  endif
# endif

# ifdef YYSTACK_ALLOC
   /* Pacify GCC's 'empty if-body' warning.  */
#  define YYSTACK_FREE(Ptr) do { /* empty */; } while (0)
#  ifndef YYSTACK_ALLOC_MAXIMUM
    /* The OS might guarantee only one guard page at the bottom of the stack,
       and a page size can be as small as 4096 bytes.  So we cannot safely
       invoke alloca (N) if N exceeds 4096.  Use a slightly smaller number
       to allow for a few compiler-allocated temporary stack slots.  */
#   define YYSTACK_ALLOC_MAXIMUM 4032 /* reasonable circa 2006 */
#  endif
# else
#  define YYSTACK_ALLOC YYMALLOC
#  define YYSTACK_FREE YYFREE
#  ifndef YYSTACK_ALLOC_MAXIMUM
#   define YYSTACK_ALLOC_MAXIMUM YYSIZE_MAXIMUM
#  endif
#  if (defined __cplusplus && ! defined EXIT_SUCCESS \
       && ! ((defined YYMALLOC || defined malloc) \
             && (defined YYFREE || defined free)))
#   include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
#   ifndef EXIT_SUCCESS
#    define EXIT_SUCCESS 0
#   endif
#  endif
#  ifndef YYMALLOC
#   define YYMALLOC malloc
#   if ! defined malloc && ! defined EXIT_SUCCESS
void *malloc (YYSIZE_T); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
#  ifndef YYFREE
#   define YYFREE free
#   if ! defined free && ! defined EXIT_SUCCESS
void free (void *); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
# endif
#endif /* 1 */

#if (! defined yyoverflow \
     && (! defined __cplusplus \
         || (defined NFT_LTYPE_IS_TRIVIAL && NFT_LTYPE_IS_TRIVIAL \
             && defined NFT_STYPE_IS_TRIVIAL && NFT_STYPE_IS_TRIVIAL)))

/* A type that is properly aligned for any stack member.  */
union yyalloc
{
  yy_state_t yyss_alloc;
  YYSTYPE yyvs_alloc;
  YYLTYPE yyls_alloc;
};

/* The size of the maximum gap between one aligned stack and the next.  */
# define YYSTACK_GAP_MAXIMUM (YYSIZEOF (union yyalloc) - 1)

/* The size of an array large to enough to hold all stacks, each with
   N elements.  */
# define YYSTACK_BYTES(N) \
     ((N) * (YYSIZEOF (yy_state_t) + YYSIZEOF (YYSTYPE) \
             + YYSIZEOF (YYLTYPE)) \
      + 2 * YYSTACK_GAP_MAXIMUM)

# define YYCOPY_NEEDED 1

/* Relocate STACK from its old location to the new one.  The
   local variables YYSIZE and YYSTACKSIZE give the old and new number of
   elements in the stack, and YYPTR gives the new location of the
   stack.  Advance YYPTR to a properly aligned location for the next
   stack.  */
# define YYSTACK_RELOCATE(Stack_alloc, Stack)                           \
    do                                                                  \
      {                                                                 \
        YYPTRDIFF_T yynewbytes;                                         \
        YYCOPY (&yyptr->Stack_alloc, Stack, yysize);                    \
        Stack = &yyptr->Stack_alloc;                                    \
        yynewbytes = yystacksize * YYSIZEOF (*Stack) + YYSTACK_GAP_MAXIMUM; \
        yyptr += yynewbytes / YYSIZEOF (*yyptr);                        \
      }                                                                 \
    while (0)

#endif

#if defined YYCOPY_NEEDED && YYCOPY_NEEDED
/* Copy COUNT objects from SRC to DST.  The source and destination do
   not overlap.  */
# ifndef YYCOPY
#  if defined __GNUC__ && 1 < __GNUC__
#   define YYCOPY(Dst, Src, Count) \
      __builtin_memcpy (Dst, Src, YY_CAST (YYSIZE_T, (Count)) * sizeof (*(Src)))
#  else
#   define YYCOPY(Dst, Src, Count)              \
      do                                        \
        {                                       \
          YYPTRDIFF_T yyi;                      \
          for (yyi = 0; yyi < (Count); yyi++)   \
            (Dst)[yyi] = (Src)[yyi];            \
        }                                       \
      while (0)
#  endif
# endif
#endif /* !YYCOPY_NEEDED */

/* YYFINAL -- State number of the termination state.  */
#define YYFINAL  2
/* YYLAST -- Last index in YYTABLE.  */
#define YYLAST   8050

/* YYNTOKENS -- Number of terminals.  */
#define YYNTOKENS  363
/* YYNNTS -- Number of nonterminals.  */
#define YYNNTS  427
/* YYNRULES -- Number of rules.  */
#define YYNRULES  1281
/* YYNSTATES -- Number of states.  */
#define YYNSTATES  2203

/* YYMAXUTOK -- Last valid token kind.  */
#define YYMAXUTOK   608


/* YYTRANSLATE(TOKEN-NUM) -- Symbol number corresponding to TOKEN-NUM
   as returned by yylex, with out-of-bounds checking.  */
#define YYTRANSLATE(YYX)                                \
  (0 <= (YYX) && (YYX) <= YYMAXUTOK                     \
   ? YY_CAST (yysymbol_kind_t, yytranslate[YYX])        \
   : YYSYMBOL_YYUNDEF)

/* YYTRANSLATE[TOKEN-NUM] -- Symbol number corresponding to TOKEN-NUM
   as returned by yylex.  */
static const yytype_int16 yytranslate[] =
{
       0,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,   360,     2,     2,     2,
     357,   358,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,   354,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,   361,     2,   362,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,   355,   359,   356,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     1,     2,     3,     4,
       5,     6,     7,     8,     9,    10,    11,    12,    13,    14,
      15,    16,    17,    18,    19,    20,    21,    22,    23,    24,
      25,    26,    27,    28,    29,    30,    31,    32,    33,    34,
      35,    36,    37,    38,    39,    40,    41,    42,    43,    44,
      45,    46,    47,    48,    49,    50,    51,    52,    53,    54,
      55,    56,    57,    58,    59,    60,    61,    62,    63,    64,
      65,    66,    67,    68,    69,    70,    71,    72,    73,    74,
      75,    76,    77,    78,    79,    80,    81,    82,    83,    84,
      85,    86,    87,    88,    89,    90,    91,    92,    93,    94,
      95,    96,    97,    98,    99,   100,   101,   102,   103,   104,
     105,   106,   107,   108,   109,   110,   111,   112,   113,   114,
     115,   116,   117,   118,   119,   120,   121,   122,   123,   124,
     125,   126,   127,   128,   129,   130,   131,   132,   133,   134,
     135,   136,   137,   138,   139,   140,   141,   142,   143,   144,
     145,   146,   147,   148,   149,   150,   151,   152,   153,   154,
     155,   156,   157,   158,   159,   160,   161,   162,   163,   164,
     165,   166,   167,   168,   169,   170,   171,   172,   173,   174,
     175,   176,   177,   178,   179,   180,   181,   182,   183,   184,
     185,   186,   187,   188,   189,   190,   191,   192,   193,   194,
     195,   196,   197,   198,   199,   200,   201,   202,   203,   204,
     205,   206,   207,   208,   209,   210,   211,   212,   213,   214,
     215,   216,   217,   218,   219,   220,   221,   222,   223,   224,
     225,   226,   227,   228,   229,   230,   231,   232,   233,   234,
     235,   236,   237,   238,   239,   240,   241,   242,   243,   244,
     245,   246,   247,   248,   249,   250,   251,   252,   253,   254,
     255,   256,   257,   258,   259,   260,   261,   262,   263,   264,
     265,   266,   267,   268,   269,   270,   271,   272,   273,   274,
     275,   276,   277,   278,   279,   280,   281,   282,   283,   284,
     285,   286,   287,   288,   289,   290,   291,   292,   293,   294,
     295,   296,   297,   298,   299,   300,   301,   302,   303,   304,
     305,   306,   307,   308,   309,   310,   311,   312,   313,   314,
     315,   316,   317,   318,   319,   320,   321,   322,   323,   324,
     325,   326,   327,   328,   329,   330,   331,   332,   333,   334,
     335,   336,   337,   338,   339,   340,   341,   342,   343,   344,
     345,   346,   347,   348,   349,   350,   351,   352,   353
};

#if NFT_DEBUG
/* YYRLINE[YYN] -- Source line where rule number YYN was defined.  */
static const yytype_int16 yyrline[] =
{
       0,   930,   930,   931,   940,   941,   944,   945,   948,   949,
     950,   951,   952,   953,   954,   955,   956,   957,   958,   959,
     960,   961,   962,   963,   964,   965,   966,   967,   968,   969,
     970,   971,   972,   973,   974,   975,   976,   977,   978,   979,
     980,   981,   982,   983,   984,   985,   986,   987,   988,   989,
     990,   991,   992,   993,   994,   995,   997,   998,   999,  1001,
    1009,  1024,  1031,  1043,  1051,  1052,  1053,  1054,  1074,  1075,
    1076,  1077,  1078,  1079,  1080,  1081,  1082,  1083,  1084,  1085,
    1086,  1087,  1088,  1091,  1095,  1102,  1106,  1114,  1118,  1122,
    1129,  1136,  1140,  1147,  1156,  1160,  1164,  1168,  1172,  1176,
    1180,  1184,  1188,  1192,  1196,  1200,  1204,  1210,  1216,  1220,
    1227,  1231,  1239,  1246,  1253,  1257,  1264,  1273,  1277,  1281,
    1285,  1289,  1293,  1297,  1301,  1307,  1313,  1314,  1317,  1318,
    1321,  1322,  1325,  1326,  1329,  1333,  1337,  1341,  1345,  1349,
    1353,  1357,  1361,  1368,  1372,  1376,  1382,  1386,  1390,  1396,
    1402,  1406,  1410,  1414,  1418,  1422,  1426,  1430,  1434,  1438,
    1442,  1446,  1450,  1454,  1458,  1462,  1466,  1470,  1474,  1478,
    1482,  1486,  1490,  1494,  1498,  1502,  1506,  1510,  1514,  1518,
    1522,  1526,  1530,  1534,  1540,  1546,  1550,  1560,  1564,  1568,
    1572,  1576,  1580,  1586,  1590,  1594,  1598,  1602,  1606,  1610,
    1616,  1623,  1629,  1637,  1643,  1651,  1660,  1661,  1664,  1665,
    1666,  1667,  1668,  1669,  1670,  1671,  1674,  1675,  1678,  1679,
    1680,  1683,  1692,  1702,  1717,  1727,  1728,  1729,  1730,  1731,
    1742,  1752,  1763,  1773,  1784,  1795,  1804,  1813,  1822,  1833,
    1844,  1858,  1868,  1869,  1870,  1871,  1872,  1873,  1874,  1879,
    1889,  1890,  1891,  1898,  1919,  1930,  1941,  1954,  1959,  1960,
    1961,  1962,  1967,  1973,  1978,  1983,  1988,  1994,  1999,  2004,
    2005,  2016,  2017,  2020,  2024,  2027,  2028,  2029,  2030,  2034,
    2039,  2040,  2041,  2042,  2043,  2046,  2047,  2048,  2049,  2054,
    2064,  2075,  2086,  2098,  2107,  2112,  2118,  2123,  2132,  2135,
    2139,  2145,  2146,  2150,  2155,  2156,  2157,  2158,  2172,  2176,
    2180,  2186,  2191,  2198,  2203,  2208,  2211,  2218,  2225,  2232,
    2245,  2252,  2253,  2265,  2270,  2271,  2272,  2273,  2277,  2287,
    2288,  2289,  2290,  2294,  2304,  2305,  2306,  2307,  2311,  2322,
    2326,  2327,  2328,  2332,  2342,  2343,  2344,  2345,  2349,  2359,
    2360,  2361,  2362,  2366,  2376,  2377,  2378,  2379,  2383,  2393,
    2394,  2395,  2396,  2400,  2410,  2411,  2412,  2413,  2414,  2417,
    2448,  2455,  2459,  2462,  2472,  2479,  2490,  2503,  2518,  2519,
    2522,  2534,  2540,  2544,  2547,  2553,  2566,  2571,  2580,  2581,
    2584,  2587,  2588,  2589,  2592,  2607,  2608,  2611,  2612,  2613,
    2614,  2615,  2616,  2619,  2628,  2637,  2645,  2653,  2661,  2669,
    2677,  2685,  2693,  2701,  2709,  2717,  2725,  2733,  2741,  2749,
    2757,  2761,  2766,  2774,  2781,  2788,  2802,  2806,  2813,  2817,
    2823,  2835,  2841,  2848,  2854,  2861,  2862,  2863,  2864,  2867,
    2868,  2869,  2870,  2871,  2872,  2873,  2874,  2875,  2876,  2877,
    2878,  2879,  2880,  2881,  2882,  2883,  2884,  2885,  2886,  2887,
    2888,  2891,  2902,  2903,  2906,  2915,  2919,  2925,  2931,  2936,
    2939,  2944,  2949,  2952,  2958,  2963,  2971,  2972,  2974,  2978,
    2986,  2990,  2993,  2997,  3003,  3004,  3007,  3013,  3017,  3020,
    3145,  3150,  3155,  3160,  3165,  3171,  3201,  3205,  3209,  3213,
    3217,  3223,  3227,  3230,  3234,  3240,  3254,  3263,  3271,  3272,
    3273,  3276,  3277,  3280,  3281,  3296,  3312,  3320,  3321,  3322,
    3325,  3326,  3329,  3336,  3337,  3340,  3354,  3361,  3362,  3377,
    3378,  3379,  3380,  3381,  3384,  3387,  3393,  3399,  3403,  3407,
    3414,  3421,  3428,  3435,  3441,  3447,  3453,  3456,  3457,  3460,
    3466,  3472,  3478,  3485,  3492,  3500,  3501,  3504,  3508,  3516,
    3520,  3523,  3528,  3533,  3537,  3543,  3559,  3578,  3584,  3585,
    3591,  3592,  3598,  3599,  3600,  3601,  3602,  3603,  3604,  3605,
    3606,  3607,  3608,  3609,  3610,  3613,  3614,  3618,  3624,  3625,
    3631,  3632,  3638,  3639,  3645,  3648,  3649,  3660,  3661,  3664,
    3668,  3671,  3677,  3683,  3684,  3687,  3688,  3689,  3692,  3696,
    3700,  3705,  3710,  3715,  3721,  3725,  3729,  3733,  3739,  3744,
    3748,  3756,  3765,  3766,  3769,  3772,  3776,  3781,  3787,  3788,
    3791,  3794,  3798,  3802,  3806,  3811,  3818,  3823,  3831,  3836,
    3845,  3846,  3852,  3853,  3854,  3857,  3858,  3862,  3866,  3872,
    3873,  3876,  3882,  3886,  3889,  3894,  3900,  3901,  3904,  3905,
    3906,  3912,  3913,  3914,  3915,  3918,  3919,  3925,  3926,  3929,
    3930,  3933,  3939,  3946,  3953,  3964,  3965,  3966,  3969,  3977,
    3989,  3996,  3999,  4005,  4009,  4012,  4018,  4027,  4038,  4044,
    4070,  4071,  4080,  4081,  4084,  4093,  4104,  4105,  4106,  4107,
    4108,  4109,  4110,  4111,  4112,  4113,  4114,  4115,  4116,  4117,
    4118,  4121,  4144,  4145,  4146,  4149,  4150,  4151,  4152,  4153,
    4156,  4160,  4163,  4167,  4174,  4177,  4193,  4194,  4198,  4204,
    4205,  4211,  4212,  4218,  4219,  4225,  4228,  4229,  4240,  4246,
    4252,  4253,  4256,  4262,  4263,  4264,  4267,  4274,  4279,  4284,
    4287,  4291,  4295,  4301,  4302,  4309,  4315,  4316,  4319,  4320,
    4323,  4329,  4335,  4339,  4342,  4346,  4350,  4360,  4364,  4367,
    4373,  4380,  4384,  4390,  4404,  4418,  4423,  4431,  4435,  4439,
    4449,  4452,  4453,  4456,  4457,  4458,  4459,  4470,  4481,  4487,
    4508,  4514,  4531,  4537,  4538,  4539,  4542,  4543,  4544,  4547,
    4548,  4551,  4567,  4573,  4579,  4586,  4600,  4608,  4616,  4622,
    4626,  4630,  4634,  4638,  4645,  4650,  4661,  4675,  4681,  4685,
    4689,  4693,  4697,  4701,  4705,  4709,  4715,  4721,  4729,  4730,
    4731,  4734,  4735,  4739,  4745,  4746,  4752,  4753,  4759,  4760,
    4766,  4769,  4770,  4771,  4780,  4791,  4792,  4795,  4803,  4804,
    4805,  4806,  4807,  4808,  4809,  4810,  4811,  4812,  4813,  4814,
    4817,  4818,  4819,  4820,  4821,  4828,  4835,  4842,  4849,  4856,
    4863,  4870,  4877,  4884,  4891,  4898,  4905,  4908,  4909,  4910,
    4911,  4912,  4913,  4914,  4917,  4921,  4925,  4929,  4933,  4937,
    4943,  4944,  4954,  4958,  4962,  4978,  4979,  4982,  4983,  4984,
    4985,  4986,  4989,  4990,  4991,  4992,  4993,  4994,  4995,  4996,
    4997,  4998,  4999,  5000,  5001,  5002,  5003,  5004,  5005,  5006,
    5007,  5008,  5009,  5010,  5011,  5012,  5015,  5035,  5039,  5053,
    5057,  5061,  5067,  5071,  5077,  5078,  5079,  5082,  5083,  5086,
    5087,  5090,  5096,  5097,  5100,  5101,  5104,  5105,  5108,  5109,
    5112,  5120,  5147,  5152,  5157,  5163,  5164,  5167,  5171,  5191,
    5192,  5193,  5194,  5197,  5201,  5205,  5211,  5212,  5215,  5216,
    5217,  5218,  5219,  5220,  5221,  5222,  5223,  5224,  5225,  5226,
    5227,  5228,  5229,  5230,  5231,  5234,  5235,  5236,  5237,  5238,
    5239,  5240,  5243,  5244,  5245,  5246,  5249,  5250,  5251,  5252,
    5255,  5256,  5259,  5265,  5273,  5286,  5293,  5299,  5305,  5314,
    5315,  5316,  5317,  5318,  5319,  5320,  5321,  5322,  5323,  5324,
    5325,  5326,  5327,  5328,  5329,  5330,  5331,  5334,  5343,  5344,
    5345,  5346,  5359,  5365,  5366,  5367,  5370,  5376,  5377,  5378,
    5379,  5380,  5383,  5389,  5390,  5391,  5392,  5393,  5394,  5395,
    5396,  5397,  5400,  5404,  5412,  5419,  5420,  5421,  5422,  5423,
    5424,  5425,  5426,  5427,  5428,  5429,  5430,  5433,  5434,  5435,
    5436,  5439,  5440,  5441,  5442,  5443,  5446,  5452,  5453,  5454,
    5455,  5456,  5457,  5458,  5461,  5467,  5468,  5469,  5470,  5473,
    5479,  5480,  5481,  5482,  5483,  5484,  5485,  5486,  5487,  5489,
    5495,  5496,  5497,  5498,  5499,  5500,  5501,  5502,  5505,  5511,
    5512,  5513,  5514,  5515,  5518,  5524,  5525,  5528,  5534,  5535,
    5536,  5539,  5545,  5546,  5547,  5548,  5551,  5557,  5558,  5559,
    5560,  5563,  5567,  5572,  5576,  5583,  5590,  5591,  5592,  5593,
    5594,  5595,  5596,  5597,  5598,  5599,  5602,  5607,  5612,  5617,
    5622,  5627,  5634,  5635,  5636,  5637,  5638,  5641,  5642,  5643,
    5644,  5645,  5646,  5647,  5648,  5649,  5650,  5651,  5652,  5661,
    5662,  5665,  5668,  5669,  5672,  5675,  5678,  5684,  5685,  5686,
    5689,  5690,  5691,  5692,  5693,  5694,  5695,  5696,  5697,  5698,
    5699,  5700,  5701,  5702,  5703,  5704,  5705,  5706,  5709,  5710,
    5711,  5714,  5715,  5716,  5717,  5720,  5721,  5722,  5723,  5724,
    5727,  5728,  5729,  5730,  5733,  5738,  5742,  5746,  5750,  5754,
    5758,  5763,  5768,  5773,  5778,  5783,  5790,  5794,  5800,  5801,
    5802,  5803,  5806,  5814,  5815,  5818,  5819,  5820,  5821,  5822,
    5823,  5824,  5825,  5828,  5834,  5835,  5838,  5844,  5845,  5846,
    5847,  5850,  5856,  5862,  5868,  5871,  5877,  5878,  5879,  5880,
    5886,  5892,  5893,  5894,  5895,  5896,  5897,  5900,  5906,  5907,
    5910,  5916,  5917,  5918,  5919,  5920,  5923,  5937,  5938,  5939,
    5940,  5941
};
#endif

/** Accessing symbol of state STATE.  */
#define YY_ACCESSING_SYMBOL(State) YY_CAST (yysymbol_kind_t, yystos[State])

#if 1
/* The user-facing name of the symbol whose (internal) number is
   YYSYMBOL.  No bounds checking.  */
static const char *yysymbol_name (yysymbol_kind_t yysymbol) YY_ATTRIBUTE_UNUSED;

/* YYTNAME[SYMBOL-NUM] -- String name of the symbol SYMBOL-NUM.
   First, the terminals, then, starting at YYNTOKENS, nonterminals.  */
static const char *const yytname[] =
{
  "\"end of file\"", "error", "\"invalid token\"", "\"junk\"",
  "\"newline\"", "\"colon\"", "\"semicolon\"", "\"comma\"", "\".\"",
  "\"==\"", "\"!=\"", "\"<\"", "\">\"", "\">=\"", "\"<=\"", "\"<<\"",
  "\">>\"", "\"&\"", "\"^\"", "\"!\"", "\"/\"", "\"*\"", "\"-\"", "\"@\"",
  "\"vmap\"", "\"+\"", "\"include\"", "\"define\"", "\"redefine\"",
  "\"undefine\"", "\"fib\"", "\"socket\"", "\"transparent\"",
  "\"wildcard\"", "\"cgroupv2\"", "\"tproxy\"", "\"osf\"", "\"synproxy\"",
  "\"mss\"", "\"wscale\"", "\"typeof\"", "\"hook\"", "\"hooks\"",
  "\"device\"", "\"devices\"", "\"table\"", "\"tables\"", "\"chain\"",
  "\"chains\"", "\"rule\"", "\"rules\"", "\"sets\"", "\"set\"",
  "\"element\"", "\"map\"", "\"maps\"", "\"flowtable\"", "\"handle\"",
  "\"ruleset\"", "\"trace\"", "\"inet\"", "\"netdev\"", "\"add\"",
  "\"update\"", "\"replace\"", "\"create\"", "\"insert\"", "\"delete\"",
  "\"get\"", "\"list\"", "\"reset\"", "\"flush\"", "\"rename\"",
  "\"describe\"", "\"import\"", "\"export\"", "\"monitor\"", "\"all\"",
  "\"accept\"", "\"drop\"", "\"continue\"", "\"jump\"", "\"goto\"",
  "\"return\"", "\"to\"", "\"constant\"", "\"interval\"", "\"dynamic\"",
  "\"auto-merge\"", "\"timeout\"", "\"gc-interval\"", "\"elements\"",
  "\"expires\"", "\"policy\"", "\"memory\"", "\"performance\"", "\"size\"",
  "\"flow\"", "\"offload\"", "\"meter\"", "\"meters\"", "\"flowtables\"",
  "\"number\"", "\"string\"", "\"quoted string\"",
  "\"string with a trailing asterisk\"", "\"ll\"", "\"nh\"", "\"th\"",
  "\"bridge\"", "\"ether\"", "\"saddr\"", "\"daddr\"", "\"type\"",
  "\"vlan\"", "\"id\"", "\"cfi\"", "\"dei\"", "\"pcp\"", "\"arp\"",
  "\"htype\"", "\"ptype\"", "\"hlen\"", "\"plen\"", "\"operation\"",
  "\"ip\"", "\"version\"", "\"hdrlength\"", "\"dscp\"", "\"ecn\"",
  "\"length\"", "\"frag-off\"", "\"ttl\"", "\"protocol\"", "\"checksum\"",
  "\"ptr\"", "\"value\"", "\"lsrr\"", "\"rr\"", "\"ssrr\"", "\"ra\"",
  "\"icmp\"", "\"code\"", "\"seq\"", "\"gateway\"", "\"mtu\"", "\"igmp\"",
  "\"mrt\"", "\"options\"", "\"ip6\"", "\"priority\"", "\"flowlabel\"",
  "\"nexthdr\"", "\"hoplimit\"", "\"icmpv6\"", "\"param-problem\"",
  "\"max-delay\"", "\"ah\"", "\"reserved\"", "\"spi\"", "\"esp\"",
  "\"comp\"", "\"flags\"", "\"cpi\"", "\"port\"", "\"udp\"", "\"sport\"",
  "\"dport\"", "\"udplite\"", "\"csumcov\"", "\"tcp\"", "\"ackseq\"",
  "\"doff\"", "\"window\"", "\"urgptr\"", "\"option\"", "\"echo\"",
  "\"eol\"", "\"mptcp\"", "\"nop\"", "\"sack\"", "\"sack0\"", "\"sack1\"",
  "\"sack2\"", "\"sack3\"", "\"sack-permitted\"", "\"fastopen\"",
  "\"md5sig\"", "\"timestamp\"", "\"count\"", "\"left\"", "\"right\"",
  "\"tsval\"", "\"tsecr\"", "\"subtype\"", "\"dccp\"", "\"sctp\"",
  "\"chunk\"", "\"data\"", "\"init\"", "\"init-ack\"", "\"heartbeat\"",
  "\"heartbeat-ack\"", "\"abort\"", "\"shutdown\"", "\"shutdown-ack\"",
  "\"error\"", "\"cookie-echo\"", "\"cookie-ack\"", "\"ecne\"", "\"cwr\"",
  "\"shutdown-complete\"", "\"asconf-ack\"", "\"forward-tsn\"",
  "\"asconf\"", "\"tsn\"", "\"stream\"", "\"ssn\"", "\"ppid\"",
  "\"init-tag\"", "\"a-rwnd\"", "\"num-outbound-streams\"",
  "\"num-inbound-streams\"", "\"initial-tsn\"", "\"cum-tsn-ack\"",
  "\"num-gap-ack-blocks\"", "\"num-dup-tsns\"", "\"lowest-tsn\"",
  "\"seqno\"", "\"new-cum-tsn\"", "\"vtag\"", "\"rt\"", "\"rt0\"",
  "\"rt2\"", "\"srh\"", "\"seg-left\"", "\"addr\"", "\"last-entry\"",
  "\"tag\"", "\"sid\"", "\"hbh\"", "\"frag\"", "\"reserved2\"",
  "\"more-fragments\"", "\"dst\"", "\"mh\"", "\"meta\"", "\"mark\"",
  "\"iif\"", "\"iifname\"", "\"iiftype\"", "\"oif\"", "\"oifname\"",
  "\"oiftype\"", "\"skuid\"", "\"skgid\"", "\"nftrace\"", "\"rtclassid\"",
  "\"ibriport\"", "\"obriport\"", "\"ibrname\"", "\"obrname\"",
  "\"pkttype\"", "\"cpu\"", "\"iifgroup\"", "\"oifgroup\"", "\"cgroup\"",
  "\"time\"", "\"classid\"", "\"nexthop\"", "\"ct\"", "\"l3proto\"",
  "\"proto-src\"", "\"proto-dst\"", "\"zone\"", "\"direction\"",
  "\"event\"", "\"expectation\"", "\"expiration\"", "\"helper\"",
  "\"label\"", "\"state\"", "\"status\"", "\"original\"", "\"reply\"",
  "\"counter\"", "\"name\"", "\"packets\"", "\"bytes\"", "\"avgpkt\"",
  "\"counters\"", "\"quotas\"", "\"limits\"", "\"synproxys\"",
  "\"helpers\"", "\"log\"", "\"prefix\"", "\"group\"", "\"snaplen\"",
  "\"queue-threshold\"", "\"level\"", "\"limit\"", "\"rate\"", "\"burst\"",
  "\"over\"", "\"until\"", "\"quota\"", "\"used\"", "\"secmark\"",
  "\"secmarks\"", "\"second\"", "\"minute\"", "\"hour\"", "\"day\"",
  "\"week\"", "\"reject\"", "\"with\"", "\"icmpx\"", "\"snat\"",
  "\"dnat\"", "\"masquerade\"", "\"redirect\"", "\"random\"",
  "\"fully-random\"", "\"persistent\"", "\"queue\"", "\"num\"",
  "\"bypass\"", "\"fanout\"", "\"dup\"", "\"fwd\"", "\"numgen\"",
  "\"inc\"", "\"mod\"", "\"offset\"", "\"jhash\"", "\"symhash\"",
  "\"seed\"", "\"position\"", "\"index\"", "\"comment\"", "\"xml\"",
  "\"json\"", "\"vm\"", "\"notrack\"", "\"exists\"", "\"missing\"",
  "\"exthdr\"", "\"ipsec\"", "\"reqid\"", "\"spnum\"", "\"in\"", "\"out\"",
  "\"xt\"", "'='", "'{'", "'}'", "'('", "')'", "'|'", "'$'", "'['", "']'",
  "$accept", "input", "stmt_separator", "opt_newline", "close_scope_ah",
  "close_scope_arp", "close_scope_at", "close_scope_comp",
  "close_scope_ct", "close_scope_counter", "close_scope_dccp",
  "close_scope_dst", "close_scope_dup", "close_scope_esp",
  "close_scope_eth", "close_scope_export", "close_scope_fib",
  "close_scope_frag", "close_scope_fwd", "close_scope_hash",
  "close_scope_hbh", "close_scope_ip", "close_scope_ip6",
  "close_scope_vlan", "close_scope_icmp", "close_scope_igmp",
  "close_scope_import", "close_scope_ipsec", "close_scope_list",
  "close_scope_limit", "close_scope_meta", "close_scope_mh",
  "close_scope_monitor", "close_scope_nat", "close_scope_numgen",
  "close_scope_osf", "close_scope_policy", "close_scope_quota",
  "close_scope_queue", "close_scope_reject", "close_scope_reset",
  "close_scope_rt", "close_scope_sctp", "close_scope_sctp_chunk",
  "close_scope_secmark", "close_scope_socket", "close_scope_tcp",
  "close_scope_tproxy", "close_scope_type", "close_scope_th",
  "close_scope_udp", "close_scope_udplite", "close_scope_log",
  "close_scope_synproxy", "close_scope_xt", "common_block", "line",
  "base_cmd", "add_cmd", "replace_cmd", "create_cmd", "insert_cmd",
  "table_or_id_spec", "chain_or_id_spec", "set_or_id_spec",
  "obj_or_id_spec", "delete_cmd", "get_cmd", "list_cmd",
  "basehook_device_name", "basehook_spec", "reset_cmd", "flush_cmd",
  "rename_cmd", "import_cmd", "export_cmd", "monitor_cmd", "monitor_event",
  "monitor_object", "monitor_format", "markup_format", "describe_cmd",
  "table_block_alloc", "table_options", "table_block", "chain_block_alloc",
  "chain_block", "subchain_block", "typeof_data_expr", "typeof_expr",
  "set_block_alloc", "set_block", "set_block_expr", "set_flag_list",
  "set_flag", "map_block_alloc", "map_block_obj_type", "map_block",
  "set_mechanism", "set_policy_spec", "flowtable_block_alloc",
  "flowtable_block", "flowtable_expr", "flowtable_list_expr",
  "flowtable_expr_member", "data_type_atom_expr", "data_type_expr",
  "obj_block_alloc", "counter_block", "quota_block", "ct_helper_block",
  "ct_timeout_block", "ct_expect_block", "limit_block", "secmark_block",
  "synproxy_block", "type_identifier", "hook_spec", "prio_spec",
  "extended_prio_name", "extended_prio_spec", "int_num", "dev_spec",
  "flags_spec", "policy_spec", "policy_expr", "chain_policy", "identifier",
  "string", "time_spec", "family_spec", "family_spec_explicit",
  "table_spec", "tableid_spec", "chain_spec", "chainid_spec",
  "chain_identifier", "set_spec", "setid_spec", "set_identifier",
  "flowtable_spec", "flowtableid_spec", "flowtable_identifier", "obj_spec",
  "objid_spec", "obj_identifier", "handle_spec", "position_spec",
  "index_spec", "rule_position", "ruleid_spec", "comment_spec",
  "ruleset_spec", "rule", "rule_alloc", "stmt_list", "stateful_stmt_list",
  "stateful_stmt", "stmt", "xt_stmt", "chain_stmt_type", "chain_stmt",
  "verdict_stmt", "verdict_map_stmt", "verdict_map_expr",
  "verdict_map_list_expr", "verdict_map_list_member_expr",
  "connlimit_stmt", "counter_stmt", "counter_stmt_alloc", "counter_args",
  "counter_arg", "log_stmt", "log_stmt_alloc", "log_args", "log_arg",
  "level_type", "log_flags", "log_flags_tcp", "log_flag_tcp", "limit_stmt",
  "quota_mode", "quota_unit", "quota_used", "quota_stmt", "limit_mode",
  "limit_burst_pkts", "limit_rate_pkts", "limit_burst_bytes",
  "limit_rate_bytes", "limit_bytes", "time_unit", "reject_stmt",
  "reject_stmt_alloc", "reject_with_expr", "reject_opts", "nat_stmt",
  "nat_stmt_alloc", "tproxy_stmt", "synproxy_stmt", "synproxy_stmt_alloc",
  "synproxy_args", "synproxy_arg", "synproxy_config", "synproxy_obj",
  "synproxy_ts", "synproxy_sack", "primary_stmt_expr", "shift_stmt_expr",
  "and_stmt_expr", "exclusive_or_stmt_expr", "inclusive_or_stmt_expr",
  "basic_stmt_expr", "concat_stmt_expr", "map_stmt_expr_set",
  "map_stmt_expr", "prefix_stmt_expr", "range_stmt_expr",
  "multiton_stmt_expr", "stmt_expr", "nat_stmt_args", "masq_stmt",
  "masq_stmt_alloc", "masq_stmt_args", "redir_stmt", "redir_stmt_alloc",
  "redir_stmt_arg", "dup_stmt", "fwd_stmt", "nf_nat_flags", "nf_nat_flag",
  "queue_stmt", "queue_stmt_compat", "queue_stmt_alloc", "queue_stmt_args",
  "queue_stmt_arg", "queue_expr", "queue_stmt_expr_simple",
  "queue_stmt_expr", "queue_stmt_flags", "queue_stmt_flag",
  "set_elem_expr_stmt", "set_elem_expr_stmt_alloc", "set_stmt",
  "set_stmt_op", "map_stmt", "meter_stmt", "flow_stmt_legacy_alloc",
  "flow_stmt_opts", "flow_stmt_opt", "meter_stmt_alloc", "match_stmt",
  "variable_expr", "symbol_expr", "set_ref_expr", "set_ref_symbol_expr",
  "integer_expr", "primary_expr", "fib_expr", "fib_result", "fib_flag",
  "fib_tuple", "osf_expr", "osf_ttl", "shift_expr", "and_expr",
  "exclusive_or_expr", "inclusive_or_expr", "basic_expr", "concat_expr",
  "prefix_rhs_expr", "range_rhs_expr", "multiton_rhs_expr", "map_expr",
  "expr", "set_expr", "set_list_expr", "set_list_member_expr",
  "meter_key_expr", "meter_key_expr_alloc", "set_elem_expr",
  "set_elem_key_expr", "set_elem_expr_alloc", "set_elem_options",
  "set_elem_option", "set_elem_expr_options", "set_elem_stmt_list",
  "set_elem_stmt", "set_elem_expr_option", "set_lhs_expr", "set_rhs_expr",
  "initializer_expr", "counter_config", "counter_obj", "quota_config",
  "quota_obj", "secmark_config", "secmark_obj", "ct_obj_type",
  "ct_cmd_type", "ct_l4protoname", "ct_helper_config", "timeout_states",
  "timeout_state", "ct_timeout_config", "ct_expect_config", "ct_obj_alloc",
  "limit_config", "limit_obj", "relational_expr", "list_rhs_expr",
  "rhs_expr", "shift_rhs_expr", "and_rhs_expr", "exclusive_or_rhs_expr",
  "inclusive_or_rhs_expr", "basic_rhs_expr", "concat_rhs_expr",
  "boolean_keys", "boolean_expr", "keyword_expr", "primary_rhs_expr",
  "relational_op", "verdict_expr", "chain_expr", "meta_expr", "meta_key",
  "meta_key_qualified", "meta_key_unqualified", "meta_stmt", "socket_expr",
  "socket_key", "offset_opt", "numgen_type", "numgen_expr", "xfrm_spnum",
  "xfrm_dir", "xfrm_state_key", "xfrm_state_proto_key", "xfrm_expr",
  "hash_expr", "nf_key_proto", "rt_expr", "rt_key", "ct_expr", "ct_dir",
  "ct_key", "ct_key_dir", "ct_key_proto_field", "ct_key_dir_optional",
  "symbol_stmt_expr", "list_stmt_expr", "ct_stmt", "payload_stmt",
  "payload_expr", "payload_raw_expr", "payload_base_spec", "eth_hdr_expr",
  "eth_hdr_field", "vlan_hdr_expr", "vlan_hdr_field", "arp_hdr_expr",
  "arp_hdr_field", "ip_hdr_expr", "ip_hdr_field", "ip_option_type",
  "ip_option_field", "icmp_hdr_expr", "icmp_hdr_field", "igmp_hdr_expr",
  "igmp_hdr_field", "ip6_hdr_expr", "ip6_hdr_field", "icmp6_hdr_expr",
  "icmp6_hdr_field", "auth_hdr_expr", "auth_hdr_field", "esp_hdr_expr",
  "esp_hdr_field", "comp_hdr_expr", "comp_hdr_field", "udp_hdr_expr",
  "udp_hdr_field", "udplite_hdr_expr", "udplite_hdr_field", "tcp_hdr_expr",
  "optstrip_stmt", "tcp_hdr_field", "tcp_hdr_option_kind_and_field",
  "tcp_hdr_option_sack", "tcp_hdr_option_type", "tcpopt_field_sack",
  "tcpopt_field_window", "tcpopt_field_tsopt", "tcpopt_field_maxseg",
  "tcpopt_field_mptcp", "dccp_hdr_expr", "dccp_hdr_field",
  "sctp_chunk_type", "sctp_chunk_common_field", "sctp_chunk_data_field",
  "sctp_chunk_init_field", "sctp_chunk_sack_field", "sctp_chunk_alloc",
  "sctp_hdr_expr", "sctp_hdr_field", "th_hdr_expr", "th_hdr_field",
  "exthdr_expr", "hbh_hdr_expr", "hbh_hdr_field", "rt_hdr_expr",
  "rt_hdr_field", "rt0_hdr_expr", "rt0_hdr_field", "rt2_hdr_expr",
  "rt2_hdr_field", "rt4_hdr_expr", "rt4_hdr_field", "frag_hdr_expr",
  "frag_hdr_field", "dst_hdr_expr", "dst_hdr_field", "mh_hdr_expr",
  "mh_hdr_field", "exthdr_exists_expr", "exthdr_key", YY_NULLPTR
};

static const char *
yysymbol_name (yysymbol_kind_t yysymbol)
{
  return yytname[yysymbol];
}
#endif

#define YYPACT_NINF (-1707)

#define yypact_value_is_default(Yyn) \
  ((Yyn) == YYPACT_NINF)

#define YYTABLE_NINF (-1002)

#define yytable_value_is_error(Yyn) \
  0

/* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
   STATE-NUM.  */
static const yytype_int16 yypact[] =
{
   -1707,  7450, -1707,   674, -1707, -1707,   162,   203,   203,   203,
     917,   917,   917,   917,   917,   917,   917,   917, -1707, -1707,
    2694,   231,  2896,   237,  2797,   144,  3355,   828,  1116,   276,
    6917,   135,   193,   301, -1707, -1707, -1707, -1707,    97,   917,
     917,   917,   917, -1707, -1707, -1707,  1011, -1707,   203, -1707,
     203,    93,  6240, -1707,   674, -1707,    63,    87,   674,   203,
   -1707,   -10,   222,  6240,   203, -1707,  -122, -1707,   203, -1707,
   -1707,   917, -1707,   917,   917,   917,   917,   917,   917,   917,
     261,   917,   917,   917,   917, -1707,   917, -1707,   917,   917,
     917,   917,   917,   917,   917,   917,   293,   917,   917,   917,
     917, -1707,   917, -1707,   917,   917,   917,   917,   917,   917,
     938,   917,   917,   917,   917,   917,   335,   917,   917,   917,
     346,   917,  1394,  1455,  1786,  1862,   917,   917,   917,  1908,
   -1707,   917,  2268,  2536,   917, -1707,   917,   917,   917,   917,
     917,   407,   917, -1707,   917, -1707,  1222,   497,   322,   377,
   -1707, -1707, -1707, -1707,   642,   855,  1162,  1547,  3479,   958,
     573,  1886,   795,  1076,   516,   367,   903,   732,  2841,   115,
     688,    92,   303,   347,   721,    84,   873,   271,   959,  6461,
   -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707,
   -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707,
   -1707,  4069, -1707, -1707,   339,  6500,   238,   931,   654,  6917,
     203, -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707,
   -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707,
   -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707,
   -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707,
   -1707, -1707, -1707, -1707, -1707, -1707,   740, -1707, -1707,   282,
   -1707, -1707,   740, -1707, -1707, -1707, -1707,  1087, -1707, -1707,
   -1707,   917,   917,   917,   -92, -1707, -1707, -1707, -1707, -1707,
   -1707, -1707,   546,   586,   596, -1707, -1707, -1707,   177,   422,
    1137, -1707, -1707, -1707,   563, -1707, -1707, -1707,    91,    91,
   -1707,   212,   203,  7702,  2985,   481, -1707,   432,   433, -1707,
   -1707, -1707, -1707, -1707,   141,   691,   224, -1707,   735,   820,
   -1707,   502,  6240, -1707, -1707, -1707, -1707, -1707, -1707, -1707,
   -1707, -1707,   709, -1707,   695, -1707, -1707, -1707,   530, -1707,
    4760, -1707, -1707,   676, -1707,   209, -1707,   311, -1707, -1707,
   -1707, -1707,   803, -1707,   113, -1707, -1707,   826, -1707, -1707,
   -1707,  1105,   848,   868,   532, -1707,   310, -1707,  5765, -1707,
   -1707, -1707,   850, -1707, -1707, -1707,   863, -1707, -1707,  6104,
    6104, -1707, -1707,   109,   541,   568, -1707, -1707,   619, -1707,
   -1707, -1707,   627, -1707,   659,   884,  6240, -1707,   -10,   222,
   -1707,  -122, -1707, -1707,   917,   917,   917,   620, -1707, -1707,
   -1707,  6240, -1707,   254, -1707, -1707, -1707,   415, -1707, -1707,
   -1707,   499, -1707, -1707, -1707, -1707,   503, -1707, -1707,  -122,
   -1707,   536,   664, -1707, -1707, -1707, -1707,   917, -1707, -1707,
   -1707, -1707,  -122, -1707, -1707, -1707,   980, -1707, -1707, -1707,
   -1707,   917, -1707, -1707, -1707, -1707, -1707, -1707,   917,   917,
   -1707, -1707, -1707,   985,   989, -1707,   917,   999, -1707,   917,
   -1707,   917, -1707,   917, -1707,   917, -1707, -1707, -1707, -1707,
     917, -1707, -1707, -1707,   917, -1707,   917, -1707, -1707, -1707,
   -1707, -1707, -1707, -1707, -1707,   917, -1707,   203, -1707, -1707,
   -1707, -1707,  1041, -1707, -1707, -1707, -1707, -1707,  1045,   176,
   -1707, -1707,   807, -1707, -1707,   996,    72, -1707, -1707, -1707,
   -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707,
     380,   600, -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707,
   -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707,
    1153, -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707,
   -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707,
   -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707,
   -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707,
   -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707,
   -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707,
   -1707, -1707, -1707, -1707, -1707, -1707, -1707,  2598, -1707, -1707,
   -1707, -1707, -1707, -1707, -1707, -1707,  4465, -1707, -1707, -1707,
   -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707,   545,
   -1707, -1707,   753, -1707, -1707, -1707, -1707, -1707, -1707,   762,
   -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707,
   -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707,
   -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707,
   -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707,
   -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707,
   -1707, -1707,  2044, -1707, -1707, -1707, -1707,   811,   622,   827,
    1034, -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707,
     817,   815, -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707,
   -1707, -1707, -1707, -1707, -1707, -1707, -1707,   740, -1707, -1707,
   -1707, -1707,   -57,  -103,   308,   151, -1707, -1707, -1707,  4961,
    1093,  7086,  6917,  1004, -1707, -1707, -1707, -1707,  1159,  1163,
      83,  1138,  1142,  1145,    71,  1172,  2044,  1209,  7086,  7086,
     837,  7086, -1707, -1707,  1099,  6917,   889,  7086,  7086,  1189,
    1181, -1707,  5834,   133, -1707,  1048, -1707, -1707, -1707,   963,
   -1707,  1180,  1231,   709, -1707, -1707,   722,  1048,  1236,  1238,
    1241,  1048,   695, -1707, -1707,   599, -1707, -1707,  7086, -1707,
    5162,  1261,   855,  1162,  1547,  3479, -1707,  1886,   662, -1707,
   -1707, -1707,  1277, -1707, -1707, -1707, -1707,  7086, -1707,  1149,
    1349,  1362,  1025,   809,   629, -1707, -1707, -1707, -1707,  1393,
    1092,  1383, -1707, -1707, -1707, -1707,  1396, -1707, -1707, -1707,
   -1707,   519, -1707, -1707,  1416,  1418, -1707, -1707, -1707,  1299,
    1329, -1707, -1707,   676, -1707, -1707,  1429, -1707, -1707, -1707,
   -1707,  1433, -1707, -1707,  5363, -1707,  1433, -1707, -1707, -1707,
      70, -1707, -1707,   803, -1707,  1436, -1707,   203, -1707,  1091,
   -1707,   203,   136, -1707,  7557,  7557,  7557,  7557,  7557,  6917,
     140,  7287, -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707,
   -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707,
   -1707, -1707, -1707, -1707, -1707, -1707,  7557, -1707, -1707, -1707,
   -1707, -1707, -1707, -1707,   281, -1707,  1206,  1431,  1435,  1101,
     645,  1464, -1707, -1707, -1707,  7287,  7086,  7086,  1371,   129,
     674,  1467, -1707,   739,   674,  1373, -1707, -1707, -1707, -1707,
   -1707, -1707, -1707, -1707, -1707,  1442,  1127,  1128,  1131, -1707,
    1133,  1134, -1707, -1707, -1707, -1707,  1203,  1191,   965,  1048,
   -1707, -1707,  1390,  1392,  1397,  1399, -1707,  1400,  1150, -1707,
   -1707, -1707, -1707, -1707, -1707, -1707,  1401, -1707, -1707, -1707,
   -1707, -1707,   917, -1707, -1707, -1707, -1707, -1707, -1707, -1707,
   -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707,  1405,
     497, -1707, -1707, -1707, -1707,  1406, -1707, -1707, -1707, -1707,
   -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707,
   -1707, -1707, -1707, -1707,   776, -1707, -1707, -1707, -1707, -1707,
   -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707,  1414,
   -1707,  1322, -1707, -1707,  1315, -1707, -1707, -1707, -1707, -1707,
   -1707, -1707, -1707, -1707,  1114, -1707,  1119,  1382, -1707, -1707,
     625,  1190,  1027,  1027, -1707, -1707, -1707,  1293, -1707, -1707,
   -1707, -1707,  1294,  1295, -1707,  1292,  1296,  1298,   216, -1707,
   -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707,  1422, -1707,
   -1707,  1425, -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707,
   -1707, -1707, -1707, -1707,  1211, -1707,  1245, -1707, -1707, -1707,
   -1707, -1707, -1707, -1707,  1426,  1427,  1198, -1707, -1707, -1707,
   -1707, -1707,  1443,   240, -1707, -1707, -1707,  1193,  1197,  1207,
    1459, -1707, -1707,   837, -1707, -1707, -1707,  1461, -1707, -1707,
   -1707, -1707,  7086,  3479,  1886,  1528,  5564, -1707,   113,   183,
    1536,  3284,  1048,  1048,  1465,  6917,  7086,  7086,  7086, -1707,
    1469,  7086,  1486,  7086, -1707, -1707, -1707, -1707,  1471, -1707,
     117,  1553, -1707, -1707,   242,   299,   622, -1707,   323,   404,
     148,  1526, -1707,  7086, -1707, -1707,   820,  1372,    58,   184,
   -1707,  1055,  1464,   820, -1707, -1707, -1707, -1707, -1707, -1707,
   -1707, -1707,  1428,   265, -1707, -1707, -1707, -1707, -1707, -1707,
   -1707, -1707, -1707,   844,   862, -1707,   948, -1707, -1707,  7086,
    1572,  7086, -1707, -1707, -1707,   552,   576,  7086, -1707, -1707,
    1220, -1707, -1707,  7086,  7086,  7086,  7086,  7086,  1477,  7086,
    7086,   153,  7086,  1433,  7086,  1498,  1575,  1502,  2916,  2916,
   -1707, -1707, -1707,  7086,  1092,  7086,  1092, -1707,  1565,  1566,
   -1707,   889, -1707,  6917, -1707,  6917, -1707, -1707, -1707,  1206,
    1431,  1435, -1707,   820, -1707, -1707, -1707, -1707, -1707, -1707,
   -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707,
    1237,  7557,  7557,  7557,  7557,  7557,  7557,  7557,  7557,  7661,
    7557,  7557,   317, -1707,   797, -1707, -1707, -1707, -1707, -1707,
    1490, -1707,   685,   442, -1707,  3082,  3474,  2319,  3332,   799,
   -1707, -1707, -1707, -1707, -1707, -1707,  1239,  1242,  1243, -1707,
   -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707,
   -1707, -1707, -1707,  1596, -1707, -1707, -1707, -1707, -1707, -1707,
   -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707,
   -1707,  3284, -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707,
   -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707,
   -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707,
   -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707,
   -1707, -1707, -1707, -1707,  1247,  1249, -1707, -1707, -1707, -1707,
   -1707, -1707,  1198,   313,  1499, -1707, -1707, -1707, -1707, -1707,
    1284, -1707, -1707, -1707,  1324,   241, -1707,  1471,  1923, -1707,
     750,   117, -1707,  1183, -1707, -1707,  7086,  7086,  1613, -1707,
    1517,  1517, -1707,   183, -1707, -1707, -1707, -1707, -1707, -1707,
   -1707, -1707, -1707,  1266,  1536,  6240,   183, -1707, -1707, -1707,
   -1707, -1707, -1707,  7086, -1707, -1707,   118,  1323,  1327,  1608,
   -1707, -1707, -1707,  1328,    70, -1707,  6917,    70,  7086,  1591,
   -1707,  7509, -1707,  1449,  1353,  1339,    58, -1707,  1517,  1517,
   -1707,   184, -1707,  5834, -1707,  4492, -1707, -1707, -1707, -1707,
    1639, -1707, -1707,  1307, -1707, -1707,  1307, -1707,  1580,  1307,
   -1707, -1707,  7086, -1707, -1707, -1707, -1707, -1707,  1149,  1349,
    1362, -1707, -1707, -1707, -1707, -1707, -1707, -1707,  1646,  7086,
    1488,  7086, -1707, -1707, -1707, -1707,  1092, -1707,  1092,  1433,
   -1707, -1707,   154,  6240,  5882,   145, -1707, -1707, -1707,  1467,
    1654, -1707, -1707,  1206,  1431,  1435, -1707,   167,  1467, -1707,
   -1707,  1055,  7557,  7661, -1707,  1551,  1623, -1707, -1707, -1707,
   -1707, -1707,   203,   203,   203,   203,   203,  1561,   372,   203,
     203,   203,   203, -1707, -1707, -1707,   674, -1707,    90, -1707,
    1567, -1707, -1707, -1707,   674,   674,   674,   674,   674,  6917,
   -1707,  1517,  1517,  1312,  1325,  1577,   657,  1178,  1492, -1707,
   -1707, -1707,   674,   674,   326, -1707,  6917,  1517,  1332,   657,
    1178, -1707, -1707, -1707,   674,   674,   326,  1574,  1340,  1584,
   -1707, -1707, -1707, -1707, -1707,  3990,  3819,  2363,  4275,  1179,
   -1707, -1707, -1707, -1707, -1707, -1707, -1707,  2049, -1707, -1707,
    1582, -1707, -1707, -1707,  1688, -1707, -1707, -1707, -1707, -1707,
   -1707, -1707, -1707, -1707,  1597, -1707, -1707, -1707, -1707, -1707,
   -1707, -1707,  1121,   616,  1812,  1598, -1707, -1707, -1707, -1707,
   -1707,  1323,  1327, -1707, -1707, -1707, -1707, -1707, -1707, -1707,
   -1707, -1707, -1707,  1328, -1707, -1707, -1707, -1707, -1707, -1707,
   -1707,  7086, -1707, -1707, -1707, -1707, -1707, -1707, -1707,  6917,
    1345,   183, -1707, -1707, -1707, -1707, -1707, -1707, -1707,  1061,
    1676, -1707,  1600, -1707,  1601, -1707,  1061,  1611, -1707, -1707,
   -1707, -1707, -1707, -1707, -1707,  7086,    91,    91,   820,  1464,
   -1707,   163,  1615, -1707,   837, -1707, -1707, -1707, -1707, -1707,
   -1707,   674, -1707,   265, -1707, -1707, -1707, -1707, -1707, -1707,
    7086, -1707,  1634, -1707,  1433,  1433,  6917, -1707,   272,  1363,
    1717,   820, -1707,  1467,  1467,  1535,  1622, -1707, -1707, -1707,
   -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707,   203,   203,
     203, -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707,
   -1707,  1624, -1707, -1707, -1707, -1707, -1707, -1707,  1377, -1707,
     674,   674,  -122, -1707, -1707, -1707, -1707, -1707, -1707, -1707,
   -1707, -1707, -1707, -1707,  1385, -1707, -1707, -1707, -1707, -1707,
    1226, -1707, -1707, -1707, -1707, -1707,   927,   674,  -122,  1059,
    1226, -1707, -1707, -1707,  1576,    56,   674, -1707, -1707, -1707,
   -1707, -1707, -1707,  1530,   668,  2534, -1707, -1707,  1627, -1707,
    1198, -1707, -1707,  1376,   653,   917, -1707, -1707, -1707, -1707,
   -1707,  1517,  1629,   653,  1631,   917, -1707, -1707, -1707, -1707,
   -1707,  1621,   917, -1707, -1707, -1707, -1707, -1707, -1707, -1707,
   -1707, -1707, -1707, -1707, -1707, -1707, -1707,  6240, -1707, -1707,
   -1707, -1707, -1707, -1707, -1707, -1707,  1447, -1707,   121, -1707,
   -1707, -1707,   117, -1707, -1707, -1707, -1707, -1707, -1707,  1635,
    1448,  1471, -1707, -1707, -1707, -1707, -1707, -1707, -1707,  7086,
    1384,  6917, -1707, -1707,  1234,  5882, -1707, -1707,  1554,   674,
    1388,  1389,  1391,  1395,  1404, -1707, -1707, -1707,  1407,  1409,
    1412,  1420, -1707,  1707,  6917, -1707, -1707, -1707, -1707, -1707,
     657, -1707,  1178, -1707,  6748, -1707, -1707,  1283, -1707,   132,
     674,    74,   674, -1707, -1707, -1707, -1707, -1707, -1707,  1744,
   -1707,  1421, -1707, -1707,   674,   674, -1707,   674,   674,   674,
     674,   674, -1707,  1619,   674, -1707,  1398, -1707, -1707, -1707,
   -1707, -1707,  1653,  1323,  1327, -1707, -1707, -1707, -1707,  1415,
     820, -1707, -1707,  1535, -1707, -1707, -1707, -1707, -1707,  1423,
    1424,  1432, -1707, -1707, -1707, -1707,  1657, -1707, -1707, -1707,
   -1707,  6917,   674,  1748,  1760, -1707,   657, -1707, -1707, -1707,
   -1707,   674,  1385,  1678, -1707, -1707, -1707,  1069, -1707, -1707,
   -1707, -1707, -1707, -1707,   158, -1707, -1707, -1707, -1707, -1707,
   -1707,  1684, -1707,  1685, -1707, -1707, -1707, -1707, -1707, -1707,
   -1707, -1707, -1707,   653, -1707, -1707, -1707, -1707, -1707, -1707,
   -1707, -1707,  1554,   916,  4164,  2829,  4689,  2208, -1707, -1707,
   -1707,  2247,  2201,  1320,  1679,  1413,  1377, -1707,  6917, -1707,
    1385, -1707, -1707, -1707, -1707, -1707, -1707, -1707,  1689,  1691,
     123, -1707, -1707,  1776,   160, -1707,   674, -1707, -1707, -1707,
   -1707,   674,   674,   674,   674,   674,  2261,   700,  2625,   674,
     674,   674,   674,    99,  1441,  1576, -1707,  1782, -1707, -1707,
   -1707, -1707, -1707, -1707, -1707,  1694,  1685,   674, -1707, -1707,
   -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707,
   -1707, -1707, -1707,    56, -1707, -1707, -1707, -1707, -1707, -1707,
   -1707,   674,   674,   674, -1707, -1707, -1707, -1707, -1707, -1707,
   -1707, -1707, -1707
};

/* YYDEFACT[STATE-NUM] -- Default reduction number in state STATE-NUM.
   Performed when YYTABLE does not specify something else to do.  Zero
   means the default is an error.  */
static const yytype_int16 yydefact[] =
{
       2,     0,     1,     0,     4,     5,     0,     0,     0,     0,
     395,   395,   395,   395,   395,   395,   395,   395,   399,   402,
     395,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,   206,   401,     9,    25,    26,     0,   395,
     395,   395,   395,    65,    64,     3,     0,    68,     0,   396,
       0,   420,     0,    63,     0,   390,     0,     0,     0,     0,
     567,    83,    85,     0,     0,   257,     0,   279,     0,   303,
      69,   395,    70,   395,   395,   395,   395,   395,   395,   395,
       0,   395,   395,   395,   395,    71,   395,    72,   395,   395,
     395,   395,   395,   395,   395,   395,     0,   395,   395,   395,
     395,    73,   395,    74,   395,   426,   395,   426,   395,   426,
     426,   395,   395,   426,   395,   426,     0,   395,   426,   426,
       0,   395,   426,   426,   426,   426,   395,   395,   395,   426,
      32,   395,   426,   426,   395,    44,   395,   395,   395,   395,
     426,     0,   395,    77,   395,    78,     0,     0,     0,   724,
     695,   391,   392,   393,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     902,   903,   904,   905,   906,   907,   908,   909,   910,   911,
     912,   913,   914,   915,   916,   917,   918,   919,   920,   921,
     923,     0,   925,   924,     0,     0,     0,     0,    31,     0,
       0,    82,   691,   690,   696,   697,   221,   707,   708,   701,
     893,   702,   705,   709,   706,   703,   704,   698,  1009,  1010,
    1011,  1012,  1013,  1014,  1015,  1016,  1017,  1018,  1019,  1020,
    1021,  1022,    50,  1024,  1025,  1026,   699,  1235,  1236,  1237,
    1238,  1239,  1240,  1241,  1242,   700,     0,   218,   219,     0,
      30,   202,     0,    19,   204,   207,    36,   208,   400,   397,
     398,   395,   395,   395,    13,   817,   790,   792,    67,    66,
     403,   405,     0,     0,     0,   422,   421,   423,     0,   557,
       0,   675,   676,   677,     0,   884,   885,   886,   462,   463,
     889,   682,     0,     0,     0,   478,   486,     0,   510,   535,
     547,   548,   624,   630,   651,     0,     0,   929,     0,     7,
      88,   428,   430,   443,   431,    58,   241,   458,   439,   466,
     438,    13,   476,    56,   484,   436,   437,    43,   538,    37,
       0,    51,    57,   555,    37,   623,    37,   629,    16,    22,
     449,    42,   649,   455,     0,   456,   441,     0,   681,   440,
     726,   729,   731,   733,   735,   736,   743,   745,     0,   744,
     688,   465,   893,   444,   450,   442,   698,   459,    59,     0,
       0,    62,   414,     0,     0,     0,    87,   408,     0,    91,
     272,   271,     0,   411,     0,     0,     0,   567,   108,   110,
     257,     0,   279,   303,   395,   395,   395,    13,   817,   790,
     792,     0,    57,     0,   132,   133,   134,     0,   126,   127,
     135,     0,   128,   129,   136,   137,     0,   130,   131,     0,
     138,     0,   140,   141,   794,   795,   793,   395,    13,    33,
      41,    48,     0,    57,   183,   427,   185,   150,   151,   152,
     153,   395,   154,   156,   180,   179,   178,   172,   395,   426,
     176,   175,   177,   794,   795,   796,   395,     0,    13,   395,
     157,   395,   160,   395,   163,   395,   169,    33,    41,    48,
     395,   166,    75,    13,   395,   187,   395,   190,    41,    76,
     193,   194,   195,   196,   199,   395,   198,     0,  1031,  1028,
    1029,    53,     0,   715,   716,   717,   718,   719,   721,     0,
     934,   936,     0,   935,    49,     0,     0,  1233,  1234,    53,
    1033,  1034,    52,    18,    52,  1037,  1038,  1039,  1040,    27,
       0,     0,  1043,  1044,  1045,  1046,  1047,     9,  1065,  1066,
    1060,  1055,  1056,  1057,  1058,  1059,  1061,  1062,  1063,  1064,
       0,    25,    52,  1080,  1079,  1078,  1081,  1082,  1083,    28,
      52,  1086,  1087,  1088,    29,  1097,  1098,  1090,  1091,  1092,
    1094,  1093,  1095,  1096,    26,    52,  1105,  1102,  1101,  1106,
    1104,  1103,  1107,    28,  1110,  1113,  1109,  1111,  1112,     8,
    1116,  1115,    17,  1118,  1119,  1120,    11,  1124,  1125,  1122,
    1123,    54,  1130,  1127,  1128,  1129,    55,  1144,  1138,  1141,
    1142,  1136,  1137,  1139,  1140,  1143,  1145,     0,  1131,    52,
    1177,  1178,    14,  1231,  1228,  1229,     0,  1230,    46,    52,
      25,  1248,   961,    26,  1247,  1250,   959,   960,    31,     0,
      45,    45,     0,    45,  1254,    45,  1257,  1256,  1258,     0,
      45,  1245,  1244,    24,  1266,  1263,  1261,  1262,  1264,  1265,
      21,  1269,  1268,    15,    52,  1272,  1275,  1271,  1274,    35,
      34,   897,   898,   899,    48,   900,    31,    34,   895,   896,
     976,   977,   983,   969,   970,   968,   978,   979,   999,   972,
     981,   974,   975,   980,   971,   973,   966,   967,   997,   996,
     998,    48,     0,    12,   984,   940,   939,     0,   743,     0,
       0,    45,    24,    21,    15,    35,  1276,   944,   945,   922,
     943,     0,   689,  1023,   201,   220,    79,   203,    80,    81,
     209,   210,   212,   211,   214,   215,   213,   216,   814,   814,
     814,    93,     0,     0,   510,     0,   417,   418,   419,     0,
       0,     0,     0,     0,   891,   890,   887,   888,     0,     0,
       0,    34,    34,     0,     0,     0,     0,    12,     0,     0,
     519,     0,   508,   509,     0,     0,     0,     0,     0,     0,
       0,     6,     0,     0,   747,     0,   429,   432,   460,     0,
     435,     0,     0,   477,   480,   445,     0,     0,     0,     0,
       0,     0,   485,   487,   446,     0,   534,   447,     0,    44,
       0,     0,    18,    27,     9,    25,   855,    26,     0,   859,
     857,   858,     0,    37,    37,   845,   846,     0,   585,   588,
     590,   592,   594,   595,   600,   605,   603,   604,   606,   608,
     546,   572,   573,   583,   847,   574,   581,   575,   582,   578,
     579,     0,   576,   577,     0,   607,   580,   448,   457,     0,
       0,   564,   563,   556,   559,   451,     0,   642,   643,   644,
     622,   627,   640,   452,     0,   628,   633,   453,   454,   645,
       0,   667,   668,   650,   652,   655,   665,     0,   693,     0,
     692,     0,     0,   683,     0,     0,     0,     0,     0,     0,
       0,     0,   877,   878,   879,   880,   881,   882,   883,    18,
      27,     9,    25,    28,   870,    26,    28,     8,    17,    11,
      54,    55,    50,    14,    46,    37,     0,   860,   830,   861,
     740,   741,   842,   829,   819,   818,   834,   836,   838,   840,
     841,   828,   862,   863,   831,     0,     0,     0,     0,     7,
       0,   784,   783,   841,     0,     0,   359,    57,   225,   242,
     258,   285,   304,   424,   107,     0,     0,     0,     0,   114,
       0,     0,   814,   814,   814,   116,     0,     0,   510,     0,
     125,   148,     0,     0,     0,     0,   139,     0,     0,   814,
     143,   146,   144,   147,   149,   171,     0,   186,   155,   174,
     173,    12,   395,   159,   158,   161,   164,   170,   165,   162,
     168,   167,   189,   188,   191,   192,   197,   200,  1030,     0,
       0,    52,   712,   713,    20,     0,   932,   725,    39,    39,
    1232,  1035,  1032,  1041,  1036,    18,    25,    18,    25,  1042,
    1067,  1068,  1069,  1070,    25,  1052,  1077,  1076,  1085,  1084,
    1089,  1100,  1099,  1108,  1114,  1117,  1121,  1126,    10,  1162,
    1168,  1166,  1157,  1158,  1161,  1163,  1152,  1153,  1154,  1155,
    1156,  1164,  1159,  1160,  1165,  1133,  1167,  1132,  1179,  1176,
    1183,  1180,  1181,  1182,  1184,  1185,  1186,  1187,  1188,  1189,
    1190,  1191,  1192,  1193,  1194,  1195,  1196,  1197,  1214,    47,
    1226,  1249,   955,   956,   962,    45,   957,  1246,     0,  1251,
    1253,     0,  1255,  1243,  1260,  1267,  1273,  1270,   894,   901,
     892,   982,   985,   986,     0,   988,     0,   987,   989,   990,
      12,    12,   991,   963,     0,     0,   937,  1278,  1277,  1279,
    1280,  1281,     0,     0,   710,   205,   217,     0,     0,     0,
       0,   324,    13,   519,   349,    33,   329,     0,    41,   354,
     791,    48,     0,    25,    26,   549,     0,   558,     0,   669,
     671,     0,     0,     0,     0,     0,     0,     0,     0,    12,
       0,     0,   991,     0,   479,    33,   517,   518,     0,    41,
       0,     0,   664,    42,   659,   658,     0,   663,   661,   662,
       0,   636,   638,     0,   461,   759,     7,     7,   761,   756,
     758,   841,   780,     7,   746,   425,   250,   482,   483,   481,
     500,    18,     0,     0,   498,   494,   489,   490,   491,   492,
     495,   493,   488,     0,     0,    50,     0,   614,   856,     0,
     609,     0,   848,   851,   852,   849,   850,     0,   854,   853,
       0,   572,   581,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,   616,     0,     0,     0,     0,     0,     0,
     561,   562,   560,     0,     0,     0,   631,   654,   659,   658,
     653,     0,    10,     0,   685,     0,   684,   727,   728,   730,
     732,   734,   737,     7,   467,   469,   742,   849,   869,   850,
     871,   868,   867,   872,   865,   866,   864,   873,   874,   875,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,   825,   824,   841,   927,  1008,   786,   785,    60,
       0,    61,     0,     0,   105,     0,     0,     0,     0,     0,
      57,   225,   242,   258,   285,   304,     0,     0,     0,    13,
      33,    41,    48,   415,   404,   406,   409,   412,   304,    12,
     184,   181,    12,     0,   720,   714,   711,    49,   722,   723,
    1048,  1050,  1049,  1051,    52,  1072,  1074,  1073,  1075,  1054,
      25,     0,  1174,  1146,  1171,  1148,  1175,  1151,  1172,  1173,
    1149,  1169,  1170,  1147,  1150,  1211,  1210,  1212,  1213,  1219,
    1201,  1202,  1203,  1204,  1216,  1205,  1206,  1207,  1208,  1209,
    1217,  1218,  1220,  1221,  1222,  1223,  1224,  1225,    52,  1200,
    1199,  1215,    46,   958,     0,     0,    25,    25,    26,    26,
     964,   965,   937,   937,     0,    23,   942,   946,   947,    31,
       0,   339,   344,   334,     0,     0,    94,     0,     0,   101,
       0,     0,    96,     0,   103,   551,     0,     0,   550,   672,
       0,     0,   766,   670,   762,  1162,  1166,  1161,  1165,  1167,
      50,    10,    10,     0,   755,     0,   753,    34,    34,    12,
     474,    12,    12,     0,    12,   507,     0,   520,   523,     0,
     516,   512,   511,   513,     0,   646,     0,     0,     0,     0,
     750,     0,   751,     0,    13,     0,   760,   769,     0,     0,
     779,   757,   767,   749,   748,     0,   499,    25,   503,   504,
      50,   502,   536,     0,   540,   537,     0,   542,     0,     0,
     544,   615,     0,   619,   621,   584,   586,   587,   589,   591,
     593,   601,   602,   596,   599,   598,   597,   611,   610,     0,
       0,     0,  1000,  1001,  1002,  1003,   625,   641,   632,   634,
     666,   694,     0,     0,     0,     0,   470,   876,   827,   821,
       0,   832,   833,   835,   837,   839,   826,   738,   820,   739,
     843,   844,     0,     0,   738,     0,     0,    57,   361,   360,
     363,   362,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,    84,   227,   226,     0,   224,     0,    52,
       0,    86,   244,   243,     0,     0,     0,     0,     0,     0,
     268,     0,     0,     0,     0,     0,     0,     0,     0,    89,
     260,   259,     0,     0,     0,   433,     0,     0,     0,     0,
       0,    90,   287,   286,     0,     0,     0,     0,     0,     0,
      13,    92,   306,   305,   124,     0,     0,     0,     0,     0,
     339,   344,   334,   117,   122,   118,   123,     0,   145,   182,
       0,   933,  1071,  1053,     0,  1198,  1227,  1252,  1259,   992,
     993,   994,   995,    38,     0,    23,   938,   954,   950,   949,
     948,    31,     0,     0,     0,     0,    13,   326,   325,   328,
     327,   520,   523,    33,   351,   350,   353,   352,    41,   331,
     330,   333,   332,   513,    48,   356,   355,   358,   357,   552,
     554,     0,   394,   764,   765,   763,  1135,   931,   930,     0,
       0,   754,   928,   926,  1005,   475,  1006,    12,  1004,     0,
     525,   527,     0,    33,     0,    33,     0,     0,    41,   660,
     656,   657,    42,    42,   637,     0,     0,     0,     7,   781,
     782,     0,     0,   771,   519,   770,   777,   778,   768,   464,
     251,     0,   497,     0,   496,    52,    52,    44,    52,   612,
       0,   618,     0,   620,   626,   635,     0,   673,     0,     0,
       0,     7,   468,   823,   822,   568,     0,   106,   416,   323,
     407,   241,   410,   257,   279,   413,   303,   223,     0,     0,
       0,   323,   323,   323,   323,   228,   388,   389,    40,   387,
     386,     0,   384,   245,   247,   246,   249,   248,     0,   255,
       0,     0,     0,   302,   301,    40,   300,   364,   366,   367,
     365,   320,   368,   321,     0,   319,   275,   276,   278,   277,
       0,   274,   269,   270,   266,   434,     0,     0,     0,     0,
       0,   298,   297,   295,     0,     0,     0,   309,   109,   111,
     112,   113,   115,     0,     0,     0,   142,    10,     0,   941,
     937,   953,   951,     0,     0,     0,    12,   341,   340,   343,
     342,     0,     0,     0,     0,     0,    12,   346,   345,   348,
     347,     0,     0,    12,   336,   335,   338,   337,   787,    95,
     815,   816,   102,    97,   789,   104,   553,     0,   686,  1007,
     529,   530,   531,   532,   533,   522,     0,   505,     0,   524,
     506,   526,     0,   515,   647,   648,   639,   752,    12,     0,
       0,     0,   252,   501,    28,    28,   545,   543,   613,     0,
       0,     0,   674,   680,     0,   472,   471,   569,   570,     0,
       0,     0,     0,     0,     0,   323,   323,   323,     0,     0,
       0,     0,   385,     0,     0,   262,   264,   265,   267,   299,
       0,    52,     0,   263,     0,   288,   296,     0,   294,     0,
       0,     0,     0,   312,   310,    12,    12,    12,  1027,     0,
      23,     0,    54,    50,     0,     0,    99,     0,     0,     0,
       0,     0,   100,     0,     0,    98,     0,   521,   528,   514,
     775,    12,     0,   520,   523,   539,   541,   617,   678,     0,
       7,   571,   565,   568,   359,   242,   258,   285,   304,     0,
       0,     0,   324,   349,   329,   354,     0,   256,   322,   261,
     273,     0,     0,     0,   253,    57,     0,    13,    33,    41,
      48,     0,     0,     0,   378,   372,   371,   375,   370,   373,
     374,   307,   317,   316,     0,   313,   318,   308,   120,   121,
     119,     0,   952,     0,   800,   799,   806,   808,   811,   812,
     809,   810,   813,     0,   802,   687,   776,    13,    33,    33,
     679,   473,   570,     0,     0,     0,     0,     0,   339,   344,
     334,     0,     0,     0,     0,   383,     0,   291,     0,   284,
       0,   280,   282,   281,   283,    52,    52,   379,     0,     0,
       7,   311,  1134,     0,     0,   803,     0,   772,   773,   774,
     566,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,   292,   254,    52,   293,
     289,   377,   376,   315,   314,     0,     0,     0,    52,    57,
     229,   230,   231,   232,    12,    12,    12,    13,    33,    41,
      48,   380,   381,     0,   369,   290,   805,   804,    40,   801,
     240,     0,     0,     0,   233,   238,   234,   239,   382,   807,
     236,   237,   235
};

/* YYPGOTO[NTERM-NUM].  */
static const yytype_int16 yypgoto[] =
{
   -1707, -1707,    -1, -1127,   881,    62, -1193,   885,  -917,  -308,
     880,  1094, -1707,   887,  -453, -1707, -1707,  1097, -1707, -1546,
    1095,    24,    13,  1282,  -545, -1707, -1707,  -583, -1707,  -462,
    -619,  1100, -1707,  -238, -1707,   783, -1706,  -437, -1097, -1707,
    -757,  -531,  -842, -1707,  -452,   450,  -863, -1707,  -411,  1300,
    -878,   900, -1707,  -406, -1707,    17, -1707, -1707,  1802, -1707,
   -1707, -1707, -1707, -1707, -1707,  1330, -1707, -1707, -1707, -1707,
   -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707,
      35, -1707,  1430, -1707,   482,  -323, -1264, -1707, -1707, -1485,
    -390, -1262,  -373,   185,  -158,  -378, -1707, -1257, -1272, -1707,
    -370, -1268,  -349, -1707,  -295,  -144, -1493,  -938,  -205,  -202,
   -1564, -1553, -1550,  -199,  -200,  -186, -1707, -1707,  -302, -1707,
   -1707, -1707, -1707, -1707, -1707, -1707, -1707,    94,  -736, -1338,
    1763,   -93,  3209, -1707,   968, -1707, -1707,   410, -1707,   259,
     702, -1707, -1707,  2300, -1707,  -808,  1462, -1707, -1707,   199,
    1767,  1103,  2558,   -44, -1707, -1707, -1270, -1243,  -318, -1707,
   -1707, -1707, -1707, -1707, -1707, -1707,    69, -1707, -1707, -1707,
   -1707,  1068, -1707, -1707, -1707,  1060, -1707, -1707, -1707,    95,
   -1707,  1556, -1342,   170, -1707, -1065, -1570, -1347, -1568, -1343,
     122,   142, -1707, -1707,  -787, -1707, -1707, -1707, -1707, -1707,
   -1707, -1707,  1012,  -292,  1470,  -146,  -208,  -327,   641,   643,
     640, -1707,  -709, -1707, -1707, -1707, -1707, -1707, -1707,  -562,
   -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707,  -303,
     624, -1707, -1707, -1707, -1707,  1018,   408,  -805,   414,  1136,
     623, -1210, -1707, -1707,  1625, -1707, -1707, -1707, -1707,  1024,
   -1707, -1707,   -59,   -17,  -768,  -271,   983,   -29, -1707, -1707,
   -1707,   883,    -9, -1707, -1707, -1707, -1707, -1707,  -137,  -157,
   -1707, -1707,   593,  -712,  1712,   -32, -1707,   706, -1168, -1707,
   -1438, -1707, -1707,   444, -1302, -1707, -1707,   425,   426, -1707,
   -1707,  1560,  -532,  1534,  -521,  1524,  -516,  1533,  1824, -1707,
   -1703, -1707, -1707,  -220, -1707, -1707,  -242,  -512,  1546, -1707,
    -357,  -275,  -774,  -769,  -763, -1707,  -223,  -711, -1707,  1594,
    1568,  -770, -1707, -1396,  -294,    85,  1656, -1707,    22, -1707,
     257, -1707, -1312, -1707,   270, -1707, -1707, -1707, -1707, -1707,
     743,  -224,   986,  1317,  1022,  1659,  1660, -1707, -1707,  -431,
     200, -1707, -1707, -1707,  1080, -1707, -1707, -1707, -1707, -1707,
   -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707,
   -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707,
   -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707,  1343,
    -980, -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707,
   -1707,   878, -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707,
   -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707, -1707,
   -1707, -1707, -1707, -1707, -1707, -1707, -1707
};

/* YYDEFGOTO[NTERM-NUM].  */
static const yytype_int16 yydefgoto[] =
{
       0,     1,  1652,   782,  1053,  1244,  1381,  1055,  1133,   741,
    1079,  1115,   877,  1054,  1242,   728,  1366,  1114,   878,  1687,
    1113,  1297,  1299,  1243,  1047,  1049,   726,   719,   482,   991,
    1118,  1117,   729,   807,  1879,  1368,  1972,   992,   879,   804,
     489,  1106,  1100,  1422,   993,  1026,   723,   857,  1031,  1018,
    1056,  1057,   795,   858,   788,  1653,    45,    46,    47,    72,
      85,    87,   416,   420,   425,   412,   101,   103,   130,   997,
     444,   135,   143,   145,   260,   263,   266,   267,   737,  1145,
     261,   211,   384,  1606,  1335,   385,  1336,  1515,  2052,  1828,
     388,  1337,   389,  1850,  1851,   392,  2061,  1338,  1632,  1835,
     394,  1339,  1992,  2074,  2075,  1843,  1844,  1960,  1445,  1450,
    1694,  1692,  1693,  1448,  1453,  1333,  1845,  1614,  1990,  2067,
    2068,  2069,  2155,  1615,  1616,  1818,  1819,  1798,   212,  1723,
      48,    49,    59,   419,    51,   423,  1801,    65,   428,  1803,
      69,   433,  1806,   414,   415,  1799,   285,   286,   287,    52,
     396,  1462,   446,  1618,   321,   322,  1634,   323,   324,   325,
     326,   327,   328,   329,  1294,  1565,  1566,   330,   331,   332,
     793,   794,   333,   334,   802,   803,  1231,  1225,  1520,  1521,
     335,  1157,  1493,  1748,   336,  1188,  1743,  1487,  1745,  1488,
    1489,  1925,   337,   338,  1524,   806,   339,   340,   341,   342,
     343,   863,   864,  1591,   383,  1958,  2032,   828,   829,   830,
     831,   832,   833,   834,  1544,   835,   836,   837,   838,   839,
     840,   344,   345,   870,   346,   347,   875,   348,   349,   871,
     872,   350,   351,   352,   883,   884,  1191,  1192,  1193,   885,
     886,  1168,  1169,   353,   354,   355,   356,   357,   892,   893,
     358,   359,   213,   841,   889,   928,   842,   360,   217,  1024,
     508,   509,   843,   516,   361,   362,   363,   364,   365,   366,
     930,   931,   932,   367,   368,   369,   783,   784,  1475,  1476,
    1207,  1208,  1209,  1463,  1464,  1511,  1506,  1507,  1512,  1210,
    1758,   950,  1700,   742,  1712,   744,  1718,   745,   437,   467,
    2004,  1907,  2134,  2135,  1890,  1900,  1147,  1707,   743,   370,
     951,   952,   936,   937,   938,   939,  1211,   941,   844,   845,
     846,   944,   945,   371,   756,   847,   677,   678,   220,   373,
     848,   514,  1435,   707,   849,  1143,   720,  1439,  1691,   223,
     850,   639,   852,   640,   853,   702,   703,  1130,  1131,   704,
     854,   855,   374,   375,   856,   228,   502,   229,   523,   230,
     529,   231,   537,   232,   551,  1044,  1380,   233,   559,   234,
     564,   235,   574,   236,   583,   237,   589,   238,   592,   239,
     596,   240,   601,   241,   606,   242,   377,   618,  1075,  1469,
    1077,  1393,  1385,  1390,  1383,  1387,   243,   622,  1098,  1421,
    1404,  1410,  1399,  1099,   244,   628,   245,   519,   246,   247,
     653,   248,   641,   249,   643,   250,   645,   251,   650,   252,
     660,   253,   663,   254,   669,   255,   716
};

/* YYTABLE[YYPACT[STATE-NUM]] -- What to do in state STATE-NUM.  If
   positive, shift that token.  If negative, reduce the rule whose
   number is the opposite.  If YYTABLE_NINF, syntax error.  */
static const yytype_int16 yytable[] =
{
      43,   216,    53,   789,   787,   757,   981,   390,   320,  1160,
     968,   934,   445,   214,   445,  1008,   445,   445,    44,   386,
     445,   218,   445,   790,   970,   445,   445,  1010,   969,   445,
     445,   445,   445,   971,   391,   214,   445,   995,  1052,   445,
     445,  1009,  1304,   218,   876,   279,   214,   445,   708,  1215,
     270,  1015,  1238,   378,   218,  1104,   986,   381,  1120,  1306,
     269,  1226,   988,  1197,   750,  1230,  1644,   264,  1646,   994,
    1032,  1212,   721,  1562,   372,  1277,   967,  1659,  1656,  1500,
    1502,  1657,  1308,   890,  1361,   372,  1513,  1658,  1447,  1561,
    1667,   957,   779,   935,  1635,  1635,  1495,   268,  1875,   975,
    1701,    56,    57,    58,  1702,  1760,   865,  1873,   873,  1713,
    1107,  1874,  1109,  1033,  1110,   219,   851,  1563,  1250,  1112,
    1683,  1685,  1289,  1724,  1287,  1288,  1790,   781,  1290,  1979,
     990,  1910,  1295,   781,  1911,  1291,   887,   219,  1739,  1881,
    1213,  1046,   280,  1120,   281,   940,  1859,   955,   219,  1048,
     282,  1856,  1791,   382,  2063,  1281,   953,   953,   387,  1786,
    1003,  1725,   393,   887,  1051,  2130,  1564,  2166,  1816,  1817,
    1766,  1767,   150,  1179,  -695,  1012,   887,  2072,  2073,  1174,
    1137,   891,  -695,  -695,  -695,  -695,   271,  1165,   214,  1167,
    2009,  1470,   214,   256,    55,  -788,   218,   102,  1028,  1153,
     218,   679,   151,   152,   153,   629,  1184,  1185,  1078,  1189,
    1152,   651,    63,  1430,  1431,  1201,  1202,   630,  1101,   631,
    1491,  1740,  1119,  1158,  2018,   775,  2072,  2073,   619,  1161,
    1150,  1155,  1496,   319,  2064,  2065,   652,   632,   210,   755,
     755,   633,     3,  1160,   634,     4,  1237,     5,  1240,  1121,
    -690,   262,  1154,  1116,   151,   152,   153,  -690,  -690,  -690,
    -690,   749,  1480,  -788,  -656,  1938,    54,     6,     7,     8,
       9,  1132,  1460,  1508,   758,  1461,  1509,  1951,  1727,  1728,
      71,   620,   621,  1830,  1831,   411,    86,   221,  1311,  1021,
     219,   724,  1788,   866,   219,   888,  -690,   727,  1151,  1857,
     222,  1312,   630,   776,   722,   214,    55,  -697,   778,   221,
     759,   982,  1276,   218,  -697,  -697,  -697,  -697,   899,  1635,
     221,  -657,   222,   144,  1311,   679,   633,   635,  1503,  1418,
       4,  -705,     5,   222,   900,  1182,   933,  1582,  -705,  -705,
    -705,  -705,   390,  1504,   372,  -222,  1419,   933,   933,   630,
     404,   927,   964,  -697,   510,   511,   512,    55,  1029,  1505,
     636,   637,   927,   927,   901,   630,   445,   980,  1298,   391,
     390,  1300,  1528,   633,   272,  1180,   273,  -705,  1420,   214,
     458,   459,   434,   390,  1325,  1326,  1644,   218,  1646,   633,
    2136,  1855,   754,   754,   214,   874,   760,   391,   661,  1437,
    1459,  1674,   218,  1855,   265,  1492,  1741,   219,  1518,  1741,
     391,  1991,  -706,  1519,  1635,  1635,   210,   379,   372,  -706,
    -706,  -706,  -706,   662,  1628,    66,    67,  1022,  1023,  1725,
     210,   283,   284,   372,   210,   463,  1471,  1472,  1175,   305,
     638,   380,  1668,     3,  1349,  1669,     4,  1527,     5,  1530,
     210,   210,   495,  2098,  2082,   307,  2099,  1351,  -706,   210,
     308,  1808,   221,  1352,   956,  1350,   221,  1939,     6,     7,
       8,     9,   983,   210,  1497,   222,   257,   258,   259,   222,
     955,   219,  2199,   210,  2066,  1328,   400,   401,   402,  1214,
    1035,  1285,   210,  1545,  2062,  1293,   219,  1148,  1149,  2053,
     210,  1792,   427,   429,   430,  1036,  1159,   382,   319,   515,
    1787,   280,   442,   210,  2131,   281,  2167,  1790,    55,   593,
     387,   453,   454,   785,   785,   393,  -695,   460,  1150,   594,
     595,   867,   868,   869,   257,   258,   259,  1263,   405,   642,
     406,  1573,  1628,  1571,  1572,  1855,  2148,  1574,   492,   493,
    1542,  1334,   496,  2007,  1575,  2146,   984,   305,  2030,  2147,
     985,  1917,  1734,  2120,  1735,  1736,  2116,  1738,  2000,   513,
     435,   710,   436,   307,  1423,  1045,  1950,  -241,   308,   221,
    1676,   785,  1370,   644,  1372,  1248,  1249,  1050,  1322,  1438,
    2019,  1017,   222,   987,  2023,  1170,  1628,  1696,  2024,  1039,
    1455,  -690,    55,  1264,  1458,  1265,    55,  1726,   503,   504,
    1365,   305,   772,   773,  1477,  1478,  1479,     3,  1196,  1482,
       4,  1484,     5,   464,   725,   436,  1296,   307,  1952,   890,
     899,  1937,   308,   867,   868,   869,  -955,  1260,  -955,    55,
     465,  1499,     6,     7,     8,     9,  1103,  1434,   746,  1809,
    1684,  1810,  1318,   221,  1102,  1934,  1935,  1774,  -697,   590,
    -956,   705,  -956,  1156,  1955,  1319,   222,  1320,   221,     3,
    1323,   706,     4,  1340,     5,   591,   901,  1531,     4,  1533,
       5,   222,  -705,  1261,  1998,  1534,   560,  1309,   747,     4,
     632,     5,  1753,  1449,     6,     7,     8,     9,   748,  1941,
    1547,     3,  1548,  1310,     4,  1891,     5,   561,   751,  1454,
    1037,  1556,  1892,  1558,   859,   860,  1194,  1160,   769,   771,
     562,  1452,  1324,  1485,  1585,  1038,     6,     7,     8,     9,
    1346,  1347,  1348,   753,   770,   214,  1775,   772,   773,  1776,
    1233,  2029,  1778,   218,   505,   506,  1318,  1359,   507,  1893,
    1206,     3,  1490,  1234,     4,  1266,     5,  1891,   214,  1330,
    1837,  1320,  1292,  -706,  1892,   927,   218,   768,  1516,  1235,
    2107,  2104,  1146,   224,  2105,   777,     6,     7,     8,     9,
    2106,   403,   785,  1894,  1197,  1838,  1839,   630,  -955,  1891,
    1759,  1811,  1812,  1813,  1814,   224,  1892,   432,  1587,  1220,
       3,  1893,  1212,     4,  1318,     5,   224,   632,   517,   518,
    1251,   633,  -956,   636,   637,  1267,   456,  1583,  2002,  1320,
    1919,  1278,   623,  2003,   781,     6,     7,     8,     9,  1258,
    1246,  1259,  1221,  1893,  1644,  1894,  1646,   219,   780,  1245,
    1647,   888,   785,  1648,  1446,  1395,   805,  1222,  -955,  1396,
    1397,  1398,  -510,  1212,   624,   625,  1688,   796,  1732,  1733,
     219,   861,  1635,  1635,   862,   896,   602,  1894,   999,   933,
     563,   891,  -956,  1968,  1969,  1970,  1971,   927,   927,   927,
     927,   927,   214,   646,   927,   626,   897,  1895,  1664,  1374,
     218,   898,  1223,   638,  1719,  1720,   958,   890,   603,   604,
    1666,   605,   946,  2101,  1840,  1016,  1375,  -788,   575,   927,
     576,  1376,  1377,   933,  1665,   947,  1236,     3,   627,  1440,
       4,  1737,     5,   959,  1841,  1842,  1536,  1537,   927,   577,
     636,   637,  1984,  1543,  1654,  1974,  1754,   578,   579,  1895,
     580,   282,     6,     7,     8,     9,   150,  1522,   224,  1329,
     581,   582,   224,  1331,   955,  1569,   785,  1523,   647,   648,
     649,  1649,  1578,  1672,   150,  1522,   520,   521,   522,  2006,
    1779,  1895,  1896,  1559,   960,  1526,  1224,    18,    19,  2012,
      62,  1282,   961,   451,   219,  1284,  2015,  1781,   654,  1783,
     890,   797,   798,   799,   800,   801,   791,   792,    18,    19,
    1965,  1966,  1967,  2163,   655,   717,   718,  1675,   785,   221,
     638,   278,  1378,   215,   962,     4,   225,     5,  1474,  -303,
    1946,  2020,   222,   996,  1996,   656,    34,  2039,  2040,  2041,
    -797,   657,   221,   597,  -798,   215,    35,   598,   225,   395,
     785,  1663,    36,   399,  1002,  1198,   215,    34,  1019,   225,
     150,  1522,   226,  1020,   772,   773,  2175,    35,   422,   395,
    1371,  1529,  1373,    36,  1987,   224,    37,  1980,  1379,   599,
     600,   552,   664,   553,   226,  1330,   449,  1320,  2078,  2079,
    2080,   257,   258,   259,  1650,   226,   665,    37,  1568,  1570,
     785,  2128,   554,   666,  2129,  1576,  1570,  1579,  1581,  1027,
     555,   556,   557,   558,  2096,   491,  1708,  1025,  1882,   888,
     227,   667,   497,   131,  1108,   658,   659,   668,   132,   133,
     894,   895,     3,  1111,  2084,     4,  1170,     5,  1474,   880,
     881,   882,   376,   730,   134,   731,  1136,   732,   733,   224,
    2085,  1186,  1187,   376,  1134,   734,   735,     6,     7,     8,
       9,   151,   152,   153,   224,  1651,   221,  1730,   214,  1916,
    1135,   136,   711,   137,  1253,  1254,   218,  1142,   138,   222,
     139,   712,   713,  1144,   140,   714,   715,  1166,   736,  1171,
       3,  1797,  1172,     4,     3,     5,  1173,     4,   215,     5,
    1176,   225,   215,  1936,  1177,   225,  1763,  1178,  1821,   291,
     292,  1190,   888,   584,   293,     6,     7,     8,     9,     6,
       7,     8,     9,   141,  1883,   142,   881,   882,  1948,   585,
    1647,  1313,  1314,  1648,  1181,  1793,  1794,   226,   586,  1546,
       4,   226,     5,  1982,   587,   588,  1251,  1251,  1251,  1251,
    1251,  1912,  1251,  1251,  1212,  1789,  1405,  1406,  1407,  1408,
    1409,  1552,  1552,  1784,  1884,  1785,   785,  2191,  2192,  2193,
     219,  1183,  1915,  1846,  1847,  1848,   214,  1849,   214,   772,
     773,  1913,  2141,  1203,   218,   524,   218,   525,   526,   527,
     528,  1927,  1217,  1930,  1204,   227,   151,   152,   153,   227,
    1040,  1041,  1042,  1043,   927,   927,   927,   927,   927,   927,
     927,   927,   927,   927,   927,   215,  1388,  1389,   225,  1391,
    1392,  1933,   295,   296,   297,  1756,  1757,   300,  1216,   214,
    2055,     3,  1426,  1427,     4,   498,     5,   218,   499,   500,
     501,  1586,  1588,  1218,  1604,  1612,  1630,  1642,  1227,  1196,
    1228,  1649,  1867,  1229,   226,  1241,     6,     7,     8,     9,
    1589,   929,  1605,  1613,  1631,  1643,  1428,  1429,   372,  1570,
    1570,  1247,   929,   929,  1944,  1945,  1255,  1947,   219,  2056,
     219,  1920,  1921,  1922,  1923,  1924,   781,  1501,  1160,   215,
    1256,     4,   225,     5,  1257,  1974,  1837,  2027,  1909,     4,
   -1000,     5,  1885,  1980,   215,  1689,  1690,   225,  1262,  2025,
    2026,  1270,   376, -1001,  1673,  1400,  1401,  1402,  1403,   150,
    1522,  1838,  1839,  1962,   867,   868,   869,  2181,   226,  1833,
    1834,   219,  -510,  1268,   786,  1269,  1963,   438,   439,   440,
     441,  1271,   221,   226,  1273,  1750,  1964,  1194,  1278,   469,
    1274,  1681,  1682,  1281,  1697,   222,  1283,  1704,  1315,  1709,
    1679,  1680,  1715,  1316,    18,    19,  2153,  2154,   214,  1978,
    1317,   785,  1698,   757,  1650,  1705,   218,  1710,  1554,  1555,
    1716,  1771,  1321,  1327,  1311,  1332,   376,  1886,  1961,   214,
     955,  1206,  1341,  1342,   927,  1986,  1343,   218,  1344,  1345,
    1150,   376,  1353,  1153,  1354,   224,   927,   372,   214,  1355,
     471,  1356,  1357,    34,  1360,  1358,   218,  1363,  1367,  1386,
    1382,  1384,  1394,    35,  1770,    18,    19,  1412,  1199,    36,
    1415,  1413,  1414,   785,  1424,  1416,  1417,  1425,  1432,  1433,
    1840,     3,  1434,  1456,     4,  1872,     5,   372,  1483,  1714,
     221,  1772,   221,    37,   899,  1436,   214,   927,  1441,  1820,
    1841,  1842,  1442,   222,   218,   222,     6,     7,     8,     9,
     219,  1444,  1443,  1451,    34,   927,   927,  1473,  2057,  1498,
    2049,  1481,  1474,  1486,    35,  1494,  1517,  1532,  1535,  1541,
      36,   219,  1549,  1550,  2058,   372,  1551,  -656,  -657,  2059,
    1829,  2060,  1584,   221,  1660,  1567,  2122,  1661,  1662,  2016,
     219,  1686,   214,  1670,    37,  1815,   222,  1829,  2124,  1677,
     218,  1678,  1695,  1823,  1824,  1825,  1826,  1827,  1721,   214,
    1722,  1729,  2123,  1883,   772,   773,  1742,   218,  1746,  1170,
    1744,  1852,  1853,  1854,  1755,  1747,  2138,  2139,  1761,   214,
    1762,  1764,   224,  1861,  1862,  1863,  1773,   218,   219,  2119,
    1777,  1780,  1782,  1795,  1604,  1612,  1630,  1642,   530,   531,
     785,  1318,  1796,  1884,  1807,  1822,  1832,   532,   533,   534,
     535,   536,  1605,  1613,  1631,  1643,  2151,  1864,   372,  1836,
       3,   764,  1866,     4,  1877,     5,  1858,  1800,  1802,  1802,
    1805,  1887,  1897,  1904,  1865,  1878,  -528,   755,   755,  1880,
    1908,  1918,  1926,  1928,   219,     6,     7,     8,     9,  1888,
    1898,  1905,   214,  1932,  2159,  2160,  2195,  1940,  1949,  1953,
     218,   219,  1954,  1957,  1959,  2013,  1989,  1973,  2197,  1999,
    2001,  2008,   221,  2010,  2017,   215,  2022,  2021,   225,  2031,
    2028,   219,  2196,  2034,  2035,   222,  2036,  2185,  2046,  2121,
    2037,  2081,  2093,   221,  2095,  2097,  2118,  2189,  1195,  2038,
    2115,   225,  2042,  2190,  2043,   929,  1198,  2044,  -255,   214,
    1942,  2100,   221,   390,   226,  2045,  2083,   218,  2108,  2109,
    2127,  2165,   151,   152,   153,   222,  2132,  2110,  2133,  2137,
    -256,  2161,  2005,  2162,  1170,  2183,  2186,   226,  1301,   390,
     391,  1885,  2011,  1307,  1303,  1302,  1993,  1138,  1140,  2014,
    1139,  1034,  1369,     3,   219,  1141,     4,  1671,     5,  1030,
     221,  1305,    70,  1655,  2050,  1860,   391,  1975,   966,  1976,
    1977,   473,   227,   222,  2198,  2164,  2048,  2111,     6,     7,
       8,     9,  2113,  1981,  2112,  2114,    18,    19,  2103,  1983,
     754,   754,   417,  2184,  1804,   227,  1985,   963,   424,  1988,
    1956,  1219,  1232,  1279,   774,  1994,  1929,   965,  1943,  2194,
     785,   219,  1887,  1897,  1904,  1272,   221,   929,   929,   929,
     929,   929,   215,  1914,   929,   225,  1995,  2102,  1931,   222,
    1888,  1898,  1905,   221,  2140,    34,  1538,  1540,  1557,  1539,
     214,  1280,  1749,  1364,  1560,    35,   222,   475,   218,   929,
    1752,    36,  1200,   221,  1580,   752,  1286,   709,   224,  1514,
    1731,   226,    18,    19,     3,  1901,   222,     4,   929,     5,
    2070,  1765,  2076,   978,   214,    37,   943,  1768,   927,   372,
     954,   976,   218,   979,   466,  2047,  2187,   943,   943,     6,
       7,     8,     9,   480,   977,  2054,  1105,   214,  2033,   762,
    1076,  1411,   942,   766,   767,   218,     0,   214,    18,    19,
       0,    34,     0,   942,   942,   218,     0,     0,     0,   227,
       0,    35,     0,     0,     0,     0,   221,    36,     0,  2071,
       0,  2077,     0,     0,     0,     0,     0,   565,   566,   222,
       0,     0,   219,  2086,  2087,     0,  2088,  2089,  2090,  2091,
    2092,    37,   567,  2094,   568,   569,   570,    34,     0,   785,
       0,     0,  1829,     0,     0,     0,   224,    35,   224,     0,
       0,     0,     0,    36,   214,  2152,   219,   571,   572,   573,
       0,     0,   218,   221,     0,     0,     0,     0,     0,     0,
       3,  2117,     0,     4,     0,     5,   222,    37,     0,   219,
    2125,  2126,     0,     0,     0,     0,     0,     0,     0,   219,
       0,  2076,     0,     0,     0,     6,     7,     8,     9,   224,
       0,     0,     0,  1902,     0,     0,     0,   214,     0,  2157,
    1647,     0,     0,  1648,  2182,   218,     0,     0,     0,     0,
       0,   214,  1588,  1612,  1630,  1642,     0,     0,     0,   218,
    1697,  1704,  1709,  1715,     0,  2156,     0,     0,     0,  2158,
    1589,  1613,  1631,  1643,  1993,     0,   372,     0,  1698,  1705,
    1710,  1716,     0,     0,     0,  2168,   219,     0,     0,     0,
    2169,  2170,  2171,  2172,  2173,  1887,  1897,  1904,  2177,  2178,
    2179,  2180,   785,     0,     0,  1122,  1123,     0,   215,     0,
       0,   225,     0,  1888,  1898,  1905,  2188,     0,  1903,  1124,
       0,     0,     0,     0,   221,     0,     0,  1125,     0,     0,
       0,     0,     0,     0,     0,     0,     0,   222,     0,   219,
    2200,  2201,  2202,  1126,     0,     0,     0,   226,     0,     0,
       0,     0,     3,   219,     0,     4,     0,     5,   221,     3,
       0,  1649,     4,     0,     5,     0,  1525,  1525,   224,  1525,
       0,   222,     0,     0,     0,  1153,     0,     6,     7,     8,
       9,   221,     0,     0,     6,     7,     8,     9,     0,  1199,
       0,   221,     0,     0,   222,     0,     0,     0,     3,  1647,
       0,     4,  1648,     5,   222,   227,     0,     0,   224,     0,
       0,     0,     3,   785,     0,     4,   215,     5,   215,   225,
       0,   225,     0,     6,     7,     8,     9,     0,     0,  1703,
       0,     0,     0,     0,     0,     0,     0,     6,     7,     8,
       9,     0,     0,     0,   929,   929,   929,   929,   929,   929,
     929,   929,   929,   929,   929,   226,   224,   226,   221,     0,
      60,     0,  1510,   484,     0,  1127,  1128,  1129,   688,   215,
       3,   222,   225,     4,     0,     5,     0,     0,    18,    19,
       0,   698,   699,   700,  1650,     0,     0,     0,     0,   274,
     275,   276,   277,     0,     0,     6,     7,     8,     9,     0,
     943,     0,     0,     0,  1883,     0,     0,     0,   226,  1619,
       0,   221,   224,   227,     3,   227,     0,     4,     0,     5,
    1649,     0,     0,   397,   222,   221,   942,    34,     0,   224,
       0,   407,   408,   409,   410,     0,     0,    35,   222,     6,
       7,     8,     9,    36,  1884,  1252,     0,     0,     0,   224,
       0,     0,     0,  1619,   443,  1876,     0,  1620,  1621,  1622,
    1623,     0,  1624,     0,     0,  1625,   376,    37,     0,     0,
       0,   468,     0,     0,     0,     0,   477,   478,   479,     0,
       0,   483,  1626,     0,   488,     0,  1590,     0,  1607,  1617,
    1633,  1645,     0,     0,     0,     0,     0,     0,     0,     0,
       0,  1620,  1621,  1622,  1623,     0,  1624,     0,   215,  1625,
       0,   225,   943,   943,   943,   943,   943,     0,     0,   943,
       0,     0,   224,     0,     0,     0,  1626,  1751,     0,  1195,
    1279,  1627,   225,     0,   929,     0,     0,     0,   942,   942,
     942,   942,   942,  1650,   943,   942,   929,   226,   215,     0,
       0,   225,     0,  1153,     0,     0,  1525,     0,     0,  1525,
       0,     0,  1525,   943,     0,     0,     0,     0,   226,     0,
     942,     0,     0,     0,     0,  1627,     0,     0,     0,   224,
       0,     0,  1885,     0,  1150,     3,     0,   226,     4,   942,
       5,   785,     0,     0,     0,     0,   215,   929,  1699,   225,
       0,  1706,     0,  1711,     0,   376,  1717,  2150,     0,     0,
       6,     7,     8,     9,  2145,   929,   929,     0,     0,     0,
       0,   738,   739,   740,     0,     0,   227,     0,     0,     0,
       0,   486,     0,     0,     0,   226,     0,   785,     0,  1628,
       0,     0,     0,     0,     0,   376,    18,    19,     0,     0,
       0,   785,   215,  2149,   305,   225,     0,     0,     0,     0,
       0,     0,     0,     0,  1510,     0,     0,  2174,     0,   215,
     307,  1058,   225,     0,     0,   308,     3,     0,     0,     4,
       0,     5,     0,  1628,     0,     0,  1059,     0,     0,   215,
       0,   226,   225,   376,     0,    34,     0,  1901,   305,     0,
       0,     6,     7,     8,     9,    35,     0,     0,   226,   785,
     224,    36,     0,     0,   307,   448,     0,   450,   452,   308,
       0,   455,     0,   457,     0,  1629,   461,   462,   226,     0,
     470,   472,   474,   476,     0,    37,     0,   481,     0,     0,
     485,   487,     0,     0,   224,     0,     0,     0,   494,   227,
    1060,     0,     0,   785,   972,   973,   974,     0,     0,     0,
       0,     0,   215,     0,     0,   225,   227,   224,     0,  1870,
       0,     0,     0,     0,     0,     0,     0,   224,     0,     0,
       0,    10,     0,     0,     0,     0,   376,   989,  1901,    11,
       0,    12,     0,    13,     0,     0,    14,    15,    16,     0,
      17,   226,     0,     0,    18,    19,     0,     0,  1607,  1617,
    1633,  1645,     0,     0,     0,     0,  1001,     0,     0,   215,
       0,  1061,   225,     0,  1062,  1063,  1064,  1065,  1066,  1067,
    1068,  1069,  1070,  1071,  1072,  1073,  1074,     0,     0,     0,
       0,     0,     0,     0,   224,  1889,  1899,  1906,     0,     0,
       0,     0,     0,    34,     0,  1902,     0,     0,   226,   227,
       0,     0,     0,    35,     0,     0,     0,     0,     0,    36,
       0,  1252,  1252,  1252,  1252,  1252,     0,  1252,  1252,     0,
       3,     0,     0,     4,    88,     5,  1553,  1553,     0,     0,
       0,     0,    89,    37,    90,     0,    91,   224,     0,    92,
      93,    94,     0,    95,     0,     6,     7,     8,     9,     0,
       0,   224,     0,     0,     0,     0,   227,     0,     0,  1619,
       0,     0,     0,     0,   785,     0,     0,     0,     0,   943,
     943,   943,   943,   943,   943,   943,   943,   943,   943,   943,
    1997,     0,     0,     0,     0,     0,  1902,     0,     0,     0,
     215,     0,     0,   225,     0,   942,   942,   942,   942,   942,
     942,   942,   942,   942,   942,   942,     0,  1620,  1621,  1622,
    1623,     0,  1624,     0,     0,  1625,     0,     0,     0,     0,
       0,     0,     0,    73,   215,     0,     0,   225,   929,   226,
       0,    74,  1626,    75,     0,     0,     0,     0,    76,    77,
      78,     0,    79,     0,     0,     0,     0,   215,     0,     0,
     225,     0,     0,     0,    38,   785,     0,   215,     0,     0,
     225,     0,     0,   226,     0,   607,  1889,  1899,  1906,    39,
       0,  2176,     0,     0,   608,     0,   809,     0,     0,     0,
       0,  1627,     0,     0,     0,    40,   226,   376,     0,   609,
      41,     0,    42,   610,     0,     0,   226,   611,   612,     0,
       0,     0,   613,   614,   615,   616,   617,  1000,     0,   151,
     152,   153,     0,     0,     0,     0,   909,     0,     0,     0,
     910,   227,     0,     0,   215,   911,     0,   225,     0,     0,
       0,   912,     0,     0,     0,   816,     0,     0,     0,     0,
       0,     0,     0,     0,   227,     0,     0,     0,     0,     0,
       0,     0,     0,     0,   227,   915,     0,    96,     0,   943,
       0,     0,     0,   226,   763,     0,     0,     0,     0,     0,
       0,   943,    97,     3,     0,     0,     4,   215,     5,     0,
     225,     0,     0,     0,     0,   942,   680,   681,    98,  1628,
     682,   215,     0,    99,   225,   100,     0,   942,     6,     7,
       8,     9,     0,     0,   305,     0,     0,     0,   683,  1592,
       0,     0,     0,     0,     0,     0,   226,     0,     0,  1593,
     307,   227,   943,     0,  1594,   308,  1595,     0,  1596,     0,
     226,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     943,   943,     0,     0,     0,     0,     0,     0,   942,     0,
       0,     0,     0,     0,     0,     0,    80,     0,     0,   785,
       0,     0,     0,     0,   764,     0,   942,   942,     0,     0,
       0,    81,     0,     0,   376,  2143,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,   819,    82,   227,   820,
     821,     0,    83,     0,    84,     0,  1590,  1617,  1633,  1645,
      50,     0,     0,     0,  1699,  1706,  1711,  1717,     0,     0,
      61,    50,    50,    64,    64,    64,    68,     0,     0,    50,
       0,     0,   684,     0,   823,   824,     0,     0,     0,     0,
       0,     0,     0,     0,  1597,     0,     0,     0,     0,  1889,
    1899,  1906,     0,     0,     0,     0,   685,   686,   687,   688,
     689,   690,   765,   691,   692,   693,   694,   695,   696,   697,
       0,     0,   698,   699,   700,     0,   210,     0,     0,     0,
      50,     0,     0,   398,    50,    64,    64,    64,    68,     0,
       0,     0,     0,   701,     0,    50,     0,   413,   418,   421,
      50,   426,    64,    64,   431,     0,   413,   413,   413,   413,
       0,    64,     0,     0,     0,   447,     0,    50,     0,     0,
      64,    64,  1465,    68,     0,     0,    64,     0,     0,     0,
       0,     0,     0,     3,     0,     0,     4,     0,     5,     0,
       0,     0,     0,     0,     0,   490,    50,    64,    64,     0,
       0,    64,  1598,    50,     0,     0,     0,     0,     6,     7,
       8,     9,     0,     0,     0,     0,     0,  1599,     0,     0,
       0,     0,  1636,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,  1600,     0,     0,  1060,     0,  1601,     0,
    1602,     0,   104,     0,     0,     0,     0,   105,     0,     0,
     106,   107,   108,   109,     0,     0,   110,   111,     0,   112,
     113,   114,     0,   115,     0,     0,     0,     0,     0,     0,
       0,  1637,   785,  1638,     0,  1624,     0,     0,  1625,     0,
       0,     0,     0,     0,     0,     0,     0,     0,  1603,     0,
       0,     0,     0,     0,     0,  1639,     0,     0,     0,     0,
       0,     0,   116,     0,   117,   118,   119,  1466,     0,     0,
    1062,  1063,  1467,  1065,  1066,  1067,  1068,  1069,  1070,  1071,
    1072,  1073,  1468,     0,     0,     3,     0,     0,     4,     0,
       5,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,  1640,     0,     0,   146,     0,     0,
       6,     7,     8,     9,   147,   148,     0,     0,     0,   288,
     149,   289,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,   943,     0,     0,   290,     0,     0,     0,
       0,     0,     0,     0,     0,     0,   291,   292,     0,     0,
       0,   293,     0,     0,   294,     0,     0,     0,     0,   942,
       0,     0,   295,   296,   297,   298,   299,   300,     0,     0,
       0,     0,     0,     0,     0,     0,     0,  1608,     0,     0,
       0,   301,     0,   302,     0,     0,   150,   151,   152,   153,
       0,     0,   154,     0,   155,     0,     0,  1609,   156,     0,
     538,   539,     0,   157,   540,     0,     0,     0,     0,   158,
       0,     0,  1628,     0,     0,   541,   542,   543,   544,   545,
     546,   547,   548,   549,     0,   159,     0,   305,     0,     0,
     160,     0,     0,   161,     0,   120,     0,     0,   162,     0,
       0,   163,     0,   307,   164,   165,  1610,     0,   308,   166,
     121,     0,   167,     0,   168,   122,   123,   124,   125,     0,
       0,     0,     0,     0,   550,     0,   126,     0,     0,     0,
     998,   127,     0,   128,   129,     0,     0,    64,     0,   169,
     170,     0,   785,     0,     0,     0,     0,     0,  1004,     0,
    1005,     0,  1006,     0,  1007,     0,     0,     0,  1641,  1011,
       0,     0,     0,  1013,     0,  1014,     0,     0,     0,     0,
       0,     0,     0,     0,    64,   171,   172,   173,   174,     0,
       0,     0,     0,     0,   175,   176,     0,     0,   177,   178,
     303,   180,   181,   182,   183,   184,   185,   186,   187,   188,
     189,   190,   191,   192,   193,   194,   195,   196,   197,   198,
     199,   200,     0,     0,   304,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,   305,
       0,     0,     0,     0,     0,     0,     0,     0,     0,   306,
       0,     0,     0,     0,     0,   307,     0,     0,     0,     0,
     308,     0,     0,     0,     0,     0,   202,   203,     0,   309,
       0,     0,   310,   311,   312,   313,     0,     0,     0,   314,
       0,     0,     0,   315,   316,   204,     0,     0,     0,   205,
     206,     0,     0,     0,   785,     0,     0,     0,   317,     0,
       3,   207,   208,     4,     0,     5,     0,   318,     0,   319,
    1611,   209,     0,     0,   210,     0,     0,     0,     0,     0,
       0,     0,   146,     0,     0,     6,     7,     8,     9,   147,
     148,     0,     0,     0,   288,   149,   289,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,   290,     0,     0,     0,     0,     0,     0,     0,     0,
       0,   291,   292,     0,     0,     0,   293,     0,     0,   294,
       0,     0,     0,     0,     0,     0,     0,   295,   296,   297,
     298,   299,   300,     0,     0,     0,     0,     0,     0,     0,
       0,     0,  1608,     0,     0,     0,   301,     0,   302,     0,
       0,   150,   151,   152,   153,     0,     0,   154,     0,   155,
       0,     0,  1609,   156,     0,     0,     0,     0,   157,     0,
       0,     0,     0,     0,   158,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     159,     0,     0,     0,     0,   160,     0,     0,   161,     0,
       0,     0,     0,   162,     0,     0,   163,     0,     0,   164,
     165,  1610,     0,     0,   166,     0,     0,   167,     0,   168,
       0,     3,     0,     0,     4,     0,     5,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,   169,   170,     6,     7,     8,     9,
       0,     0,     0,     0,     0,     0,     0,  1592,     0,     0,
       0,     0,     0,     0,     0,     0,     0,  1593,     0,     0,
       0,     0,  1594,     0,  1595,     0,  1596,     0,     0,     0,
     171,   172,   173,   174,     0,     0,     0,     0,     0,   175,
     176,     0,     0,   177,   178,   303,   180,   181,   182,   183,
     184,   185,   186,   187,   188,   189,   190,   191,   192,   193,
     194,   195,   196,   197,   198,   199,   200,     0,     0,   304,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,   305,     0,     0,     0,     0,     0,
       0,     0,     0,     0,   306,     0,     0,     0,     0,     0,
     307,     0,     0,     0,     0,   308,     0,     0,     0,     0,
       0,   202,   203,     0,   309,     0,     0,   310,   311,   312,
     313,     0,     0,     0,   314,     0,     0,     0,   315,   316,
     204,     0,  1597,     0,   205,   206,     0,     0,     0,   785,
       0,     0,     0,   317,     0,     3,   207,   208,     4,     0,
       5,     0,   318,     0,   319,  1869,   209,     0,     0,   210,
     680,   681,     0,     0,   682,     0,     0,   146,     0,     0,
       6,     7,     8,     9,   147,   148,     0,     0,     0,   288,
     149,   289,   683,     0,     0,     0,     0,     0,     0,     0,
       0,  1362,     0,     0,     0,     0,   290,     0,     0,     0,
       0,     0,     0,     0,     0,     0,   291,   292,     0,     0,
       0,   293,     0,     0,   294,     0,     0,     0,     0,     0,
       0,     0,   295,   296,   297,   298,   299,   300,     0,     0,
       0,     0,     0,     0,     0,     0,     0,  1608,     0,     0,
    1598,   301,     0,   302,     0,     0,   150,   151,   152,   153,
       0,     0,   154,     0,   155,  1599,     3,  1609,   156,     4,
       0,     5,     0,   157,     0,     0,     0,     0,     0,   158,
       0,  1600,     0,     0,     0,     0,  1601,     0,  1602,     0,
       0,     6,     7,     8,     9,   159,     0,     0,     0,     0,
     160,     0,     0,   161,     0,  1636,   684,     0,   162,     0,
       0,   163,     0,     0,   164,   165,  1610,     0,     0,   166,
     785,     0,   167,     0,   168,     0,     0,     0,     0,     0,
     685,   686,   687,   688,   689,   690,  1868,   691,   692,   693,
     694,   695,   696,   697,     0,     0,   698,   699,   700,   169,
     170,     0,     0,     0,  1637,     0,  1638,     0,  1624,     0,
       0,  1625,     0,     0,     0,     0,     0,   701,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,  1639,     0,
       0,     0,     0,     0,     0,   171,   172,   173,   174,     0,
       0,     0,     0,     0,   175,   176,     0,     0,   177,   178,
     303,   180,   181,   182,   183,   184,   185,   186,   187,   188,
     189,   190,   191,   192,   193,   194,   195,   196,   197,   198,
     199,   200,     0,     0,   304,     0,     0,  1640,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,   305,
       0,     0,     0,     0,     0,     0,     0,     0,     0,   306,
       0,     0,     0,     0,     0,   307,     0,     0,     0,     0,
     308,     0,     0,     0,     0,     0,   202,   203,     0,   309,
       0,     0,   310,   311,   312,   313,     0,     0,     0,   314,
       0,     0,     0,   315,   316,   204,     4,     0,     5,   205,
     206,     0,     0,     0,   785,     0,     0,     0,   317,     0,
       0,   207,   208,     0,     0,   146,     0,   318,     0,   319,
    2142,   209,   147,   148,   210,     0,     0,   288,   149,   289,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,   290,  1628,     0,     0,     0,     0,
       0,     0,     0,     0,   291,   292,     0,     0,     0,   293,
     305,     0,   294,     0,     0,     0,     0,     0,     0,     0,
     295,   296,   297,   298,   299,   300,   307,     0,     0,     0,
       0,   308,     0,     0,     0,     0,     0,     0,     0,   301,
       0,   302,     0,     0,   150,   151,   152,   153,     0,     0,
     154,     0,   155,     0,     0,     0,   156,     0,     0,     0,
       0,   157,     0,     0,     0,   785,     0,   158,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,  1871,     0,   159,     0,     0,     0,     0,   160,     0,
       0,   161,     0,     0,     0,  1080,   162,     0,     0,   163,
       0,     0,   164,   165,     0,     0,     0,   166,     0,     0,
     167,     0,   168,  1081,  1082,  1083,  1084,  1085,  1086,  1087,
    1088,  1089,  1090,  1091,  1092,  1093,  1094,  1095,  1096,  1097,
       0,     0,     0,     0,     0,     0,     0,   169,   170,     0,
       3,     0,     0,     4,     0,     5,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     6,     7,     8,     9,     0,
       0,     0,     0,   171,   172,   173,   174,     0,     0,  1636,
       0,     0,   175,   176,     0,     0,   177,   178,   303,   180,
     181,   182,   183,   184,   185,   186,   187,   188,   189,   190,
     191,   192,   193,   194,   195,   196,   197,   198,   199,   200,
       0,     0,   304,     0,     0,   808,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,   305,  1637,     0,
    1638,     0,  1624,   146,     0,  1625,     0,   306,     0,     0,
       0,   148,     0,   307,     0,     0,   149,     0,   308,     0,
       0,     0,  1639,     0,   202,   203,     0,   309,     0,     0,
     310,   311,   312,   313,     0,     0,     0,   314,     0,     0,
       0,   315,   316,   204,     0,     0,     0,   205,   206,     0,
     809,     0,     0,     0,     0,     0,   317,     0,     0,   207,
     208,     0,     0,     0,   810,   318,   811,   319,  1769,   209,
       0,  1640,   210,     0,     0,     0,     0,     0,     0,     0,
       0,     0,   150,   151,   152,   153,     0,     0,   154,     0,
     812,     0,     0,     0,   813,     0,     0,     0,     0,   814,
       0,     0,     0,     0,     0,   815,     0,     0,     0,   816,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,   159,     0,     0,     0,     0,   160,     0,     0,   817,
       0,     0,     0,     0,   162,     0,     0,   163,     0,     0,
     164,   165,     0,     0,     0,   166,     0,     0,   167,     0,
     168,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,   169,   170,     0,     0,  1628,
       0,     0,     0,     0,     0,     0,  1162,     0,     0,     0,
       0,     0,     0,     0,   305,     0,     0,     0,     0,     0,
       0,     0,     0,     0,   146,     0,     0,     0,     0,     0,
     307,   818,   148,     0,     0,   308,     0,   149,     0,     0,
       0,     0,     0,     0,     0,     0,   179,   180,   181,   182,
     183,   184,   185,   186,   187,   188,   189,   190,   191,   192,
     193,   194,   195,   196,   197,   198,   199,   200,     0,   785,
     201,   809,     0,     0,     0,     0,     0,     0,     0,     0,
     819,     0,     0,   820,   821,  2144,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,   822,     0,     0,     0,
       0,     0,     0,   150,   151,   152,   153,     0,     0,   154,
       0,   812,   202,   203,     0,   813,     0,     0,   823,   824,
     814,     0,     0,     0,     0,     0,  1163,     0,     0,     0,
     816,   204,     0,     0,     0,   205,   206,     0,     0,     0,
       0,     0,   159,     0,     0,   825,   826,   160,   676,     0,
    1164,     0,     0,     0,     0,   162,     0,   827,   163,     0,
     210,   164,   165,     0,     0,     0,   166,     0,     0,   167,
       0,   168,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,   169,   170,     0,     0,
       0,     0,     0,     0,     0,     0,     0,  1239,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,   146,     0,     0,     0,     0,
       0,     0,   818,   148,     0,     0,     0,     0,   149,     0,
       0,     0,     0,     0,     0,     0,     0,   179,   180,   181,
     182,   183,   184,   185,   186,   187,   188,   189,   190,   191,
     192,   193,   194,   195,   196,   197,   198,   199,   200,     0,
       0,   201,   809,     0,     0,     0,     0,     0,     0,     0,
       0,   819,     0,     0,   820,   821,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,   150,   151,   152,   153,     0,     0,
     154,     0,   812,   202,   203,     0,   813,     0,     0,   823,
     824,   814,     0,     0,     0,     0,     0,  1163,     0,     0,
       0,   816,   204,     0,     0,     0,   205,   206,     0,     0,
       0,     0,     0,   159,     0,     0,   825,   826,   160,   676,
       0,  1164,     0,     0,     0,     0,   162,     0,   827,   163,
       0,   210,   164,   165,     0,     0,     0,   166,     0,     0,
     167,     0,   168,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,   169,   170,     0,
       0,     0,     0,     0,     0,     0,     0,     0,  1275,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,   146,     0,     0,     0,
       0,     0,     0,   818,   148,     0,     0,     0,     0,   149,
       0,     0,     0,     0,     0,     0,     0,     0,   179,   180,
     181,   182,   183,   184,   185,   186,   187,   188,   189,   190,
     191,   192,   193,   194,   195,   196,   197,   198,   199,   200,
       0,     0,   201,   809,     0,     0,     0,     0,     0,     0,
       0,     0,   819,     0,     0,   820,   821,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,   150,   151,   152,   153,     0,
       0,   154,     0,   812,   202,   203,     0,   813,     0,     0,
     823,   824,   814,     0,     0,     0,     0,     0,  1163,     0,
       0,     0,   816,   204,     0,     0,     0,   205,   206,     0,
       0,     0,     0,     0,   159,     0,     0,   825,   826,   160,
     676,     0,  1164,     0,     0,     0,     0,   162,     0,   827,
     163,     0,   210,   164,   165,     0,     0,     0,   166,     0,
       0,   167,     0,   168,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,   169,   170,
       0,     0,     0,     0,     0,     0,     0,     0,     0,  1457,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,   146,     0,     0,
       0,     0,     0,     0,   818,   148,     0,     0,     0,     0,
     149,     0,     0,     0,     0,     0,     0,     0,     0,   179,
     180,   181,   182,   183,   184,   185,   186,   187,   188,   189,
     190,   191,   192,   193,   194,   195,   196,   197,   198,   199,
     200,     0,     0,   201,   809,     0,     0,     0,     0,     0,
       0,     0,     0,   819,     0,     0,   820,   821,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,   150,   151,   152,   153,
       0,     0,   154,     0,   812,   202,   203,     0,   813,     0,
       0,   823,   824,   814,     0,     0,     0,     0,     0,  1163,
       0,     0,     0,   816,   204,     0,     0,     0,   205,   206,
       0,     0,     0,     0,     0,   159,     0,     0,   825,   826,
     160,   676,     0,  1164,     0,     0,     0,     0,   162,     0,
     827,   163,     0,   210,   164,   165,     0,     0,     0,   166,
       0,     0,   167,     0,   168,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,   169,
     170,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,   902,   903,   904,   905,   906,   907,
       0,     0,     0,     0,   908,     0,     0,     0,   887,     0,
       0,     0,     0,     0,     0,   818,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     179,   180,   181,   182,   183,   184,   185,   186,   187,   188,
     189,   190,   191,   192,   193,   194,   195,   196,   197,   198,
     199,   200,     0,     0,   201,   809,     0,     0,     0,     0,
       0,     0,     0,     0,   819,     0,     0,   820,   821,     0,
       0,     0,     0,     0,     0,  1205,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,   150,   151,   152,
     153,     0,     0,     0,     0,   909,   202,   203,     0,   910,
       0,     0,   823,   824,   911,     0,     0,     0,     0,     0,
     912,     0,     0,     0,   816,   204,     0,     0,     0,   205,
     206,     0,     0,  1205,   809,     0,   913,     0,     0,   825,
     826,   914,   676,     0,   915,     0,     0,     0,     0,   916,
       0,   827,   917,     0,   210,   918,   919,     0,     0,     0,
     920,     0,     0,   921,     0,   922,   150,   151,   152,   153,
       0,     0,     0,     0,   909,     0,     0,     0,   910,     0,
       0,     0,   809,   911,     0,     0,     0,     0,     0,   912,
     923,   924,     0,   816,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,   913,     0,     0,     0,     0,
     914,     0,     0,   915,   150,   151,   152,   153,   916,     0,
       0,   917,   909,     0,   918,   919,   910,     0,     0,   920,
       0,   911,   921,     0,   922,     0,     0,   912,     0,     0,
       0,   816,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,   913,     0,     0,     0,     0,   914,   923,
     924,   915,     0,     0,     0,     0,   916,     0,     0,   917,
       0,     0,   918,   919,     0,   819,     0,   920,   820,   821,
     921,     0,   922,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,   923,   924,     0,
       0,     0,     0,   823,   824,     0,   925,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     825,   826,     0,     0,   819,     0,     0,   820,   821,     0,
     319,     0,   926,     0,     0,   210,   948,   887,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,   823,   824,     0,   925,     0,     0,     0,     0,
       0,     0,   819,     0,     0,   820,   821,     0,     0,     0,
       0,     0,     0,     0,   809,     0,     0,     0,     0,   825,
     826,     0,     0,     0,     0,     0,     0,     0,     0,   319,
       0,   926,     0,     0,   210,     0,     0,     0,     0,     0,
     823,   824,     0,   925,     0,     0,   150,   151,   152,   153,
       0,     0,     0,     0,   909,     0,     0,     0,   910,     0,
       0,     0,     0,   911,     0,     0,     0,   825,   826,   912,
       0,     0,     0,   816,     0,     0,     0,     0,     0,   926,
       0,     0,   210,     0,     0,   913,     0,     0,     0,     0,
     914,     0,     0,   915,     0,     0,     0,     0,   916,     0,
       0,   917,     0,   146,   918,   919,     0,     0,     0,   920,
     147,   148,   921,     0,   922,   288,   149,   289,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,   290,     0,     0,     0,     0,     0,     0,   923,
     924,     0,   291,   292,     0,     0,     0,   293,     0,     0,
     294,     0,     0,     0,     0,     0,     0,     0,   295,   296,
     297,   298,   299,   300,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,   301,     0,   302,
       0,     0,   150,   151,   152,   153,     0,     0,   154,     0,
     155,     0,     0,     0,   156,     0,     0,     0,     0,   157,
       0,     0,     0,     0,     0,   158,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,   159,     0,     0,   819,     0,   160,   820,   821,   161,
       0,     0,     0,     0,   162,     0,     0,   163,     0,     0,
     164,   165,     0,     0,     0,   166,     0,     0,   167,     0,
     168,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,   823,   824,     0,   925,     0,     0,     0,     0,
       0,     0,     0,     0,     0,   169,   170,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,   825,
     826,     0,     0,     0,     0,     0,     0,     0,     0,   949,
       0,   926,     0,     0,   210,     0,     0,     0,     0,     0,
       0,   171,   172,   173,   174,     0,     0,     0,     0,     0,
     175,   176,     0,     0,   177,   178,   303,   180,   181,   182,
     183,   184,   185,   186,   187,   188,   189,   190,   191,   192,
     193,   194,   195,   196,   197,   198,   199,   200,     0,     0,
     304,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,   146,     0,   305,     0,     0,     0,     0,
     147,   148,     0,     0,     0,   306,   149,     0,     0,     0,
       0,   307,     0,     0,     0,     0,   308,     0,     0,     0,
       0,     0,   202,   203,     0,   309,     0,     0,   310,   311,
     312,   313,     0,     0,   670,   314,     0,     0,     0,   315,
     316,   204,     0,     0,     0,   205,   206,     0,     0,     0,
       0,     0,     0,     0,   317,     0,     0,   207,   208,     0,
       0,   671,     0,   318,   672,   319,     0,   209,     0,     0,
     210,     0,   150,   151,   152,   153,     0,     0,   154,     0,
     155,   673,     0,     0,   156,     0,     0,     0,     0,   157,
       0,     0,     0,     0,     0,   158,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,   159,     0,     0,     0,     0,   160,     0,     0,   161,
       0,     0,     0,     0,   162,     0,     0,   163,     0,     0,
     164,   165,     0,     0,     0,   166,     0,     0,   167,     0,
     168,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,   169,   170,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,   180,   181,
     182,   183,   184,   185,   186,   187,   188,   189,   190,   191,
     192,   193,   194,   195,   196,   197,   198,   199,   200,     0,
       0,   171,   172,   173,   174,     0,     0,     0,     0,     0,
     175,   176,     0,     0,   177,   178,   179,   180,   181,   182,
     183,   184,   185,   186,   187,   188,   189,   190,   191,   192,
     193,   194,   195,   196,   197,   198,   199,   200,     0,   674,
     201,   146,     0,   202,   203,     0,     0,     0,   147,   148,
       0,     0,     0,   675,   149,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,   676,
       0,     0,   202,   203,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,   204,     0,     0,  2051,   205,   206,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,   207,   208,     0,
     150,   151,   152,   153,     0,   319,   154,   209,   155,     0,
     210,     0,   156,     0,     0,     0,     0,   157,     0,     0,
       0,     0,     0,   158,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,   159,
       0,     0,     0,     0,   160,     0,     0,   161,     0,     0,
       0,     0,   162,     0,     0,   163,     0,     0,   164,   165,
       0,     0,     0,   166,     0,     0,   167,     0,   168,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     146,     0,     0,   169,   170,     0,     0,   147,   148,     0,
       0,     0,     0,   149,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,   171,
     172,   173,   174,     0,     0,     0,     0,     0,   175,   176,
       0,     0,   177,   178,   179,   180,   181,   182,   183,   184,
     185,   186,   187,   188,   189,   190,   191,   192,   193,   194,
     195,   196,   197,   198,   199,   200,     0,     0,   201,   150,
     151,   152,   153,     0,     0,   154,     0,   155,     0,     0,
       0,   156,     0,     0,     0,     0,   157,     0,     0,     0,
       0,     0,   158,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,   159,     0,
     202,   203,     0,   160,     0,     0,   161,     0,     0,     0,
       0,   162,     0,     0,   163,     0,     0,   164,   165,   204,
       0,     0,   166,   205,   206,   167,     0,   168,     0,     0,
       0,     0,     0,     0,     0,   207,   208,     0,     0,     0,
       0,     0,     0,     0,     0,   209,     0,     0,   210,   146,
       0,     0,   169,   170,     0,     0,     0,   148,     0,     0,
       0,     0,   149,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,   171,   172,
     173,   174,     0,     0,     0,     0,   809,   175,   176,     0,
       0,   177,   178,   179,   180,   181,   182,   183,   184,   185,
     186,   187,   188,   189,   190,   191,   192,   193,   194,   195,
     196,   197,   198,   199,   200,     0,     0,   201,   150,   151,
     152,   153,     0,     0,   154,     0,   812,     0,     0,     0,
     813,     0,     0,     0,     0,   814,     0,     0,     0,     0,
       0,  1163,     0,     0,     0,   816,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,   159,     0,   202,
     203,     0,   160,     0,     0,  1164,     0,     0,     0,     0,
     162,     0,     0,   163,     0,     0,   164,   165,   204,     0,
       0,   166,   205,   206,   167,     0,   168,     0,     0,     0,
       0,     0,     0,     0,   207,   208,     0,     0,     0,     0,
       0,     0,     0,     0,   209,     0,     0,   210,     0,     0,
       0,   169,   170,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     887,     0,     0,     0,     0,     0,     0,   818,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,   179,   180,   181,   182,   183,   184,   185,   186,
     187,   188,   189,   190,   191,   192,   193,   194,   195,   196,
     197,   198,   199,   200,     0,     0,   201,   809,     0,     0,
       0,     0,     0,     0,     0,     0,   819,     0,     0,   820,
     821,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,   150,
     151,   152,   153,     0,     0,     0,     0,   909,   202,   203,
       0,   910,     0,     0,   823,   824,   911,     0,     0,     0,
       0,     0,   912,     0,     0,     0,   816,   204,     0,     0,
       0,   205,   206,     0,     0,     0,     0,     0,   913,     0,
       0,   825,   826,   914,   676,     0,   915,     0,     0,     0,
       0,   916,     0,   827,   917,     0,   210,   918,   919,     0,
       2,     3,   920,     0,     4,   921,     5,   922,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     6,     7,     8,     9,
       0,     0,   923,   924,     0,     0,     0,    10,     0,     0,
       0,     0,     0,     0,     0,    11,     0,    12,     0,    13,
       0,     0,    14,    15,    16,     0,    17,     0,     0,     0,
      18,    19,    20,     0,    21,    22,    23,    24,    25,    26,
      27,    28,    29,    30,    31,    32,    33,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,  -395,     0,     0,     0,     0,     0,    34,
       0,     0,     0,     0,     0,     0,     0,   819,     0,    35,
     820,   821,     0,     0,     0,    36,     0,     0,     0,   809,
       0,     0,     0,     0,     0,     0,     0,   295,   296,   297,
    1756,  1757,   300,     0,     0,     0,     0,     0,     0,    37,
       0,     0,     0,     0,     0,   823,   824,     0,   925,     0,
       0,   150,   151,   152,   153,     0,     0,     0,     0,   909,
       0,     0,     0,   910,     0,     0,     0,   809,   911,     0,
       0,     0,   825,   826,   912,     0,     0,     0,   816,     0,
       0,     0,   319,     0,   926,     0,     0,   210,     0,     0,
     913,     0,     0,     0,     0,   914,     0,     0,   915,   150,
     151,   152,   153,   916,     0,     0,   917,   909,     0,   918,
     919,   910,     0,     0,   920,     0,   911,   921,     0,   922,
       0,     0,   912,     0,     0,     0,   816,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,   913,     0,
       0,     0,     0,   914,   923,   924,   915,     0,     0,     0,
       0,   916,     0,     0,   917,     0,     0,   918,   919,     0,
      38,     0,   920,     0,     0,   921,     0,   922,     0,     0,
       0,   809,     0,     0,     0,    39,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,    40,   923,   924,     0,     0,    41,     0,    42,     0,
       0,     0,     0,  1577,   151,   152,   153,     0,     0,     0,
       0,   909,     0,     0,     0,   910,     0,     0,     0,     0,
     911,     0,     0,     0,     0,     0,   912,     0,     0,   819,
     816,     0,   820,   821,     0,     0,     0,     0,     0,     0,
       0,     0,   913,     0,     0,   761,     0,   914,     0,     0,
     915,     0,     0,     0,     0,   916,     0,     0,   917,     0,
       0,   918,   919,     0,     0,     0,   920,   823,   824,   921,
     925,   922,   671,     0,     0,   672,     0,   819,     0,     0,
     820,   821,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,   673,     0,   825,   826,   923,   924,     0,     0,
       0,     0,     0,     0,     0,     0,   926,     0,     0,   210,
       0,     0,     0,     0,     0,   823,   824,     0,   925,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,   825,   826,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,   926,     0,     0,   210,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,   819,     0,     0,   820,   821,     0,     0,     0,   180,
     181,   182,   183,   184,   185,   186,   187,   188,   189,   190,
     191,   192,   193,   194,   195,   196,   197,   198,   199,   200,
       0,     0,     0,     0,     0,     0,     0,     0,     0,   823,
     824,     0,   925,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,   825,   826,     0,     0,
     674,     0,     0,     0,   202,   203,     0,     0,   926,     0,
       0,   210,     0,     0,   675,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     676
};

static const yytype_int16 yycheck[] =
{
       1,    30,     3,   326,   322,   299,   412,    66,    52,   745,
     400,   368,   105,    30,   107,   477,   109,   110,     1,    63,
     113,    30,   115,   331,   402,   118,   119,   479,   401,   122,
     123,   124,   125,   403,    66,    52,   129,   443,   583,   132,
     133,   478,   920,    52,   347,    46,    63,   140,   205,   785,
      37,   488,   809,    54,    63,   638,   429,    58,   677,   922,
      36,   797,   432,   775,   288,   801,  1338,    32,  1338,   442,
     523,   782,   209,  1283,    52,   880,   399,  1345,  1342,  1206,
    1207,  1343,   924,   354,  1001,    63,  1213,  1344,  1153,  1282,
    1358,   383,   316,   368,  1337,  1338,  1193,    35,  1662,   407,
    1447,     7,     8,     9,  1447,  1501,   344,  1660,   346,  1451,
     641,  1661,   643,   524,   645,    30,   340,  1285,   827,   650,
    1432,  1433,   896,  1461,   894,   895,  1564,     4,   897,  1835,
     438,  1701,   900,     4,  1702,   898,    23,    52,    20,  1685,
       7,   552,    48,   762,    50,   368,  1639,    38,    63,   560,
      57,  1636,     7,    59,    22,     7,   379,   380,    64,     5,
     468,  1463,    68,    23,   575,     7,  1293,     7,    78,    79,
    1508,  1509,   102,   102,     7,   483,    23,   103,   104,    96,
     711,    45,    15,    16,    17,    18,    89,   749,   205,   751,
    1893,  1171,   209,    58,   103,   287,   205,    53,   126,   302,
     209,   179,   103,   104,   105,   113,   768,   769,   619,   771,
     742,   127,    13,  1130,  1131,   777,   778,   125,   629,   127,
     103,   103,   674,   744,   103,    84,   103,   104,   113,   745,
     287,   743,    84,   355,   102,   103,   152,   145,   360,   298,
     299,   149,     1,   979,   152,     4,   808,     6,   810,   701,
       8,    58,   355,   664,   103,   104,   105,    15,    16,    17,
      18,    84,  1179,   355,    22,   102,   104,    26,    27,    28,
      29,   702,    89,    89,    62,    92,    92,     5,  1471,  1472,
      49,   166,   167,  1621,  1622,    86,    49,    30,     7,   113,
     205,   256,  1562,    84,   209,   354,    54,   262,   355,  1637,
      30,    20,   125,   162,   210,   322,   103,     8,    84,    52,
      98,    57,   874,   322,    15,    16,    17,    18,     8,  1562,
      63,    22,    52,    47,     7,   303,   149,   235,   270,   113,
       4,     8,     6,    63,    24,   766,   368,    20,    15,    16,
      17,    18,   401,   285,   322,   355,   130,   379,   380,   125,
      89,   368,   396,    54,    32,    33,    34,   103,   286,   301,
     268,   269,   379,   380,    54,   125,   459,   411,   913,   401,
     429,   916,  1235,   149,   277,   304,   279,    54,   162,   396,
      45,    46,    89,   442,   946,   947,  1658,   396,  1658,   149,
    2093,  1634,   298,   299,   411,    84,   302,   429,   127,   159,
    1168,  1381,   411,  1646,   103,   288,   288,   322,   143,   288,
     442,   355,     8,   148,  1657,  1658,   360,   354,   396,    15,
      16,    17,    18,   152,   270,    15,    16,   251,   252,  1731,
     360,   338,   339,   411,   360,    89,  1172,  1173,   355,   285,
     348,   354,  1359,     1,   976,  1362,     4,  1234,     6,  1236,
     360,   360,    45,  2023,  2000,   301,  2024,   978,    54,   360,
     306,    89,   205,   979,   355,   977,   209,   304,    26,    27,
      28,    29,    57,   360,   326,   205,   341,   342,   343,   209,
      38,   396,  2188,   360,   352,   356,    76,    77,    78,   356,
     110,   355,   360,  1261,  1987,   355,   411,   739,   740,  1984,
     360,   356,    92,    93,    94,   125,   355,   413,   355,   132,
     356,   417,   102,   360,   356,   421,   356,  1955,   103,   152,
     426,   111,   112,   340,   340,   431,   359,   117,   287,   162,
     163,   322,   323,   324,   341,   342,   343,   840,   277,   236,
     279,  1315,   270,  1313,  1314,  1788,  2110,  1316,   138,   139,
    1259,   957,   142,  1891,  1317,  2108,    57,   285,  1954,  2109,
      57,  1729,  1479,  2056,  1481,  1482,  2051,  1484,  1880,   247,
     277,   333,   279,   301,  1105,   551,  1786,   355,   306,   322,
    1422,   340,  1035,   236,  1037,   823,   824,   574,   945,   349,
    1932,   497,   322,    57,  1941,   752,   270,   356,  1941,   537,
    1162,   359,   103,    84,  1166,    86,   103,  1470,   111,   112,
    1021,   285,   304,   305,  1176,  1177,  1178,     1,   775,  1181,
       4,  1183,     6,   277,   342,   279,   901,   301,   356,   900,
       8,  1758,   306,   322,   323,   324,    84,     8,    86,   103,
     294,  1203,    26,    27,    28,    29,   633,   334,   102,   277,
     337,   279,     7,   396,   630,  1752,  1753,  1520,   359,   143,
      84,   322,    86,   355,  1791,    20,   396,    22,   411,     1,
     945,   332,     4,   965,     6,   159,    54,  1239,     4,  1241,
       6,   411,   359,    54,  1877,  1247,   113,   925,   102,     4,
     145,     6,  1497,  1155,    26,    27,    28,    29,   102,  1764,
    1262,     1,  1264,   926,     4,    89,     6,   134,   286,  1161,
     110,  1273,    96,  1275,    38,    39,   775,  1453,   286,   286,
     147,  1158,   945,  1185,    39,   125,    26,    27,    28,    29,
     972,   973,   974,   170,   302,   752,  1523,   304,   305,  1526,
     141,  1951,  1529,   752,   247,   248,     7,   989,   251,   133,
     782,     1,  1189,   154,     4,   236,     6,    89,   775,    20,
     103,    22,   899,   359,    96,   782,   775,   286,  1221,   170,
    2038,  2035,   737,    30,  2036,    84,    26,    27,    28,    29,
    2037,    79,   340,   167,  1496,   128,   129,   125,   236,    89,
    1501,  1599,  1600,  1601,  1602,    52,    96,    95,   356,    77,
       1,   133,  1513,     4,     7,     6,    63,   145,   166,   167,
     827,   149,   236,   268,   269,   296,   114,    20,   165,    22,
    1737,   880,   134,   170,     4,    26,    27,    28,    29,    20,
     817,    22,   110,   133,  2106,   167,  2106,   752,   103,   815,
      41,   900,   340,    44,  1152,   220,   316,   125,   296,   224,
     225,   226,   102,  1564,   166,   167,  1439,   162,  1477,  1478,
     775,   185,  2105,  2106,   188,    17,   134,   167,   458,   901,
     297,    45,   296,  1811,  1812,  1813,  1814,   894,   895,   896,
     897,   898,   899,   162,   901,   197,    18,   271,  1350,   113,
     899,   359,   170,   348,  1456,  1457,   355,  1168,   166,   167,
    1352,   169,    52,  2030,   247,   495,   130,   287,   113,   926,
     115,   135,   136,   945,  1351,    52,   317,     1,   230,  1143,
       4,  1483,     6,   355,   267,   268,  1253,  1254,   945,   134,
     268,   269,     5,  1260,  1340,     8,  1498,   142,   143,   271,
     145,    57,    26,    27,    28,    29,   102,   103,   205,   950,
     155,   156,   209,   954,    38,  1312,   340,   113,   237,   238,
     239,   162,  1319,  1374,   102,   103,   111,   112,   113,  1886,
    1532,   271,   356,  1276,   355,   113,   254,    60,    61,  1896,
      12,   887,   355,    45,   899,   891,  1903,  1549,   115,  1551,
    1261,   296,   297,   298,   299,   300,   287,   288,    60,    61,
    1808,  1809,  1810,  2130,   131,   351,   352,  1418,   340,   752,
     348,     0,   236,    30,   355,     4,    30,     6,  1175,   355,
    1777,  1938,   752,    43,   356,   152,   109,  1965,  1966,  1967,
      45,   158,   775,   130,    45,    52,   119,   134,    52,    71,
     340,  1349,   125,    75,    45,   775,    63,   109,     7,    63,
     102,   103,    30,     8,   304,   305,   356,   119,    90,    91,
    1036,   113,  1038,   125,     5,   322,   149,     8,  1044,   166,
     167,   113,   113,   115,    52,    20,   108,    22,  1995,  1996,
    1997,   341,   342,   343,   285,    63,   127,   149,  1311,  1312,
     340,    22,   134,   134,    25,  1318,  1319,  1320,  1321,   103,
     142,   143,   144,   145,  2021,   137,   356,   300,  1691,  1168,
      30,   152,   144,   285,   361,   242,   243,   158,   290,   291,
      15,    16,     1,   361,  2002,     4,  1283,     6,  1285,   326,
     327,   328,    52,    46,   306,    48,   102,    50,    51,   396,
    2003,   304,   305,    63,   333,    58,    59,    26,    27,    28,
      29,   103,   104,   105,   411,   356,   899,  1475,  1175,  1721,
     333,    45,   231,    47,    15,    16,  1175,   350,    52,   899,
      54,   240,   241,   358,    58,   244,   245,    84,    91,   175,
       1,  1587,    23,     4,     1,     6,    23,     4,   205,     6,
      52,   205,   209,  1755,    52,   209,  1504,    52,  1609,    62,
      63,   102,  1261,   127,    67,    26,    27,    28,    29,    26,
      27,    28,    29,    97,    93,    99,   327,   328,  1780,   143,
      41,    15,    16,    44,    52,  1582,  1583,   205,   152,  1261,
       4,   209,     6,     7,   158,   159,  1253,  1254,  1255,  1256,
    1257,  1703,  1259,  1260,  1955,  1563,   219,   220,   221,   222,
     223,  1268,  1269,  1556,   133,  1558,   340,  2174,  2175,  2176,
    1175,    52,  1714,    85,    86,    87,  1283,    89,  1285,   304,
     305,  1708,   356,    84,  1283,   113,  1285,   115,   116,   117,
     118,  1743,   102,  1745,   103,   205,   103,   104,   105,   209,
     137,   138,   139,   140,  1311,  1312,  1313,  1314,  1315,  1316,
    1317,  1318,  1319,  1320,  1321,   322,   192,   193,   322,   190,
     191,  1748,    78,    79,    80,    81,    82,    83,   355,  1336,
      37,     1,   111,   112,     4,   103,     6,  1336,   106,   107,
     108,  1332,  1333,   102,  1335,  1336,  1337,  1338,   102,  1496,
     102,   162,  1650,   102,   322,    84,    26,    27,    28,    29,
    1333,   368,  1335,  1336,  1337,  1338,   111,   112,  1336,  1582,
    1583,    84,   379,   380,  1775,  1776,    17,  1778,  1283,    86,
    1285,   310,   311,   312,   313,   314,     4,     5,  2114,   396,
      18,     4,   396,     6,   359,     8,   103,  1949,  1696,     4,
       7,     6,   271,     8,   411,   111,   112,   411,     5,  1944,
    1945,   102,   322,     7,  1380,   215,   216,   217,   218,   102,
     103,   128,   129,  1803,   322,   323,   324,  2153,   396,    94,
      95,  1336,   102,     7,   321,     7,  1804,    97,    98,    99,
     100,   102,  1175,   411,     5,  1494,  1806,  1496,  1497,    45,
       7,  1428,  1429,     7,  1445,  1175,   355,  1448,    17,  1450,
    1426,  1427,  1453,    18,    60,    61,    43,    44,  1475,  1832,
     359,   340,  1445,  1757,   285,  1448,  1475,  1450,  1268,  1269,
    1453,  1515,     8,   102,     7,   102,   396,   356,  1801,  1496,
      38,  1513,   355,   355,  1501,  1858,   355,  1496,   355,   355,
     287,   411,   102,   302,   102,   752,  1513,  1475,  1515,   102,
      45,   102,   102,   109,   103,   355,  1515,   102,   102,   194,
      96,   189,   130,   119,  1515,    60,    61,   224,   775,   125,
     228,   227,   227,   340,   102,   229,   228,   102,   102,   102,
     247,     1,   334,     5,     4,   356,     6,  1515,    52,   356,
    1283,  1517,  1285,   149,     8,   102,  1563,  1564,   355,  1608,
     267,   268,   355,  1283,  1563,  1285,    26,    27,    28,    29,
    1475,   102,   355,   102,   109,  1582,  1583,   102,   285,    43,
    1981,   102,  1729,   102,   119,    22,   148,     5,   358,   102,
     125,  1496,    84,     8,   301,  1563,    84,    22,    22,   306,
    1619,   308,   102,  1336,   355,   358,  2058,   355,   355,  1917,
    1515,   102,  1619,     7,   149,  1606,  1336,  1636,  2060,   362,
    1619,   362,   288,  1614,  1615,  1616,  1617,  1618,     5,  1636,
     103,   355,  2059,    93,   304,   305,   303,  1636,    20,  1786,
     303,  1632,  1633,  1634,    43,   307,  2098,  2099,   189,  1656,
     287,   302,   899,  1644,  1645,  1646,     7,  1656,  1563,  2055,
      70,     5,   164,   102,  1655,  1656,  1657,  1658,   111,   112,
     340,     7,    39,   133,   103,    98,   354,   120,   121,   122,
     123,   124,  1655,  1656,  1657,  1658,   356,   103,  1656,   102,
       1,   189,    98,     4,   102,     6,   354,  1593,  1594,  1595,
    1596,  1692,  1693,  1694,   354,     7,    20,  1756,  1757,   102,
     102,   356,   102,   102,  1619,    26,    27,    28,    29,  1692,
    1693,  1694,  1729,   102,  2125,  2126,  2178,   102,    84,   356,
    1729,  1636,     5,   188,   102,   104,   150,   103,  2180,   102,
     354,   102,  1475,   102,   287,   752,   288,   102,   752,   185,
     356,  1656,  2179,   355,   355,  1475,   355,  2158,    41,  2057,
     355,     7,   133,  1496,   356,   102,     8,  2168,   775,   355,
     103,   775,   355,  2169,   355,   782,  1496,   355,     8,  1786,
    1771,   356,  1515,  1832,   752,   355,   355,  1786,   355,   355,
     102,     5,   103,   104,   105,  1515,   102,   355,   103,  2097,
       8,   102,  1885,   102,  1951,   354,   102,   775,   917,  1858,
    1832,   271,  1895,   923,   919,   918,  1865,   712,   714,  1902,
     713,   529,  1029,     1,  1729,   715,     4,  1367,     6,   519,
    1563,   921,    20,  1341,  1982,  1640,  1858,  1828,   398,  1830,
    1831,    45,   752,  1563,  2183,  2130,  1980,  2042,    26,    27,
      28,    29,  2044,  1844,  2043,  2045,    60,    61,  2034,  1850,
    1756,  1757,    89,  2155,  1595,   775,  1857,   395,    91,  1860,
    1791,   793,   802,   880,   308,  1866,  1744,   397,  1773,  2177,
     340,  1786,  1873,  1874,  1875,   863,  1619,   894,   895,   896,
     897,   898,   899,  1713,   901,   899,   356,  2033,  1746,  1619,
    1873,  1874,  1875,  1636,  2102,   109,  1255,  1257,  1274,  1256,
    1917,   883,  1494,  1020,  1281,   119,  1636,    45,  1917,   926,
    1496,   125,   776,  1656,  1321,   290,   892,   205,  1175,  1213,
    1476,   899,    60,    61,     1,   113,  1656,     4,   945,     6,
    1989,  1506,  1991,   409,  1951,   149,   368,  1511,  1955,  1917,
     380,   407,  1951,   410,   120,  1974,  2166,   379,   380,    26,
      27,    28,    29,    45,   408,  1984,   639,  1974,  1959,   303,
     617,  1083,   368,   304,   304,  1974,    -1,  1984,    60,    61,
      -1,   109,    -1,   379,   380,  1984,    -1,    -1,    -1,   899,
      -1,   119,    -1,    -1,    -1,    -1,  1729,   125,    -1,  1990,
      -1,  1992,    -1,    -1,    -1,    -1,    -1,   111,   112,  1729,
      -1,    -1,  1917,  2004,  2005,    -1,  2007,  2008,  2009,  2010,
    2011,   149,   126,  2014,   128,   129,   130,   109,    -1,   340,
      -1,    -1,  2051,    -1,    -1,    -1,  1283,   119,  1285,    -1,
      -1,    -1,    -1,   125,  2051,   356,  1951,   151,   152,   153,
      -1,    -1,  2051,  1786,    -1,    -1,    -1,    -1,    -1,    -1,
       1,  2052,    -1,     4,    -1,     6,  1786,   149,    -1,  1974,
    2061,  2062,    -1,    -1,    -1,    -1,    -1,    -1,    -1,  1984,
      -1,  2130,    -1,    -1,    -1,    26,    27,    28,    29,  1336,
      -1,    -1,    -1,   271,    -1,    -1,    -1,  2104,    -1,  2118,
      41,    -1,    -1,    44,  2153,  2104,    -1,    -1,    -1,    -1,
      -1,  2118,  2103,  2104,  2105,  2106,    -1,    -1,    -1,  2118,
    2111,  2112,  2113,  2114,    -1,  2116,    -1,    -1,    -1,  2120,
    2103,  2104,  2105,  2106,  2183,    -1,  2104,    -1,  2111,  2112,
    2113,  2114,    -1,    -1,    -1,  2136,  2051,    -1,    -1,    -1,
    2141,  2142,  2143,  2144,  2145,  2146,  2147,  2148,  2149,  2150,
    2151,  2152,   340,    -1,    -1,   111,   112,    -1,  1175,    -1,
      -1,  1175,    -1,  2146,  2147,  2148,  2167,    -1,   356,   125,
      -1,    -1,    -1,    -1,  1917,    -1,    -1,   133,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,  1917,    -1,  2104,
    2191,  2192,  2193,   149,    -1,    -1,    -1,  1175,    -1,    -1,
      -1,    -1,     1,  2118,    -1,     4,    -1,     6,  1951,     1,
      -1,   162,     4,    -1,     6,    -1,  1233,  1234,  1475,  1236,
      -1,  1951,    -1,    -1,    -1,   302,    -1,    26,    27,    28,
      29,  1974,    -1,    -1,    26,    27,    28,    29,    -1,  1496,
      -1,  1984,    -1,    -1,  1974,    -1,    -1,    -1,     1,    41,
      -1,     4,    44,     6,  1984,  1175,    -1,    -1,  1515,    -1,
      -1,    -1,     1,   340,    -1,     4,  1283,     6,  1285,  1283,
      -1,  1285,    -1,    26,    27,    28,    29,    -1,    -1,   356,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    26,    27,    28,
      29,    -1,    -1,    -1,  1311,  1312,  1313,  1314,  1315,  1316,
    1317,  1318,  1319,  1320,  1321,  1283,  1563,  1285,  2051,    -1,
      10,    -1,  1209,    45,    -1,   271,   272,   273,   274,  1336,
       1,  2051,  1336,     4,    -1,     6,    -1,    -1,    60,    61,
      -1,   287,   288,   289,   285,    -1,    -1,    -1,    -1,    39,
      40,    41,    42,    -1,    -1,    26,    27,    28,    29,    -1,
     782,    -1,    -1,    -1,    93,    -1,    -1,    -1,  1336,    40,
      -1,  2104,  1619,  1283,     1,  1285,    -1,     4,    -1,     6,
     162,    -1,    -1,    73,  2104,  2118,   782,   109,    -1,  1636,
      -1,    81,    82,    83,    84,    -1,    -1,   119,  2118,    26,
      27,    28,    29,   125,   133,   827,    -1,    -1,    -1,  1656,
      -1,    -1,    -1,    40,   104,   356,    -1,    88,    89,    90,
      91,    -1,    93,    -1,    -1,    96,  1336,   149,    -1,    -1,
      -1,   121,    -1,    -1,    -1,    -1,   126,   127,   128,    -1,
      -1,   131,   113,    -1,   134,    -1,  1333,    -1,  1335,  1336,
    1337,  1338,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    88,    89,    90,    91,    -1,    93,    -1,  1475,    96,
      -1,  1475,   894,   895,   896,   897,   898,    -1,    -1,   901,
      -1,    -1,  1729,    -1,    -1,    -1,   113,  1494,    -1,  1496,
    1497,   162,  1496,    -1,  1501,    -1,    -1,    -1,   894,   895,
     896,   897,   898,   285,   926,   901,  1513,  1475,  1515,    -1,
      -1,  1515,    -1,   302,    -1,    -1,  1523,    -1,    -1,  1526,
      -1,    -1,  1529,   945,    -1,    -1,    -1,    -1,  1496,    -1,
     926,    -1,    -1,    -1,    -1,   162,    -1,    -1,    -1,  1786,
      -1,    -1,   271,    -1,   287,     1,    -1,  1515,     4,   945,
       6,   340,    -1,    -1,    -1,    -1,  1563,  1564,  1445,  1563,
      -1,  1448,    -1,  1450,    -1,  1475,  1453,   356,    -1,    -1,
      26,    27,    28,    29,   356,  1582,  1583,    -1,    -1,    -1,
      -1,   271,   272,   273,    -1,    -1,  1496,    -1,    -1,    -1,
      -1,    45,    -1,    -1,    -1,  1563,    -1,   340,    -1,   270,
      -1,    -1,    -1,    -1,    -1,  1515,    60,    61,    -1,    -1,
      -1,   340,  1619,   356,   285,  1619,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,  1511,    -1,    -1,   356,    -1,  1636,
     301,    23,  1636,    -1,    -1,   306,     1,    -1,    -1,     4,
      -1,     6,    -1,   270,    -1,    -1,    38,    -1,    -1,  1656,
      -1,  1619,  1656,  1563,    -1,   109,    -1,   113,   285,    -1,
      -1,    26,    27,    28,    29,   119,    -1,    -1,  1636,   340,
    1917,   125,    -1,    -1,   301,   107,    -1,   109,   110,   306,
      -1,   113,    -1,   115,    -1,   356,   118,   119,  1656,    -1,
     122,   123,   124,   125,    -1,   149,    -1,   129,    -1,    -1,
     132,   133,    -1,    -1,  1951,    -1,    -1,    -1,   140,  1619,
     102,    -1,    -1,   340,   404,   405,   406,    -1,    -1,    -1,
      -1,    -1,  1729,    -1,    -1,  1729,  1636,  1974,    -1,   356,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,  1984,    -1,    -1,
      -1,    37,    -1,    -1,    -1,    -1,  1656,   437,   113,    45,
      -1,    47,    -1,    49,    -1,    -1,    52,    53,    54,    -1,
      56,  1729,    -1,    -1,    60,    61,    -1,    -1,  1655,  1656,
    1657,  1658,    -1,    -1,    -1,    -1,   466,    -1,    -1,  1786,
      -1,   173,  1786,    -1,   176,   177,   178,   179,   180,   181,
     182,   183,   184,   185,   186,   187,   188,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,  2051,  1692,  1693,  1694,    -1,    -1,
      -1,    -1,    -1,   109,    -1,   271,    -1,    -1,  1786,  1729,
      -1,    -1,    -1,   119,    -1,    -1,    -1,    -1,    -1,   125,
      -1,  1253,  1254,  1255,  1256,  1257,    -1,  1259,  1260,    -1,
       1,    -1,    -1,     4,    37,     6,  1268,  1269,    -1,    -1,
      -1,    -1,    45,   149,    47,    -1,    49,  2104,    -1,    52,
      53,    54,    -1,    56,    -1,    26,    27,    28,    29,    -1,
      -1,  2118,    -1,    -1,    -1,    -1,  1786,    -1,    -1,    40,
      -1,    -1,    -1,    -1,   340,    -1,    -1,    -1,    -1,  1311,
    1312,  1313,  1314,  1315,  1316,  1317,  1318,  1319,  1320,  1321,
     356,    -1,    -1,    -1,    -1,    -1,   271,    -1,    -1,    -1,
    1917,    -1,    -1,  1917,    -1,  1311,  1312,  1313,  1314,  1315,
    1316,  1317,  1318,  1319,  1320,  1321,    -1,    88,    89,    90,
      91,    -1,    93,    -1,    -1,    96,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    37,  1951,    -1,    -1,  1951,  1955,  1917,
      -1,    45,   113,    47,    -1,    -1,    -1,    -1,    52,    53,
      54,    -1,    56,    -1,    -1,    -1,    -1,  1974,    -1,    -1,
    1974,    -1,    -1,    -1,   270,   340,    -1,  1984,    -1,    -1,
    1984,    -1,    -1,  1951,    -1,   134,  1873,  1874,  1875,   285,
      -1,   356,    -1,    -1,   143,    -1,    70,    -1,    -1,    -1,
      -1,   162,    -1,    -1,    -1,   301,  1974,  1917,    -1,   158,
     306,    -1,   308,   162,    -1,    -1,  1984,   166,   167,    -1,
      -1,    -1,   171,   172,   173,   174,   175,   459,    -1,   103,
     104,   105,    -1,    -1,    -1,    -1,   110,    -1,    -1,    -1,
     114,  1951,    -1,    -1,  2051,   119,    -1,  2051,    -1,    -1,
      -1,   125,    -1,    -1,    -1,   129,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,  1974,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,  1984,   149,    -1,   270,    -1,  1501,
      -1,    -1,    -1,  2051,    89,    -1,    -1,    -1,    -1,    -1,
      -1,  1513,   285,     1,    -1,    -1,     4,  2104,     6,    -1,
    2104,    -1,    -1,    -1,    -1,  1501,   111,   112,   301,   270,
     115,  2118,    -1,   306,  2118,   308,    -1,  1513,    26,    27,
      28,    29,    -1,    -1,   285,    -1,    -1,    -1,   133,    37,
      -1,    -1,    -1,    -1,    -1,    -1,  2104,    -1,    -1,    47,
     301,  2051,  1564,    -1,    52,   306,    54,    -1,    56,    -1,
    2118,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
    1582,  1583,    -1,    -1,    -1,    -1,    -1,    -1,  1564,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   270,    -1,    -1,   340,
      -1,    -1,    -1,    -1,   189,    -1,  1582,  1583,    -1,    -1,
      -1,   285,    -1,    -1,  2104,   356,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   280,   301,  2118,   283,
     284,    -1,   306,    -1,   308,    -1,  2103,  2104,  2105,  2106,
       1,    -1,    -1,    -1,  2111,  2112,  2113,  2114,    -1,    -1,
      11,    12,    13,    14,    15,    16,    17,    -1,    -1,    20,
      -1,    -1,   247,    -1,   318,   319,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   162,    -1,    -1,    -1,    -1,  2146,
    2147,  2148,    -1,    -1,    -1,    -1,   271,   272,   273,   274,
     275,   276,   277,   278,   279,   280,   281,   282,   283,   284,
      -1,    -1,   287,   288,   289,    -1,   360,    -1,    -1,    -1,
      71,    -1,    -1,    74,    75,    76,    77,    78,    79,    -1,
      -1,    -1,    -1,   308,    -1,    86,    -1,    88,    89,    90,
      91,    92,    93,    94,    95,    -1,    97,    98,    99,   100,
      -1,   102,    -1,    -1,    -1,   106,    -1,   108,    -1,    -1,
     111,   112,    38,   114,    -1,    -1,   117,    -1,    -1,    -1,
      -1,    -1,    -1,     1,    -1,    -1,     4,    -1,     6,    -1,
      -1,    -1,    -1,    -1,    -1,   136,   137,   138,   139,    -1,
      -1,   142,   270,   144,    -1,    -1,    -1,    -1,    26,    27,
      28,    29,    -1,    -1,    -1,    -1,    -1,   285,    -1,    -1,
      -1,    -1,    40,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   301,    -1,    -1,   102,    -1,   306,    -1,
     308,    -1,    37,    -1,    -1,    -1,    -1,    42,    -1,    -1,
      45,    46,    47,    48,    -1,    -1,    51,    52,    -1,    54,
      55,    56,    -1,    58,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    89,   340,    91,    -1,    93,    -1,    -1,    96,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   356,    -1,
      -1,    -1,    -1,    -1,    -1,   113,    -1,    -1,    -1,    -1,
      -1,    -1,    97,    -1,    99,   100,   101,   173,    -1,    -1,
     176,   177,   178,   179,   180,   181,   182,   183,   184,   185,
     186,   187,   188,    -1,    -1,     1,    -1,    -1,     4,    -1,
       6,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   162,    -1,    -1,    23,    -1,    -1,
      26,    27,    28,    29,    30,    31,    -1,    -1,    -1,    35,
      36,    37,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,  1955,    -1,    -1,    52,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    62,    63,    -1,    -1,
      -1,    67,    -1,    -1,    70,    -1,    -1,    -1,    -1,  1955,
      -1,    -1,    78,    79,    80,    81,    82,    83,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    93,    -1,    -1,
      -1,    97,    -1,    99,    -1,    -1,   102,   103,   104,   105,
      -1,    -1,   108,    -1,   110,    -1,    -1,   113,   114,    -1,
     111,   112,    -1,   119,   115,    -1,    -1,    -1,    -1,   125,
      -1,    -1,   270,    -1,    -1,   126,   127,   128,   129,   130,
     131,   132,   133,   134,    -1,   141,    -1,   285,    -1,    -1,
     146,    -1,    -1,   149,    -1,   270,    -1,    -1,   154,    -1,
      -1,   157,    -1,   301,   160,   161,   162,    -1,   306,   165,
     285,    -1,   168,    -1,   170,   290,   291,   292,   293,    -1,
      -1,    -1,    -1,    -1,   175,    -1,   301,    -1,    -1,    -1,
     451,   306,    -1,   308,   309,    -1,    -1,   458,    -1,   195,
     196,    -1,   340,    -1,    -1,    -1,    -1,    -1,   469,    -1,
     471,    -1,   473,    -1,   475,    -1,    -1,    -1,   356,   480,
      -1,    -1,    -1,   484,    -1,   486,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   495,   231,   232,   233,   234,    -1,
      -1,    -1,    -1,    -1,   240,   241,    -1,    -1,   244,   245,
     246,   247,   248,   249,   250,   251,   252,   253,   254,   255,
     256,   257,   258,   259,   260,   261,   262,   263,   264,   265,
     266,   267,    -1,    -1,   270,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   285,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   295,
      -1,    -1,    -1,    -1,    -1,   301,    -1,    -1,    -1,    -1,
     306,    -1,    -1,    -1,    -1,    -1,   312,   313,    -1,   315,
      -1,    -1,   318,   319,   320,   321,    -1,    -1,    -1,   325,
      -1,    -1,    -1,   329,   330,   331,    -1,    -1,    -1,   335,
     336,    -1,    -1,    -1,   340,    -1,    -1,    -1,   344,    -1,
       1,   347,   348,     4,    -1,     6,    -1,   353,    -1,   355,
     356,   357,    -1,    -1,   360,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    23,    -1,    -1,    26,    27,    28,    29,    30,
      31,    -1,    -1,    -1,    35,    36,    37,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    52,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    62,    63,    -1,    -1,    -1,    67,    -1,    -1,    70,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    78,    79,    80,
      81,    82,    83,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    93,    -1,    -1,    -1,    97,    -1,    99,    -1,
      -1,   102,   103,   104,   105,    -1,    -1,   108,    -1,   110,
      -1,    -1,   113,   114,    -1,    -1,    -1,    -1,   119,    -1,
      -1,    -1,    -1,    -1,   125,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
     141,    -1,    -1,    -1,    -1,   146,    -1,    -1,   149,    -1,
      -1,    -1,    -1,   154,    -1,    -1,   157,    -1,    -1,   160,
     161,   162,    -1,    -1,   165,    -1,    -1,   168,    -1,   170,
      -1,     1,    -1,    -1,     4,    -1,     6,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   195,   196,    26,    27,    28,    29,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    37,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    47,    -1,    -1,
      -1,    -1,    52,    -1,    54,    -1,    56,    -1,    -1,    -1,
     231,   232,   233,   234,    -1,    -1,    -1,    -1,    -1,   240,
     241,    -1,    -1,   244,   245,   246,   247,   248,   249,   250,
     251,   252,   253,   254,   255,   256,   257,   258,   259,   260,
     261,   262,   263,   264,   265,   266,   267,    -1,    -1,   270,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   285,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   295,    -1,    -1,    -1,    -1,    -1,
     301,    -1,    -1,    -1,    -1,   306,    -1,    -1,    -1,    -1,
      -1,   312,   313,    -1,   315,    -1,    -1,   318,   319,   320,
     321,    -1,    -1,    -1,   325,    -1,    -1,    -1,   329,   330,
     331,    -1,   162,    -1,   335,   336,    -1,    -1,    -1,   340,
      -1,    -1,    -1,   344,    -1,     1,   347,   348,     4,    -1,
       6,    -1,   353,    -1,   355,   356,   357,    -1,    -1,   360,
     111,   112,    -1,    -1,   115,    -1,    -1,    23,    -1,    -1,
      26,    27,    28,    29,    30,    31,    -1,    -1,    -1,    35,
      36,    37,   133,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,  1002,    -1,    -1,    -1,    -1,    52,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    62,    63,    -1,    -1,
      -1,    67,    -1,    -1,    70,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    78,    79,    80,    81,    82,    83,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    93,    -1,    -1,
     270,    97,    -1,    99,    -1,    -1,   102,   103,   104,   105,
      -1,    -1,   108,    -1,   110,   285,     1,   113,   114,     4,
      -1,     6,    -1,   119,    -1,    -1,    -1,    -1,    -1,   125,
      -1,   301,    -1,    -1,    -1,    -1,   306,    -1,   308,    -1,
      -1,    26,    27,    28,    29,   141,    -1,    -1,    -1,    -1,
     146,    -1,    -1,   149,    -1,    40,   247,    -1,   154,    -1,
      -1,   157,    -1,    -1,   160,   161,   162,    -1,    -1,   165,
     340,    -1,   168,    -1,   170,    -1,    -1,    -1,    -1,    -1,
     271,   272,   273,   274,   275,   276,   356,   278,   279,   280,
     281,   282,   283,   284,    -1,    -1,   287,   288,   289,   195,
     196,    -1,    -1,    -1,    89,    -1,    91,    -1,    93,    -1,
      -1,    96,    -1,    -1,    -1,    -1,    -1,   308,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   113,    -1,
      -1,    -1,    -1,    -1,    -1,   231,   232,   233,   234,    -1,
      -1,    -1,    -1,    -1,   240,   241,    -1,    -1,   244,   245,
     246,   247,   248,   249,   250,   251,   252,   253,   254,   255,
     256,   257,   258,   259,   260,   261,   262,   263,   264,   265,
     266,   267,    -1,    -1,   270,    -1,    -1,   162,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   285,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   295,
      -1,    -1,    -1,    -1,    -1,   301,    -1,    -1,    -1,    -1,
     306,    -1,    -1,    -1,    -1,    -1,   312,   313,    -1,   315,
      -1,    -1,   318,   319,   320,   321,    -1,    -1,    -1,   325,
      -1,    -1,    -1,   329,   330,   331,     4,    -1,     6,   335,
     336,    -1,    -1,    -1,   340,    -1,    -1,    -1,   344,    -1,
      -1,   347,   348,    -1,    -1,    23,    -1,   353,    -1,   355,
     356,   357,    30,    31,   360,    -1,    -1,    35,    36,    37,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    52,   270,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    62,    63,    -1,    -1,    -1,    67,
     285,    -1,    70,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      78,    79,    80,    81,    82,    83,   301,    -1,    -1,    -1,
      -1,   306,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    97,
      -1,    99,    -1,    -1,   102,   103,   104,   105,    -1,    -1,
     108,    -1,   110,    -1,    -1,    -1,   114,    -1,    -1,    -1,
      -1,   119,    -1,    -1,    -1,   340,    -1,   125,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,   356,    -1,   141,    -1,    -1,    -1,    -1,   146,    -1,
      -1,   149,    -1,    -1,    -1,   180,   154,    -1,    -1,   157,
      -1,    -1,   160,   161,    -1,    -1,    -1,   165,    -1,    -1,
     168,    -1,   170,   198,   199,   200,   201,   202,   203,   204,
     205,   206,   207,   208,   209,   210,   211,   212,   213,   214,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,   195,   196,    -1,
       1,    -1,    -1,     4,    -1,     6,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    26,    27,    28,    29,    -1,
      -1,    -1,    -1,   231,   232,   233,   234,    -1,    -1,    40,
      -1,    -1,   240,   241,    -1,    -1,   244,   245,   246,   247,
     248,   249,   250,   251,   252,   253,   254,   255,   256,   257,
     258,   259,   260,   261,   262,   263,   264,   265,   266,   267,
      -1,    -1,   270,    -1,    -1,     5,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,   285,    89,    -1,
      91,    -1,    93,    23,    -1,    96,    -1,   295,    -1,    -1,
      -1,    31,    -1,   301,    -1,    -1,    36,    -1,   306,    -1,
      -1,    -1,   113,    -1,   312,   313,    -1,   315,    -1,    -1,
     318,   319,   320,   321,    -1,    -1,    -1,   325,    -1,    -1,
      -1,   329,   330,   331,    -1,    -1,    -1,   335,   336,    -1,
      70,    -1,    -1,    -1,    -1,    -1,   344,    -1,    -1,   347,
     348,    -1,    -1,    -1,    84,   353,    86,   355,   356,   357,
      -1,   162,   360,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,   102,   103,   104,   105,    -1,    -1,   108,    -1,
     110,    -1,    -1,    -1,   114,    -1,    -1,    -1,    -1,   119,
      -1,    -1,    -1,    -1,    -1,   125,    -1,    -1,    -1,   129,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,   141,    -1,    -1,    -1,    -1,   146,    -1,    -1,   149,
      -1,    -1,    -1,    -1,   154,    -1,    -1,   157,    -1,    -1,
     160,   161,    -1,    -1,    -1,   165,    -1,    -1,   168,    -1,
     170,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,   195,   196,    -1,    -1,   270,
      -1,    -1,    -1,    -1,    -1,    -1,     5,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   285,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    23,    -1,    -1,    -1,    -1,    -1,
     301,   231,    31,    -1,    -1,   306,    -1,    36,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   246,   247,   248,   249,
     250,   251,   252,   253,   254,   255,   256,   257,   258,   259,
     260,   261,   262,   263,   264,   265,   266,   267,    -1,   340,
     270,    70,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
     280,    -1,    -1,   283,   284,   356,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   296,    -1,    -1,    -1,
      -1,    -1,    -1,   102,   103,   104,   105,    -1,    -1,   108,
      -1,   110,   312,   313,    -1,   114,    -1,    -1,   318,   319,
     119,    -1,    -1,    -1,    -1,    -1,   125,    -1,    -1,    -1,
     129,   331,    -1,    -1,    -1,   335,   336,    -1,    -1,    -1,
      -1,    -1,   141,    -1,    -1,   345,   346,   146,   348,    -1,
     149,    -1,    -1,    -1,    -1,   154,    -1,   357,   157,    -1,
     360,   160,   161,    -1,    -1,    -1,   165,    -1,    -1,   168,
      -1,   170,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   195,   196,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,     5,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    23,    -1,    -1,    -1,    -1,
      -1,    -1,   231,    31,    -1,    -1,    -1,    -1,    36,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,   246,   247,   248,
     249,   250,   251,   252,   253,   254,   255,   256,   257,   258,
     259,   260,   261,   262,   263,   264,   265,   266,   267,    -1,
      -1,   270,    70,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,   280,    -1,    -1,   283,   284,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   102,   103,   104,   105,    -1,    -1,
     108,    -1,   110,   312,   313,    -1,   114,    -1,    -1,   318,
     319,   119,    -1,    -1,    -1,    -1,    -1,   125,    -1,    -1,
      -1,   129,   331,    -1,    -1,    -1,   335,   336,    -1,    -1,
      -1,    -1,    -1,   141,    -1,    -1,   345,   346,   146,   348,
      -1,   149,    -1,    -1,    -1,    -1,   154,    -1,   357,   157,
      -1,   360,   160,   161,    -1,    -1,    -1,   165,    -1,    -1,
     168,    -1,   170,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,   195,   196,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,     5,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    23,    -1,    -1,    -1,
      -1,    -1,    -1,   231,    31,    -1,    -1,    -1,    -1,    36,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   246,   247,
     248,   249,   250,   251,   252,   253,   254,   255,   256,   257,
     258,   259,   260,   261,   262,   263,   264,   265,   266,   267,
      -1,    -1,   270,    70,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,   280,    -1,    -1,   283,   284,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,   102,   103,   104,   105,    -1,
      -1,   108,    -1,   110,   312,   313,    -1,   114,    -1,    -1,
     318,   319,   119,    -1,    -1,    -1,    -1,    -1,   125,    -1,
      -1,    -1,   129,   331,    -1,    -1,    -1,   335,   336,    -1,
      -1,    -1,    -1,    -1,   141,    -1,    -1,   345,   346,   146,
     348,    -1,   149,    -1,    -1,    -1,    -1,   154,    -1,   357,
     157,    -1,   360,   160,   161,    -1,    -1,    -1,   165,    -1,
      -1,   168,    -1,   170,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   195,   196,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,     5,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    23,    -1,    -1,
      -1,    -1,    -1,    -1,   231,    31,    -1,    -1,    -1,    -1,
      36,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   246,
     247,   248,   249,   250,   251,   252,   253,   254,   255,   256,
     257,   258,   259,   260,   261,   262,   263,   264,   265,   266,
     267,    -1,    -1,   270,    70,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   280,    -1,    -1,   283,   284,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   102,   103,   104,   105,
      -1,    -1,   108,    -1,   110,   312,   313,    -1,   114,    -1,
      -1,   318,   319,   119,    -1,    -1,    -1,    -1,    -1,   125,
      -1,    -1,    -1,   129,   331,    -1,    -1,    -1,   335,   336,
      -1,    -1,    -1,    -1,    -1,   141,    -1,    -1,   345,   346,
     146,   348,    -1,   149,    -1,    -1,    -1,    -1,   154,    -1,
     357,   157,    -1,   360,   160,   161,    -1,    -1,    -1,   165,
      -1,    -1,   168,    -1,   170,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   195,
     196,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,     9,    10,    11,    12,    13,    14,
      -1,    -1,    -1,    -1,    19,    -1,    -1,    -1,    23,    -1,
      -1,    -1,    -1,    -1,    -1,   231,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
     246,   247,   248,   249,   250,   251,   252,   253,   254,   255,
     256,   257,   258,   259,   260,   261,   262,   263,   264,   265,
     266,   267,    -1,    -1,   270,    70,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   280,    -1,    -1,   283,   284,    -1,
      -1,    -1,    -1,    -1,    -1,    21,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,   102,   103,   104,
     105,    -1,    -1,    -1,    -1,   110,   312,   313,    -1,   114,
      -1,    -1,   318,   319,   119,    -1,    -1,    -1,    -1,    -1,
     125,    -1,    -1,    -1,   129,   331,    -1,    -1,    -1,   335,
     336,    -1,    -1,    21,    70,    -1,   141,    -1,    -1,   345,
     346,   146,   348,    -1,   149,    -1,    -1,    -1,    -1,   154,
      -1,   357,   157,    -1,   360,   160,   161,    -1,    -1,    -1,
     165,    -1,    -1,   168,    -1,   170,   102,   103,   104,   105,
      -1,    -1,    -1,    -1,   110,    -1,    -1,    -1,   114,    -1,
      -1,    -1,    70,   119,    -1,    -1,    -1,    -1,    -1,   125,
     195,   196,    -1,   129,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,   141,    -1,    -1,    -1,    -1,
     146,    -1,    -1,   149,   102,   103,   104,   105,   154,    -1,
      -1,   157,   110,    -1,   160,   161,   114,    -1,    -1,   165,
      -1,   119,   168,    -1,   170,    -1,    -1,   125,    -1,    -1,
      -1,   129,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   141,    -1,    -1,    -1,    -1,   146,   195,
     196,   149,    -1,    -1,    -1,    -1,   154,    -1,    -1,   157,
      -1,    -1,   160,   161,    -1,   280,    -1,   165,   283,   284,
     168,    -1,   170,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,   195,   196,    -1,
      -1,    -1,    -1,   318,   319,    -1,   321,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
     345,   346,    -1,    -1,   280,    -1,    -1,   283,   284,    -1,
     355,    -1,   357,    -1,    -1,   360,    22,    23,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,   318,   319,    -1,   321,    -1,    -1,    -1,    -1,
      -1,    -1,   280,    -1,    -1,   283,   284,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    70,    -1,    -1,    -1,    -1,   345,
     346,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   355,
      -1,   357,    -1,    -1,   360,    -1,    -1,    -1,    -1,    -1,
     318,   319,    -1,   321,    -1,    -1,   102,   103,   104,   105,
      -1,    -1,    -1,    -1,   110,    -1,    -1,    -1,   114,    -1,
      -1,    -1,    -1,   119,    -1,    -1,    -1,   345,   346,   125,
      -1,    -1,    -1,   129,    -1,    -1,    -1,    -1,    -1,   357,
      -1,    -1,   360,    -1,    -1,   141,    -1,    -1,    -1,    -1,
     146,    -1,    -1,   149,    -1,    -1,    -1,    -1,   154,    -1,
      -1,   157,    -1,    23,   160,   161,    -1,    -1,    -1,   165,
      30,    31,   168,    -1,   170,    35,    36,    37,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    52,    -1,    -1,    -1,    -1,    -1,    -1,   195,
     196,    -1,    62,    63,    -1,    -1,    -1,    67,    -1,    -1,
      70,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    78,    79,
      80,    81,    82,    83,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    97,    -1,    99,
      -1,    -1,   102,   103,   104,   105,    -1,    -1,   108,    -1,
     110,    -1,    -1,    -1,   114,    -1,    -1,    -1,    -1,   119,
      -1,    -1,    -1,    -1,    -1,   125,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,   141,    -1,    -1,   280,    -1,   146,   283,   284,   149,
      -1,    -1,    -1,    -1,   154,    -1,    -1,   157,    -1,    -1,
     160,   161,    -1,    -1,    -1,   165,    -1,    -1,   168,    -1,
     170,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,   318,   319,    -1,   321,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,   195,   196,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   345,
     346,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   355,
      -1,   357,    -1,    -1,   360,    -1,    -1,    -1,    -1,    -1,
      -1,   231,   232,   233,   234,    -1,    -1,    -1,    -1,    -1,
     240,   241,    -1,    -1,   244,   245,   246,   247,   248,   249,
     250,   251,   252,   253,   254,   255,   256,   257,   258,   259,
     260,   261,   262,   263,   264,   265,   266,   267,    -1,    -1,
     270,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    23,    -1,   285,    -1,    -1,    -1,    -1,
      30,    31,    -1,    -1,    -1,   295,    36,    -1,    -1,    -1,
      -1,   301,    -1,    -1,    -1,    -1,   306,    -1,    -1,    -1,
      -1,    -1,   312,   313,    -1,   315,    -1,    -1,   318,   319,
     320,   321,    -1,    -1,   103,   325,    -1,    -1,    -1,   329,
     330,   331,    -1,    -1,    -1,   335,   336,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   344,    -1,    -1,   347,   348,    -1,
      -1,   130,    -1,   353,   133,   355,    -1,   357,    -1,    -1,
     360,    -1,   102,   103,   104,   105,    -1,    -1,   108,    -1,
     110,   150,    -1,    -1,   114,    -1,    -1,    -1,    -1,   119,
      -1,    -1,    -1,    -1,    -1,   125,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,   141,    -1,    -1,    -1,    -1,   146,    -1,    -1,   149,
      -1,    -1,    -1,    -1,   154,    -1,    -1,   157,    -1,    -1,
     160,   161,    -1,    -1,    -1,   165,    -1,    -1,   168,    -1,
     170,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,   195,   196,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   247,   248,
     249,   250,   251,   252,   253,   254,   255,   256,   257,   258,
     259,   260,   261,   262,   263,   264,   265,   266,   267,    -1,
      -1,   231,   232,   233,   234,    -1,    -1,    -1,    -1,    -1,
     240,   241,    -1,    -1,   244,   245,   246,   247,   248,   249,
     250,   251,   252,   253,   254,   255,   256,   257,   258,   259,
     260,   261,   262,   263,   264,   265,   266,   267,    -1,   308,
     270,    23,    -1,   312,   313,    -1,    -1,    -1,    30,    31,
      -1,    -1,    -1,   322,    36,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   348,
      -1,    -1,   312,   313,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,   331,    -1,    -1,    86,   335,   336,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,   347,   348,    -1,
     102,   103,   104,   105,    -1,   355,   108,   357,   110,    -1,
     360,    -1,   114,    -1,    -1,    -1,    -1,   119,    -1,    -1,
      -1,    -1,    -1,   125,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   141,
      -1,    -1,    -1,    -1,   146,    -1,    -1,   149,    -1,    -1,
      -1,    -1,   154,    -1,    -1,   157,    -1,    -1,   160,   161,
      -1,    -1,    -1,   165,    -1,    -1,   168,    -1,   170,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      23,    -1,    -1,   195,   196,    -1,    -1,    30,    31,    -1,
      -1,    -1,    -1,    36,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   231,
     232,   233,   234,    -1,    -1,    -1,    -1,    -1,   240,   241,
      -1,    -1,   244,   245,   246,   247,   248,   249,   250,   251,
     252,   253,   254,   255,   256,   257,   258,   259,   260,   261,
     262,   263,   264,   265,   266,   267,    -1,    -1,   270,   102,
     103,   104,   105,    -1,    -1,   108,    -1,   110,    -1,    -1,
      -1,   114,    -1,    -1,    -1,    -1,   119,    -1,    -1,    -1,
      -1,    -1,   125,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   141,    -1,
     312,   313,    -1,   146,    -1,    -1,   149,    -1,    -1,    -1,
      -1,   154,    -1,    -1,   157,    -1,    -1,   160,   161,   331,
      -1,    -1,   165,   335,   336,   168,    -1,   170,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,   347,   348,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,   357,    -1,    -1,   360,    23,
      -1,    -1,   195,   196,    -1,    -1,    -1,    31,    -1,    -1,
      -1,    -1,    36,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   231,   232,
     233,   234,    -1,    -1,    -1,    -1,    70,   240,   241,    -1,
      -1,   244,   245,   246,   247,   248,   249,   250,   251,   252,
     253,   254,   255,   256,   257,   258,   259,   260,   261,   262,
     263,   264,   265,   266,   267,    -1,    -1,   270,   102,   103,
     104,   105,    -1,    -1,   108,    -1,   110,    -1,    -1,    -1,
     114,    -1,    -1,    -1,    -1,   119,    -1,    -1,    -1,    -1,
      -1,   125,    -1,    -1,    -1,   129,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,   141,    -1,   312,
     313,    -1,   146,    -1,    -1,   149,    -1,    -1,    -1,    -1,
     154,    -1,    -1,   157,    -1,    -1,   160,   161,   331,    -1,
      -1,   165,   335,   336,   168,    -1,   170,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   347,   348,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   357,    -1,    -1,   360,    -1,    -1,
      -1,   195,   196,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      23,    -1,    -1,    -1,    -1,    -1,    -1,   231,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,   246,   247,   248,   249,   250,   251,   252,   253,
     254,   255,   256,   257,   258,   259,   260,   261,   262,   263,
     264,   265,   266,   267,    -1,    -1,   270,    70,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   280,    -1,    -1,   283,
     284,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   102,
     103,   104,   105,    -1,    -1,    -1,    -1,   110,   312,   313,
      -1,   114,    -1,    -1,   318,   319,   119,    -1,    -1,    -1,
      -1,    -1,   125,    -1,    -1,    -1,   129,   331,    -1,    -1,
      -1,   335,   336,    -1,    -1,    -1,    -1,    -1,   141,    -1,
      -1,   345,   346,   146,   348,    -1,   149,    -1,    -1,    -1,
      -1,   154,    -1,   357,   157,    -1,   360,   160,   161,    -1,
       0,     1,   165,    -1,     4,   168,     6,   170,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    26,    27,    28,    29,
      -1,    -1,   195,   196,    -1,    -1,    -1,    37,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    45,    -1,    47,    -1,    49,
      -1,    -1,    52,    53,    54,    -1,    56,    -1,    -1,    -1,
      60,    61,    62,    -1,    64,    65,    66,    67,    68,    69,
      70,    71,    72,    73,    74,    75,    76,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   103,    -1,    -1,    -1,    -1,    -1,   109,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,   280,    -1,   119,
     283,   284,    -1,    -1,    -1,   125,    -1,    -1,    -1,    70,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    78,    79,    80,
      81,    82,    83,    -1,    -1,    -1,    -1,    -1,    -1,   149,
      -1,    -1,    -1,    -1,    -1,   318,   319,    -1,   321,    -1,
      -1,   102,   103,   104,   105,    -1,    -1,    -1,    -1,   110,
      -1,    -1,    -1,   114,    -1,    -1,    -1,    70,   119,    -1,
      -1,    -1,   345,   346,   125,    -1,    -1,    -1,   129,    -1,
      -1,    -1,   355,    -1,   357,    -1,    -1,   360,    -1,    -1,
     141,    -1,    -1,    -1,    -1,   146,    -1,    -1,   149,   102,
     103,   104,   105,   154,    -1,    -1,   157,   110,    -1,   160,
     161,   114,    -1,    -1,   165,    -1,   119,   168,    -1,   170,
      -1,    -1,   125,    -1,    -1,    -1,   129,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   141,    -1,
      -1,    -1,    -1,   146,   195,   196,   149,    -1,    -1,    -1,
      -1,   154,    -1,    -1,   157,    -1,    -1,   160,   161,    -1,
     270,    -1,   165,    -1,    -1,   168,    -1,   170,    -1,    -1,
      -1,    70,    -1,    -1,    -1,   285,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,   301,   195,   196,    -1,    -1,   306,    -1,   308,    -1,
      -1,    -1,    -1,   102,   103,   104,   105,    -1,    -1,    -1,
      -1,   110,    -1,    -1,    -1,   114,    -1,    -1,    -1,    -1,
     119,    -1,    -1,    -1,    -1,    -1,   125,    -1,    -1,   280,
     129,    -1,   283,   284,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,   141,    -1,    -1,   103,    -1,   146,    -1,    -1,
     149,    -1,    -1,    -1,    -1,   154,    -1,    -1,   157,    -1,
      -1,   160,   161,    -1,    -1,    -1,   165,   318,   319,   168,
     321,   170,   130,    -1,    -1,   133,    -1,   280,    -1,    -1,
     283,   284,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,   150,    -1,   345,   346,   195,   196,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   357,    -1,    -1,   360,
      -1,    -1,    -1,    -1,    -1,   318,   319,    -1,   321,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,   345,   346,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   357,    -1,    -1,   360,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,   280,    -1,    -1,   283,   284,    -1,    -1,    -1,   247,
     248,   249,   250,   251,   252,   253,   254,   255,   256,   257,
     258,   259,   260,   261,   262,   263,   264,   265,   266,   267,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   318,
     319,    -1,   321,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   345,   346,    -1,    -1,
     308,    -1,    -1,    -1,   312,   313,    -1,    -1,   357,    -1,
      -1,   360,    -1,    -1,   322,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
     348
};

/* YYSTOS[STATE-NUM] -- The symbol kind of the accessing symbol of
   state STATE-NUM.  */
static const yytype_int16 yystos[] =
{
       0,   364,     0,     1,     4,     6,    26,    27,    28,    29,
      37,    45,    47,    49,    52,    53,    54,    56,    60,    61,
      62,    64,    65,    66,    67,    68,    69,    70,    71,    72,
      73,    74,    75,    76,   109,   119,   125,   149,   270,   285,
     301,   306,   308,   365,   418,   419,   420,   421,   493,   494,
     495,   497,   512,   365,   104,   103,   490,   490,   490,   495,
     506,   495,   497,   512,   495,   500,   500,   500,   495,   503,
     421,    49,   422,    37,    45,    47,    52,    53,    54,    56,
     270,   285,   301,   306,   308,   423,    49,   424,    37,    45,
      47,    49,    52,    53,    54,    56,   270,   285,   301,   306,
     308,   429,    53,   430,    37,    42,    45,    46,    47,    48,
      51,    52,    54,    55,    56,    58,    97,    99,   100,   101,
     270,   285,   290,   291,   292,   293,   301,   306,   308,   309,
     431,   285,   290,   291,   306,   434,    45,    47,    52,    54,
      58,    97,    99,   435,    47,   436,    23,    30,    31,    36,
     102,   103,   104,   105,   108,   110,   114,   119,   125,   141,
     146,   149,   154,   157,   160,   161,   165,   168,   170,   195,
     196,   231,   232,   233,   234,   240,   241,   244,   245,   246,
     247,   248,   249,   250,   251,   252,   253,   254,   255,   256,
     257,   258,   259,   260,   261,   262,   263,   264,   265,   266,
     267,   270,   312,   313,   331,   335,   336,   347,   348,   357,
     360,   444,   491,   615,   616,   619,   620,   621,   625,   688,
     691,   693,   697,   702,   703,   705,   707,   717,   718,   720,
     722,   724,   726,   730,   732,   734,   736,   738,   740,   742,
     744,   746,   748,   759,   767,   769,   771,   772,   774,   776,
     778,   780,   782,   784,   786,   788,    58,   341,   342,   343,
     437,   443,    58,   438,   443,   103,   439,   440,   368,   384,
     385,    89,   277,   279,   506,   506,   506,   506,     0,   365,
     490,   490,    57,   338,   339,   509,   510,   511,    35,    37,
      52,    62,    63,    67,    70,    78,    79,    80,    81,    82,
      83,    97,    99,   246,   270,   285,   295,   301,   306,   315,
     318,   319,   320,   321,   325,   329,   330,   344,   353,   355,
     516,   517,   518,   520,   521,   522,   523,   524,   525,   526,
     530,   531,   532,   535,   536,   543,   547,   555,   556,   559,
     560,   561,   562,   563,   584,   585,   587,   588,   590,   591,
     594,   595,   596,   606,   607,   608,   609,   610,   613,   614,
     620,   627,   628,   629,   630,   631,   632,   636,   637,   638,
     672,   686,   691,   692,   715,   716,   717,   749,   365,   354,
     354,   365,   490,   567,   445,   448,   516,   490,   453,   455,
     615,   638,   458,   490,   463,   497,   513,   506,   495,   497,
     500,   500,   500,   503,    89,   277,   279,   506,   506,   506,
     506,   512,   428,   495,   506,   507,   425,   493,   495,   496,
     426,   495,   497,   498,   513,   427,   495,   500,   501,   500,
     500,   495,   503,   504,    89,   277,   279,   661,   428,   428,
     428,   428,   500,   506,   433,   494,   515,   495,   515,   497,
     515,    45,   515,   500,   500,   515,   503,   515,    45,    46,
     500,   515,   515,    89,   277,   294,   661,   662,   506,    45,
     515,    45,   515,    45,   515,    45,   515,   506,   506,   506,
      45,   515,   391,   506,    45,   515,    45,   515,   506,   403,
     495,   497,   500,   500,   515,    45,   500,   497,   103,   106,
     107,   108,   719,   111,   112,   247,   248,   251,   623,   624,
      32,    33,    34,   247,   694,   132,   626,   166,   167,   770,
     111,   112,   113,   721,   113,   115,   116,   117,   118,   723,
     111,   112,   120,   121,   122,   123,   124,   725,   111,   112,
     115,   126,   127,   128,   129,   130,   131,   132,   133,   134,
     175,   727,   113,   115,   134,   142,   143,   144,   145,   731,
     113,   134,   147,   297,   733,   111,   112,   126,   128,   129,
     130,   151,   152,   153,   735,   113,   115,   134,   142,   143,
     145,   155,   156,   737,   127,   143,   152,   158,   159,   739,
     143,   159,   741,   152,   162,   163,   743,   130,   134,   166,
     167,   745,   134,   166,   167,   169,   747,   134,   143,   158,
     162,   166,   167,   171,   172,   173,   174,   175,   750,   113,
     166,   167,   760,   134,   166,   167,   197,   230,   768,   113,
     125,   127,   145,   149,   152,   235,   268,   269,   348,   704,
     706,   775,   236,   777,   236,   779,   162,   237,   238,   239,
     781,   127,   152,   773,   115,   131,   152,   158,   242,   243,
     783,   127,   152,   785,   113,   127,   134,   152,   158,   787,
     103,   130,   133,   150,   308,   322,   348,   689,   690,   691,
     111,   112,   115,   133,   247,   271,   272,   273,   274,   275,
     276,   278,   279,   280,   281,   282,   283,   284,   287,   288,
     289,   308,   708,   709,   712,   322,   332,   696,   632,   637,
     333,   231,   240,   241,   244,   245,   789,   351,   352,   390,
     699,   631,   490,   409,   443,   342,   389,   443,   378,   395,
      46,    48,    50,    51,    58,    59,    91,   441,   506,   506,
     506,   372,   656,   671,   658,   660,   102,   102,   102,    84,
     704,   286,   607,   170,   490,   615,   687,   687,    62,    98,
     490,   103,   689,    89,   189,   277,   708,   709,   286,   286,
     302,   286,   304,   305,   544,    84,   162,    84,    84,   704,
     103,     4,   366,   639,   640,   340,   514,   521,   417,   448,
     372,   287,   288,   533,   534,   415,   162,   296,   297,   298,
     299,   300,   537,   538,   402,   316,   558,   396,     5,    70,
      84,    86,   110,   114,   119,   125,   129,   149,   231,   280,
     283,   284,   296,   318,   319,   345,   346,   357,   570,   571,
     572,   573,   574,   575,   576,   578,   579,   580,   581,   582,
     583,   616,   619,   625,   681,   682,   683,   688,   693,   697,
     703,   704,   705,   707,   713,   714,   717,   410,   416,    38,
      39,   185,   188,   564,   565,   396,    84,   322,   323,   324,
     586,   592,   593,   396,    84,   589,   592,   375,   381,   401,
     326,   327,   328,   597,   598,   602,   603,    23,   615,   617,
     618,    45,   611,   612,    15,    16,    17,    18,   359,     8,
      24,    54,     9,    10,    11,    12,    13,    14,    19,   110,
     114,   119,   125,   141,   146,   149,   154,   157,   160,   161,
     165,   168,   170,   195,   196,   321,   357,   616,   618,   619,
     633,   634,   635,   638,   673,   674,   675,   676,   677,   678,
     679,   680,   682,   683,   684,   685,    52,    52,    22,   355,
     654,   673,   674,   679,   654,    38,   355,   566,   355,   355,
     355,   355,   355,   509,   516,   567,   445,   448,   453,   455,
     458,   463,   506,   506,   506,   372,   656,   671,   658,   660,
     516,   416,    57,    57,    57,    57,   455,    57,   463,   506,
     372,   392,   400,   407,   455,   416,    43,   432,   495,   500,
     515,   506,    45,   372,   495,   495,   495,   495,   392,   400,
     407,   495,   372,   495,   495,   400,   500,   490,   412,     7,
       8,   113,   251,   252,   622,   300,   408,   103,   126,   286,
     412,   411,   377,   411,   386,   110,   125,   110,   125,   368,
     137,   138,   139,   140,   728,   384,   411,   387,   411,   388,
     385,   411,   387,   367,   376,   370,   413,   414,    23,    38,
     102,   173,   176,   177,   178,   179,   180,   181,   182,   183,
     184,   185,   186,   187,   188,   751,   752,   753,   411,   373,
     180,   198,   199,   200,   201,   202,   203,   204,   205,   206,
     207,   208,   209,   210,   211,   212,   213,   214,   761,   766,
     405,   411,   384,   385,   390,   706,   404,   404,   361,   404,
     404,   361,   404,   383,   380,   374,   411,   394,   393,   407,
     393,   407,   111,   112,   125,   133,   149,   271,   272,   273,
     710,   711,   712,   371,   333,   333,   102,   404,   383,   380,
     374,   394,   350,   698,   358,   442,   443,   669,   669,   669,
     287,   355,   655,   302,   355,   670,   355,   544,   657,   355,
     491,   659,     5,   125,   149,   582,    84,   582,   604,   605,
     632,   175,    23,    23,    96,   355,    52,    52,    52,   102,
     304,    52,   712,    52,   582,   582,   304,   305,   548,   582,
     102,   599,   600,   601,   615,   619,   632,   636,   697,   703,
     602,   582,   582,    84,   103,    21,   638,   643,   644,   645,
     652,   679,   680,     7,   356,   491,   355,   102,   102,   534,
      77,   110,   125,   170,   254,   540,   491,   102,   102,   102,
     491,   539,   538,   141,   154,   170,   317,   582,   403,     5,
     582,    84,   377,   386,   368,   384,   385,    84,   396,   396,
     575,   616,   683,    15,    16,    17,    18,   359,    20,    22,
       8,    54,     5,   592,    84,    86,   236,   296,     7,     7,
     102,   102,   565,     5,     7,     5,   582,   600,   615,   619,
     598,     7,   490,   355,   490,   355,   612,   684,   684,   675,
     676,   677,   631,   355,   527,   617,   674,   384,   387,   385,
     387,   367,   376,   370,   413,   414,   409,   373,   405,   396,
     679,     7,    20,    15,    16,    17,    18,   359,     7,    20,
      22,     8,   673,   674,   679,   582,   582,   102,   356,   365,
      20,   365,   102,   478,   416,   447,   449,   454,   460,   464,
     566,   355,   355,   355,   355,   355,   669,   669,   669,   655,
     670,   657,   659,   102,   102,   102,   102,   102,   355,   669,
     103,   371,   495,   102,   624,   411,   379,   102,   398,   398,
     377,   384,   377,   384,   113,   130,   135,   136,   236,   384,
     729,   369,    96,   757,   189,   755,   194,   758,   192,   193,
     756,   190,   191,   754,   130,   220,   224,   225,   226,   765,
     215,   216,   217,   218,   763,   219,   220,   221,   222,   223,
     764,   764,   224,   227,   227,   228,   229,   228,   113,   130,
     162,   762,   406,   404,   102,   102,   111,   112,   111,   112,
     371,   371,   102,   102,   334,   695,   102,   159,   349,   700,
     704,   355,   355,   355,   102,   471,   372,   548,   476,   392,
     472,   102,   400,   477,   407,   582,     5,     5,   582,   617,
      89,    92,   514,   646,   647,    38,   173,   178,   188,   752,
     753,   491,   491,   102,   632,   641,   642,   582,   582,   582,
     371,   102,   582,    52,   582,   392,   102,   550,   552,   553,
     400,   103,   288,   545,    22,   401,    84,   326,    43,   582,
     366,     5,   366,   270,   285,   301,   649,   650,    89,    92,
     514,   648,   651,   366,   640,   450,   377,   148,   143,   148,
     541,   542,   103,   113,   557,   619,   113,   557,   409,   113,
     557,   582,     5,   582,   582,   358,   570,   570,   571,   572,
     573,   102,   575,   570,   577,   617,   638,   582,   582,    84,
       8,    84,   616,   683,   713,   713,   582,   593,   582,   592,
     603,   369,   604,   641,   366,   528,   529,   358,   679,   673,
     679,   684,   684,   675,   676,   677,   679,   102,   673,   679,
     635,   679,    20,    20,   102,    39,   365,   356,   365,   418,
     514,   566,    37,    47,    52,    54,    56,   162,   270,   285,
     301,   306,   308,   356,   365,   418,   446,   514,    93,   113,
     162,   356,   365,   418,   480,   486,   487,   514,   516,    40,
      88,    89,    90,    91,    93,    96,   113,   162,   270,   356,
     365,   418,   461,   514,   519,   520,    40,    89,    91,   113,
     162,   356,   365,   418,   461,   514,   519,    41,    44,   162,
     285,   356,   365,   418,   416,   447,   449,   454,   460,   464,
     355,   355,   355,   372,   392,   400,   407,   464,   371,   371,
       7,   408,   411,   384,   753,   411,   405,   362,   362,   384,
     384,   385,   385,   695,   337,   695,   102,   382,   390,   111,
     112,   701,   474,   475,   473,   288,   356,   365,   418,   514,
     655,   550,   552,   356,   365,   418,   514,   670,   356,   365,
     418,   514,   657,   545,   356,   365,   418,   514,   659,   582,
     582,     5,   103,   492,   492,   647,   409,   369,   369,   355,
     521,   646,   393,   393,   371,   371,   371,   582,   371,    20,
     103,   288,   303,   549,   303,   551,    20,   307,   546,   599,
     615,   619,   601,   600,   582,    43,    81,    82,   653,   680,
     686,   189,   287,   372,   302,   650,   492,   492,   651,   356,
     365,   516,   384,     7,   409,   557,   557,    70,   557,   582,
       5,   582,   164,   582,   592,   592,     5,   356,   519,   521,
     643,     7,   356,   673,   673,   102,    39,   416,   490,   508,
     490,   499,   490,   502,   502,   490,   505,   103,    89,   277,
     279,   508,   508,   508,   508,   365,    78,    79,   488,   489,
     615,   411,    98,   365,   365,   365,   365,   365,   452,   620,
     492,   492,   354,    94,    95,   462,   102,   103,   128,   129,
     247,   267,   268,   468,   469,   479,    85,    86,    87,    89,
     456,   457,   365,   365,   365,   520,   452,   492,   354,   469,
     456,   365,   365,   365,   103,   354,    98,   372,   356,   356,
     356,   356,   356,   474,   475,   473,   356,   102,     7,   397,
     102,   382,   390,    93,   133,   271,   356,   365,   418,   514,
     667,    89,    96,   133,   167,   271,   356,   365,   418,   514,
     668,   113,   271,   356,   365,   418,   514,   664,   102,   372,
     549,   551,   392,   400,   546,   407,   582,   641,   356,   371,
     310,   311,   312,   313,   314,   554,   102,   392,   102,   553,
     392,   554,   102,   400,   401,   401,   582,   366,   102,   304,
     102,   548,   365,   542,   411,   411,   403,   411,   582,    84,
     604,     5,   356,   356,     5,   366,   529,   188,   568,   102,
     470,   448,   453,   458,   463,   508,   508,   508,   470,   470,
     470,   470,   399,   103,     8,   365,   365,   365,   455,   399,
       8,   365,     7,   365,     5,   365,   455,     5,   365,   150,
     481,   355,   465,   615,   365,   356,   356,   356,   369,   102,
     695,   354,   165,   170,   663,   494,   371,   492,   102,   663,
     102,   494,   371,   104,   494,   371,   521,   287,   103,   545,
     371,   102,   288,   550,   552,   387,   387,   582,   356,   604,
     686,   185,   569,   365,   355,   355,   355,   355,   355,   470,
     470,   470,   355,   355,   355,   355,    41,   620,   468,   411,
     457,    86,   451,   452,   620,    37,    86,   285,   301,   306,
     308,   459,   469,    22,   102,   103,   352,   482,   483,   484,
     615,   365,   103,   104,   466,   467,   615,   365,   371,   371,
     371,     7,   382,   355,   413,   409,   365,   365,   365,   365,
     365,   365,   365,   133,   365,   356,   371,   102,   549,   551,
     356,   366,   568,   478,   449,   454,   460,   464,   355,   355,
     355,   471,   476,   472,   477,   103,   452,   365,     8,   416,
     469,   372,   392,   400,   407,   365,   365,   102,    22,    25,
       7,   356,   102,   103,   665,   666,   663,   372,   392,   392,
     569,   356,   356,   356,   356,   356,   474,   475,   473,   356,
     356,   356,   356,    43,    44,   485,   365,   620,   365,   411,
     411,   102,   102,   366,   467,     5,     7,   356,   365,   365,
     365,   365,   365,   365,   356,   356,   356,   365,   365,   365,
     365,   491,   615,   354,   481,   411,   102,   666,   365,   411,
     416,   371,   371,   371,   372,   392,   400,   407,   465,   399,
     365,   365,   365
};

/* YYR1[RULE-NUM] -- Symbol kind of the left-hand side of rule RULE-NUM.  */
static const yytype_int16 yyr1[] =
{
       0,   363,   364,   364,   365,   365,   366,   366,   367,   368,
     369,   370,   371,   372,   373,   374,   375,   376,   377,   378,
     379,   380,   381,   382,   383,   384,   385,   386,   387,   388,
     389,   390,   391,   392,   393,   394,   395,   396,   397,   398,
     399,   400,   401,   402,   403,   404,   405,   406,   407,   408,
     409,   410,   411,   412,   413,   414,   415,   416,   417,   418,
     418,   418,   418,   418,   419,   419,   419,   419,   420,   420,
     420,   420,   420,   420,   420,   420,   420,   420,   420,   420,
     420,   420,   420,   421,   421,   421,   421,   421,   421,   421,
     421,   421,   421,   421,   421,   421,   421,   421,   421,   421,
     421,   421,   421,   421,   421,   421,   421,   422,   423,   423,
     423,   423,   423,   423,   423,   423,   423,   423,   423,   423,
     423,   423,   423,   423,   423,   424,   425,   425,   426,   426,
     427,   427,   428,   428,   429,   429,   429,   429,   429,   429,
     429,   429,   429,   429,   429,   429,   429,   429,   429,   430,
     431,   431,   431,   431,   431,   431,   431,   431,   431,   431,
     431,   431,   431,   431,   431,   431,   431,   431,   431,   431,
     431,   431,   431,   431,   431,   431,   431,   431,   431,   431,
     431,   431,   431,   431,   432,   433,   433,   434,   434,   434,
     434,   434,   434,   435,   435,   435,   435,   435,   435,   435,
     436,   437,   437,   438,   438,   439,   440,   440,   441,   441,
     441,   441,   441,   441,   441,   441,   442,   442,   443,   443,
     443,   444,   445,   446,   446,   447,   447,   447,   447,   447,
     447,   447,   447,   447,   447,   447,   447,   447,   447,   447,
     447,   448,   449,   449,   449,   449,   449,   449,   449,   449,
     450,   450,   450,   451,   451,   452,   452,   453,   454,   454,
     454,   454,   454,   454,   454,   454,   454,   454,   454,   454,
     454,   455,   455,   456,   456,   457,   457,   457,   457,   458,
     459,   459,   459,   459,   459,   460,   460,   460,   460,   460,
     460,   460,   460,   460,   460,   460,   460,   460,   460,   461,
     461,   462,   462,   463,   464,   464,   464,   464,   464,   464,
     464,   465,   465,   466,   466,   466,   467,   467,   467,   468,
     468,   469,   469,   470,   471,   471,   471,   471,   471,   472,
     472,   472,   472,   472,   473,   473,   473,   473,   473,   474,
     474,   474,   474,   474,   475,   475,   475,   475,   475,   476,
     476,   476,   476,   476,   477,   477,   477,   477,   477,   478,
     478,   478,   478,   478,   479,   479,   479,   479,   479,   480,
     481,   482,   482,   483,   483,   483,   483,   483,   484,   484,
     485,   485,   485,   485,   486,   487,   488,   488,   489,   489,
     490,   491,   491,   491,   492,   493,   493,   494,   494,   494,
     494,   494,   494,   495,   496,   497,   498,   499,   500,   501,
     502,   503,   504,   505,   506,   507,   508,   509,   510,   511,
     512,   512,   512,   512,   513,   514,   515,   515,   516,   516,
     517,   518,   518,   519,   519,   520,   520,   520,   520,   521,
     521,   521,   521,   521,   521,   521,   521,   521,   521,   521,
     521,   521,   521,   521,   521,   521,   521,   521,   521,   521,
     521,   522,   523,   523,   524,   525,   525,   526,   527,   527,
     528,   528,   528,   529,   530,   530,   531,   531,   532,   532,
     533,   533,   534,   534,   535,   535,   536,   537,   537,   538,
     538,   538,   538,   538,   538,   539,   540,   540,   540,   540,
     540,   541,   541,   542,   542,   543,   543,   543,   544,   544,
     544,   545,   545,   546,   546,   547,   547,   548,   548,   548,
     549,   549,   550,   551,   551,   552,   552,   553,   553,   554,
     554,   554,   554,   554,   555,   556,   557,   557,   558,   558,
     558,   558,   558,   558,   558,   558,   559,   560,   560,   561,
     561,   561,   561,   561,   561,   562,   562,   563,   563,   564,
     564,   565,   565,   565,   565,   566,   566,   567,   568,   568,
     569,   569,   570,   570,   570,   570,   570,   570,   570,   570,
     570,   570,   570,   570,   570,   571,   571,   571,   572,   572,
     573,   573,   574,   574,   575,   576,   576,   577,   577,   578,
     578,   579,   580,   581,   581,   582,   582,   582,   583,   583,
     583,   583,   583,   583,   583,   583,   583,   583,   583,   583,
     583,   583,   584,   584,   585,   586,   586,   586,   587,   587,
     588,   589,   589,   589,   589,   589,   590,   590,   591,   591,
     592,   592,   593,   593,   593,   594,   594,   594,   594,   595,
     595,   596,   597,   597,   598,   598,   599,   599,   600,   600,
     600,   601,   601,   601,   601,   602,   602,   603,   603,   604,
     604,   605,   606,   606,   606,   607,   607,   607,   608,   608,
     609,   609,   610,   611,   611,   612,   613,   613,   614,   615,
     616,   616,   617,   617,   618,   619,   620,   620,   620,   620,
     620,   620,   620,   620,   620,   620,   620,   620,   620,   620,
     620,   621,   622,   622,   622,   623,   623,   623,   623,   623,
     624,   624,   625,   625,   626,   626,   627,   627,   627,   628,
     628,   629,   629,   630,   630,   631,   632,   632,   633,   634,
     635,   635,   636,   637,   637,   637,   638,   639,   639,   639,
     640,   640,   640,   641,   641,   642,   643,   643,   644,   644,
     645,   645,   646,   646,   647,   647,   647,   648,   648,   649,
     649,   650,   650,   650,   650,   650,   650,   651,   651,   651,
     652,   653,   653,   654,   654,   654,   654,   655,   656,   657,
     658,   659,   660,   661,   661,   661,   662,   662,   662,   663,
     663,   664,   664,   665,   665,   666,   667,   667,   667,   668,
     668,   668,   668,   668,   669,   670,   670,   671,   672,   672,
     672,   672,   672,   672,   672,   672,   673,   673,   674,   674,
     674,   675,   675,   675,   676,   676,   677,   677,   678,   678,
     679,   680,   680,   680,   680,   681,   681,   682,   683,   683,
     683,   683,   683,   683,   683,   683,   683,   683,   683,   683,
     684,   684,   684,   684,   684,   684,   684,   684,   684,   684,
     684,   684,   684,   684,   684,   684,   684,   685,   685,   685,
     685,   685,   685,   685,   686,   686,   686,   686,   686,   686,
     687,   687,   688,   688,   688,   689,   689,   690,   690,   690,
     690,   690,   691,   691,   691,   691,   691,   691,   691,   691,
     691,   691,   691,   691,   691,   691,   691,   691,   691,   691,
     691,   691,   691,   691,   691,   691,   692,   692,   692,   692,
     692,   692,   693,   693,   694,   694,   694,   695,   695,   696,
     696,   697,   698,   698,   699,   699,   700,   700,   701,   701,
     702,   702,   703,   703,   703,   704,   704,   705,   705,   706,
     706,   706,   706,   707,   707,   707,   708,   708,   709,   709,
     709,   709,   709,   709,   709,   709,   709,   709,   709,   709,
     709,   709,   709,   709,   709,   710,   710,   710,   710,   710,
     710,   710,   711,   711,   711,   711,   712,   712,   712,   712,
     713,   713,   714,   714,   715,   715,   715,   715,   716,   717,
     717,   717,   717,   717,   717,   717,   717,   717,   717,   717,
     717,   717,   717,   717,   717,   717,   717,   718,   719,   719,
     719,   719,   720,   721,   721,   721,   722,   723,   723,   723,
     723,   723,   724,   725,   725,   725,   725,   725,   725,   725,
     725,   725,   726,   726,   726,   727,   727,   727,   727,   727,
     727,   727,   727,   727,   727,   727,   727,   728,   728,   728,
     728,   729,   729,   729,   729,   729,   730,   731,   731,   731,
     731,   731,   731,   731,   732,   733,   733,   733,   733,   734,
     735,   735,   735,   735,   735,   735,   735,   735,   735,   736,
     737,   737,   737,   737,   737,   737,   737,   737,   738,   739,
     739,   739,   739,   739,   740,   741,   741,   742,   743,   743,
     743,   744,   745,   745,   745,   745,   746,   747,   747,   747,
     747,   748,   748,   748,   748,   749,   750,   750,   750,   750,
     750,   750,   750,   750,   750,   750,   751,   751,   751,   751,
     751,   751,   752,   752,   752,   752,   752,   753,   753,   753,
     753,   753,   753,   753,   753,   753,   753,   753,   753,   754,
     754,   755,   756,   756,   757,   758,   759,   760,   760,   760,
     761,   761,   761,   761,   761,   761,   761,   761,   761,   761,
     761,   761,   761,   761,   761,   761,   761,   761,   762,   762,
     762,   763,   763,   763,   763,   764,   764,   764,   764,   764,
     765,   765,   765,   765,   766,   766,   766,   766,   766,   766,
     766,   766,   766,   766,   766,   766,   767,   767,   768,   768,
     768,   768,   769,   770,   770,   771,   771,   771,   771,   771,
     771,   771,   771,   772,   773,   773,   774,   775,   775,   775,
     775,   776,   777,   778,   779,   780,   781,   781,   781,   781,
     782,   783,   783,   783,   783,   783,   783,   784,   785,   785,
     786,   787,   787,   787,   787,   787,   788,   789,   789,   789,
     789,   789
};

/* YYR2[RULE-NUM] -- Number of symbols on the right-hand side of rule RULE-NUM.  */
static const yytype_int8 yyr2[] =
{
       0,     2,     0,     2,     1,     1,     1,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     3,
       5,     5,     3,     2,     1,     1,     2,     2,     1,     2,
       2,     2,     2,     2,     2,     3,     3,     2,     2,     3,
       3,     3,     2,     2,     6,     2,     6,     3,     2,     6,
       6,     3,     6,     3,     5,     7,     5,     7,     8,     8,
       8,     5,     7,     5,     7,     5,     7,     3,     2,     6,
       2,     6,     6,     6,     3,     6,     3,     5,     5,     8,
       8,     8,     5,     5,     5,     3,     1,     1,     1,     1,
       1,     1,     1,     1,     2,     2,     2,     2,     2,     3,
       2,     2,     6,     3,     3,     5,     3,     3,     3,     3,
       2,     2,     2,     2,     2,     3,     2,     2,     3,     3,
       2,     3,     3,     2,     3,     3,     2,     3,     3,     2,
       3,     3,     2,     3,     3,     2,     2,     2,     2,     2,
       2,     4,     5,     2,     2,     1,     2,     2,     3,     3,
       2,     3,     3,     2,     2,     2,     2,     3,     2,     2,
       3,     2,     1,     2,     1,     3,     0,     1,     0,     1,
       1,     1,     1,     1,     1,     1,     0,     1,     1,     1,
       2,     1,     0,     2,     1,     0,     2,     2,     3,     8,
       8,     8,     8,     9,     9,    10,    10,    10,     9,     9,
       9,     0,     0,     2,     2,     3,     3,     3,     3,     3,
       0,     2,     3,     1,     3,     1,     3,     0,     0,     2,
       2,     5,     4,     4,     4,     4,     3,     4,     2,     3,
       3,     1,     1,     3,     1,     1,     1,     1,     1,     0,
       2,     2,     2,     2,     2,     0,     2,     2,     4,     7,
       8,     6,     7,     7,     4,     3,     4,     3,     3,     3,
       2,     1,     1,     0,     0,     2,     2,     5,     5,     3,
       4,     3,     1,     1,     3,     3,     1,     1,     1,     1,
       1,     1,     3,     0,     0,     2,     2,     2,     2,     0,
       2,     2,     2,     2,     0,     2,     2,     2,     2,     0,
       2,     2,     2,     2,     0,     2,     2,     2,     2,     0,
       2,     2,     2,     2,     0,     2,     2,     2,     2,     0,
       2,     2,     2,     2,     1,     1,     1,     1,     1,     7,
       2,     1,     1,     1,     1,     1,     3,     3,     1,     2,
       2,     2,     3,     0,     2,     3,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     0,     1,     2,     2,     1,
       2,     1,     1,     2,     3,     2,     3,     1,     2,     3,
       1,     2,     3,     1,     2,     3,     1,     2,     2,     2,
       1,     2,     2,     2,     2,     2,     0,     1,     1,     2,
       1,     1,     2,     1,     2,     2,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     2,     2,     2,     2,     1,
       1,     2,     2,     2,     2,     1,     1,     2,     1,     1,
       2,     3,     1,     1,     5,     1,     1,     3,     3,     1,
       1,     3,     3,     5,     4,     5,     1,     2,     1,     3,
       1,     2,     2,     2,     1,     2,     1,     1,     2,     2,
       2,     2,     2,     2,     2,     1,     3,     3,     1,     2,
       1,     3,     1,     1,     1,     6,     6,     4,     1,     1,
       0,     1,     1,     0,     3,     6,     4,     1,     1,     0,
       0,     3,     3,     0,     2,     2,     3,     2,     2,     1,
       1,     1,     1,     1,     2,     1,     1,     1,     0,     6,
       3,     6,     3,     5,     3,     5,     2,     1,     1,     3,
       4,     4,     5,     6,     5,     1,     2,     1,     3,     1,
       2,     2,     2,     1,     1,     6,     8,     0,     0,     1,
       0,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     3,     1,     3,     3,     1,     3,
       1,     3,     1,     3,     1,     1,     3,     1,     1,     3,
       1,     3,     3,     1,     1,     1,     1,     1,     1,     2,
       3,     3,     4,     5,     2,     3,     2,     6,     4,     3,
       4,     3,     2,     1,     1,     3,     4,     1,     2,     1,
       1,     2,     3,     1,     3,     4,     3,     5,     3,     6,
       1,     3,     1,     1,     1,     2,     4,     6,     6,     1,
       2,     1,     1,     2,     2,     1,     1,     1,     1,     1,
       3,     1,     1,     1,     1,     1,     3,     1,     1,     1,
       2,     1,     4,     5,     6,     1,     1,     1,     7,     8,
       6,     1,     1,     1,     2,     2,     6,     8,     1,     2,
       1,     1,     1,     1,     3,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       3,     4,     1,     1,     2,     1,     1,     1,     1,     1,
       3,     1,     4,     4,     0,     2,     1,     3,     3,     1,
       3,     1,     3,     1,     3,     1,     1,     3,     3,     3,
       1,     1,     3,     1,     1,     1,     3,     1,     3,     3,
       3,     3,     5,     1,     2,     1,     1,     2,     1,     1,
       2,     1,     1,     2,     2,     2,     1,     1,     2,     1,
       2,     2,     6,     6,     6,     4,     5,     2,     2,     1,
       1,     1,     1,     1,     1,     2,     2,     4,     0,     4,
       0,     1,     0,     1,     1,     1,     1,     1,     1,     2,
       2,     6,     3,     1,     3,     3,     3,     7,     3,     3,
       3,     3,     3,     3,     0,     4,     4,     0,     2,     2,
       4,     4,     5,     5,     3,     3,     3,     3,     1,     1,
       1,     1,     3,     3,     1,     3,     1,     3,     1,     3,
       1,     1,     1,     3,     3,     1,     1,     1,     2,     2,
       2,     2,     2,     2,     2,     1,     2,     1,     1,     1,
       1,     1,     1,     1,     2,     2,     2,     2,     2,     2,
       1,     2,     2,     2,     2,     2,     3,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     2,     2,     1,
       1,     1,     3,     1,     3,     1,     1,     1,     1,     1,
       1,     2,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     2,     1,     1,     1,     5,     3,     5,     1,
       5,     5,     3,     5,     1,     1,     1,     0,     2,     1,
       1,     6,     2,     0,     1,     1,     1,     1,     1,     1,
       5,     6,     8,     6,     5,     2,     2,     3,     4,     1,
       1,     1,     2,     3,     4,     4,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     2,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     3,     3,     3,     3,     1,     1,     1,     1,
       1,     1,     3,     3,     5,     5,     5,     6,     3,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     2,     1,     1,     1,     7,     1,     1,
       2,     1,     3,     1,     1,     2,     3,     1,     1,     1,
       1,     2,     3,     1,     1,     1,     1,     1,     3,     3,
       3,     3,     3,     5,     4,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     2,     1,     1,     1,     1,     3,     2,     1,     1,
       1,     1,     1,     1,     3,     2,     1,     1,     1,     3,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     3,
       2,     1,     1,     1,     1,     1,     1,     1,     3,     1,
       1,     1,     1,     1,     3,     1,     1,     3,     1,     1,
       1,     3,     1,     1,     1,     1,     3,     1,     1,     1,
       1,     2,     3,     3,     9,     5,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     2,     2,     2,     2,
       2,     2,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     3,     1,     1,     2,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     2,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     3,     5,     1,     1,
       1,     1,     3,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     3,     1,     1,     3,     1,     1,     2,
       1,     3,     4,     3,     1,     3,     1,     1,     1,     4,
       3,     1,     1,     1,     1,     1,     1,     3,     1,     1,
       3,     1,     1,     2,     1,     1,     2,     2,     2,     2,
       2,     2
};


enum { YYENOMEM = -2 };

#define yyerrok         (yyerrstatus = 0)
#define yyclearin       (yychar = NFT_EMPTY)

#define YYACCEPT        goto yyacceptlab
#define YYABORT         goto yyabortlab
#define YYERROR         goto yyerrorlab
#define YYNOMEM         goto yyexhaustedlab


#define YYRECOVERING()  (!!yyerrstatus)

#define YYBACKUP(Token, Value)                                    \
  do                                                              \
    if (yychar == NFT_EMPTY)                                        \
      {                                                           \
        yychar = (Token);                                         \
        yylval = (Value);                                         \
        YYPOPSTACK (yylen);                                       \
        yystate = *yyssp;                                         \
        goto yybackup;                                            \
      }                                                           \
    else                                                          \
      {                                                           \
        yyerror (&yylloc, nft, scanner, state, YY_("syntax error: cannot back up")); \
        YYERROR;                                                  \
      }                                                           \
  while (0)

/* Backward compatibility with an undocumented macro.
   Use NFT_error or NFT_UNDEF. */
#define YYERRCODE NFT_UNDEF

/* YYLLOC_DEFAULT -- Set CURRENT to span from RHS[1] to RHS[N].
   If N is 0, then set CURRENT to the empty location which ends
   the previous symbol: RHS[0] (always defined).  */

#ifndef YYLLOC_DEFAULT
# define YYLLOC_DEFAULT(Current, Rhs, N)                                \
    do                                                                  \
      if (N)                                                            \
        {                                                               \
          (Current).first_line   = YYRHSLOC (Rhs, 1).first_line;        \
          (Current).first_column = YYRHSLOC (Rhs, 1).first_column;      \
          (Current).last_line    = YYRHSLOC (Rhs, N).last_line;         \
          (Current).last_column  = YYRHSLOC (Rhs, N).last_column;       \
        }                                                               \
      else                                                              \
        {                                                               \
          (Current).first_line   = (Current).last_line   =              \
            YYRHSLOC (Rhs, 0).last_line;                                \
          (Current).first_column = (Current).last_column =              \
            YYRHSLOC (Rhs, 0).last_column;                              \
        }                                                               \
    while (0)
#endif

#define YYRHSLOC(Rhs, K) ((Rhs)[K])


/* Enable debugging if requested.  */
#if NFT_DEBUG

# ifndef YYFPRINTF
#  include <stdio.h> /* INFRINGES ON USER NAME SPACE */
#  define YYFPRINTF fprintf
# endif

# define YYDPRINTF(Args)                        \
do {                                            \
  if (yydebug)                                  \
    YYFPRINTF Args;                             \
} while (0)


/* YYLOCATION_PRINT -- Print the location on the stream.
   This macro was not mandated originally: define only if we know
   we won't break user code: when these are the locations we know.  */

# ifndef YYLOCATION_PRINT

#  if defined YY_LOCATION_PRINT

   /* Temporary convenience wrapper in case some people defined the
      undocumented and private YY_LOCATION_PRINT macros.  */
#   define YYLOCATION_PRINT(File, Loc)  YY_LOCATION_PRINT(File, *(Loc))

#  elif defined NFT_LTYPE_IS_TRIVIAL && NFT_LTYPE_IS_TRIVIAL

/* Print *YYLOCP on YYO.  Private, do not rely on its existence. */

YY_ATTRIBUTE_UNUSED
static int
yy_location_print_ (FILE *yyo, YYLTYPE const * const yylocp)
{
  int res = 0;
  int end_col = 0 != yylocp->last_column ? yylocp->last_column - 1 : 0;
  if (0 <= yylocp->first_line)
    {
      res += YYFPRINTF (yyo, "%d", yylocp->first_line);
      if (0 <= yylocp->first_column)
        res += YYFPRINTF (yyo, ".%d", yylocp->first_column);
    }
  if (0 <= yylocp->last_line)
    {
      if (yylocp->first_line < yylocp->last_line)
        {
          res += YYFPRINTF (yyo, "-%d", yylocp->last_line);
          if (0 <= end_col)
            res += YYFPRINTF (yyo, ".%d", end_col);
        }
      else if (0 <= end_col && yylocp->first_column < end_col)
        res += YYFPRINTF (yyo, "-%d", end_col);
    }
  return res;
}

#   define YYLOCATION_PRINT  yy_location_print_

    /* Temporary convenience wrapper in case some people defined the
       undocumented and private YY_LOCATION_PRINT macros.  */
#   define YY_LOCATION_PRINT(File, Loc)  YYLOCATION_PRINT(File, &(Loc))

#  else

#   define YYLOCATION_PRINT(File, Loc) ((void) 0)
    /* Temporary convenience wrapper in case some people defined the
       undocumented and private YY_LOCATION_PRINT macros.  */
#   define YY_LOCATION_PRINT  YYLOCATION_PRINT

#  endif
# endif /* !defined YYLOCATION_PRINT */


# define YY_SYMBOL_PRINT(Title, Kind, Value, Location)                    \
do {                                                                      \
  if (yydebug)                                                            \
    {                                                                     \
      YYFPRINTF (stderr, "%s ", Title);                                   \
      yy_symbol_print (stderr,                                            \
                  Kind, Value, Location, nft, scanner, state); \
      YYFPRINTF (stderr, "\n");                                           \
    }                                                                     \
} while (0)


/*-----------------------------------.
| Print this symbol's value on YYO.  |
`-----------------------------------*/

static void
yy_symbol_value_print (FILE *yyo,
                       yysymbol_kind_t yykind, YYSTYPE const * const yyvaluep, YYLTYPE const * const yylocationp, struct nft_ctx *nft, void *scanner, struct parser_state *state)
{
  FILE *yyoutput = yyo;
  YY_USE (yyoutput);
  YY_USE (yylocationp);
  YY_USE (nft);
  YY_USE (scanner);
  YY_USE (state);
  if (!yyvaluep)
    return;
  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  YY_USE (yykind);
  YY_IGNORE_MAYBE_UNINITIALIZED_END
}


/*---------------------------.
| Print this symbol on YYO.  |
`---------------------------*/

static void
yy_symbol_print (FILE *yyo,
                 yysymbol_kind_t yykind, YYSTYPE const * const yyvaluep, YYLTYPE const * const yylocationp, struct nft_ctx *nft, void *scanner, struct parser_state *state)
{
  YYFPRINTF (yyo, "%s %s (",
             yykind < YYNTOKENS ? "token" : "nterm", yysymbol_name (yykind));

  YYLOCATION_PRINT (yyo, yylocationp);
  YYFPRINTF (yyo, ": ");
  yy_symbol_value_print (yyo, yykind, yyvaluep, yylocationp, nft, scanner, state);
  YYFPRINTF (yyo, ")");
}

/*------------------------------------------------------------------.
| yy_stack_print -- Print the state stack from its BOTTOM up to its |
| TOP (included).                                                   |
`------------------------------------------------------------------*/

static void
yy_stack_print (yy_state_t *yybottom, yy_state_t *yytop)
{
  YYFPRINTF (stderr, "Stack now");
  for (; yybottom <= yytop; yybottom++)
    {
      int yybot = *yybottom;
      YYFPRINTF (stderr, " %d", yybot);
    }
  YYFPRINTF (stderr, "\n");
}

# define YY_STACK_PRINT(Bottom, Top)                            \
do {                                                            \
  if (yydebug)                                                  \
    yy_stack_print ((Bottom), (Top));                           \
} while (0)


/*------------------------------------------------.
| Report that the YYRULE is going to be reduced.  |
`------------------------------------------------*/

static void
yy_reduce_print (yy_state_t *yyssp, YYSTYPE *yyvsp, YYLTYPE *yylsp,
                 int yyrule, struct nft_ctx *nft, void *scanner, struct parser_state *state)
{
  int yylno = yyrline[yyrule];
  int yynrhs = yyr2[yyrule];
  int yyi;
  YYFPRINTF (stderr, "Reducing stack by rule %d (line %d):\n",
             yyrule - 1, yylno);
  /* The symbols being reduced.  */
  for (yyi = 0; yyi < yynrhs; yyi++)
    {
      YYFPRINTF (stderr, "   $%d = ", yyi + 1);
      yy_symbol_print (stderr,
                       YY_ACCESSING_SYMBOL (+yyssp[yyi + 1 - yynrhs]),
                       &yyvsp[(yyi + 1) - (yynrhs)],
                       &(yylsp[(yyi + 1) - (yynrhs)]), nft, scanner, state);
      YYFPRINTF (stderr, "\n");
    }
}

# define YY_REDUCE_PRINT(Rule)          \
do {                                    \
  if (yydebug)                          \
    yy_reduce_print (yyssp, yyvsp, yylsp, Rule, nft, scanner, state); \
} while (0)

/* Nonzero means print parse trace.  It is left uninitialized so that
   multiple parsers can coexist.  */
int yydebug;
#else /* !NFT_DEBUG */
# define YYDPRINTF(Args) ((void) 0)
# define YY_SYMBOL_PRINT(Title, Kind, Value, Location)
# define YY_STACK_PRINT(Bottom, Top)
# define YY_REDUCE_PRINT(Rule)
#endif /* !NFT_DEBUG */


/* YYINITDEPTH -- initial size of the parser's stacks.  */
#ifndef YYINITDEPTH
# define YYINITDEPTH 200
#endif

/* YYMAXDEPTH -- maximum size the stacks can grow to (effective only
   if the built-in stack extension method is used).

   Do not make this value too large; the results are undefined if
   YYSTACK_ALLOC_MAXIMUM < YYSTACK_BYTES (YYMAXDEPTH)
   evaluated with infinite-precision integer arithmetic.  */

#ifndef YYMAXDEPTH
# define YYMAXDEPTH 10000
#endif


/* Context of a parse error.  */
typedef struct
{
  yy_state_t *yyssp;
  yysymbol_kind_t yytoken;
  YYLTYPE *yylloc;
} yypcontext_t;

/* Put in YYARG at most YYARGN of the expected tokens given the
   current YYCTX, and return the number of tokens stored in YYARG.  If
   YYARG is null, return the number of expected tokens (guaranteed to
   be less than YYNTOKENS).  Return YYENOMEM on memory exhaustion.
   Return 0 if there are more than YYARGN expected tokens, yet fill
   YYARG up to YYARGN. */
static int
yypcontext_expected_tokens (const yypcontext_t *yyctx,
                            yysymbol_kind_t yyarg[], int yyargn)
{
  /* Actual size of YYARG. */
  int yycount = 0;
  int yyn = yypact[+*yyctx->yyssp];
  if (!yypact_value_is_default (yyn))
    {
      /* Start YYX at -YYN if negative to avoid negative indexes in
         YYCHECK.  In other words, skip the first -YYN actions for
         this state because they are default actions.  */
      int yyxbegin = yyn < 0 ? -yyn : 0;
      /* Stay within bounds of both yycheck and yytname.  */
      int yychecklim = YYLAST - yyn + 1;
      int yyxend = yychecklim < YYNTOKENS ? yychecklim : YYNTOKENS;
      int yyx;
      for (yyx = yyxbegin; yyx < yyxend; ++yyx)
        if (yycheck[yyx + yyn] == yyx && yyx != YYSYMBOL_YYerror
            && !yytable_value_is_error (yytable[yyx + yyn]))
          {
            if (!yyarg)
              ++yycount;
            else if (yycount == yyargn)
              return 0;
            else
              yyarg[yycount++] = YY_CAST (yysymbol_kind_t, yyx);
          }
    }
  if (yyarg && yycount == 0 && 0 < yyargn)
    yyarg[0] = YYSYMBOL_YYEMPTY;
  return yycount;
}




#ifndef yystrlen
# if defined __GLIBC__ && defined _STRING_H
#  define yystrlen(S) (YY_CAST (YYPTRDIFF_T, strlen (S)))
# else
/* Return the length of YYSTR.  */
static YYPTRDIFF_T
yystrlen (const char *yystr)
{
  YYPTRDIFF_T yylen;
  for (yylen = 0; yystr[yylen]; yylen++)
    continue;
  return yylen;
}
# endif
#endif

#ifndef yystpcpy
# if defined __GLIBC__ && defined _STRING_H && defined _GNU_SOURCE
#  define yystpcpy stpcpy
# else
/* Copy YYSRC to YYDEST, returning the address of the terminating '\0' in
   YYDEST.  */
static char *
yystpcpy (char *yydest, const char *yysrc)
{
  char *yyd = yydest;
  const char *yys = yysrc;

  while ((*yyd++ = *yys++) != '\0')
    continue;

  return yyd - 1;
}
# endif
#endif

#ifndef yytnamerr
/* Copy to YYRES the contents of YYSTR after stripping away unnecessary
   quotes and backslashes, so that it's suitable for yyerror.  The
   heuristic is that double-quoting is unnecessary unless the string
   contains an apostrophe, a comma, or backslash (other than
   backslash-backslash).  YYSTR is taken from yytname.  If YYRES is
   null, do not copy; instead, return the length of what the result
   would have been.  */
static YYPTRDIFF_T
yytnamerr (char *yyres, const char *yystr)
{
  if (*yystr == '"')
    {
      YYPTRDIFF_T yyn = 0;
      char const *yyp = yystr;
      for (;;)
        switch (*++yyp)
          {
          case '\'':
          case ',':
            goto do_not_strip_quotes;

          case '\\':
            if (*++yyp != '\\')
              goto do_not_strip_quotes;
            else
              goto append;

          append:
          default:
            if (yyres)
              yyres[yyn] = *yyp;
            yyn++;
            break;

          case '"':
            if (yyres)
              yyres[yyn] = '\0';
            return yyn;
          }
    do_not_strip_quotes: ;
    }

  if (yyres)
    return yystpcpy (yyres, yystr) - yyres;
  else
    return yystrlen (yystr);
}
#endif


static int
yy_syntax_error_arguments (const yypcontext_t *yyctx,
                           yysymbol_kind_t yyarg[], int yyargn)
{
  /* Actual size of YYARG. */
  int yycount = 0;
  /* There are many possibilities here to consider:
     - If this state is a consistent state with a default action, then
       the only way this function was invoked is if the default action
       is an error action.  In that case, don't check for expected
       tokens because there are none.
     - The only way there can be no lookahead present (in yychar) is if
       this state is a consistent state with a default action.  Thus,
       detecting the absence of a lookahead is sufficient to determine
       that there is no unexpected or expected token to report.  In that
       case, just report a simple "syntax error".
     - Don't assume there isn't a lookahead just because this state is a
       consistent state with a default action.  There might have been a
       previous inconsistent state, consistent state with a non-default
       action, or user semantic action that manipulated yychar.
     - Of course, the expected token list depends on states to have
       correct lookahead information, and it depends on the parser not
       to perform extra reductions after fetching a lookahead from the
       scanner and before detecting a syntax error.  Thus, state merging
       (from LALR or IELR) and default reductions corrupt the expected
       token list.  However, the list is correct for canonical LR with
       one exception: it will still contain any token that will not be
       accepted due to an error action in a later state.
  */
  if (yyctx->yytoken != YYSYMBOL_YYEMPTY)
    {
      int yyn;
      if (yyarg)
        yyarg[yycount] = yyctx->yytoken;
      ++yycount;
      yyn = yypcontext_expected_tokens (yyctx,
                                        yyarg ? yyarg + 1 : yyarg, yyargn - 1);
      if (yyn == YYENOMEM)
        return YYENOMEM;
      else
        yycount += yyn;
    }
  return yycount;
}

/* Copy into *YYMSG, which is of size *YYMSG_ALLOC, an error message
   about the unexpected token YYTOKEN for the state stack whose top is
   YYSSP.

   Return 0 if *YYMSG was successfully written.  Return -1 if *YYMSG is
   not large enough to hold the message.  In that case, also set
   *YYMSG_ALLOC to the required number of bytes.  Return YYENOMEM if the
   required number of bytes is too large to store.  */
static int
yysyntax_error (YYPTRDIFF_T *yymsg_alloc, char **yymsg,
                const yypcontext_t *yyctx)
{
  enum { YYARGS_MAX = 5 };
  /* Internationalized format string. */
  const char *yyformat = YY_NULLPTR;
  /* Arguments of yyformat: reported tokens (one for the "unexpected",
     one per "expected"). */
  yysymbol_kind_t yyarg[YYARGS_MAX];
  /* Cumulated lengths of YYARG.  */
  YYPTRDIFF_T yysize = 0;

  /* Actual size of YYARG. */
  int yycount = yy_syntax_error_arguments (yyctx, yyarg, YYARGS_MAX);
  if (yycount == YYENOMEM)
    return YYENOMEM;

  switch (yycount)
    {
#define YYCASE_(N, S)                       \
      case N:                               \
        yyformat = S;                       \
        break
    default: /* Avoid compiler warnings. */
      YYCASE_(0, YY_("syntax error"));
      YYCASE_(1, YY_("syntax error, unexpected %s"));
      YYCASE_(2, YY_("syntax error, unexpected %s, expecting %s"));
      YYCASE_(3, YY_("syntax error, unexpected %s, expecting %s or %s"));
      YYCASE_(4, YY_("syntax error, unexpected %s, expecting %s or %s or %s"));
      YYCASE_(5, YY_("syntax error, unexpected %s, expecting %s or %s or %s or %s"));
#undef YYCASE_
    }

  /* Compute error message size.  Don't count the "%s"s, but reserve
     room for the terminator.  */
  yysize = yystrlen (yyformat) - 2 * yycount + 1;
  {
    int yyi;
    for (yyi = 0; yyi < yycount; ++yyi)
      {
        YYPTRDIFF_T yysize1
          = yysize + yytnamerr (YY_NULLPTR, yytname[yyarg[yyi]]);
        if (yysize <= yysize1 && yysize1 <= YYSTACK_ALLOC_MAXIMUM)
          yysize = yysize1;
        else
          return YYENOMEM;
      }
  }

  if (*yymsg_alloc < yysize)
    {
      *yymsg_alloc = 2 * yysize;
      if (! (yysize <= *yymsg_alloc
             && *yymsg_alloc <= YYSTACK_ALLOC_MAXIMUM))
        *yymsg_alloc = YYSTACK_ALLOC_MAXIMUM;
      return -1;
    }

  /* Avoid sprintf, as that infringes on the user's name space.
     Don't have undefined behavior even if the translation
     produced a string with the wrong number of "%s"s.  */
  {
    char *yyp = *yymsg;
    int yyi = 0;
    while ((*yyp = *yyformat) != '\0')
      if (*yyp == '%' && yyformat[1] == 's' && yyi < yycount)
        {
          yyp += yytnamerr (yyp, yytname[yyarg[yyi++]]);
          yyformat += 2;
        }
      else
        {
          ++yyp;
          ++yyformat;
        }
  }
  return 0;
}


/*-----------------------------------------------.
| Release the memory associated to this symbol.  |
`-----------------------------------------------*/

static void
yydestruct (const char *yymsg,
            yysymbol_kind_t yykind, YYSTYPE *yyvaluep, YYLTYPE *yylocationp, struct nft_ctx *nft, void *scanner, struct parser_state *state)
{
  YY_USE (yyvaluep);
  YY_USE (yylocationp);
  YY_USE (nft);
  YY_USE (scanner);
  YY_USE (state);
  if (!yymsg)
    yymsg = "Deleting";
  YY_SYMBOL_PRINT (yymsg, yykind, yyvaluep, yylocationp);

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  switch (yykind)
    {
    case YYSYMBOL_STRING: /* "string"  */
#line 331 "../../nft/nftables/src/parser_bison.y"
            { xfree(((*yyvaluep).string)); }
#line 5492 "parser_bison.tab.c"
        break;

    case YYSYMBOL_QUOTED_STRING: /* "quoted string"  */
#line 331 "../../nft/nftables/src/parser_bison.y"
            { xfree(((*yyvaluep).string)); }
#line 5498 "parser_bison.tab.c"
        break;

    case YYSYMBOL_ASTERISK_STRING: /* "string with a trailing asterisk"  */
#line 331 "../../nft/nftables/src/parser_bison.y"
            { xfree(((*yyvaluep).string)); }
#line 5504 "parser_bison.tab.c"
        break;

    case YYSYMBOL_line: /* line  */
#line 643 "../../nft/nftables/src/parser_bison.y"
            { cmd_free(((*yyvaluep).cmd)); }
#line 5510 "parser_bison.tab.c"
        break;

    case YYSYMBOL_base_cmd: /* base_cmd  */
#line 646 "../../nft/nftables/src/parser_bison.y"
            { cmd_free(((*yyvaluep).cmd)); }
#line 5516 "parser_bison.tab.c"
        break;

    case YYSYMBOL_add_cmd: /* add_cmd  */
#line 646 "../../nft/nftables/src/parser_bison.y"
            { cmd_free(((*yyvaluep).cmd)); }
#line 5522 "parser_bison.tab.c"
        break;

    case YYSYMBOL_replace_cmd: /* replace_cmd  */
#line 646 "../../nft/nftables/src/parser_bison.y"
            { cmd_free(((*yyvaluep).cmd)); }
#line 5528 "parser_bison.tab.c"
        break;

    case YYSYMBOL_create_cmd: /* create_cmd  */
#line 646 "../../nft/nftables/src/parser_bison.y"
            { cmd_free(((*yyvaluep).cmd)); }
#line 5534 "parser_bison.tab.c"
        break;

    case YYSYMBOL_insert_cmd: /* insert_cmd  */
#line 646 "../../nft/nftables/src/parser_bison.y"
            { cmd_free(((*yyvaluep).cmd)); }
#line 5540 "parser_bison.tab.c"
        break;

    case YYSYMBOL_table_or_id_spec: /* table_or_id_spec  */
#line 649 "../../nft/nftables/src/parser_bison.y"
            { handle_free(&((*yyvaluep).handle)); }
#line 5546 "parser_bison.tab.c"
        break;

    case YYSYMBOL_chain_or_id_spec: /* chain_or_id_spec  */
#line 651 "../../nft/nftables/src/parser_bison.y"
            { handle_free(&((*yyvaluep).handle)); }
#line 5552 "parser_bison.tab.c"
        break;

    case YYSYMBOL_set_or_id_spec: /* set_or_id_spec  */
#line 656 "../../nft/nftables/src/parser_bison.y"
            { handle_free(&((*yyvaluep).handle)); }
#line 5558 "parser_bison.tab.c"
        break;

    case YYSYMBOL_obj_or_id_spec: /* obj_or_id_spec  */
#line 658 "../../nft/nftables/src/parser_bison.y"
            { handle_free(&((*yyvaluep).handle)); }
#line 5564 "parser_bison.tab.c"
        break;

    case YYSYMBOL_delete_cmd: /* delete_cmd  */
#line 646 "../../nft/nftables/src/parser_bison.y"
            { cmd_free(((*yyvaluep).cmd)); }
#line 5570 "parser_bison.tab.c"
        break;

    case YYSYMBOL_get_cmd: /* get_cmd  */
#line 646 "../../nft/nftables/src/parser_bison.y"
            { cmd_free(((*yyvaluep).cmd)); }
#line 5576 "parser_bison.tab.c"
        break;

    case YYSYMBOL_list_cmd: /* list_cmd  */
#line 646 "../../nft/nftables/src/parser_bison.y"
            { cmd_free(((*yyvaluep).cmd)); }
#line 5582 "parser_bison.tab.c"
        break;

    case YYSYMBOL_basehook_device_name: /* basehook_device_name  */
#line 670 "../../nft/nftables/src/parser_bison.y"
            { xfree(((*yyvaluep).string)); }
#line 5588 "parser_bison.tab.c"
        break;

    case YYSYMBOL_basehook_spec: /* basehook_spec  */
#line 664 "../../nft/nftables/src/parser_bison.y"
            { handle_free(&((*yyvaluep).handle)); }
#line 5594 "parser_bison.tab.c"
        break;

    case YYSYMBOL_reset_cmd: /* reset_cmd  */
#line 646 "../../nft/nftables/src/parser_bison.y"
            { cmd_free(((*yyvaluep).cmd)); }
#line 5600 "parser_bison.tab.c"
        break;

    case YYSYMBOL_flush_cmd: /* flush_cmd  */
#line 646 "../../nft/nftables/src/parser_bison.y"
            { cmd_free(((*yyvaluep).cmd)); }
#line 5606 "parser_bison.tab.c"
        break;

    case YYSYMBOL_rename_cmd: /* rename_cmd  */
#line 646 "../../nft/nftables/src/parser_bison.y"
            { cmd_free(((*yyvaluep).cmd)); }
#line 5612 "parser_bison.tab.c"
        break;

    case YYSYMBOL_import_cmd: /* import_cmd  */
#line 646 "../../nft/nftables/src/parser_bison.y"
            { cmd_free(((*yyvaluep).cmd)); }
#line 5618 "parser_bison.tab.c"
        break;

    case YYSYMBOL_export_cmd: /* export_cmd  */
#line 646 "../../nft/nftables/src/parser_bison.y"
            { cmd_free(((*yyvaluep).cmd)); }
#line 5624 "parser_bison.tab.c"
        break;

    case YYSYMBOL_monitor_cmd: /* monitor_cmd  */
#line 646 "../../nft/nftables/src/parser_bison.y"
            { cmd_free(((*yyvaluep).cmd)); }
#line 5630 "parser_bison.tab.c"
        break;

    case YYSYMBOL_monitor_event: /* monitor_event  */
#line 889 "../../nft/nftables/src/parser_bison.y"
            { xfree(((*yyvaluep).string)); }
#line 5636 "parser_bison.tab.c"
        break;

    case YYSYMBOL_describe_cmd: /* describe_cmd  */
#line 646 "../../nft/nftables/src/parser_bison.y"
            { cmd_free(((*yyvaluep).cmd)); }
#line 5642 "parser_bison.tab.c"
        break;

    case YYSYMBOL_table_block_alloc: /* table_block_alloc  */
#line 676 "../../nft/nftables/src/parser_bison.y"
            { close_scope(state); table_free(((*yyvaluep).table)); }
#line 5648 "parser_bison.tab.c"
        break;

    case YYSYMBOL_chain_block_alloc: /* chain_block_alloc  */
#line 678 "../../nft/nftables/src/parser_bison.y"
            { close_scope(state); chain_free(((*yyvaluep).chain)); }
#line 5654 "parser_bison.tab.c"
        break;

    case YYSYMBOL_typeof_data_expr: /* typeof_data_expr  */
#line 750 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 5660 "parser_bison.tab.c"
        break;

    case YYSYMBOL_typeof_expr: /* typeof_expr  */
#line 750 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 5666 "parser_bison.tab.c"
        break;

    case YYSYMBOL_set_block_alloc: /* set_block_alloc  */
#line 687 "../../nft/nftables/src/parser_bison.y"
            { set_free(((*yyvaluep).set)); }
#line 5672 "parser_bison.tab.c"
        break;

    case YYSYMBOL_set_block_expr: /* set_block_expr  */
#line 791 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 5678 "parser_bison.tab.c"
        break;

    case YYSYMBOL_map_block_alloc: /* map_block_alloc  */
#line 690 "../../nft/nftables/src/parser_bison.y"
            { set_free(((*yyvaluep).set)); }
#line 5684 "parser_bison.tab.c"
        break;

    case YYSYMBOL_flowtable_block_alloc: /* flowtable_block_alloc  */
#line 694 "../../nft/nftables/src/parser_bison.y"
            { flowtable_free(((*yyvaluep).flowtable)); }
#line 5690 "parser_bison.tab.c"
        break;

    case YYSYMBOL_flowtable_expr: /* flowtable_expr  */
#line 791 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 5696 "parser_bison.tab.c"
        break;

    case YYSYMBOL_flowtable_list_expr: /* flowtable_list_expr  */
#line 791 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 5702 "parser_bison.tab.c"
        break;

    case YYSYMBOL_flowtable_expr_member: /* flowtable_expr_member  */
#line 791 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 5708 "parser_bison.tab.c"
        break;

    case YYSYMBOL_data_type_atom_expr: /* data_type_atom_expr  */
#line 640 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 5714 "parser_bison.tab.c"
        break;

    case YYSYMBOL_data_type_expr: /* data_type_expr  */
#line 640 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 5720 "parser_bison.tab.c"
        break;

    case YYSYMBOL_obj_block_alloc: /* obj_block_alloc  */
#line 697 "../../nft/nftables/src/parser_bison.y"
            { obj_free(((*yyvaluep).obj)); }
#line 5726 "parser_bison.tab.c"
        break;

    case YYSYMBOL_type_identifier: /* type_identifier  */
#line 635 "../../nft/nftables/src/parser_bison.y"
            { xfree(((*yyvaluep).string)); }
#line 5732 "parser_bison.tab.c"
        break;

    case YYSYMBOL_extended_prio_name: /* extended_prio_name  */
#line 670 "../../nft/nftables/src/parser_bison.y"
            { xfree(((*yyvaluep).string)); }
#line 5738 "parser_bison.tab.c"
        break;

    case YYSYMBOL_dev_spec: /* dev_spec  */
#line 673 "../../nft/nftables/src/parser_bison.y"
            { xfree(((*yyvaluep).expr)); }
#line 5744 "parser_bison.tab.c"
        break;

    case YYSYMBOL_policy_expr: /* policy_expr  */
#line 748 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 5750 "parser_bison.tab.c"
        break;

    case YYSYMBOL_identifier: /* identifier  */
#line 635 "../../nft/nftables/src/parser_bison.y"
            { xfree(((*yyvaluep).string)); }
#line 5756 "parser_bison.tab.c"
        break;

    case YYSYMBOL_string: /* string  */
#line 635 "../../nft/nftables/src/parser_bison.y"
            { xfree(((*yyvaluep).string)); }
#line 5762 "parser_bison.tab.c"
        break;

    case YYSYMBOL_table_spec: /* table_spec  */
#line 649 "../../nft/nftables/src/parser_bison.y"
            { handle_free(&((*yyvaluep).handle)); }
#line 5768 "parser_bison.tab.c"
        break;

    case YYSYMBOL_tableid_spec: /* tableid_spec  */
#line 649 "../../nft/nftables/src/parser_bison.y"
            { handle_free(&((*yyvaluep).handle)); }
#line 5774 "parser_bison.tab.c"
        break;

    case YYSYMBOL_chain_spec: /* chain_spec  */
#line 651 "../../nft/nftables/src/parser_bison.y"
            { handle_free(&((*yyvaluep).handle)); }
#line 5780 "parser_bison.tab.c"
        break;

    case YYSYMBOL_chainid_spec: /* chainid_spec  */
#line 651 "../../nft/nftables/src/parser_bison.y"
            { handle_free(&((*yyvaluep).handle)); }
#line 5786 "parser_bison.tab.c"
        break;

    case YYSYMBOL_chain_identifier: /* chain_identifier  */
#line 654 "../../nft/nftables/src/parser_bison.y"
            { handle_free(&((*yyvaluep).handle)); }
#line 5792 "parser_bison.tab.c"
        break;

    case YYSYMBOL_set_spec: /* set_spec  */
#line 656 "../../nft/nftables/src/parser_bison.y"
            { handle_free(&((*yyvaluep).handle)); }
#line 5798 "parser_bison.tab.c"
        break;

    case YYSYMBOL_setid_spec: /* setid_spec  */
#line 656 "../../nft/nftables/src/parser_bison.y"
            { handle_free(&((*yyvaluep).handle)); }
#line 5804 "parser_bison.tab.c"
        break;

    case YYSYMBOL_set_identifier: /* set_identifier  */
#line 661 "../../nft/nftables/src/parser_bison.y"
            { handle_free(&((*yyvaluep).handle)); }
#line 5810 "parser_bison.tab.c"
        break;

    case YYSYMBOL_flowtable_spec: /* flowtable_spec  */
#line 654 "../../nft/nftables/src/parser_bison.y"
            { handle_free(&((*yyvaluep).handle)); }
#line 5816 "parser_bison.tab.c"
        break;

    case YYSYMBOL_flowtableid_spec: /* flowtableid_spec  */
#line 661 "../../nft/nftables/src/parser_bison.y"
            { handle_free(&((*yyvaluep).handle)); }
#line 5822 "parser_bison.tab.c"
        break;

    case YYSYMBOL_obj_spec: /* obj_spec  */
#line 658 "../../nft/nftables/src/parser_bison.y"
            { handle_free(&((*yyvaluep).handle)); }
#line 5828 "parser_bison.tab.c"
        break;

    case YYSYMBOL_objid_spec: /* objid_spec  */
#line 658 "../../nft/nftables/src/parser_bison.y"
            { handle_free(&((*yyvaluep).handle)); }
#line 5834 "parser_bison.tab.c"
        break;

    case YYSYMBOL_obj_identifier: /* obj_identifier  */
#line 661 "../../nft/nftables/src/parser_bison.y"
            { handle_free(&((*yyvaluep).handle)); }
#line 5840 "parser_bison.tab.c"
        break;

    case YYSYMBOL_handle_spec: /* handle_spec  */
#line 654 "../../nft/nftables/src/parser_bison.y"
            { handle_free(&((*yyvaluep).handle)); }
#line 5846 "parser_bison.tab.c"
        break;

    case YYSYMBOL_position_spec: /* position_spec  */
#line 654 "../../nft/nftables/src/parser_bison.y"
            { handle_free(&((*yyvaluep).handle)); }
#line 5852 "parser_bison.tab.c"
        break;

    case YYSYMBOL_index_spec: /* index_spec  */
#line 654 "../../nft/nftables/src/parser_bison.y"
            { handle_free(&((*yyvaluep).handle)); }
#line 5858 "parser_bison.tab.c"
        break;

    case YYSYMBOL_rule_position: /* rule_position  */
#line 654 "../../nft/nftables/src/parser_bison.y"
            { handle_free(&((*yyvaluep).handle)); }
#line 5864 "parser_bison.tab.c"
        break;

    case YYSYMBOL_ruleid_spec: /* ruleid_spec  */
#line 654 "../../nft/nftables/src/parser_bison.y"
            { handle_free(&((*yyvaluep).handle)); }
#line 5870 "parser_bison.tab.c"
        break;

    case YYSYMBOL_comment_spec: /* comment_spec  */
#line 635 "../../nft/nftables/src/parser_bison.y"
            { xfree(((*yyvaluep).string)); }
#line 5876 "parser_bison.tab.c"
        break;

    case YYSYMBOL_ruleset_spec: /* ruleset_spec  */
#line 654 "../../nft/nftables/src/parser_bison.y"
            { handle_free(&((*yyvaluep).handle)); }
#line 5882 "parser_bison.tab.c"
        break;

    case YYSYMBOL_rule: /* rule  */
#line 680 "../../nft/nftables/src/parser_bison.y"
            { rule_free(((*yyvaluep).rule)); }
#line 5888 "parser_bison.tab.c"
        break;

    case YYSYMBOL_stmt_list: /* stmt_list  */
#line 700 "../../nft/nftables/src/parser_bison.y"
            { stmt_list_free(((*yyvaluep).list)); xfree(((*yyvaluep).list)); }
#line 5894 "parser_bison.tab.c"
        break;

    case YYSYMBOL_stateful_stmt_list: /* stateful_stmt_list  */
#line 700 "../../nft/nftables/src/parser_bison.y"
            { stmt_list_free(((*yyvaluep).list)); xfree(((*yyvaluep).list)); }
#line 5900 "parser_bison.tab.c"
        break;

    case YYSYMBOL_stateful_stmt: /* stateful_stmt  */
#line 704 "../../nft/nftables/src/parser_bison.y"
            { stmt_free(((*yyvaluep).stmt)); }
#line 5906 "parser_bison.tab.c"
        break;

    case YYSYMBOL_stmt: /* stmt  */
#line 702 "../../nft/nftables/src/parser_bison.y"
            { stmt_free(((*yyvaluep).stmt)); }
#line 5912 "parser_bison.tab.c"
        break;

    case YYSYMBOL_xt_stmt: /* xt_stmt  */
#line 906 "../../nft/nftables/src/parser_bison.y"
            { stmt_free(((*yyvaluep).stmt)); }
#line 5918 "parser_bison.tab.c"
        break;

    case YYSYMBOL_chain_stmt: /* chain_stmt  */
#line 727 "../../nft/nftables/src/parser_bison.y"
            { stmt_free(((*yyvaluep).stmt)); }
#line 5924 "parser_bison.tab.c"
        break;

    case YYSYMBOL_verdict_stmt: /* verdict_stmt  */
#line 702 "../../nft/nftables/src/parser_bison.y"
            { stmt_free(((*yyvaluep).stmt)); }
#line 5930 "parser_bison.tab.c"
        break;

    case YYSYMBOL_verdict_map_stmt: /* verdict_map_stmt  */
#line 785 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 5936 "parser_bison.tab.c"
        break;

    case YYSYMBOL_verdict_map_expr: /* verdict_map_expr  */
#line 788 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 5942 "parser_bison.tab.c"
        break;

    case YYSYMBOL_verdict_map_list_expr: /* verdict_map_list_expr  */
#line 788 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 5948 "parser_bison.tab.c"
        break;

    case YYSYMBOL_verdict_map_list_member_expr: /* verdict_map_list_member_expr  */
#line 788 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 5954 "parser_bison.tab.c"
        break;

    case YYSYMBOL_connlimit_stmt: /* connlimit_stmt  */
#line 715 "../../nft/nftables/src/parser_bison.y"
            { stmt_free(((*yyvaluep).stmt)); }
#line 5960 "parser_bison.tab.c"
        break;

    case YYSYMBOL_counter_stmt: /* counter_stmt  */
#line 704 "../../nft/nftables/src/parser_bison.y"
            { stmt_free(((*yyvaluep).stmt)); }
#line 5966 "parser_bison.tab.c"
        break;

    case YYSYMBOL_counter_stmt_alloc: /* counter_stmt_alloc  */
#line 704 "../../nft/nftables/src/parser_bison.y"
            { stmt_free(((*yyvaluep).stmt)); }
#line 5972 "parser_bison.tab.c"
        break;

    case YYSYMBOL_log_stmt: /* log_stmt  */
#line 712 "../../nft/nftables/src/parser_bison.y"
            { stmt_free(((*yyvaluep).stmt)); }
#line 5978 "parser_bison.tab.c"
        break;

    case YYSYMBOL_log_stmt_alloc: /* log_stmt_alloc  */
#line 712 "../../nft/nftables/src/parser_bison.y"
            { stmt_free(((*yyvaluep).stmt)); }
#line 5984 "parser_bison.tab.c"
        break;

    case YYSYMBOL_limit_stmt: /* limit_stmt  */
#line 715 "../../nft/nftables/src/parser_bison.y"
            { stmt_free(((*yyvaluep).stmt)); }
#line 5990 "parser_bison.tab.c"
        break;

    case YYSYMBOL_quota_unit: /* quota_unit  */
#line 670 "../../nft/nftables/src/parser_bison.y"
            { xfree(((*yyvaluep).string)); }
#line 5996 "parser_bison.tab.c"
        break;

    case YYSYMBOL_quota_stmt: /* quota_stmt  */
#line 715 "../../nft/nftables/src/parser_bison.y"
            { stmt_free(((*yyvaluep).stmt)); }
#line 6002 "parser_bison.tab.c"
        break;

    case YYSYMBOL_reject_stmt: /* reject_stmt  */
#line 718 "../../nft/nftables/src/parser_bison.y"
            { stmt_free(((*yyvaluep).stmt)); }
#line 6008 "parser_bison.tab.c"
        break;

    case YYSYMBOL_reject_stmt_alloc: /* reject_stmt_alloc  */
#line 718 "../../nft/nftables/src/parser_bison.y"
            { stmt_free(((*yyvaluep).stmt)); }
#line 6014 "parser_bison.tab.c"
        break;

    case YYSYMBOL_reject_with_expr: /* reject_with_expr  */
#line 733 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6020 "parser_bison.tab.c"
        break;

    case YYSYMBOL_nat_stmt: /* nat_stmt  */
#line 720 "../../nft/nftables/src/parser_bison.y"
            { stmt_free(((*yyvaluep).stmt)); }
#line 6026 "parser_bison.tab.c"
        break;

    case YYSYMBOL_nat_stmt_alloc: /* nat_stmt_alloc  */
#line 720 "../../nft/nftables/src/parser_bison.y"
            { stmt_free(((*yyvaluep).stmt)); }
#line 6032 "parser_bison.tab.c"
        break;

    case YYSYMBOL_tproxy_stmt: /* tproxy_stmt  */
#line 723 "../../nft/nftables/src/parser_bison.y"
            { stmt_free(((*yyvaluep).stmt)); }
#line 6038 "parser_bison.tab.c"
        break;

    case YYSYMBOL_synproxy_stmt: /* synproxy_stmt  */
#line 725 "../../nft/nftables/src/parser_bison.y"
            { stmt_free(((*yyvaluep).stmt)); }
#line 6044 "parser_bison.tab.c"
        break;

    case YYSYMBOL_synproxy_stmt_alloc: /* synproxy_stmt_alloc  */
#line 725 "../../nft/nftables/src/parser_bison.y"
            { stmt_free(((*yyvaluep).stmt)); }
#line 6050 "parser_bison.tab.c"
        break;

    case YYSYMBOL_synproxy_obj: /* synproxy_obj  */
#line 811 "../../nft/nftables/src/parser_bison.y"
            { obj_free(((*yyvaluep).obj)); }
#line 6056 "parser_bison.tab.c"
        break;

    case YYSYMBOL_primary_stmt_expr: /* primary_stmt_expr  */
#line 772 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6062 "parser_bison.tab.c"
        break;

    case YYSYMBOL_shift_stmt_expr: /* shift_stmt_expr  */
#line 774 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6068 "parser_bison.tab.c"
        break;

    case YYSYMBOL_and_stmt_expr: /* and_stmt_expr  */
#line 776 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6074 "parser_bison.tab.c"
        break;

    case YYSYMBOL_exclusive_or_stmt_expr: /* exclusive_or_stmt_expr  */
#line 776 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6080 "parser_bison.tab.c"
        break;

    case YYSYMBOL_inclusive_or_stmt_expr: /* inclusive_or_stmt_expr  */
#line 776 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6086 "parser_bison.tab.c"
        break;

    case YYSYMBOL_basic_stmt_expr: /* basic_stmt_expr  */
#line 772 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6092 "parser_bison.tab.c"
        break;

    case YYSYMBOL_concat_stmt_expr: /* concat_stmt_expr  */
#line 764 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6098 "parser_bison.tab.c"
        break;

    case YYSYMBOL_map_stmt_expr_set: /* map_stmt_expr_set  */
#line 764 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6104 "parser_bison.tab.c"
        break;

    case YYSYMBOL_map_stmt_expr: /* map_stmt_expr  */
#line 764 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6110 "parser_bison.tab.c"
        break;

    case YYSYMBOL_prefix_stmt_expr: /* prefix_stmt_expr  */
#line 769 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6116 "parser_bison.tab.c"
        break;

    case YYSYMBOL_range_stmt_expr: /* range_stmt_expr  */
#line 769 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6122 "parser_bison.tab.c"
        break;

    case YYSYMBOL_multiton_stmt_expr: /* multiton_stmt_expr  */
#line 767 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6128 "parser_bison.tab.c"
        break;

    case YYSYMBOL_stmt_expr: /* stmt_expr  */
#line 764 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6134 "parser_bison.tab.c"
        break;

    case YYSYMBOL_masq_stmt: /* masq_stmt  */
#line 720 "../../nft/nftables/src/parser_bison.y"
            { stmt_free(((*yyvaluep).stmt)); }
#line 6140 "parser_bison.tab.c"
        break;

    case YYSYMBOL_masq_stmt_alloc: /* masq_stmt_alloc  */
#line 720 "../../nft/nftables/src/parser_bison.y"
            { stmt_free(((*yyvaluep).stmt)); }
#line 6146 "parser_bison.tab.c"
        break;

    case YYSYMBOL_redir_stmt: /* redir_stmt  */
#line 720 "../../nft/nftables/src/parser_bison.y"
            { stmt_free(((*yyvaluep).stmt)); }
#line 6152 "parser_bison.tab.c"
        break;

    case YYSYMBOL_redir_stmt_alloc: /* redir_stmt_alloc  */
#line 720 "../../nft/nftables/src/parser_bison.y"
            { stmt_free(((*yyvaluep).stmt)); }
#line 6158 "parser_bison.tab.c"
        break;

    case YYSYMBOL_dup_stmt: /* dup_stmt  */
#line 736 "../../nft/nftables/src/parser_bison.y"
            { stmt_free(((*yyvaluep).stmt)); }
#line 6164 "parser_bison.tab.c"
        break;

    case YYSYMBOL_fwd_stmt: /* fwd_stmt  */
#line 738 "../../nft/nftables/src/parser_bison.y"
            { stmt_free(((*yyvaluep).stmt)); }
#line 6170 "parser_bison.tab.c"
        break;

    case YYSYMBOL_queue_stmt: /* queue_stmt  */
#line 731 "../../nft/nftables/src/parser_bison.y"
            { stmt_free(((*yyvaluep).stmt)); }
#line 6176 "parser_bison.tab.c"
        break;

    case YYSYMBOL_queue_stmt_compat: /* queue_stmt_compat  */
#line 731 "../../nft/nftables/src/parser_bison.y"
            { stmt_free(((*yyvaluep).stmt)); }
#line 6182 "parser_bison.tab.c"
        break;

    case YYSYMBOL_queue_stmt_alloc: /* queue_stmt_alloc  */
#line 731 "../../nft/nftables/src/parser_bison.y"
            { stmt_free(((*yyvaluep).stmt)); }
#line 6188 "parser_bison.tab.c"
        break;

    case YYSYMBOL_queue_expr: /* queue_expr  */
#line 733 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6194 "parser_bison.tab.c"
        break;

    case YYSYMBOL_queue_stmt_expr_simple: /* queue_stmt_expr_simple  */
#line 733 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6200 "parser_bison.tab.c"
        break;

    case YYSYMBOL_queue_stmt_expr: /* queue_stmt_expr  */
#line 733 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6206 "parser_bison.tab.c"
        break;

    case YYSYMBOL_set_elem_expr_stmt: /* set_elem_expr_stmt  */
#line 795 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6212 "parser_bison.tab.c"
        break;

    case YYSYMBOL_set_elem_expr_stmt_alloc: /* set_elem_expr_stmt_alloc  */
#line 795 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6218 "parser_bison.tab.c"
        break;

    case YYSYMBOL_set_stmt: /* set_stmt  */
#line 740 "../../nft/nftables/src/parser_bison.y"
            { stmt_free(((*yyvaluep).stmt)); }
#line 6224 "parser_bison.tab.c"
        break;

    case YYSYMBOL_map_stmt: /* map_stmt  */
#line 743 "../../nft/nftables/src/parser_bison.y"
            { stmt_free(((*yyvaluep).stmt)); }
#line 6230 "parser_bison.tab.c"
        break;

    case YYSYMBOL_meter_stmt: /* meter_stmt  */
#line 745 "../../nft/nftables/src/parser_bison.y"
            { stmt_free(((*yyvaluep).stmt)); }
#line 6236 "parser_bison.tab.c"
        break;

    case YYSYMBOL_flow_stmt_legacy_alloc: /* flow_stmt_legacy_alloc  */
#line 745 "../../nft/nftables/src/parser_bison.y"
            { stmt_free(((*yyvaluep).stmt)); }
#line 6242 "parser_bison.tab.c"
        break;

    case YYSYMBOL_meter_stmt_alloc: /* meter_stmt_alloc  */
#line 745 "../../nft/nftables/src/parser_bison.y"
            { stmt_free(((*yyvaluep).stmt)); }
#line 6248 "parser_bison.tab.c"
        break;

    case YYSYMBOL_match_stmt: /* match_stmt  */
#line 702 "../../nft/nftables/src/parser_bison.y"
            { stmt_free(((*yyvaluep).stmt)); }
#line 6254 "parser_bison.tab.c"
        break;

    case YYSYMBOL_variable_expr: /* variable_expr  */
#line 748 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6260 "parser_bison.tab.c"
        break;

    case YYSYMBOL_symbol_expr: /* symbol_expr  */
#line 748 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6266 "parser_bison.tab.c"
        break;

    case YYSYMBOL_set_ref_expr: /* set_ref_expr  */
#line 756 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6272 "parser_bison.tab.c"
        break;

    case YYSYMBOL_set_ref_symbol_expr: /* set_ref_symbol_expr  */
#line 756 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6278 "parser_bison.tab.c"
        break;

    case YYSYMBOL_integer_expr: /* integer_expr  */
#line 748 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6284 "parser_bison.tab.c"
        break;

    case YYSYMBOL_primary_expr: /* primary_expr  */
#line 750 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6290 "parser_bison.tab.c"
        break;

    case YYSYMBOL_fib_expr: /* fib_expr  */
#line 880 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6296 "parser_bison.tab.c"
        break;

    case YYSYMBOL_osf_expr: /* osf_expr  */
#line 885 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6302 "parser_bison.tab.c"
        break;

    case YYSYMBOL_shift_expr: /* shift_expr  */
#line 750 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6308 "parser_bison.tab.c"
        break;

    case YYSYMBOL_and_expr: /* and_expr  */
#line 750 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6314 "parser_bison.tab.c"
        break;

    case YYSYMBOL_exclusive_or_expr: /* exclusive_or_expr  */
#line 752 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6320 "parser_bison.tab.c"
        break;

    case YYSYMBOL_inclusive_or_expr: /* inclusive_or_expr  */
#line 752 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6326 "parser_bison.tab.c"
        break;

    case YYSYMBOL_basic_expr: /* basic_expr  */
#line 754 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6332 "parser_bison.tab.c"
        break;

    case YYSYMBOL_concat_expr: /* concat_expr  */
#line 779 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6338 "parser_bison.tab.c"
        break;

    case YYSYMBOL_prefix_rhs_expr: /* prefix_rhs_expr  */
#line 761 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6344 "parser_bison.tab.c"
        break;

    case YYSYMBOL_range_rhs_expr: /* range_rhs_expr  */
#line 761 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6350 "parser_bison.tab.c"
        break;

    case YYSYMBOL_multiton_rhs_expr: /* multiton_rhs_expr  */
#line 759 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6356 "parser_bison.tab.c"
        break;

    case YYSYMBOL_map_expr: /* map_expr  */
#line 782 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6362 "parser_bison.tab.c"
        break;

    case YYSYMBOL_expr: /* expr  */
#line 801 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6368 "parser_bison.tab.c"
        break;

    case YYSYMBOL_set_expr: /* set_expr  */
#line 791 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6374 "parser_bison.tab.c"
        break;

    case YYSYMBOL_set_list_expr: /* set_list_expr  */
#line 791 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6380 "parser_bison.tab.c"
        break;

    case YYSYMBOL_set_list_member_expr: /* set_list_member_expr  */
#line 791 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6386 "parser_bison.tab.c"
        break;

    case YYSYMBOL_meter_key_expr: /* meter_key_expr  */
#line 798 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6392 "parser_bison.tab.c"
        break;

    case YYSYMBOL_meter_key_expr_alloc: /* meter_key_expr_alloc  */
#line 798 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6398 "parser_bison.tab.c"
        break;

    case YYSYMBOL_set_elem_expr: /* set_elem_expr  */
#line 793 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6404 "parser_bison.tab.c"
        break;

    case YYSYMBOL_set_elem_key_expr: /* set_elem_key_expr  */
#line 926 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6410 "parser_bison.tab.c"
        break;

    case YYSYMBOL_set_elem_expr_alloc: /* set_elem_expr_alloc  */
#line 793 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6416 "parser_bison.tab.c"
        break;

    case YYSYMBOL_set_elem_stmt_list: /* set_elem_stmt_list  */
#line 700 "../../nft/nftables/src/parser_bison.y"
            { stmt_list_free(((*yyvaluep).list)); xfree(((*yyvaluep).list)); }
#line 6422 "parser_bison.tab.c"
        break;

    case YYSYMBOL_set_elem_stmt: /* set_elem_stmt  */
#line 702 "../../nft/nftables/src/parser_bison.y"
            { stmt_free(((*yyvaluep).stmt)); }
#line 6428 "parser_bison.tab.c"
        break;

    case YYSYMBOL_set_lhs_expr: /* set_lhs_expr  */
#line 793 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6434 "parser_bison.tab.c"
        break;

    case YYSYMBOL_set_rhs_expr: /* set_rhs_expr  */
#line 793 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6440 "parser_bison.tab.c"
        break;

    case YYSYMBOL_initializer_expr: /* initializer_expr  */
#line 801 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6446 "parser_bison.tab.c"
        break;

    case YYSYMBOL_counter_obj: /* counter_obj  */
#line 811 "../../nft/nftables/src/parser_bison.y"
            { obj_free(((*yyvaluep).obj)); }
#line 6452 "parser_bison.tab.c"
        break;

    case YYSYMBOL_quota_obj: /* quota_obj  */
#line 811 "../../nft/nftables/src/parser_bison.y"
            { obj_free(((*yyvaluep).obj)); }
#line 6458 "parser_bison.tab.c"
        break;

    case YYSYMBOL_secmark_obj: /* secmark_obj  */
#line 811 "../../nft/nftables/src/parser_bison.y"
            { obj_free(((*yyvaluep).obj)); }
#line 6464 "parser_bison.tab.c"
        break;

    case YYSYMBOL_timeout_states: /* timeout_states  */
#line 919 "../../nft/nftables/src/parser_bison.y"
            { xfree(((*yyvaluep).list)); }
#line 6470 "parser_bison.tab.c"
        break;

    case YYSYMBOL_timeout_state: /* timeout_state  */
#line 919 "../../nft/nftables/src/parser_bison.y"
            { xfree(((*yyvaluep).list)); }
#line 6476 "parser_bison.tab.c"
        break;

    case YYSYMBOL_ct_obj_alloc: /* ct_obj_alloc  */
#line 811 "../../nft/nftables/src/parser_bison.y"
            { obj_free(((*yyvaluep).obj)); }
#line 6482 "parser_bison.tab.c"
        break;

    case YYSYMBOL_limit_obj: /* limit_obj  */
#line 811 "../../nft/nftables/src/parser_bison.y"
            { obj_free(((*yyvaluep).obj)); }
#line 6488 "parser_bison.tab.c"
        break;

    case YYSYMBOL_relational_expr: /* relational_expr  */
#line 814 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6494 "parser_bison.tab.c"
        break;

    case YYSYMBOL_list_rhs_expr: /* list_rhs_expr  */
#line 806 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6500 "parser_bison.tab.c"
        break;

    case YYSYMBOL_rhs_expr: /* rhs_expr  */
#line 804 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6506 "parser_bison.tab.c"
        break;

    case YYSYMBOL_shift_rhs_expr: /* shift_rhs_expr  */
#line 806 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6512 "parser_bison.tab.c"
        break;

    case YYSYMBOL_and_rhs_expr: /* and_rhs_expr  */
#line 808 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6518 "parser_bison.tab.c"
        break;

    case YYSYMBOL_exclusive_or_rhs_expr: /* exclusive_or_rhs_expr  */
#line 808 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6524 "parser_bison.tab.c"
        break;

    case YYSYMBOL_inclusive_or_rhs_expr: /* inclusive_or_rhs_expr  */
#line 808 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6530 "parser_bison.tab.c"
        break;

    case YYSYMBOL_basic_rhs_expr: /* basic_rhs_expr  */
#line 804 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6536 "parser_bison.tab.c"
        break;

    case YYSYMBOL_concat_rhs_expr: /* concat_rhs_expr  */
#line 804 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6542 "parser_bison.tab.c"
        break;

    case YYSYMBOL_boolean_expr: /* boolean_expr  */
#line 909 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6548 "parser_bison.tab.c"
        break;

    case YYSYMBOL_keyword_expr: /* keyword_expr  */
#line 801 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6554 "parser_bison.tab.c"
        break;

    case YYSYMBOL_primary_rhs_expr: /* primary_rhs_expr  */
#line 806 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6560 "parser_bison.tab.c"
        break;

    case YYSYMBOL_verdict_expr: /* verdict_expr  */
#line 748 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6566 "parser_bison.tab.c"
        break;

    case YYSYMBOL_chain_expr: /* chain_expr  */
#line 748 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6572 "parser_bison.tab.c"
        break;

    case YYSYMBOL_meta_expr: /* meta_expr  */
#line 862 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6578 "parser_bison.tab.c"
        break;

    case YYSYMBOL_meta_stmt: /* meta_stmt  */
#line 710 "../../nft/nftables/src/parser_bison.y"
            { stmt_free(((*yyvaluep).stmt)); }
#line 6584 "parser_bison.tab.c"
        break;

    case YYSYMBOL_socket_expr: /* socket_expr  */
#line 866 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6590 "parser_bison.tab.c"
        break;

    case YYSYMBOL_numgen_expr: /* numgen_expr  */
#line 827 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6596 "parser_bison.tab.c"
        break;

    case YYSYMBOL_xfrm_expr: /* xfrm_expr  */
#line 923 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6602 "parser_bison.tab.c"
        break;

    case YYSYMBOL_hash_expr: /* hash_expr  */
#line 827 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6608 "parser_bison.tab.c"
        break;

    case YYSYMBOL_rt_expr: /* rt_expr  */
#line 872 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6614 "parser_bison.tab.c"
        break;

    case YYSYMBOL_ct_expr: /* ct_expr  */
#line 876 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6620 "parser_bison.tab.c"
        break;

    case YYSYMBOL_symbol_stmt_expr: /* symbol_stmt_expr  */
#line 806 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6626 "parser_bison.tab.c"
        break;

    case YYSYMBOL_list_stmt_expr: /* list_stmt_expr  */
#line 774 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6632 "parser_bison.tab.c"
        break;

    case YYSYMBOL_ct_stmt: /* ct_stmt  */
#line 708 "../../nft/nftables/src/parser_bison.y"
            { stmt_free(((*yyvaluep).stmt)); }
#line 6638 "parser_bison.tab.c"
        break;

    case YYSYMBOL_payload_stmt: /* payload_stmt  */
#line 706 "../../nft/nftables/src/parser_bison.y"
            { stmt_free(((*yyvaluep).stmt)); }
#line 6644 "parser_bison.tab.c"
        break;

    case YYSYMBOL_payload_expr: /* payload_expr  */
#line 818 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6650 "parser_bison.tab.c"
        break;

    case YYSYMBOL_payload_raw_expr: /* payload_raw_expr  */
#line 818 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6656 "parser_bison.tab.c"
        break;

    case YYSYMBOL_eth_hdr_expr: /* eth_hdr_expr  */
#line 821 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6662 "parser_bison.tab.c"
        break;

    case YYSYMBOL_vlan_hdr_expr: /* vlan_hdr_expr  */
#line 821 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6668 "parser_bison.tab.c"
        break;

    case YYSYMBOL_arp_hdr_expr: /* arp_hdr_expr  */
#line 824 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6674 "parser_bison.tab.c"
        break;

    case YYSYMBOL_ip_hdr_expr: /* ip_hdr_expr  */
#line 827 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6680 "parser_bison.tab.c"
        break;

    case YYSYMBOL_icmp_hdr_expr: /* icmp_hdr_expr  */
#line 827 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6686 "parser_bison.tab.c"
        break;

    case YYSYMBOL_igmp_hdr_expr: /* igmp_hdr_expr  */
#line 827 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6692 "parser_bison.tab.c"
        break;

    case YYSYMBOL_ip6_hdr_expr: /* ip6_hdr_expr  */
#line 831 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6698 "parser_bison.tab.c"
        break;

    case YYSYMBOL_icmp6_hdr_expr: /* icmp6_hdr_expr  */
#line 831 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6704 "parser_bison.tab.c"
        break;

    case YYSYMBOL_auth_hdr_expr: /* auth_hdr_expr  */
#line 834 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6710 "parser_bison.tab.c"
        break;

    case YYSYMBOL_esp_hdr_expr: /* esp_hdr_expr  */
#line 834 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6716 "parser_bison.tab.c"
        break;

    case YYSYMBOL_comp_hdr_expr: /* comp_hdr_expr  */
#line 834 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6722 "parser_bison.tab.c"
        break;

    case YYSYMBOL_udp_hdr_expr: /* udp_hdr_expr  */
#line 837 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6728 "parser_bison.tab.c"
        break;

    case YYSYMBOL_udplite_hdr_expr: /* udplite_hdr_expr  */
#line 837 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6734 "parser_bison.tab.c"
        break;

    case YYSYMBOL_tcp_hdr_expr: /* tcp_hdr_expr  */
#line 895 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6740 "parser_bison.tab.c"
        break;

    case YYSYMBOL_optstrip_stmt: /* optstrip_stmt  */
#line 903 "../../nft/nftables/src/parser_bison.y"
            { stmt_free(((*yyvaluep).stmt)); }
#line 6746 "parser_bison.tab.c"
        break;

    case YYSYMBOL_dccp_hdr_expr: /* dccp_hdr_expr  */
#line 840 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6752 "parser_bison.tab.c"
        break;

    case YYSYMBOL_sctp_chunk_alloc: /* sctp_chunk_alloc  */
#line 840 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6758 "parser_bison.tab.c"
        break;

    case YYSYMBOL_sctp_hdr_expr: /* sctp_hdr_expr  */
#line 840 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6764 "parser_bison.tab.c"
        break;

    case YYSYMBOL_th_hdr_expr: /* th_hdr_expr  */
#line 846 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6770 "parser_bison.tab.c"
        break;

    case YYSYMBOL_exthdr_expr: /* exthdr_expr  */
#line 850 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6776 "parser_bison.tab.c"
        break;

    case YYSYMBOL_hbh_hdr_expr: /* hbh_hdr_expr  */
#line 852 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6782 "parser_bison.tab.c"
        break;

    case YYSYMBOL_rt_hdr_expr: /* rt_hdr_expr  */
#line 855 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6788 "parser_bison.tab.c"
        break;

    case YYSYMBOL_rt0_hdr_expr: /* rt0_hdr_expr  */
#line 855 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6794 "parser_bison.tab.c"
        break;

    case YYSYMBOL_rt2_hdr_expr: /* rt2_hdr_expr  */
#line 855 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6800 "parser_bison.tab.c"
        break;

    case YYSYMBOL_rt4_hdr_expr: /* rt4_hdr_expr  */
#line 855 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6806 "parser_bison.tab.c"
        break;

    case YYSYMBOL_frag_hdr_expr: /* frag_hdr_expr  */
#line 852 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6812 "parser_bison.tab.c"
        break;

    case YYSYMBOL_dst_hdr_expr: /* dst_hdr_expr  */
#line 852 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6818 "parser_bison.tab.c"
        break;

    case YYSYMBOL_mh_hdr_expr: /* mh_hdr_expr  */
#line 858 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6824 "parser_bison.tab.c"
        break;

    case YYSYMBOL_exthdr_exists_expr: /* exthdr_exists_expr  */
#line 913 "../../nft/nftables/src/parser_bison.y"
            { expr_free(((*yyvaluep).expr)); }
#line 6830 "parser_bison.tab.c"
        break;

      default:
        break;
    }
  YY_IGNORE_MAYBE_UNINITIALIZED_END
}






/*----------.
| yyparse.  |
`----------*/

int
yyparse (struct nft_ctx *nft, void *scanner, struct parser_state *state)
{
/* Lookahead token kind.  */
int yychar;


/* The semantic value of the lookahead symbol.  */
/* Default value used for initialization, for pacifying older GCCs
   or non-GCC compilers.  */
YY_INITIAL_VALUE (static YYSTYPE yyval_default;)
YYSTYPE yylval YY_INITIAL_VALUE (= yyval_default);

/* Location data for the lookahead symbol.  */
static YYLTYPE yyloc_default
# if defined NFT_LTYPE_IS_TRIVIAL && NFT_LTYPE_IS_TRIVIAL
  = { 1, 1, 1, 1 }
# endif
;
YYLTYPE yylloc = yyloc_default;

    /* Number of syntax errors so far.  */
    int yynerrs = 0;

    yy_state_fast_t yystate = 0;
    /* Number of tokens to shift before error messages enabled.  */
    int yyerrstatus = 0;

    /* Refer to the stacks through separate pointers, to allow yyoverflow
       to reallocate them elsewhere.  */

    /* Their size.  */
    YYPTRDIFF_T yystacksize = YYINITDEPTH;

    /* The state stack: array, bottom, top.  */
    yy_state_t yyssa[YYINITDEPTH];
    yy_state_t *yyss = yyssa;
    yy_state_t *yyssp = yyss;

    /* The semantic value stack: array, bottom, top.  */
    YYSTYPE yyvsa[YYINITDEPTH];
    YYSTYPE *yyvs = yyvsa;
    YYSTYPE *yyvsp = yyvs;

    /* The location stack: array, bottom, top.  */
    YYLTYPE yylsa[YYINITDEPTH];
    YYLTYPE *yyls = yylsa;
    YYLTYPE *yylsp = yyls;

  int yyn;
  /* The return value of yyparse.  */
  int yyresult;
  /* Lookahead symbol kind.  */
  yysymbol_kind_t yytoken = YYSYMBOL_YYEMPTY;
  /* The variables used to return semantic value and location from the
     action routines.  */
  YYSTYPE yyval;
  YYLTYPE yyloc;

  /* The locations where the error started and ended.  */
  YYLTYPE yyerror_range[3];

  /* Buffer for error messages, and its allocated size.  */
  char yymsgbuf[128];
  char *yymsg = yymsgbuf;
  YYPTRDIFF_T yymsg_alloc = sizeof yymsgbuf;

#define YYPOPSTACK(N)   (yyvsp -= (N), yyssp -= (N), yylsp -= (N))

  /* The number of symbols on the RHS of the reduced rule.
     Keep to zero when no symbol should be popped.  */
  int yylen = 0;

  YYDPRINTF ((stderr, "Starting parse\n"));

  yychar = NFT_EMPTY; /* Cause a token to be read.  */


/* User initialization code.  */
#line 170 "../../nft/nftables/src/parser_bison.y"
{
	location_init(scanner, state, &yylloc);
	if (nft->debug_mask & NFT_DEBUG_SCANNER)
		nft_set_debug(1, scanner);
	if (nft->debug_mask & NFT_DEBUG_PARSER)
		yydebug = 1;
}

#line 6936 "parser_bison.tab.c"

  yylsp[0] = yylloc;
  goto yysetstate;


/*------------------------------------------------------------.
| yynewstate -- push a new state, which is found in yystate.  |
`------------------------------------------------------------*/
yynewstate:
  /* In all cases, when you get here, the value and location stacks
     have just been pushed.  So pushing a state here evens the stacks.  */
  yyssp++;


/*--------------------------------------------------------------------.
| yysetstate -- set current state (the top of the stack) to yystate.  |
`--------------------------------------------------------------------*/
yysetstate:
  YYDPRINTF ((stderr, "Entering state %d\n", yystate));
  YY_ASSERT (0 <= yystate && yystate < YYNSTATES);
  YY_IGNORE_USELESS_CAST_BEGIN
  *yyssp = YY_CAST (yy_state_t, yystate);
  YY_IGNORE_USELESS_CAST_END
  YY_STACK_PRINT (yyss, yyssp);

  if (yyss + yystacksize - 1 <= yyssp)
#if !defined yyoverflow && !defined YYSTACK_RELOCATE
    YYNOMEM;
#else
    {
      /* Get the current used size of the three stacks, in elements.  */
      YYPTRDIFF_T yysize = yyssp - yyss + 1;

# if defined yyoverflow
      {
        /* Give user a chance to reallocate the stack.  Use copies of
           these so that the &'s don't force the real ones into
           memory.  */
        yy_state_t *yyss1 = yyss;
        YYSTYPE *yyvs1 = yyvs;
        YYLTYPE *yyls1 = yyls;

        /* Each stack pointer address is followed by the size of the
           data in use in that stack, in bytes.  This used to be a
           conditional around just the two extra args, but that might
           be undefined if yyoverflow is a macro.  */
        yyoverflow (YY_("memory exhausted"),
                    &yyss1, yysize * YYSIZEOF (*yyssp),
                    &yyvs1, yysize * YYSIZEOF (*yyvsp),
                    &yyls1, yysize * YYSIZEOF (*yylsp),
                    &yystacksize);
        yyss = yyss1;
        yyvs = yyvs1;
        yyls = yyls1;
      }
# else /* defined YYSTACK_RELOCATE */
      /* Extend the stack our own way.  */
      if (YYMAXDEPTH <= yystacksize)
        YYNOMEM;
      yystacksize *= 2;
      if (YYMAXDEPTH < yystacksize)
        yystacksize = YYMAXDEPTH;

      {
        yy_state_t *yyss1 = yyss;
        union yyalloc *yyptr =
          YY_CAST (union yyalloc *,
                   YYSTACK_ALLOC (YY_CAST (YYSIZE_T, YYSTACK_BYTES (yystacksize))));
        if (! yyptr)
          YYNOMEM;
        YYSTACK_RELOCATE (yyss_alloc, yyss);
        YYSTACK_RELOCATE (yyvs_alloc, yyvs);
        YYSTACK_RELOCATE (yyls_alloc, yyls);
#  undef YYSTACK_RELOCATE
        if (yyss1 != yyssa)
          YYSTACK_FREE (yyss1);
      }
# endif

      yyssp = yyss + yysize - 1;
      yyvsp = yyvs + yysize - 1;
      yylsp = yyls + yysize - 1;

      YY_IGNORE_USELESS_CAST_BEGIN
      YYDPRINTF ((stderr, "Stack size increased to %ld\n",
                  YY_CAST (long, yystacksize)));
      YY_IGNORE_USELESS_CAST_END

      if (yyss + yystacksize - 1 <= yyssp)
        YYABORT;
    }
#endif /* !defined yyoverflow && !defined YYSTACK_RELOCATE */


  if (yystate == YYFINAL)
    YYACCEPT;

  goto yybackup;


/*-----------.
| yybackup.  |
`-----------*/
yybackup:
  /* Do appropriate processing given the current state.  Read a
     lookahead token if we need one and don't already have one.  */

  /* First try to decide what to do without reference to lookahead token.  */
  yyn = yypact[yystate];
  if (yypact_value_is_default (yyn))
    goto yydefault;

  /* Not known => get a lookahead token if don't already have one.  */

  /* YYCHAR is either empty, or end-of-input, or a valid lookahead.  */
  if (yychar == NFT_EMPTY)
    {
      YYDPRINTF ((stderr, "Reading a token\n"));
      yychar = yylex (&yylval, &yylloc, scanner);
    }

  if (yychar <= TOKEN_EOF)
    {
      yychar = TOKEN_EOF;
      yytoken = YYSYMBOL_YYEOF;
      YYDPRINTF ((stderr, "Now at end of input.\n"));
    }
  else if (yychar == NFT_error)
    {
      /* The scanner already issued an error message, process directly
         to error recovery.  But do not keep the error token as
         lookahead, it is too special and may lead us to an endless
         loop in error recovery. */
      yychar = NFT_UNDEF;
      yytoken = YYSYMBOL_YYerror;
      yyerror_range[1] = yylloc;
      goto yyerrlab1;
    }
  else
    {
      yytoken = YYTRANSLATE (yychar);
      YY_SYMBOL_PRINT ("Next token is", yytoken, &yylval, &yylloc);
    }

  /* If the proper action on seeing token YYTOKEN is to reduce or to
     detect an error, take that action.  */
  yyn += yytoken;
  if (yyn < 0 || YYLAST < yyn || yycheck[yyn] != yytoken)
    goto yydefault;
  yyn = yytable[yyn];
  if (yyn <= 0)
    {
      if (yytable_value_is_error (yyn))
        goto yyerrlab;
      yyn = -yyn;
      goto yyreduce;
    }

  /* Count tokens shifted since error; after three, turn off error
     status.  */
  if (yyerrstatus)
    yyerrstatus--;

  /* Shift the lookahead token.  */
  YY_SYMBOL_PRINT ("Shifting", yytoken, &yylval, &yylloc);
  yystate = yyn;
  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  *++yyvsp = yylval;
  YY_IGNORE_MAYBE_UNINITIALIZED_END
  *++yylsp = yylloc;

  /* Discard the shifted token.  */
  yychar = NFT_EMPTY;
  goto yynewstate;


/*-----------------------------------------------------------.
| yydefault -- do the default action for the current state.  |
`-----------------------------------------------------------*/
yydefault:
  yyn = yydefact[yystate];
  if (yyn == 0)
    goto yyerrlab;
  goto yyreduce;


/*-----------------------------.
| yyreduce -- do a reduction.  |
`-----------------------------*/
yyreduce:
  /* yyn is the number of a rule to reduce with.  */
  yylen = yyr2[yyn];

  /* If YYLEN is nonzero, implement the default value of the action:
     '$$ = $1'.

     Otherwise, the following line sets YYVAL to garbage.
     This behavior is undocumented and Bison
     users should not rely upon it.  Assigning to YYVAL
     unconditionally makes the parser a bit smaller, and it avoids a
     GCC warning that YYVAL may be used uninitialized.  */
  yyval = yyvsp[1-yylen];

  /* Default location. */
  YYLLOC_DEFAULT (yyloc, (yylsp - yylen), yylen);
  yyerror_range[1] = yyloc;
  YY_REDUCE_PRINT (yyn);
  switch (yyn)
    {
  case 3: /* input: input line  */
#line 932 "../../nft/nftables/src/parser_bison.y"
                        {
				if ((yyvsp[0].cmd) != NULL) {
					(yyvsp[0].cmd)->location = (yylsp[0]);
					list_add_tail(&(yyvsp[0].cmd)->list, state->cmds);
				}
			}
#line 7154 "parser_bison.tab.c"
    break;

  case 8: /* close_scope_ah: %empty  */
#line 948 "../../nft/nftables/src/parser_bison.y"
                          { scanner_pop_start_cond(nft->scanner, PARSER_SC_EXPR_AH); }
#line 7160 "parser_bison.tab.c"
    break;

  case 9: /* close_scope_arp: %empty  */
#line 949 "../../nft/nftables/src/parser_bison.y"
                          { scanner_pop_start_cond(nft->scanner, PARSER_SC_ARP); }
#line 7166 "parser_bison.tab.c"
    break;

  case 10: /* close_scope_at: %empty  */
#line 950 "../../nft/nftables/src/parser_bison.y"
                          { scanner_pop_start_cond(nft->scanner, PARSER_SC_AT); }
#line 7172 "parser_bison.tab.c"
    break;

  case 11: /* close_scope_comp: %empty  */
#line 951 "../../nft/nftables/src/parser_bison.y"
                          { scanner_pop_start_cond(nft->scanner, PARSER_SC_EXPR_COMP); }
#line 7178 "parser_bison.tab.c"
    break;

  case 12: /* close_scope_ct: %empty  */
#line 952 "../../nft/nftables/src/parser_bison.y"
                          { scanner_pop_start_cond(nft->scanner, PARSER_SC_CT); }
#line 7184 "parser_bison.tab.c"
    break;

  case 13: /* close_scope_counter: %empty  */
#line 953 "../../nft/nftables/src/parser_bison.y"
                          { scanner_pop_start_cond(nft->scanner, PARSER_SC_COUNTER); }
#line 7190 "parser_bison.tab.c"
    break;

  case 14: /* close_scope_dccp: %empty  */
#line 954 "../../nft/nftables/src/parser_bison.y"
                          { scanner_pop_start_cond(nft->scanner, PARSER_SC_EXPR_DCCP); }
#line 7196 "parser_bison.tab.c"
    break;

  case 15: /* close_scope_dst: %empty  */
#line 955 "../../nft/nftables/src/parser_bison.y"
                          { scanner_pop_start_cond(nft->scanner, PARSER_SC_EXPR_DST); }
#line 7202 "parser_bison.tab.c"
    break;

  case 16: /* close_scope_dup: %empty  */
#line 956 "../../nft/nftables/src/parser_bison.y"
                          { scanner_pop_start_cond(nft->scanner, PARSER_SC_STMT_DUP); }
#line 7208 "parser_bison.tab.c"
    break;

  case 17: /* close_scope_esp: %empty  */
#line 957 "../../nft/nftables/src/parser_bison.y"
                          { scanner_pop_start_cond(nft->scanner, PARSER_SC_EXPR_ESP); }
#line 7214 "parser_bison.tab.c"
    break;

  case 18: /* close_scope_eth: %empty  */
#line 958 "../../nft/nftables/src/parser_bison.y"
                          { scanner_pop_start_cond(nft->scanner, PARSER_SC_ETH); }
#line 7220 "parser_bison.tab.c"
    break;

  case 19: /* close_scope_export: %empty  */
#line 959 "../../nft/nftables/src/parser_bison.y"
                          { scanner_pop_start_cond(nft->scanner, PARSER_SC_CMD_EXPORT); }
#line 7226 "parser_bison.tab.c"
    break;

  case 20: /* close_scope_fib: %empty  */
#line 960 "../../nft/nftables/src/parser_bison.y"
                          { scanner_pop_start_cond(nft->scanner, PARSER_SC_EXPR_FIB); }
#line 7232 "parser_bison.tab.c"
    break;

  case 21: /* close_scope_frag: %empty  */
#line 961 "../../nft/nftables/src/parser_bison.y"
                          { scanner_pop_start_cond(nft->scanner, PARSER_SC_EXPR_FRAG); }
#line 7238 "parser_bison.tab.c"
    break;

  case 22: /* close_scope_fwd: %empty  */
#line 962 "../../nft/nftables/src/parser_bison.y"
                          { scanner_pop_start_cond(nft->scanner, PARSER_SC_STMT_FWD); }
#line 7244 "parser_bison.tab.c"
    break;

  case 23: /* close_scope_hash: %empty  */
#line 963 "../../nft/nftables/src/parser_bison.y"
                          { scanner_pop_start_cond(nft->scanner, PARSER_SC_EXPR_HASH); }
#line 7250 "parser_bison.tab.c"
    break;

  case 24: /* close_scope_hbh: %empty  */
#line 964 "../../nft/nftables/src/parser_bison.y"
                          { scanner_pop_start_cond(nft->scanner, PARSER_SC_EXPR_HBH); }
#line 7256 "parser_bison.tab.c"
    break;

  case 25: /* close_scope_ip: %empty  */
#line 965 "../../nft/nftables/src/parser_bison.y"
                          { scanner_pop_start_cond(nft->scanner, PARSER_SC_IP); }
#line 7262 "parser_bison.tab.c"
    break;

  case 26: /* close_scope_ip6: %empty  */
#line 966 "../../nft/nftables/src/parser_bison.y"
                          { scanner_pop_start_cond(nft->scanner, PARSER_SC_IP6); }
#line 7268 "parser_bison.tab.c"
    break;

  case 27: /* close_scope_vlan: %empty  */
#line 967 "../../nft/nftables/src/parser_bison.y"
                          { scanner_pop_start_cond(nft->scanner, PARSER_SC_VLAN); }
#line 7274 "parser_bison.tab.c"
    break;

  case 28: /* close_scope_icmp: %empty  */
#line 968 "../../nft/nftables/src/parser_bison.y"
                          { scanner_pop_start_cond(nft->scanner, PARSER_SC_ICMP); }
#line 7280 "parser_bison.tab.c"
    break;

  case 29: /* close_scope_igmp: %empty  */
#line 969 "../../nft/nftables/src/parser_bison.y"
                          { scanner_pop_start_cond(nft->scanner, PARSER_SC_IGMP); }
#line 7286 "parser_bison.tab.c"
    break;

  case 30: /* close_scope_import: %empty  */
#line 970 "../../nft/nftables/src/parser_bison.y"
                          { scanner_pop_start_cond(nft->scanner, PARSER_SC_CMD_IMPORT); }
#line 7292 "parser_bison.tab.c"
    break;

  case 31: /* close_scope_ipsec: %empty  */
#line 971 "../../nft/nftables/src/parser_bison.y"
                          { scanner_pop_start_cond(nft->scanner, PARSER_SC_EXPR_IPSEC); }
#line 7298 "parser_bison.tab.c"
    break;

  case 32: /* close_scope_list: %empty  */
#line 972 "../../nft/nftables/src/parser_bison.y"
                          { scanner_pop_start_cond(nft->scanner, PARSER_SC_CMD_LIST); }
#line 7304 "parser_bison.tab.c"
    break;

  case 33: /* close_scope_limit: %empty  */
#line 973 "../../nft/nftables/src/parser_bison.y"
                          { scanner_pop_start_cond(nft->scanner, PARSER_SC_LIMIT); }
#line 7310 "parser_bison.tab.c"
    break;

  case 34: /* close_scope_meta: %empty  */
#line 974 "../../nft/nftables/src/parser_bison.y"
                          { scanner_pop_start_cond(nft->scanner, PARSER_SC_META); }
#line 7316 "parser_bison.tab.c"
    break;

  case 35: /* close_scope_mh: %empty  */
#line 975 "../../nft/nftables/src/parser_bison.y"
                          { scanner_pop_start_cond(nft->scanner, PARSER_SC_EXPR_MH); }
#line 7322 "parser_bison.tab.c"
    break;

  case 36: /* close_scope_monitor: %empty  */
#line 976 "../../nft/nftables/src/parser_bison.y"
                          { scanner_pop_start_cond(nft->scanner, PARSER_SC_CMD_MONITOR); }
#line 7328 "parser_bison.tab.c"
    break;

  case 37: /* close_scope_nat: %empty  */
#line 977 "../../nft/nftables/src/parser_bison.y"
                          { scanner_pop_start_cond(nft->scanner, PARSER_SC_STMT_NAT); }
#line 7334 "parser_bison.tab.c"
    break;

  case 38: /* close_scope_numgen: %empty  */
#line 978 "../../nft/nftables/src/parser_bison.y"
                          { scanner_pop_start_cond(nft->scanner, PARSER_SC_EXPR_NUMGEN); }
#line 7340 "parser_bison.tab.c"
    break;

  case 39: /* close_scope_osf: %empty  */
#line 979 "../../nft/nftables/src/parser_bison.y"
                          { scanner_pop_start_cond(nft->scanner, PARSER_SC_EXPR_OSF); }
#line 7346 "parser_bison.tab.c"
    break;

  case 40: /* close_scope_policy: %empty  */
#line 980 "../../nft/nftables/src/parser_bison.y"
                          { scanner_pop_start_cond(nft->scanner, PARSER_SC_POLICY); }
#line 7352 "parser_bison.tab.c"
    break;

  case 41: /* close_scope_quota: %empty  */
#line 981 "../../nft/nftables/src/parser_bison.y"
                          { scanner_pop_start_cond(nft->scanner, PARSER_SC_QUOTA); }
#line 7358 "parser_bison.tab.c"
    break;

  case 42: /* close_scope_queue: %empty  */
#line 982 "../../nft/nftables/src/parser_bison.y"
                          { scanner_pop_start_cond(nft->scanner, PARSER_SC_EXPR_QUEUE); }
#line 7364 "parser_bison.tab.c"
    break;

  case 43: /* close_scope_reject: %empty  */
#line 983 "../../nft/nftables/src/parser_bison.y"
                          { scanner_pop_start_cond(nft->scanner, PARSER_SC_STMT_REJECT); }
#line 7370 "parser_bison.tab.c"
    break;

  case 44: /* close_scope_reset: %empty  */
#line 984 "../../nft/nftables/src/parser_bison.y"
                          { scanner_pop_start_cond(nft->scanner, PARSER_SC_CMD_RESET); }
#line 7376 "parser_bison.tab.c"
    break;

  case 45: /* close_scope_rt: %empty  */
#line 985 "../../nft/nftables/src/parser_bison.y"
                          { scanner_pop_start_cond(nft->scanner, PARSER_SC_EXPR_RT); }
#line 7382 "parser_bison.tab.c"
    break;

  case 46: /* close_scope_sctp: %empty  */
#line 986 "../../nft/nftables/src/parser_bison.y"
                          { scanner_pop_start_cond(nft->scanner, PARSER_SC_SCTP); }
#line 7388 "parser_bison.tab.c"
    break;

  case 47: /* close_scope_sctp_chunk: %empty  */
#line 987 "../../nft/nftables/src/parser_bison.y"
                          { scanner_pop_start_cond(nft->scanner, PARSER_SC_EXPR_SCTP_CHUNK); }
#line 7394 "parser_bison.tab.c"
    break;

  case 48: /* close_scope_secmark: %empty  */
#line 988 "../../nft/nftables/src/parser_bison.y"
                          { scanner_pop_start_cond(nft->scanner, PARSER_SC_SECMARK); }
#line 7400 "parser_bison.tab.c"
    break;

  case 49: /* close_scope_socket: %empty  */
#line 989 "../../nft/nftables/src/parser_bison.y"
                          { scanner_pop_start_cond(nft->scanner, PARSER_SC_EXPR_SOCKET); }
#line 7406 "parser_bison.tab.c"
    break;

  case 50: /* close_scope_tcp: %empty  */
#line 990 "../../nft/nftables/src/parser_bison.y"
                          { scanner_pop_start_cond(nft->scanner, PARSER_SC_TCP); }
#line 7412 "parser_bison.tab.c"
    break;

  case 51: /* close_scope_tproxy: %empty  */
#line 991 "../../nft/nftables/src/parser_bison.y"
                          { scanner_pop_start_cond(nft->scanner, PARSER_SC_STMT_TPROXY); }
#line 7418 "parser_bison.tab.c"
    break;

  case 52: /* close_scope_type: %empty  */
#line 992 "../../nft/nftables/src/parser_bison.y"
                          { scanner_pop_start_cond(nft->scanner, PARSER_SC_TYPE); }
#line 7424 "parser_bison.tab.c"
    break;

  case 53: /* close_scope_th: %empty  */
#line 993 "../../nft/nftables/src/parser_bison.y"
                          { scanner_pop_start_cond(nft->scanner, PARSER_SC_EXPR_TH); }
#line 7430 "parser_bison.tab.c"
    break;

  case 54: /* close_scope_udp: %empty  */
#line 994 "../../nft/nftables/src/parser_bison.y"
                          { scanner_pop_start_cond(nft->scanner, PARSER_SC_EXPR_UDP); }
#line 7436 "parser_bison.tab.c"
    break;

  case 55: /* close_scope_udplite: %empty  */
#line 995 "../../nft/nftables/src/parser_bison.y"
                          { scanner_pop_start_cond(nft->scanner, PARSER_SC_EXPR_UDPLITE); }
#line 7442 "parser_bison.tab.c"
    break;

  case 56: /* close_scope_log: %empty  */
#line 997 "../../nft/nftables/src/parser_bison.y"
                          { scanner_pop_start_cond(nft->scanner, PARSER_SC_STMT_LOG); }
#line 7448 "parser_bison.tab.c"
    break;

  case 57: /* close_scope_synproxy: %empty  */
#line 998 "../../nft/nftables/src/parser_bison.y"
                          { scanner_pop_start_cond(nft->scanner, PARSER_SC_STMT_SYNPROXY); }
#line 7454 "parser_bison.tab.c"
    break;

  case 58: /* close_scope_xt: %empty  */
#line 999 "../../nft/nftables/src/parser_bison.y"
                          { scanner_pop_start_cond(nft->scanner, PARSER_SC_XT); }
#line 7460 "parser_bison.tab.c"
    break;

  case 59: /* common_block: "include" "quoted string" stmt_separator  */
#line 1002 "../../nft/nftables/src/parser_bison.y"
                        {
				if (scanner_include_file(nft, scanner, (yyvsp[-1].string), &(yyloc)) < 0) {
					xfree((yyvsp[-1].string));
					YYERROR;
				}
				xfree((yyvsp[-1].string));
			}
#line 7472 "parser_bison.tab.c"
    break;

  case 60: /* common_block: "define" identifier '=' initializer_expr stmt_separator  */
#line 1010 "../../nft/nftables/src/parser_bison.y"
                        {
				struct scope *scope = current_scope(state);

				if (symbol_lookup(scope, (yyvsp[-3].string)) != NULL) {
					erec_queue(error(&(yylsp[-3]), "redefinition of symbol '%s'", (yyvsp[-3].string)),
						   state->msgs);
					expr_free((yyvsp[-1].expr));
					xfree((yyvsp[-3].string));
					YYERROR;
				}

				symbol_bind(scope, (yyvsp[-3].string), (yyvsp[-1].expr));
				xfree((yyvsp[-3].string));
			}
#line 7491 "parser_bison.tab.c"
    break;

  case 61: /* common_block: "redefine" identifier '=' initializer_expr stmt_separator  */
#line 1025 "../../nft/nftables/src/parser_bison.y"
                        {
				struct scope *scope = current_scope(state);

				symbol_bind(scope, (yyvsp[-3].string), (yyvsp[-1].expr));
				xfree((yyvsp[-3].string));
			}
#line 7502 "parser_bison.tab.c"
    break;

  case 62: /* common_block: "undefine" identifier stmt_separator  */
#line 1032 "../../nft/nftables/src/parser_bison.y"
                        {
				struct scope *scope = current_scope(state);

				if (symbol_unbind(scope, (yyvsp[-1].string)) < 0) {
					erec_queue(error(&(yylsp[-1]), "undefined symbol '%s'", (yyvsp[-1].string)),
						   state->msgs);
					xfree((yyvsp[-1].string));
					YYERROR;
				}
				xfree((yyvsp[-1].string));
			}
#line 7518 "parser_bison.tab.c"
    break;

  case 63: /* common_block: error stmt_separator  */
#line 1044 "../../nft/nftables/src/parser_bison.y"
                        {
				if (++state->nerrs == nft->parser_max_errors)
					YYABORT;
				yyerrok;
			}
#line 7528 "parser_bison.tab.c"
    break;

  case 64: /* line: common_block  */
#line 1051 "../../nft/nftables/src/parser_bison.y"
                                                                { (yyval.cmd) = NULL; }
#line 7534 "parser_bison.tab.c"
    break;

  case 65: /* line: stmt_separator  */
#line 1052 "../../nft/nftables/src/parser_bison.y"
                                                                { (yyval.cmd) = NULL; }
#line 7540 "parser_bison.tab.c"
    break;

  case 66: /* line: base_cmd stmt_separator  */
#line 1053 "../../nft/nftables/src/parser_bison.y"
                                                                { (yyval.cmd) = (yyvsp[-1].cmd); }
#line 7546 "parser_bison.tab.c"
    break;

  case 67: /* line: base_cmd "end of file"  */
#line 1055 "../../nft/nftables/src/parser_bison.y"
                        {
				/*
				 * Very hackish workaround for bison >= 2.4: previous versions
				 * terminated parsing after EOF, 2.4+ tries to get further input
				 * in 'input' and calls the scanner again, causing a crash when
				 * the final input buffer has been popped. Terminate manually to
				 * avoid this. The correct fix should be to adjust the grammar
				 * to accept EOF in input, but for unknown reasons it does not
				 * work.
				 */
				if ((yyvsp[-1].cmd) != NULL) {
					(yyvsp[-1].cmd)->location = (yylsp[-1]);
					list_add_tail(&(yyvsp[-1].cmd)->list, state->cmds);
				}
				(yyval.cmd) = NULL;
				YYACCEPT;
			}
#line 7568 "parser_bison.tab.c"
    break;

  case 68: /* base_cmd: add_cmd  */
#line 1074 "../../nft/nftables/src/parser_bison.y"
                                                                { (yyval.cmd) = (yyvsp[0].cmd); }
#line 7574 "parser_bison.tab.c"
    break;

  case 69: /* base_cmd: "add" add_cmd  */
#line 1075 "../../nft/nftables/src/parser_bison.y"
                                                                { (yyval.cmd) = (yyvsp[0].cmd); }
#line 7580 "parser_bison.tab.c"
    break;

  case 70: /* base_cmd: "replace" replace_cmd  */
#line 1076 "../../nft/nftables/src/parser_bison.y"
                                                                { (yyval.cmd) = (yyvsp[0].cmd); }
#line 7586 "parser_bison.tab.c"
    break;

  case 71: /* base_cmd: "create" create_cmd  */
#line 1077 "../../nft/nftables/src/parser_bison.y"
                                                                { (yyval.cmd) = (yyvsp[0].cmd); }
#line 7592 "parser_bison.tab.c"
    break;

  case 72: /* base_cmd: "insert" insert_cmd  */
#line 1078 "../../nft/nftables/src/parser_bison.y"
                                                                { (yyval.cmd) = (yyvsp[0].cmd); }
#line 7598 "parser_bison.tab.c"
    break;

  case 73: /* base_cmd: "delete" delete_cmd  */
#line 1079 "../../nft/nftables/src/parser_bison.y"
                                                                { (yyval.cmd) = (yyvsp[0].cmd); }
#line 7604 "parser_bison.tab.c"
    break;

  case 74: /* base_cmd: "get" get_cmd  */
#line 1080 "../../nft/nftables/src/parser_bison.y"
                                                                { (yyval.cmd) = (yyvsp[0].cmd); }
#line 7610 "parser_bison.tab.c"
    break;

  case 75: /* base_cmd: "list" list_cmd close_scope_list  */
#line 1081 "../../nft/nftables/src/parser_bison.y"
                                                                                        { (yyval.cmd) = (yyvsp[-1].cmd); }
#line 7616 "parser_bison.tab.c"
    break;

  case 76: /* base_cmd: "reset" reset_cmd close_scope_reset  */
#line 1082 "../../nft/nftables/src/parser_bison.y"
                                                                                        { (yyval.cmd) = (yyvsp[-1].cmd); }
#line 7622 "parser_bison.tab.c"
    break;

  case 77: /* base_cmd: "flush" flush_cmd  */
#line 1083 "../../nft/nftables/src/parser_bison.y"
                                                                { (yyval.cmd) = (yyvsp[0].cmd); }
#line 7628 "parser_bison.tab.c"
    break;

  case 78: /* base_cmd: "rename" rename_cmd  */
#line 1084 "../../nft/nftables/src/parser_bison.y"
                                                                { (yyval.cmd) = (yyvsp[0].cmd); }
#line 7634 "parser_bison.tab.c"
    break;

  case 79: /* base_cmd: "import" import_cmd close_scope_import  */
#line 1085 "../../nft/nftables/src/parser_bison.y"
                                                                                        { (yyval.cmd) = (yyvsp[-1].cmd); }
#line 7640 "parser_bison.tab.c"
    break;

  case 80: /* base_cmd: "export" export_cmd close_scope_export  */
#line 1086 "../../nft/nftables/src/parser_bison.y"
                                                                                        { (yyval.cmd) = (yyvsp[-1].cmd); }
#line 7646 "parser_bison.tab.c"
    break;

  case 81: /* base_cmd: "monitor" monitor_cmd close_scope_monitor  */
#line 1087 "../../nft/nftables/src/parser_bison.y"
                                                                                        { (yyval.cmd) = (yyvsp[-1].cmd); }
#line 7652 "parser_bison.tab.c"
    break;

  case 82: /* base_cmd: "describe" describe_cmd  */
#line 1088 "../../nft/nftables/src/parser_bison.y"
                                                                { (yyval.cmd) = (yyvsp[0].cmd); }
#line 7658 "parser_bison.tab.c"
    break;

  case 83: /* add_cmd: "table" table_spec  */
#line 1092 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_ADD, CMD_OBJ_TABLE, &(yyvsp[0].handle), &(yyloc), NULL);
			}
#line 7666 "parser_bison.tab.c"
    break;

  case 84: /* add_cmd: "table" table_spec table_block_alloc '{' table_block '}'  */
#line 1097 "../../nft/nftables/src/parser_bison.y"
                        {
				handle_merge(&(yyvsp[-3].table)->handle, &(yyvsp[-4].handle));
				close_scope(state);
				(yyval.cmd) = cmd_alloc(CMD_ADD, CMD_OBJ_TABLE, &(yyvsp[-4].handle), &(yyloc), (yyvsp[-1].table));
			}
#line 7676 "parser_bison.tab.c"
    break;

  case 85: /* add_cmd: "chain" chain_spec  */
#line 1103 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_ADD, CMD_OBJ_CHAIN, &(yyvsp[0].handle), &(yyloc), NULL);
			}
#line 7684 "parser_bison.tab.c"
    break;

  case 86: /* add_cmd: "chain" chain_spec chain_block_alloc '{' chain_block '}'  */
#line 1108 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[-1].chain)->location = (yylsp[-1]);
				handle_merge(&(yyvsp[-3].chain)->handle, &(yyvsp[-4].handle));
				close_scope(state);
				(yyval.cmd) = cmd_alloc(CMD_ADD, CMD_OBJ_CHAIN, &(yyvsp[-4].handle), &(yyloc), (yyvsp[-1].chain));
			}
#line 7695 "parser_bison.tab.c"
    break;

  case 87: /* add_cmd: "rule" rule_position rule  */
#line 1115 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_ADD, CMD_OBJ_RULE, &(yyvsp[-1].handle), &(yyloc), (yyvsp[0].rule));
			}
#line 7703 "parser_bison.tab.c"
    break;

  case 88: /* add_cmd: rule_position rule  */
#line 1119 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_ADD, CMD_OBJ_RULE, &(yyvsp[-1].handle), &(yyloc), (yyvsp[0].rule));
			}
#line 7711 "parser_bison.tab.c"
    break;

  case 89: /* add_cmd: "set" set_spec set_block_alloc '{' set_block '}'  */
#line 1124 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[-1].set)->location = (yylsp[-1]);
				handle_merge(&(yyvsp[-3].set)->handle, &(yyvsp[-4].handle));
				(yyval.cmd) = cmd_alloc(CMD_ADD, CMD_OBJ_SET, &(yyvsp[-4].handle), &(yyloc), (yyvsp[-1].set));
			}
#line 7721 "parser_bison.tab.c"
    break;

  case 90: /* add_cmd: "map" set_spec map_block_alloc '{' map_block '}'  */
#line 1131 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[-1].set)->location = (yylsp[-1]);
				handle_merge(&(yyvsp[-3].set)->handle, &(yyvsp[-4].handle));
				(yyval.cmd) = cmd_alloc(CMD_ADD, CMD_OBJ_SET, &(yyvsp[-4].handle), &(yyloc), (yyvsp[-1].set));
			}
#line 7731 "parser_bison.tab.c"
    break;

  case 91: /* add_cmd: "element" set_spec set_block_expr  */
#line 1137 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_ADD, CMD_OBJ_ELEMENTS, &(yyvsp[-1].handle), &(yyloc), (yyvsp[0].expr));
			}
#line 7739 "parser_bison.tab.c"
    break;

  case 92: /* add_cmd: "flowtable" flowtable_spec flowtable_block_alloc '{' flowtable_block '}'  */
#line 1142 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[-1].flowtable)->location = (yylsp[-1]);
				handle_merge(&(yyvsp[-3].flowtable)->handle, &(yyvsp[-4].handle));
				(yyval.cmd) = cmd_alloc(CMD_ADD, CMD_OBJ_FLOWTABLE, &(yyvsp[-4].handle), &(yyloc), (yyvsp[-1].flowtable));
			}
#line 7749 "parser_bison.tab.c"
    break;

  case 93: /* add_cmd: "counter" obj_spec close_scope_counter  */
#line 1148 "../../nft/nftables/src/parser_bison.y"
                        {
				struct obj *obj;

				obj = obj_alloc(&(yyloc));
				obj->type = NFT_OBJECT_COUNTER;
				handle_merge(&obj->handle, &(yyvsp[-1].handle));
				(yyval.cmd) = cmd_alloc(CMD_ADD, CMD_OBJ_COUNTER, &(yyvsp[-1].handle), &(yyloc), obj);
			}
#line 7762 "parser_bison.tab.c"
    break;

  case 94: /* add_cmd: "counter" obj_spec counter_obj counter_config close_scope_counter  */
#line 1157 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_ADD, CMD_OBJ_COUNTER, &(yyvsp[-3].handle), &(yyloc), (yyvsp[-2].obj));
			}
#line 7770 "parser_bison.tab.c"
    break;

  case 95: /* add_cmd: "counter" obj_spec counter_obj '{' counter_block '}' close_scope_counter  */
#line 1161 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_ADD, CMD_OBJ_COUNTER, &(yyvsp[-5].handle), &(yyloc), (yyvsp[-4].obj));
			}
#line 7778 "parser_bison.tab.c"
    break;

  case 96: /* add_cmd: "quota" obj_spec quota_obj quota_config close_scope_quota  */
#line 1165 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_ADD, CMD_OBJ_QUOTA, &(yyvsp[-3].handle), &(yyloc), (yyvsp[-2].obj));
			}
#line 7786 "parser_bison.tab.c"
    break;

  case 97: /* add_cmd: "quota" obj_spec quota_obj '{' quota_block '}' close_scope_quota  */
#line 1169 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_ADD, CMD_OBJ_QUOTA, &(yyvsp[-5].handle), &(yyloc), (yyvsp[-4].obj));
			}
#line 7794 "parser_bison.tab.c"
    break;

  case 98: /* add_cmd: "ct" "helper" obj_spec ct_obj_alloc '{' ct_helper_block '}' close_scope_ct  */
#line 1173 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc_obj_ct(CMD_ADD, NFT_OBJECT_CT_HELPER, &(yyvsp[-5].handle), &(yyloc), (yyvsp[-4].obj));
			}
#line 7802 "parser_bison.tab.c"
    break;

  case 99: /* add_cmd: "ct" "timeout" obj_spec ct_obj_alloc '{' ct_timeout_block '}' close_scope_ct  */
#line 1177 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc_obj_ct(CMD_ADD, NFT_OBJECT_CT_TIMEOUT, &(yyvsp[-5].handle), &(yyloc), (yyvsp[-4].obj));
			}
#line 7810 "parser_bison.tab.c"
    break;

  case 100: /* add_cmd: "ct" "expectation" obj_spec ct_obj_alloc '{' ct_expect_block '}' close_scope_ct  */
#line 1181 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc_obj_ct(CMD_ADD, NFT_OBJECT_CT_EXPECT, &(yyvsp[-5].handle), &(yyloc), (yyvsp[-4].obj));
			}
#line 7818 "parser_bison.tab.c"
    break;

  case 101: /* add_cmd: "limit" obj_spec limit_obj limit_config close_scope_limit  */
#line 1185 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_ADD, CMD_OBJ_LIMIT, &(yyvsp[-3].handle), &(yyloc), (yyvsp[-2].obj));
			}
#line 7826 "parser_bison.tab.c"
    break;

  case 102: /* add_cmd: "limit" obj_spec limit_obj '{' limit_block '}' close_scope_limit  */
#line 1189 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_ADD, CMD_OBJ_LIMIT, &(yyvsp[-5].handle), &(yyloc), (yyvsp[-4].obj));
			}
#line 7834 "parser_bison.tab.c"
    break;

  case 103: /* add_cmd: "secmark" obj_spec secmark_obj secmark_config close_scope_secmark  */
#line 1193 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_ADD, CMD_OBJ_SECMARK, &(yyvsp[-3].handle), &(yyloc), (yyvsp[-2].obj));
			}
#line 7842 "parser_bison.tab.c"
    break;

  case 104: /* add_cmd: "secmark" obj_spec secmark_obj '{' secmark_block '}' close_scope_secmark  */
#line 1197 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_ADD, CMD_OBJ_SECMARK, &(yyvsp[-5].handle), &(yyloc), (yyvsp[-4].obj));
			}
#line 7850 "parser_bison.tab.c"
    break;

  case 105: /* add_cmd: "synproxy" obj_spec synproxy_obj synproxy_config close_scope_synproxy  */
#line 1201 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_ADD, CMD_OBJ_SYNPROXY, &(yyvsp[-3].handle), &(yyloc), (yyvsp[-2].obj));
			}
#line 7858 "parser_bison.tab.c"
    break;

  case 106: /* add_cmd: "synproxy" obj_spec synproxy_obj '{' synproxy_block '}' close_scope_synproxy  */
#line 1205 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_ADD, CMD_OBJ_SYNPROXY, &(yyvsp[-5].handle), &(yyloc), (yyvsp[-4].obj));
			}
#line 7866 "parser_bison.tab.c"
    break;

  case 107: /* replace_cmd: "rule" ruleid_spec rule  */
#line 1211 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_REPLACE, CMD_OBJ_RULE, &(yyvsp[-1].handle), &(yyloc), (yyvsp[0].rule));
			}
#line 7874 "parser_bison.tab.c"
    break;

  case 108: /* create_cmd: "table" table_spec  */
#line 1217 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_CREATE, CMD_OBJ_TABLE, &(yyvsp[0].handle), &(yyloc), NULL);
			}
#line 7882 "parser_bison.tab.c"
    break;

  case 109: /* create_cmd: "table" table_spec table_block_alloc '{' table_block '}'  */
#line 1222 "../../nft/nftables/src/parser_bison.y"
                        {
				handle_merge(&(yyvsp[-3].table)->handle, &(yyvsp[-4].handle));
				close_scope(state);
				(yyval.cmd) = cmd_alloc(CMD_CREATE, CMD_OBJ_TABLE, &(yyvsp[-4].handle), &(yyloc), (yyvsp[-1].table));
			}
#line 7892 "parser_bison.tab.c"
    break;

  case 110: /* create_cmd: "chain" chain_spec  */
#line 1228 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_CREATE, CMD_OBJ_CHAIN, &(yyvsp[0].handle), &(yyloc), NULL);
			}
#line 7900 "parser_bison.tab.c"
    break;

  case 111: /* create_cmd: "chain" chain_spec chain_block_alloc '{' chain_block '}'  */
#line 1233 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[-1].chain)->location = (yylsp[-1]);
				handle_merge(&(yyvsp[-3].chain)->handle, &(yyvsp[-4].handle));
				close_scope(state);
				(yyval.cmd) = cmd_alloc(CMD_CREATE, CMD_OBJ_CHAIN, &(yyvsp[-4].handle), &(yyloc), (yyvsp[-1].chain));
			}
#line 7911 "parser_bison.tab.c"
    break;

  case 112: /* create_cmd: "set" set_spec set_block_alloc '{' set_block '}'  */
#line 1241 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[-1].set)->location = (yylsp[-1]);
				handle_merge(&(yyvsp[-3].set)->handle, &(yyvsp[-4].handle));
				(yyval.cmd) = cmd_alloc(CMD_CREATE, CMD_OBJ_SET, &(yyvsp[-4].handle), &(yyloc), (yyvsp[-1].set));
			}
#line 7921 "parser_bison.tab.c"
    break;

  case 113: /* create_cmd: "map" set_spec map_block_alloc '{' map_block '}'  */
#line 1248 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[-1].set)->location = (yylsp[-1]);
				handle_merge(&(yyvsp[-3].set)->handle, &(yyvsp[-4].handle));
				(yyval.cmd) = cmd_alloc(CMD_CREATE, CMD_OBJ_SET, &(yyvsp[-4].handle), &(yyloc), (yyvsp[-1].set));
			}
#line 7931 "parser_bison.tab.c"
    break;

  case 114: /* create_cmd: "element" set_spec set_block_expr  */
#line 1254 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_CREATE, CMD_OBJ_ELEMENTS, &(yyvsp[-1].handle), &(yyloc), (yyvsp[0].expr));
			}
#line 7939 "parser_bison.tab.c"
    break;

  case 115: /* create_cmd: "flowtable" flowtable_spec flowtable_block_alloc '{' flowtable_block '}'  */
#line 1259 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[-1].flowtable)->location = (yylsp[-1]);
				handle_merge(&(yyvsp[-3].flowtable)->handle, &(yyvsp[-4].handle));
				(yyval.cmd) = cmd_alloc(CMD_CREATE, CMD_OBJ_FLOWTABLE, &(yyvsp[-4].handle), &(yyloc), (yyvsp[-1].flowtable));
			}
#line 7949 "parser_bison.tab.c"
    break;

  case 116: /* create_cmd: "counter" obj_spec close_scope_counter  */
#line 1265 "../../nft/nftables/src/parser_bison.y"
                        {
				struct obj *obj;

				obj = obj_alloc(&(yyloc));
				obj->type = NFT_OBJECT_COUNTER;
				handle_merge(&obj->handle, &(yyvsp[-1].handle));
				(yyval.cmd) = cmd_alloc(CMD_CREATE, CMD_OBJ_COUNTER, &(yyvsp[-1].handle), &(yyloc), obj);
			}
#line 7962 "parser_bison.tab.c"
    break;

  case 117: /* create_cmd: "counter" obj_spec counter_obj counter_config close_scope_counter  */
#line 1274 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_CREATE, CMD_OBJ_COUNTER, &(yyvsp[-3].handle), &(yyloc), (yyvsp[-2].obj));
			}
#line 7970 "parser_bison.tab.c"
    break;

  case 118: /* create_cmd: "quota" obj_spec quota_obj quota_config close_scope_quota  */
#line 1278 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_CREATE, CMD_OBJ_QUOTA, &(yyvsp[-3].handle), &(yyloc), (yyvsp[-2].obj));
			}
#line 7978 "parser_bison.tab.c"
    break;

  case 119: /* create_cmd: "ct" "helper" obj_spec ct_obj_alloc '{' ct_helper_block '}' close_scope_ct  */
#line 1282 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc_obj_ct(CMD_CREATE, NFT_OBJECT_CT_HELPER, &(yyvsp[-5].handle), &(yyloc), (yyvsp[-4].obj));
			}
#line 7986 "parser_bison.tab.c"
    break;

  case 120: /* create_cmd: "ct" "timeout" obj_spec ct_obj_alloc '{' ct_timeout_block '}' close_scope_ct  */
#line 1286 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc_obj_ct(CMD_CREATE, NFT_OBJECT_CT_TIMEOUT, &(yyvsp[-5].handle), &(yyloc), (yyvsp[-4].obj));
			}
#line 7994 "parser_bison.tab.c"
    break;

  case 121: /* create_cmd: "ct" "expectation" obj_spec ct_obj_alloc '{' ct_expect_block '}' close_scope_ct  */
#line 1290 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc_obj_ct(CMD_CREATE, NFT_OBJECT_CT_EXPECT, &(yyvsp[-5].handle), &(yyloc), (yyvsp[-4].obj));
			}
#line 8002 "parser_bison.tab.c"
    break;

  case 122: /* create_cmd: "limit" obj_spec limit_obj limit_config close_scope_limit  */
#line 1294 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_CREATE, CMD_OBJ_LIMIT, &(yyvsp[-3].handle), &(yyloc), (yyvsp[-2].obj));
			}
#line 8010 "parser_bison.tab.c"
    break;

  case 123: /* create_cmd: "secmark" obj_spec secmark_obj secmark_config close_scope_secmark  */
#line 1298 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_CREATE, CMD_OBJ_SECMARK, &(yyvsp[-3].handle), &(yyloc), (yyvsp[-2].obj));
			}
#line 8018 "parser_bison.tab.c"
    break;

  case 124: /* create_cmd: "synproxy" obj_spec synproxy_obj synproxy_config close_scope_synproxy  */
#line 1302 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_CREATE, CMD_OBJ_SYNPROXY, &(yyvsp[-3].handle), &(yyloc), (yyvsp[-2].obj));
			}
#line 8026 "parser_bison.tab.c"
    break;

  case 125: /* insert_cmd: "rule" rule_position rule  */
#line 1308 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_INSERT, CMD_OBJ_RULE, &(yyvsp[-1].handle), &(yyloc), (yyvsp[0].rule));
			}
#line 8034 "parser_bison.tab.c"
    break;

  case 134: /* delete_cmd: "table" table_or_id_spec  */
#line 1330 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_DELETE, CMD_OBJ_TABLE, &(yyvsp[0].handle), &(yyloc), NULL);
			}
#line 8042 "parser_bison.tab.c"
    break;

  case 135: /* delete_cmd: "chain" chain_or_id_spec  */
#line 1334 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_DELETE, CMD_OBJ_CHAIN, &(yyvsp[0].handle), &(yyloc), NULL);
			}
#line 8050 "parser_bison.tab.c"
    break;

  case 136: /* delete_cmd: "rule" ruleid_spec  */
#line 1338 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_DELETE, CMD_OBJ_RULE, &(yyvsp[0].handle), &(yyloc), NULL);
			}
#line 8058 "parser_bison.tab.c"
    break;

  case 137: /* delete_cmd: "set" set_or_id_spec  */
#line 1342 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_DELETE, CMD_OBJ_SET, &(yyvsp[0].handle), &(yyloc), NULL);
			}
#line 8066 "parser_bison.tab.c"
    break;

  case 138: /* delete_cmd: "map" set_spec  */
#line 1346 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_DELETE, CMD_OBJ_SET, &(yyvsp[0].handle), &(yyloc), NULL);
			}
#line 8074 "parser_bison.tab.c"
    break;

  case 139: /* delete_cmd: "element" set_spec set_block_expr  */
#line 1350 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_DELETE, CMD_OBJ_ELEMENTS, &(yyvsp[-1].handle), &(yyloc), (yyvsp[0].expr));
			}
#line 8082 "parser_bison.tab.c"
    break;

  case 140: /* delete_cmd: "flowtable" flowtable_spec  */
#line 1354 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_DELETE, CMD_OBJ_FLOWTABLE, &(yyvsp[0].handle), &(yyloc), NULL);
			}
#line 8090 "parser_bison.tab.c"
    break;

  case 141: /* delete_cmd: "flowtable" flowtableid_spec  */
#line 1358 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_DELETE, CMD_OBJ_FLOWTABLE, &(yyvsp[0].handle), &(yyloc), NULL);
			}
#line 8098 "parser_bison.tab.c"
    break;

  case 142: /* delete_cmd: "flowtable" flowtable_spec flowtable_block_alloc '{' flowtable_block '}'  */
#line 1363 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[-1].flowtable)->location = (yylsp[-1]);
				handle_merge(&(yyvsp[-3].flowtable)->handle, &(yyvsp[-4].handle));
				(yyval.cmd) = cmd_alloc(CMD_DELETE, CMD_OBJ_FLOWTABLE, &(yyvsp[-4].handle), &(yyloc), (yyvsp[-1].flowtable));
			}
#line 8108 "parser_bison.tab.c"
    break;

  case 143: /* delete_cmd: "counter" obj_or_id_spec close_scope_counter  */
#line 1369 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_DELETE, CMD_OBJ_COUNTER, &(yyvsp[-1].handle), &(yyloc), NULL);
			}
#line 8116 "parser_bison.tab.c"
    break;

  case 144: /* delete_cmd: "quota" obj_or_id_spec close_scope_quota  */
#line 1373 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_DELETE, CMD_OBJ_QUOTA, &(yyvsp[-1].handle), &(yyloc), NULL);
			}
#line 8124 "parser_bison.tab.c"
    break;

  case 145: /* delete_cmd: "ct" ct_obj_type obj_spec ct_obj_alloc close_scope_ct  */
#line 1377 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc_obj_ct(CMD_DELETE, (yyvsp[-3].val), &(yyvsp[-2].handle), &(yyloc), (yyvsp[-1].obj));
				if ((yyvsp[-3].val) == NFT_OBJECT_CT_TIMEOUT)
					init_list_head(&(yyvsp[-1].obj)->ct_timeout.timeout_list);
			}
#line 8134 "parser_bison.tab.c"
    break;

  case 146: /* delete_cmd: "limit" obj_or_id_spec close_scope_limit  */
#line 1383 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_DELETE, CMD_OBJ_LIMIT, &(yyvsp[-1].handle), &(yyloc), NULL);
			}
#line 8142 "parser_bison.tab.c"
    break;

  case 147: /* delete_cmd: "secmark" obj_or_id_spec close_scope_secmark  */
#line 1387 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_DELETE, CMD_OBJ_SECMARK, &(yyvsp[-1].handle), &(yyloc), NULL);
			}
#line 8150 "parser_bison.tab.c"
    break;

  case 148: /* delete_cmd: "synproxy" obj_or_id_spec close_scope_synproxy  */
#line 1391 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_DELETE, CMD_OBJ_SYNPROXY, &(yyvsp[-1].handle), &(yyloc), NULL);
			}
#line 8158 "parser_bison.tab.c"
    break;

  case 149: /* get_cmd: "element" set_spec set_block_expr  */
#line 1397 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_GET, CMD_OBJ_ELEMENTS, &(yyvsp[-1].handle), &(yyloc), (yyvsp[0].expr));
			}
#line 8166 "parser_bison.tab.c"
    break;

  case 150: /* list_cmd: "table" table_spec  */
#line 1403 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_LIST, CMD_OBJ_TABLE, &(yyvsp[0].handle), &(yyloc), NULL);
			}
#line 8174 "parser_bison.tab.c"
    break;

  case 151: /* list_cmd: "tables" ruleset_spec  */
#line 1407 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_LIST, CMD_OBJ_TABLE, &(yyvsp[0].handle), &(yyloc), NULL);
			}
#line 8182 "parser_bison.tab.c"
    break;

  case 152: /* list_cmd: "chain" chain_spec  */
#line 1411 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_LIST, CMD_OBJ_CHAIN, &(yyvsp[0].handle), &(yyloc), NULL);
			}
#line 8190 "parser_bison.tab.c"
    break;

  case 153: /* list_cmd: "chains" ruleset_spec  */
#line 1415 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_LIST, CMD_OBJ_CHAINS, &(yyvsp[0].handle), &(yyloc), NULL);
			}
#line 8198 "parser_bison.tab.c"
    break;

  case 154: /* list_cmd: "sets" ruleset_spec  */
#line 1419 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_LIST, CMD_OBJ_SETS, &(yyvsp[0].handle), &(yyloc), NULL);
			}
#line 8206 "parser_bison.tab.c"
    break;

  case 155: /* list_cmd: "sets" "table" table_spec  */
#line 1423 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_LIST, CMD_OBJ_SETS, &(yyvsp[0].handle), &(yyloc), NULL);
			}
#line 8214 "parser_bison.tab.c"
    break;

  case 156: /* list_cmd: "set" set_spec  */
#line 1427 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_LIST, CMD_OBJ_SET, &(yyvsp[0].handle), &(yyloc), NULL);
			}
#line 8222 "parser_bison.tab.c"
    break;

  case 157: /* list_cmd: "counters" ruleset_spec  */
#line 1431 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_LIST, CMD_OBJ_COUNTERS, &(yyvsp[0].handle), &(yyloc), NULL);
			}
#line 8230 "parser_bison.tab.c"
    break;

  case 158: /* list_cmd: "counters" "table" table_spec  */
#line 1435 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_LIST, CMD_OBJ_COUNTERS, &(yyvsp[0].handle), &(yyloc), NULL);
			}
#line 8238 "parser_bison.tab.c"
    break;

  case 159: /* list_cmd: "counter" obj_spec close_scope_counter  */
#line 1439 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_LIST, CMD_OBJ_COUNTER, &(yyvsp[-1].handle), &(yyloc), NULL);
			}
#line 8246 "parser_bison.tab.c"
    break;

  case 160: /* list_cmd: "quotas" ruleset_spec  */
#line 1443 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_LIST, CMD_OBJ_QUOTAS, &(yyvsp[0].handle), &(yyloc), NULL);
			}
#line 8254 "parser_bison.tab.c"
    break;

  case 161: /* list_cmd: "quotas" "table" table_spec  */
#line 1447 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_LIST, CMD_OBJ_QUOTAS, &(yyvsp[0].handle), &(yyloc), NULL);
			}
#line 8262 "parser_bison.tab.c"
    break;

  case 162: /* list_cmd: "quota" obj_spec close_scope_quota  */
#line 1451 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_LIST, CMD_OBJ_QUOTA, &(yyvsp[-1].handle), &(yyloc), NULL);
			}
#line 8270 "parser_bison.tab.c"
    break;

  case 163: /* list_cmd: "limits" ruleset_spec  */
#line 1455 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_LIST, CMD_OBJ_LIMITS, &(yyvsp[0].handle), &(yyloc), NULL);
			}
#line 8278 "parser_bison.tab.c"
    break;

  case 164: /* list_cmd: "limits" "table" table_spec  */
#line 1459 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_LIST, CMD_OBJ_LIMITS, &(yyvsp[0].handle), &(yyloc), NULL);
			}
#line 8286 "parser_bison.tab.c"
    break;

  case 165: /* list_cmd: "limit" obj_spec close_scope_limit  */
#line 1463 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_LIST, CMD_OBJ_LIMIT, &(yyvsp[-1].handle), &(yyloc), NULL);
			}
#line 8294 "parser_bison.tab.c"
    break;

  case 166: /* list_cmd: "secmarks" ruleset_spec  */
#line 1467 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_LIST, CMD_OBJ_SECMARKS, &(yyvsp[0].handle), &(yyloc), NULL);
			}
#line 8302 "parser_bison.tab.c"
    break;

  case 167: /* list_cmd: "secmarks" "table" table_spec  */
#line 1471 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_LIST, CMD_OBJ_SECMARKS, &(yyvsp[0].handle), &(yyloc), NULL);
			}
#line 8310 "parser_bison.tab.c"
    break;

  case 168: /* list_cmd: "secmark" obj_spec close_scope_secmark  */
#line 1475 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_LIST, CMD_OBJ_SECMARK, &(yyvsp[-1].handle), &(yyloc), NULL);
			}
#line 8318 "parser_bison.tab.c"
    break;

  case 169: /* list_cmd: "synproxys" ruleset_spec  */
#line 1479 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_LIST, CMD_OBJ_SYNPROXYS, &(yyvsp[0].handle), &(yyloc), NULL);
			}
#line 8326 "parser_bison.tab.c"
    break;

  case 170: /* list_cmd: "synproxys" "table" table_spec  */
#line 1483 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_LIST, CMD_OBJ_SYNPROXYS, &(yyvsp[0].handle), &(yyloc), NULL);
			}
#line 8334 "parser_bison.tab.c"
    break;

  case 171: /* list_cmd: "synproxy" obj_spec close_scope_synproxy  */
#line 1487 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_LIST, CMD_OBJ_SYNPROXY, &(yyvsp[-1].handle), &(yyloc), NULL);
			}
#line 8342 "parser_bison.tab.c"
    break;

  case 172: /* list_cmd: "ruleset" ruleset_spec  */
#line 1491 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_LIST, CMD_OBJ_RULESET, &(yyvsp[0].handle), &(yyloc), NULL);
			}
#line 8350 "parser_bison.tab.c"
    break;

  case 173: /* list_cmd: "flow" "tables" ruleset_spec  */
#line 1495 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_LIST, CMD_OBJ_METERS, &(yyvsp[0].handle), &(yyloc), NULL);
			}
#line 8358 "parser_bison.tab.c"
    break;

  case 174: /* list_cmd: "flow" "table" set_spec  */
#line 1499 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_LIST, CMD_OBJ_METER, &(yyvsp[0].handle), &(yyloc), NULL);
			}
#line 8366 "parser_bison.tab.c"
    break;

  case 175: /* list_cmd: "meters" ruleset_spec  */
#line 1503 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_LIST, CMD_OBJ_METERS, &(yyvsp[0].handle), &(yyloc), NULL);
			}
#line 8374 "parser_bison.tab.c"
    break;

  case 176: /* list_cmd: "meter" set_spec  */
#line 1507 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_LIST, CMD_OBJ_METER, &(yyvsp[0].handle), &(yyloc), NULL);
			}
#line 8382 "parser_bison.tab.c"
    break;

  case 177: /* list_cmd: "flowtables" ruleset_spec  */
#line 1511 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_LIST, CMD_OBJ_FLOWTABLES, &(yyvsp[0].handle), &(yyloc), NULL);
			}
#line 8390 "parser_bison.tab.c"
    break;

  case 178: /* list_cmd: "flowtable" flowtable_spec  */
#line 1515 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_LIST, CMD_OBJ_FLOWTABLE, &(yyvsp[0].handle), &(yyloc), NULL);
			}
#line 8398 "parser_bison.tab.c"
    break;

  case 179: /* list_cmd: "maps" ruleset_spec  */
#line 1519 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_LIST, CMD_OBJ_MAPS, &(yyvsp[0].handle), &(yyloc), NULL);
			}
#line 8406 "parser_bison.tab.c"
    break;

  case 180: /* list_cmd: "map" set_spec  */
#line 1523 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_LIST, CMD_OBJ_MAP, &(yyvsp[0].handle), &(yyloc), NULL);
			}
#line 8414 "parser_bison.tab.c"
    break;

  case 181: /* list_cmd: "ct" ct_obj_type obj_spec close_scope_ct  */
#line 1527 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc_obj_ct(CMD_LIST, (yyvsp[-2].val), &(yyvsp[-1].handle), &(yyloc), NULL);
			}
#line 8422 "parser_bison.tab.c"
    break;

  case 182: /* list_cmd: "ct" ct_cmd_type "table" table_spec close_scope_ct  */
#line 1531 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_LIST, (yyvsp[-3].val), &(yyvsp[-1].handle), &(yyloc), NULL);
			}
#line 8430 "parser_bison.tab.c"
    break;

  case 183: /* list_cmd: "hooks" basehook_spec  */
#line 1535 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_LIST, CMD_OBJ_HOOKS, &(yyvsp[0].handle), &(yyloc), NULL);
			}
#line 8438 "parser_bison.tab.c"
    break;

  case 184: /* basehook_device_name: "device" "string"  */
#line 1541 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.string) = (yyvsp[0].string);
			}
#line 8446 "parser_bison.tab.c"
    break;

  case 185: /* basehook_spec: ruleset_spec  */
#line 1547 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.handle) = (yyvsp[0].handle);
			}
#line 8454 "parser_bison.tab.c"
    break;

  case 186: /* basehook_spec: ruleset_spec basehook_device_name  */
#line 1551 "../../nft/nftables/src/parser_bison.y"
                        {
				if ((yyvsp[0].string)) {
					(yyvsp[-1].handle).obj.name = (yyvsp[0].string);
					(yyvsp[-1].handle).obj.location = (yylsp[0]);
				}
				(yyval.handle) = (yyvsp[-1].handle);
			}
#line 8466 "parser_bison.tab.c"
    break;

  case 187: /* reset_cmd: "counters" ruleset_spec  */
#line 1561 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_RESET, CMD_OBJ_COUNTERS, &(yyvsp[0].handle), &(yyloc), NULL);
			}
#line 8474 "parser_bison.tab.c"
    break;

  case 188: /* reset_cmd: "counters" "table" table_spec  */
#line 1565 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_RESET, CMD_OBJ_COUNTERS, &(yyvsp[0].handle), &(yyloc), NULL);
			}
#line 8482 "parser_bison.tab.c"
    break;

  case 189: /* reset_cmd: "counter" obj_spec close_scope_counter  */
#line 1569 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_RESET, CMD_OBJ_COUNTER, &(yyvsp[-1].handle),&(yyloc), NULL);
			}
#line 8490 "parser_bison.tab.c"
    break;

  case 190: /* reset_cmd: "quotas" ruleset_spec  */
#line 1573 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_RESET, CMD_OBJ_QUOTAS, &(yyvsp[0].handle), &(yyloc), NULL);
			}
#line 8498 "parser_bison.tab.c"
    break;

  case 191: /* reset_cmd: "quotas" "table" table_spec  */
#line 1577 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_RESET, CMD_OBJ_QUOTAS, &(yyvsp[0].handle), &(yyloc), NULL);
			}
#line 8506 "parser_bison.tab.c"
    break;

  case 192: /* reset_cmd: "quota" obj_spec close_scope_quota  */
#line 1581 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_RESET, CMD_OBJ_QUOTA, &(yyvsp[-1].handle), &(yyloc), NULL);
			}
#line 8514 "parser_bison.tab.c"
    break;

  case 193: /* flush_cmd: "table" table_spec  */
#line 1587 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_FLUSH, CMD_OBJ_TABLE, &(yyvsp[0].handle), &(yyloc), NULL);
			}
#line 8522 "parser_bison.tab.c"
    break;

  case 194: /* flush_cmd: "chain" chain_spec  */
#line 1591 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_FLUSH, CMD_OBJ_CHAIN, &(yyvsp[0].handle), &(yyloc), NULL);
			}
#line 8530 "parser_bison.tab.c"
    break;

  case 195: /* flush_cmd: "set" set_spec  */
#line 1595 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_FLUSH, CMD_OBJ_SET, &(yyvsp[0].handle), &(yyloc), NULL);
			}
#line 8538 "parser_bison.tab.c"
    break;

  case 196: /* flush_cmd: "map" set_spec  */
#line 1599 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_FLUSH, CMD_OBJ_MAP, &(yyvsp[0].handle), &(yyloc), NULL);
			}
#line 8546 "parser_bison.tab.c"
    break;

  case 197: /* flush_cmd: "flow" "table" set_spec  */
#line 1603 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_FLUSH, CMD_OBJ_METER, &(yyvsp[0].handle), &(yyloc), NULL);
			}
#line 8554 "parser_bison.tab.c"
    break;

  case 198: /* flush_cmd: "meter" set_spec  */
#line 1607 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_FLUSH, CMD_OBJ_METER, &(yyvsp[0].handle), &(yyloc), NULL);
			}
#line 8562 "parser_bison.tab.c"
    break;

  case 199: /* flush_cmd: "ruleset" ruleset_spec  */
#line 1611 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_FLUSH, CMD_OBJ_RULESET, &(yyvsp[0].handle), &(yyloc), NULL);
			}
#line 8570 "parser_bison.tab.c"
    break;

  case 200: /* rename_cmd: "chain" chain_spec identifier  */
#line 1617 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.cmd) = cmd_alloc(CMD_RENAME, CMD_OBJ_CHAIN, &(yyvsp[-1].handle), &(yyloc), NULL);
				(yyval.cmd)->arg = (yyvsp[0].string);
			}
#line 8579 "parser_bison.tab.c"
    break;

  case 201: /* import_cmd: "ruleset" markup_format  */
#line 1624 "../../nft/nftables/src/parser_bison.y"
                        {
				struct handle h = { .family = NFPROTO_UNSPEC };
				struct markup *markup = markup_alloc((yyvsp[0].val));
				(yyval.cmd) = cmd_alloc(CMD_IMPORT, CMD_OBJ_MARKUP, &h, &(yyloc), markup);
			}
#line 8589 "parser_bison.tab.c"
    break;

  case 202: /* import_cmd: markup_format  */
#line 1630 "../../nft/nftables/src/parser_bison.y"
                        {
				struct handle h = { .family = NFPROTO_UNSPEC };
				struct markup *markup = markup_alloc((yyvsp[0].val));
				(yyval.cmd) = cmd_alloc(CMD_IMPORT, CMD_OBJ_MARKUP, &h, &(yyloc), markup);
			}
#line 8599 "parser_bison.tab.c"
    break;

  case 203: /* export_cmd: "ruleset" markup_format  */
#line 1638 "../../nft/nftables/src/parser_bison.y"
                        {
				struct handle h = { .family = NFPROTO_UNSPEC };
				struct markup *markup = markup_alloc((yyvsp[0].val));
				(yyval.cmd) = cmd_alloc(CMD_EXPORT, CMD_OBJ_MARKUP, &h, &(yyloc), markup);
			}
#line 8609 "parser_bison.tab.c"
    break;

  case 204: /* export_cmd: markup_format  */
#line 1644 "../../nft/nftables/src/parser_bison.y"
                        {
				struct handle h = { .family = NFPROTO_UNSPEC };
				struct markup *markup = markup_alloc((yyvsp[0].val));
				(yyval.cmd) = cmd_alloc(CMD_EXPORT, CMD_OBJ_MARKUP, &h, &(yyloc), markup);
			}
#line 8619 "parser_bison.tab.c"
    break;

  case 205: /* monitor_cmd: monitor_event monitor_object monitor_format  */
#line 1652 "../../nft/nftables/src/parser_bison.y"
                        {
				struct handle h = { .family = NFPROTO_UNSPEC };
				struct monitor *m = monitor_alloc((yyvsp[0].val), (yyvsp[-1].val), (yyvsp[-2].string));
				m->location = (yylsp[-2]);
				(yyval.cmd) = cmd_alloc(CMD_MONITOR, CMD_OBJ_MONITOR, &h, &(yyloc), m);
			}
#line 8630 "parser_bison.tab.c"
    break;

  case 206: /* monitor_event: %empty  */
#line 1660 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.string) = NULL; }
#line 8636 "parser_bison.tab.c"
    break;

  case 207: /* monitor_event: "string"  */
#line 1661 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.string) = (yyvsp[0].string); }
#line 8642 "parser_bison.tab.c"
    break;

  case 208: /* monitor_object: %empty  */
#line 1664 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = CMD_MONITOR_OBJ_ANY; }
#line 8648 "parser_bison.tab.c"
    break;

  case 209: /* monitor_object: "tables"  */
#line 1665 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = CMD_MONITOR_OBJ_TABLES; }
#line 8654 "parser_bison.tab.c"
    break;

  case 210: /* monitor_object: "chains"  */
#line 1666 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = CMD_MONITOR_OBJ_CHAINS; }
#line 8660 "parser_bison.tab.c"
    break;

  case 211: /* monitor_object: "sets"  */
#line 1667 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = CMD_MONITOR_OBJ_SETS; }
#line 8666 "parser_bison.tab.c"
    break;

  case 212: /* monitor_object: "rules"  */
#line 1668 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = CMD_MONITOR_OBJ_RULES; }
#line 8672 "parser_bison.tab.c"
    break;

  case 213: /* monitor_object: "elements"  */
#line 1669 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = CMD_MONITOR_OBJ_ELEMS; }
#line 8678 "parser_bison.tab.c"
    break;

  case 214: /* monitor_object: "ruleset"  */
#line 1670 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = CMD_MONITOR_OBJ_RULESET; }
#line 8684 "parser_bison.tab.c"
    break;

  case 215: /* monitor_object: "trace"  */
#line 1671 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = CMD_MONITOR_OBJ_TRACE; }
#line 8690 "parser_bison.tab.c"
    break;

  case 216: /* monitor_format: %empty  */
#line 1674 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = NFTNL_OUTPUT_DEFAULT; }
#line 8696 "parser_bison.tab.c"
    break;

  case 218: /* markup_format: "xml"  */
#line 1678 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = __NFT_OUTPUT_NOTSUPP; }
#line 8702 "parser_bison.tab.c"
    break;

  case 219: /* markup_format: "json"  */
#line 1679 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = NFTNL_OUTPUT_JSON; }
#line 8708 "parser_bison.tab.c"
    break;

  case 220: /* markup_format: "vm" "json"  */
#line 1680 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = NFTNL_OUTPUT_JSON; }
#line 8714 "parser_bison.tab.c"
    break;

  case 221: /* describe_cmd: primary_expr  */
#line 1684 "../../nft/nftables/src/parser_bison.y"
                        {
				struct handle h = { .family = NFPROTO_UNSPEC };
				(yyval.cmd) = cmd_alloc(CMD_DESCRIBE, CMD_OBJ_EXPR, &h, &(yyloc), NULL);
				(yyval.cmd)->expr = (yyvsp[0].expr);
			}
#line 8724 "parser_bison.tab.c"
    break;

  case 222: /* table_block_alloc: %empty  */
#line 1692 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.table) = table_alloc();
				if (open_scope(state, &(yyval.table)->scope) < 0) {
					erec_queue(error(&(yyloc), "too many levels of nesting"),
						   state->msgs);
					state->nerrs++;
				}
			}
#line 8737 "parser_bison.tab.c"
    break;

  case 223: /* table_options: "flags" "string"  */
#line 1703 "../../nft/nftables/src/parser_bison.y"
                        {
				if (strcmp((yyvsp[0].string), "dormant") == 0) {
					(yyvsp[-2].table)->flags |= TABLE_F_DORMANT;
					xfree((yyvsp[0].string));
				} else if (strcmp((yyvsp[0].string), "owner") == 0) {
					(yyvsp[-2].table)->flags |= TABLE_F_OWNER;
					xfree((yyvsp[0].string));
				} else {
					erec_queue(error(&(yylsp[0]), "unknown table option %s", (yyvsp[0].string)),
						   state->msgs);
					xfree((yyvsp[0].string));
					YYERROR;
				}
			}
#line 8756 "parser_bison.tab.c"
    break;

  case 224: /* table_options: comment_spec  */
#line 1718 "../../nft/nftables/src/parser_bison.y"
                        {
				if (already_set((yyvsp[-1].table)->comment, &(yyloc), state)) {
					xfree((yyvsp[0].string));
					YYERROR;
				}
				(yyvsp[-1].table)->comment = (yyvsp[0].string);
			}
#line 8768 "parser_bison.tab.c"
    break;

  case 225: /* table_block: %empty  */
#line 1727 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.table) = (yyvsp[(-1) - (0)].table); }
#line 8774 "parser_bison.tab.c"
    break;

  case 229: /* table_block: table_block "chain" chain_identifier chain_block_alloc '{' chain_block '}' stmt_separator  */
#line 1734 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[-4].chain)->location = (yylsp[-5]);
				handle_merge(&(yyvsp[-4].chain)->handle, &(yyvsp[-5].handle));
				handle_free(&(yyvsp[-5].handle));
				close_scope(state);
				list_add_tail(&(yyvsp[-4].chain)->list, &(yyvsp[-7].table)->chains);
				(yyval.table) = (yyvsp[-7].table);
			}
#line 8787 "parser_bison.tab.c"
    break;

  case 230: /* table_block: table_block "set" set_identifier set_block_alloc '{' set_block '}' stmt_separator  */
#line 1745 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[-4].set)->location = (yylsp[-5]);
				handle_merge(&(yyvsp[-4].set)->handle, &(yyvsp[-5].handle));
				handle_free(&(yyvsp[-5].handle));
				list_add_tail(&(yyvsp[-4].set)->list, &(yyvsp[-7].table)->sets);
				(yyval.table) = (yyvsp[-7].table);
			}
#line 8799 "parser_bison.tab.c"
    break;

  case 231: /* table_block: table_block "map" set_identifier map_block_alloc '{' map_block '}' stmt_separator  */
#line 1755 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[-4].set)->location = (yylsp[-5]);
				handle_merge(&(yyvsp[-4].set)->handle, &(yyvsp[-5].handle));
				handle_free(&(yyvsp[-5].handle));
				list_add_tail(&(yyvsp[-4].set)->list, &(yyvsp[-7].table)->sets);
				(yyval.table) = (yyvsp[-7].table);
			}
#line 8811 "parser_bison.tab.c"
    break;

  case 232: /* table_block: table_block "flowtable" flowtable_identifier flowtable_block_alloc '{' flowtable_block '}' stmt_separator  */
#line 1766 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[-4].flowtable)->location = (yylsp[-5]);
				handle_merge(&(yyvsp[-4].flowtable)->handle, &(yyvsp[-5].handle));
				handle_free(&(yyvsp[-5].handle));
				list_add_tail(&(yyvsp[-4].flowtable)->list, &(yyvsp[-7].table)->flowtables);
				(yyval.table) = (yyvsp[-7].table);
			}
#line 8823 "parser_bison.tab.c"
    break;

  case 233: /* table_block: table_block "counter" obj_identifier obj_block_alloc '{' counter_block '}' stmt_separator close_scope_counter  */
#line 1776 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[-5].obj)->location = (yylsp[-6]);
				(yyvsp[-5].obj)->type = NFT_OBJECT_COUNTER;
				handle_merge(&(yyvsp[-5].obj)->handle, &(yyvsp[-6].handle));
				handle_free(&(yyvsp[-6].handle));
				list_add_tail(&(yyvsp[-5].obj)->list, &(yyvsp[-8].table)->objs);
				(yyval.table) = (yyvsp[-8].table);
			}
#line 8836 "parser_bison.tab.c"
    break;

  case 234: /* table_block: table_block "quota" obj_identifier obj_block_alloc '{' quota_block '}' stmt_separator close_scope_quota  */
#line 1787 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[-5].obj)->location = (yylsp[-6]);
				(yyvsp[-5].obj)->type = NFT_OBJECT_QUOTA;
				handle_merge(&(yyvsp[-5].obj)->handle, &(yyvsp[-6].handle));
				handle_free(&(yyvsp[-6].handle));
				list_add_tail(&(yyvsp[-5].obj)->list, &(yyvsp[-8].table)->objs);
				(yyval.table) = (yyvsp[-8].table);
			}
#line 8849 "parser_bison.tab.c"
    break;

  case 235: /* table_block: table_block "ct" "helper" obj_identifier obj_block_alloc '{' ct_helper_block '}' close_scope_ct stmt_separator  */
#line 1796 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[-5].obj)->location = (yylsp[-6]);
				(yyvsp[-5].obj)->type = NFT_OBJECT_CT_HELPER;
				handle_merge(&(yyvsp[-5].obj)->handle, &(yyvsp[-6].handle));
				handle_free(&(yyvsp[-6].handle));
				list_add_tail(&(yyvsp[-5].obj)->list, &(yyvsp[-9].table)->objs);
				(yyval.table) = (yyvsp[-9].table);
			}
#line 8862 "parser_bison.tab.c"
    break;

  case 236: /* table_block: table_block "ct" "timeout" obj_identifier obj_block_alloc '{' ct_timeout_block '}' close_scope_ct stmt_separator  */
#line 1805 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[-5].obj)->location = (yylsp[-6]);
				(yyvsp[-5].obj)->type = NFT_OBJECT_CT_TIMEOUT;
				handle_merge(&(yyvsp[-5].obj)->handle, &(yyvsp[-6].handle));
				handle_free(&(yyvsp[-6].handle));
				list_add_tail(&(yyvsp[-5].obj)->list, &(yyvsp[-9].table)->objs);
				(yyval.table) = (yyvsp[-9].table);
			}
#line 8875 "parser_bison.tab.c"
    break;

  case 237: /* table_block: table_block "ct" "expectation" obj_identifier obj_block_alloc '{' ct_expect_block '}' close_scope_ct stmt_separator  */
#line 1814 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[-5].obj)->location = (yylsp[-6]);
				(yyvsp[-5].obj)->type = NFT_OBJECT_CT_EXPECT;
				handle_merge(&(yyvsp[-5].obj)->handle, &(yyvsp[-6].handle));
				handle_free(&(yyvsp[-6].handle));
				list_add_tail(&(yyvsp[-5].obj)->list, &(yyvsp[-9].table)->objs);
				(yyval.table) = (yyvsp[-9].table);
			}
#line 8888 "parser_bison.tab.c"
    break;

  case 238: /* table_block: table_block "limit" obj_identifier obj_block_alloc '{' limit_block '}' stmt_separator close_scope_limit  */
#line 1825 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[-5].obj)->location = (yylsp[-6]);
				(yyvsp[-5].obj)->type = NFT_OBJECT_LIMIT;
				handle_merge(&(yyvsp[-5].obj)->handle, &(yyvsp[-6].handle));
				handle_free(&(yyvsp[-6].handle));
				list_add_tail(&(yyvsp[-5].obj)->list, &(yyvsp[-8].table)->objs);
				(yyval.table) = (yyvsp[-8].table);
			}
#line 8901 "parser_bison.tab.c"
    break;

  case 239: /* table_block: table_block "secmark" obj_identifier obj_block_alloc '{' secmark_block '}' stmt_separator close_scope_secmark  */
#line 1836 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[-5].obj)->location = (yylsp[-6]);
				(yyvsp[-5].obj)->type = NFT_OBJECT_SECMARK;
				handle_merge(&(yyvsp[-5].obj)->handle, &(yyvsp[-6].handle));
				handle_free(&(yyvsp[-6].handle));
				list_add_tail(&(yyvsp[-5].obj)->list, &(yyvsp[-8].table)->objs);
				(yyval.table) = (yyvsp[-8].table);
			}
#line 8914 "parser_bison.tab.c"
    break;

  case 240: /* table_block: table_block "synproxy" obj_identifier obj_block_alloc '{' synproxy_block '}' stmt_separator close_scope_synproxy  */
#line 1847 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[-5].obj)->location = (yylsp[-6]);
				(yyvsp[-5].obj)->type = NFT_OBJECT_SYNPROXY;
				handle_merge(&(yyvsp[-5].obj)->handle, &(yyvsp[-6].handle));
				handle_free(&(yyvsp[-6].handle));
				list_add_tail(&(yyvsp[-5].obj)->list, &(yyvsp[-8].table)->objs);
				(yyval.table) = (yyvsp[-8].table);
			}
#line 8927 "parser_bison.tab.c"
    break;

  case 241: /* chain_block_alloc: %empty  */
#line 1858 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.chain) = chain_alloc(NULL);
				if (open_scope(state, &(yyval.chain)->scope) < 0) {
					erec_queue(error(&(yyloc), "too many levels of nesting"),
						   state->msgs);
					state->nerrs++;
				}
			}
#line 8940 "parser_bison.tab.c"
    break;

  case 242: /* chain_block: %empty  */
#line 1868 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.chain) = (yyvsp[(-1) - (0)].chain); }
#line 8946 "parser_bison.tab.c"
    break;

  case 248: /* chain_block: chain_block rule stmt_separator  */
#line 1875 "../../nft/nftables/src/parser_bison.y"
                        {
				list_add_tail(&(yyvsp[-1].rule)->list, &(yyvsp[-2].chain)->rules);
				(yyval.chain) = (yyvsp[-2].chain);
			}
#line 8955 "parser_bison.tab.c"
    break;

  case 249: /* chain_block: chain_block comment_spec stmt_separator  */
#line 1880 "../../nft/nftables/src/parser_bison.y"
                        {
				if (already_set((yyvsp[-2].chain)->comment, &(yylsp[-1]), state)) {
					xfree((yyvsp[-1].string));
					YYERROR;
				}
				(yyvsp[-2].chain)->comment = (yyvsp[-1].string);
			}
#line 8967 "parser_bison.tab.c"
    break;

  case 250: /* subchain_block: %empty  */
#line 1889 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.chain) = (yyvsp[(-1) - (0)].chain); }
#line 8973 "parser_bison.tab.c"
    break;

  case 252: /* subchain_block: subchain_block rule stmt_separator  */
#line 1892 "../../nft/nftables/src/parser_bison.y"
                        {
				list_add_tail(&(yyvsp[-1].rule)->list, &(yyvsp[-2].chain)->rules);
				(yyval.chain) = (yyvsp[-2].chain);
			}
#line 8982 "parser_bison.tab.c"
    break;

  case 253: /* typeof_data_expr: primary_expr  */
#line 1899 "../../nft/nftables/src/parser_bison.y"
                        {
				struct expr *e = (yyvsp[0].expr);

				if (e->etype == EXPR_SYMBOL &&
				    strcmp("verdict", e->identifier) == 0) {
					struct expr *v = verdict_expr_alloc(&(yylsp[0]), NF_ACCEPT, NULL);

					expr_free(e);
					v->flags &= ~EXPR_F_CONSTANT;
					e = v;
				}

				if (expr_ops(e)->build_udata == NULL) {
					erec_queue(error(&(yylsp[0]), "map data type '%s' lacks typeof serialization", expr_ops(e)->name),
						   state->msgs);
					expr_free(e);
					YYERROR;
				}
				(yyval.expr) = e;
			}
#line 9007 "parser_bison.tab.c"
    break;

  case 254: /* typeof_data_expr: typeof_expr "." primary_expr  */
#line 1920 "../../nft/nftables/src/parser_bison.y"
                        {
				struct location rhs[] = {
					[1]	= (yylsp[-1]),
					[2]	= (yylsp[0]),
				};

				(yyval.expr) = handle_concat_expr(&(yyloc), (yyval.expr), (yyvsp[-2].expr), (yyvsp[0].expr), rhs);
			}
#line 9020 "parser_bison.tab.c"
    break;

  case 255: /* typeof_expr: primary_expr  */
#line 1931 "../../nft/nftables/src/parser_bison.y"
                        {
				if (expr_ops((yyvsp[0].expr))->build_udata == NULL) {
					erec_queue(error(&(yylsp[0]), "primary expression type '%s' lacks typeof serialization", expr_ops((yyvsp[0].expr))->name),
						   state->msgs);
					expr_free((yyvsp[0].expr));
					YYERROR;
				}

				(yyval.expr) = (yyvsp[0].expr);
			}
#line 9035 "parser_bison.tab.c"
    break;

  case 256: /* typeof_expr: typeof_expr "." primary_expr  */
#line 1942 "../../nft/nftables/src/parser_bison.y"
                        {
				struct location rhs[] = {
					[1]	= (yylsp[-1]),
					[2]	= (yylsp[0]),
				};

				(yyval.expr) = handle_concat_expr(&(yyloc), (yyval.expr), (yyvsp[-2].expr), (yyvsp[0].expr), rhs);
			}
#line 9048 "parser_bison.tab.c"
    break;

  case 257: /* set_block_alloc: %empty  */
#line 1954 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.set) = set_alloc(NULL);
			}
#line 9056 "parser_bison.tab.c"
    break;

  case 258: /* set_block: %empty  */
#line 1959 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.set) = (yyvsp[(-1) - (0)].set); }
#line 9062 "parser_bison.tab.c"
    break;

  case 261: /* set_block: set_block "type" data_type_expr stmt_separator close_scope_type  */
#line 1963 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[-4].set)->key = (yyvsp[-2].expr);
				(yyval.set) = (yyvsp[-4].set);
			}
#line 9071 "parser_bison.tab.c"
    break;

  case 262: /* set_block: set_block "typeof" typeof_expr stmt_separator  */
#line 1968 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[-3].set)->key = (yyvsp[-1].expr);
				datatype_set((yyvsp[-3].set)->key, (yyvsp[-1].expr)->dtype);
				(yyval.set) = (yyvsp[-3].set);
			}
#line 9081 "parser_bison.tab.c"
    break;

  case 263: /* set_block: set_block "flags" set_flag_list stmt_separator  */
#line 1974 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[-3].set)->flags = (yyvsp[-1].val);
				(yyval.set) = (yyvsp[-3].set);
			}
#line 9090 "parser_bison.tab.c"
    break;

  case 264: /* set_block: set_block "timeout" time_spec stmt_separator  */
#line 1979 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[-3].set)->timeout = (yyvsp[-1].val);
				(yyval.set) = (yyvsp[-3].set);
			}
#line 9099 "parser_bison.tab.c"
    break;

  case 265: /* set_block: set_block "gc-interval" time_spec stmt_separator  */
#line 1984 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[-3].set)->gc_int = (yyvsp[-1].val);
				(yyval.set) = (yyvsp[-3].set);
			}
#line 9108 "parser_bison.tab.c"
    break;

  case 266: /* set_block: set_block stateful_stmt_list stmt_separator  */
#line 1989 "../../nft/nftables/src/parser_bison.y"
                        {
				list_splice_tail((yyvsp[-1].list), &(yyvsp[-2].set)->stmt_list);
				(yyval.set) = (yyvsp[-2].set);
				free((yyvsp[-1].list));
			}
#line 9118 "parser_bison.tab.c"
    break;

  case 267: /* set_block: set_block "elements" '=' set_block_expr  */
#line 1995 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[-3].set)->init = (yyvsp[0].expr);
				(yyval.set) = (yyvsp[-3].set);
			}
#line 9127 "parser_bison.tab.c"
    break;

  case 268: /* set_block: set_block "auto-merge"  */
#line 2000 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[-1].set)->automerge = true;
				(yyval.set) = (yyvsp[-1].set);
			}
#line 9136 "parser_bison.tab.c"
    break;

  case 270: /* set_block: set_block comment_spec stmt_separator  */
#line 2006 "../../nft/nftables/src/parser_bison.y"
                        {
				if (already_set((yyvsp[-2].set)->comment, &(yylsp[-1]), state)) {
					xfree((yyvsp[-1].string));
					YYERROR;
				}
				(yyvsp[-2].set)->comment = (yyvsp[-1].string);
				(yyval.set) = (yyvsp[-2].set);
			}
#line 9149 "parser_bison.tab.c"
    break;

  case 273: /* set_flag_list: set_flag_list "comma" set_flag  */
#line 2021 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.val) = (yyvsp[-2].val) | (yyvsp[0].val);
			}
#line 9157 "parser_bison.tab.c"
    break;

  case 275: /* set_flag: "constant"  */
#line 2027 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = NFT_SET_CONSTANT; }
#line 9163 "parser_bison.tab.c"
    break;

  case 276: /* set_flag: "interval"  */
#line 2028 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = NFT_SET_INTERVAL; }
#line 9169 "parser_bison.tab.c"
    break;

  case 277: /* set_flag: "timeout"  */
#line 2029 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = NFT_SET_TIMEOUT; }
#line 9175 "parser_bison.tab.c"
    break;

  case 278: /* set_flag: "dynamic"  */
#line 2030 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = NFT_SET_EVAL; }
#line 9181 "parser_bison.tab.c"
    break;

  case 279: /* map_block_alloc: %empty  */
#line 2034 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.set) = set_alloc(NULL);
			}
#line 9189 "parser_bison.tab.c"
    break;

  case 280: /* map_block_obj_type: "counter" close_scope_counter  */
#line 2039 "../../nft/nftables/src/parser_bison.y"
                                                            { (yyval.val) = NFT_OBJECT_COUNTER; }
#line 9195 "parser_bison.tab.c"
    break;

  case 281: /* map_block_obj_type: "quota" close_scope_quota  */
#line 2040 "../../nft/nftables/src/parser_bison.y"
                                                          { (yyval.val) = NFT_OBJECT_QUOTA; }
#line 9201 "parser_bison.tab.c"
    break;

  case 282: /* map_block_obj_type: "limit" close_scope_limit  */
#line 2041 "../../nft/nftables/src/parser_bison.y"
                                                          { (yyval.val) = NFT_OBJECT_LIMIT; }
#line 9207 "parser_bison.tab.c"
    break;

  case 283: /* map_block_obj_type: "secmark" close_scope_secmark  */
#line 2042 "../../nft/nftables/src/parser_bison.y"
                                                            { (yyval.val) = NFT_OBJECT_SECMARK; }
#line 9213 "parser_bison.tab.c"
    break;

  case 284: /* map_block_obj_type: "synproxy" close_scope_synproxy  */
#line 2043 "../../nft/nftables/src/parser_bison.y"
                                                              { (yyval.val) = NFT_OBJECT_SYNPROXY; }
#line 9219 "parser_bison.tab.c"
    break;

  case 285: /* map_block: %empty  */
#line 2046 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.set) = (yyvsp[(-1) - (0)].set); }
#line 9225 "parser_bison.tab.c"
    break;

  case 288: /* map_block: map_block "timeout" time_spec stmt_separator  */
#line 2050 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[-3].set)->timeout = (yyvsp[-1].val);
				(yyval.set) = (yyvsp[-3].set);
			}
#line 9234 "parser_bison.tab.c"
    break;

  case 289: /* map_block: map_block "type" data_type_expr "colon" data_type_expr stmt_separator close_scope_type  */
#line 2057 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[-6].set)->key = (yyvsp[-4].expr);
				(yyvsp[-6].set)->data = (yyvsp[-2].expr);

				(yyvsp[-6].set)->flags |= NFT_SET_MAP;
				(yyval.set) = (yyvsp[-6].set);
			}
#line 9246 "parser_bison.tab.c"
    break;

  case 290: /* map_block: map_block "type" data_type_expr "colon" "interval" data_type_expr stmt_separator close_scope_type  */
#line 2067 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[-7].set)->key = (yyvsp[-5].expr);
				(yyvsp[-7].set)->data = (yyvsp[-2].expr);
				(yyvsp[-7].set)->data->flags |= EXPR_F_INTERVAL;

				(yyvsp[-7].set)->flags |= NFT_SET_MAP;
				(yyval.set) = (yyvsp[-7].set);
			}
#line 9259 "parser_bison.tab.c"
    break;

  case 291: /* map_block: map_block "typeof" typeof_expr "colon" typeof_data_expr stmt_separator  */
#line 2078 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[-5].set)->key = (yyvsp[-3].expr);
				datatype_set((yyvsp[-5].set)->key, (yyvsp[-3].expr)->dtype);
				(yyvsp[-5].set)->data = (yyvsp[-1].expr);

				(yyvsp[-5].set)->flags |= NFT_SET_MAP;
				(yyval.set) = (yyvsp[-5].set);
			}
#line 9272 "parser_bison.tab.c"
    break;

  case 292: /* map_block: map_block "typeof" typeof_expr "colon" "interval" typeof_expr stmt_separator  */
#line 2089 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[-6].set)->key = (yyvsp[-4].expr);
				datatype_set((yyvsp[-6].set)->key, (yyvsp[-4].expr)->dtype);
				(yyvsp[-6].set)->data = (yyvsp[-1].expr);
				(yyvsp[-6].set)->data->flags |= EXPR_F_INTERVAL;

				(yyvsp[-6].set)->flags |= NFT_SET_MAP;
				(yyval.set) = (yyvsp[-6].set);
			}
#line 9286 "parser_bison.tab.c"
    break;

  case 293: /* map_block: map_block "type" data_type_expr "colon" map_block_obj_type stmt_separator close_scope_type  */
#line 2101 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[-6].set)->key = (yyvsp[-4].expr);
				(yyvsp[-6].set)->objtype = (yyvsp[-2].val);
				(yyvsp[-6].set)->flags  |= NFT_SET_OBJECT;
				(yyval.set) = (yyvsp[-6].set);
			}
#line 9297 "parser_bison.tab.c"
    break;

  case 294: /* map_block: map_block "flags" set_flag_list stmt_separator  */
#line 2108 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[-3].set)->flags |= (yyvsp[-1].val);
				(yyval.set) = (yyvsp[-3].set);
			}
#line 9306 "parser_bison.tab.c"
    break;

  case 295: /* map_block: map_block stateful_stmt_list stmt_separator  */
#line 2113 "../../nft/nftables/src/parser_bison.y"
                        {
				list_splice_tail((yyvsp[-1].list), &(yyvsp[-2].set)->stmt_list);
				(yyval.set) = (yyvsp[-2].set);
				free((yyvsp[-1].list));
			}
#line 9316 "parser_bison.tab.c"
    break;

  case 296: /* map_block: map_block "elements" '=' set_block_expr  */
#line 2119 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[-3].set)->init = (yyvsp[0].expr);
				(yyval.set) = (yyvsp[-3].set);
			}
#line 9325 "parser_bison.tab.c"
    break;

  case 297: /* map_block: map_block comment_spec stmt_separator  */
#line 2124 "../../nft/nftables/src/parser_bison.y"
                        {
				if (already_set((yyvsp[-2].set)->comment, &(yylsp[-1]), state)) {
					xfree((yyvsp[-1].string));
					YYERROR;
				}
				(yyvsp[-2].set)->comment = (yyvsp[-1].string);
				(yyval.set) = (yyvsp[-2].set);
			}
#line 9338 "parser_bison.tab.c"
    break;

  case 299: /* set_mechanism: "policy" set_policy_spec close_scope_policy  */
#line 2136 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[-3].set)->policy = (yyvsp[-1].val);
			}
#line 9346 "parser_bison.tab.c"
    break;

  case 300: /* set_mechanism: "size" "number"  */
#line 2140 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[-2].set)->desc.size = (yyvsp[0].val);
			}
#line 9354 "parser_bison.tab.c"
    break;

  case 301: /* set_policy_spec: "performance"  */
#line 2145 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = NFT_SET_POL_PERFORMANCE; }
#line 9360 "parser_bison.tab.c"
    break;

  case 302: /* set_policy_spec: "memory"  */
#line 2146 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = NFT_SET_POL_MEMORY; }
#line 9366 "parser_bison.tab.c"
    break;

  case 303: /* flowtable_block_alloc: %empty  */
#line 2150 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.flowtable) = flowtable_alloc(NULL);
			}
#line 9374 "parser_bison.tab.c"
    break;

  case 304: /* flowtable_block: %empty  */
#line 2155 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.flowtable) = (yyvsp[(-1) - (0)].flowtable); }
#line 9380 "parser_bison.tab.c"
    break;

  case 307: /* flowtable_block: flowtable_block "hook" "string" prio_spec stmt_separator  */
#line 2159 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.flowtable)->hook.loc = (yylsp[-2]);
				(yyval.flowtable)->hook.name = chain_hookname_lookup((yyvsp[-2].string));
				if ((yyval.flowtable)->hook.name == NULL) {
					erec_queue(error(&(yylsp[-2]), "unknown chain hook"),
						   state->msgs);
					xfree((yyvsp[-2].string));
					YYERROR;
				}
				xfree((yyvsp[-2].string));

				(yyval.flowtable)->priority = (yyvsp[-1].prio_spec);
			}
#line 9398 "parser_bison.tab.c"
    break;

  case 308: /* flowtable_block: flowtable_block "devices" '=' flowtable_expr stmt_separator  */
#line 2173 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.flowtable)->dev_expr = (yyvsp[-1].expr);
			}
#line 9406 "parser_bison.tab.c"
    break;

  case 309: /* flowtable_block: flowtable_block "counter" close_scope_counter  */
#line 2177 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.flowtable)->flags |= NFT_FLOWTABLE_COUNTER;
			}
#line 9414 "parser_bison.tab.c"
    break;

  case 310: /* flowtable_block: flowtable_block "flags" "offload" stmt_separator  */
#line 2181 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.flowtable)->flags |= FLOWTABLE_F_HW_OFFLOAD;
			}
#line 9422 "parser_bison.tab.c"
    break;

  case 311: /* flowtable_expr: '{' flowtable_list_expr '}'  */
#line 2187 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[-1].expr)->location = (yyloc);
				(yyval.expr) = (yyvsp[-1].expr);
			}
#line 9431 "parser_bison.tab.c"
    break;

  case 312: /* flowtable_expr: variable_expr  */
#line 2192 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[0].expr)->location = (yyloc);
				(yyval.expr) = (yyvsp[0].expr);
			}
#line 9440 "parser_bison.tab.c"
    break;

  case 313: /* flowtable_list_expr: flowtable_expr_member  */
#line 2199 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = compound_expr_alloc(&(yyloc), EXPR_LIST);
				compound_expr_add((yyval.expr), (yyvsp[0].expr));
			}
#line 9449 "parser_bison.tab.c"
    break;

  case 314: /* flowtable_list_expr: flowtable_list_expr "comma" flowtable_expr_member  */
#line 2204 "../../nft/nftables/src/parser_bison.y"
                        {
				compound_expr_add((yyvsp[-2].expr), (yyvsp[0].expr));
				(yyval.expr) = (yyvsp[-2].expr);
			}
#line 9458 "parser_bison.tab.c"
    break;

  case 316: /* flowtable_expr_member: "quoted string"  */
#line 2212 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = constant_expr_alloc(&(yyloc), &string_type,
							 BYTEORDER_HOST_ENDIAN,
							 strlen((yyvsp[0].string)) * BITS_PER_BYTE, (yyvsp[0].string));
				xfree((yyvsp[0].string));
			}
#line 9469 "parser_bison.tab.c"
    break;

  case 317: /* flowtable_expr_member: "string"  */
#line 2219 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = constant_expr_alloc(&(yyloc), &string_type,
							 BYTEORDER_HOST_ENDIAN,
							 strlen((yyvsp[0].string)) * BITS_PER_BYTE, (yyvsp[0].string));
				xfree((yyvsp[0].string));
			}
#line 9480 "parser_bison.tab.c"
    break;

  case 318: /* flowtable_expr_member: variable_expr  */
#line 2226 "../../nft/nftables/src/parser_bison.y"
                        {
				datatype_set((yyvsp[0].expr)->sym->expr, &ifname_type);
				(yyval.expr) = (yyvsp[0].expr);
			}
#line 9489 "parser_bison.tab.c"
    break;

  case 319: /* data_type_atom_expr: type_identifier  */
#line 2233 "../../nft/nftables/src/parser_bison.y"
                        {
				const struct datatype *dtype = datatype_lookup_byname((yyvsp[0].string));
				if (dtype == NULL) {
					erec_queue(error(&(yylsp[0]), "unknown datatype %s", (yyvsp[0].string)),
						   state->msgs);
					xfree((yyvsp[0].string));
					YYERROR;
				}
				(yyval.expr) = constant_expr_alloc(&(yylsp[0]), dtype, dtype->byteorder,
							 dtype->size, NULL);
				xfree((yyvsp[0].string));
			}
#line 9506 "parser_bison.tab.c"
    break;

  case 320: /* data_type_atom_expr: "time"  */
#line 2246 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = constant_expr_alloc(&(yylsp[0]), &time_type, time_type.byteorder,
							 time_type.size, NULL);
			}
#line 9515 "parser_bison.tab.c"
    break;

  case 322: /* data_type_expr: data_type_expr "." data_type_atom_expr  */
#line 2254 "../../nft/nftables/src/parser_bison.y"
                        {
				struct location rhs[] = {
					[1]	= (yylsp[-1]),
					[2]	= (yylsp[0]),
				};

				(yyval.expr) = handle_concat_expr(&(yyloc), (yyval.expr), (yyvsp[-2].expr), (yyvsp[0].expr), rhs);
			}
#line 9528 "parser_bison.tab.c"
    break;

  case 323: /* obj_block_alloc: %empty  */
#line 2265 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.obj) = obj_alloc(NULL);
			}
#line 9536 "parser_bison.tab.c"
    break;

  case 324: /* counter_block: %empty  */
#line 2270 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.obj) = (yyvsp[(-1) - (0)].obj); }
#line 9542 "parser_bison.tab.c"
    break;

  case 327: /* counter_block: counter_block counter_config  */
#line 2274 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.obj) = (yyvsp[-1].obj);
			}
#line 9550 "parser_bison.tab.c"
    break;

  case 328: /* counter_block: counter_block comment_spec  */
#line 2278 "../../nft/nftables/src/parser_bison.y"
                        {
				if (already_set((yyvsp[-1].obj)->comment, &(yylsp[0]), state)) {
					xfree((yyvsp[0].string));
					YYERROR;
				}
				(yyvsp[-1].obj)->comment = (yyvsp[0].string);
			}
#line 9562 "parser_bison.tab.c"
    break;

  case 329: /* quota_block: %empty  */
#line 2287 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.obj) = (yyvsp[(-1) - (0)].obj); }
#line 9568 "parser_bison.tab.c"
    break;

  case 332: /* quota_block: quota_block quota_config  */
#line 2291 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.obj) = (yyvsp[-1].obj);
			}
#line 9576 "parser_bison.tab.c"
    break;

  case 333: /* quota_block: quota_block comment_spec  */
#line 2295 "../../nft/nftables/src/parser_bison.y"
                        {
				if (already_set((yyvsp[-1].obj)->comment, &(yylsp[0]), state)) {
					xfree((yyvsp[0].string));
					YYERROR;
				}
				(yyvsp[-1].obj)->comment = (yyvsp[0].string);
			}
#line 9588 "parser_bison.tab.c"
    break;

  case 334: /* ct_helper_block: %empty  */
#line 2304 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.obj) = (yyvsp[(-1) - (0)].obj); }
#line 9594 "parser_bison.tab.c"
    break;

  case 337: /* ct_helper_block: ct_helper_block ct_helper_config  */
#line 2308 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.obj) = (yyvsp[-1].obj);
			}
#line 9602 "parser_bison.tab.c"
    break;

  case 338: /* ct_helper_block: ct_helper_block comment_spec  */
#line 2312 "../../nft/nftables/src/parser_bison.y"
                        {
				if (already_set((yyvsp[-1].obj)->comment, &(yylsp[0]), state)) {
					xfree((yyvsp[0].string));
					YYERROR;
				}
				(yyvsp[-1].obj)->comment = (yyvsp[0].string);
			}
#line 9614 "parser_bison.tab.c"
    break;

  case 339: /* ct_timeout_block: %empty  */
#line 2322 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.obj) = (yyvsp[(-1) - (0)].obj);
				init_list_head(&(yyval.obj)->ct_timeout.timeout_list);
			}
#line 9623 "parser_bison.tab.c"
    break;

  case 342: /* ct_timeout_block: ct_timeout_block ct_timeout_config  */
#line 2329 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.obj) = (yyvsp[-1].obj);
			}
#line 9631 "parser_bison.tab.c"
    break;

  case 343: /* ct_timeout_block: ct_timeout_block comment_spec  */
#line 2333 "../../nft/nftables/src/parser_bison.y"
                        {
				if (already_set((yyvsp[-1].obj)->comment, &(yylsp[0]), state)) {
					xfree((yyvsp[0].string));
					YYERROR;
				}
				(yyvsp[-1].obj)->comment = (yyvsp[0].string);
			}
#line 9643 "parser_bison.tab.c"
    break;

  case 344: /* ct_expect_block: %empty  */
#line 2342 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.obj) = (yyvsp[(-1) - (0)].obj); }
#line 9649 "parser_bison.tab.c"
    break;

  case 347: /* ct_expect_block: ct_expect_block ct_expect_config  */
#line 2346 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.obj) = (yyvsp[-1].obj);
			}
#line 9657 "parser_bison.tab.c"
    break;

  case 348: /* ct_expect_block: ct_expect_block comment_spec  */
#line 2350 "../../nft/nftables/src/parser_bison.y"
                        {
				if (already_set((yyvsp[-1].obj)->comment, &(yylsp[0]), state)) {
					xfree((yyvsp[0].string));
					YYERROR;
				}
				(yyvsp[-1].obj)->comment = (yyvsp[0].string);
			}
#line 9669 "parser_bison.tab.c"
    break;

  case 349: /* limit_block: %empty  */
#line 2359 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.obj) = (yyvsp[(-1) - (0)].obj); }
#line 9675 "parser_bison.tab.c"
    break;

  case 352: /* limit_block: limit_block limit_config  */
#line 2363 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.obj) = (yyvsp[-1].obj);
			}
#line 9683 "parser_bison.tab.c"
    break;

  case 353: /* limit_block: limit_block comment_spec  */
#line 2367 "../../nft/nftables/src/parser_bison.y"
                        {
				if (already_set((yyvsp[-1].obj)->comment, &(yylsp[0]), state)) {
					xfree((yyvsp[0].string));
					YYERROR;
				}
				(yyvsp[-1].obj)->comment = (yyvsp[0].string);
			}
#line 9695 "parser_bison.tab.c"
    break;

  case 354: /* secmark_block: %empty  */
#line 2376 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.obj) = (yyvsp[(-1) - (0)].obj); }
#line 9701 "parser_bison.tab.c"
    break;

  case 357: /* secmark_block: secmark_block secmark_config  */
#line 2380 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.obj) = (yyvsp[-1].obj);
			}
#line 9709 "parser_bison.tab.c"
    break;

  case 358: /* secmark_block: secmark_block comment_spec  */
#line 2384 "../../nft/nftables/src/parser_bison.y"
                        {
				if (already_set((yyvsp[-1].obj)->comment, &(yylsp[0]), state)) {
					xfree((yyvsp[0].string));
					YYERROR;
				}
				(yyvsp[-1].obj)->comment = (yyvsp[0].string);
			}
#line 9721 "parser_bison.tab.c"
    break;

  case 359: /* synproxy_block: %empty  */
#line 2393 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.obj) = (yyvsp[(-1) - (0)].obj); }
#line 9727 "parser_bison.tab.c"
    break;

  case 362: /* synproxy_block: synproxy_block synproxy_config  */
#line 2397 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.obj) = (yyvsp[-1].obj);
			}
#line 9735 "parser_bison.tab.c"
    break;

  case 363: /* synproxy_block: synproxy_block comment_spec  */
#line 2401 "../../nft/nftables/src/parser_bison.y"
                        {
				if (already_set((yyvsp[-1].obj)->comment, &(yylsp[0]), state)) {
					xfree((yyvsp[0].string));
					YYERROR;
				}
				(yyvsp[-1].obj)->comment = (yyvsp[0].string);
			}
#line 9747 "parser_bison.tab.c"
    break;

  case 364: /* type_identifier: "string"  */
#line 2410 "../../nft/nftables/src/parser_bison.y"
                                        { (yyval.string) = (yyvsp[0].string); }
#line 9753 "parser_bison.tab.c"
    break;

  case 365: /* type_identifier: "mark"  */
#line 2411 "../../nft/nftables/src/parser_bison.y"
                                        { (yyval.string) = xstrdup("mark"); }
#line 9759 "parser_bison.tab.c"
    break;

  case 366: /* type_identifier: "dscp"  */
#line 2412 "../../nft/nftables/src/parser_bison.y"
                                        { (yyval.string) = xstrdup("dscp"); }
#line 9765 "parser_bison.tab.c"
    break;

  case 367: /* type_identifier: "ecn"  */
#line 2413 "../../nft/nftables/src/parser_bison.y"
                                        { (yyval.string) = xstrdup("ecn"); }
#line 9771 "parser_bison.tab.c"
    break;

  case 368: /* type_identifier: "classid"  */
#line 2414 "../../nft/nftables/src/parser_bison.y"
                                        { (yyval.string) = xstrdup("classid"); }
#line 9777 "parser_bison.tab.c"
    break;

  case 369: /* hook_spec: "type" close_scope_type "string" "hook" "string" dev_spec prio_spec  */
#line 2418 "../../nft/nftables/src/parser_bison.y"
                        {
				const char *chain_type = chain_type_name_lookup((yyvsp[-4].string));

				if (chain_type == NULL) {
					erec_queue(error(&(yylsp[-4]), "unknown chain type"),
						   state->msgs);
					xfree((yyvsp[-4].string));
					YYERROR;
				}
				(yyvsp[-7].chain)->type.loc = (yylsp[-4]);
				(yyvsp[-7].chain)->type.str = xstrdup(chain_type);
				xfree((yyvsp[-4].string));

				(yyvsp[-7].chain)->loc = (yyloc);
				(yyvsp[-7].chain)->hook.loc = (yylsp[-2]);
				(yyvsp[-7].chain)->hook.name = chain_hookname_lookup((yyvsp[-2].string));
				if ((yyvsp[-7].chain)->hook.name == NULL) {
					erec_queue(error(&(yylsp[-2]), "unknown chain hook"),
						   state->msgs);
					xfree((yyvsp[-2].string));
					YYERROR;
				}
				xfree((yyvsp[-2].string));

				(yyvsp[-7].chain)->dev_expr	= (yyvsp[-1].expr);
				(yyvsp[-7].chain)->priority	= (yyvsp[0].prio_spec);
				(yyvsp[-7].chain)->flags	|= CHAIN_F_BASECHAIN;
			}
#line 9810 "parser_bison.tab.c"
    break;

  case 370: /* prio_spec: "priority" extended_prio_spec  */
#line 2449 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.prio_spec) = (yyvsp[0].prio_spec);
				(yyval.prio_spec).loc = (yyloc);
			}
#line 9819 "parser_bison.tab.c"
    break;

  case 371: /* extended_prio_name: "out"  */
#line 2456 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.string) = strdup("out");
			}
#line 9827 "parser_bison.tab.c"
    break;

  case 373: /* extended_prio_spec: int_num  */
#line 2463 "../../nft/nftables/src/parser_bison.y"
                        {
				struct prio_spec spec = {0};

				spec.expr = constant_expr_alloc(&(yyloc), &integer_type,
								BYTEORDER_HOST_ENDIAN,
								sizeof(int) *
								BITS_PER_BYTE, &(yyvsp[0].val32));
				(yyval.prio_spec) = spec;
			}
#line 9841 "parser_bison.tab.c"
    break;

  case 374: /* extended_prio_spec: variable_expr  */
#line 2473 "../../nft/nftables/src/parser_bison.y"
                        {
				struct prio_spec spec = {0};

				spec.expr = (yyvsp[0].expr);
				(yyval.prio_spec) = spec;
			}
#line 9852 "parser_bison.tab.c"
    break;

  case 375: /* extended_prio_spec: extended_prio_name  */
#line 2480 "../../nft/nftables/src/parser_bison.y"
                        {
				struct prio_spec spec = {0};

				spec.expr = constant_expr_alloc(&(yyloc), &string_type,
								BYTEORDER_HOST_ENDIAN,
								strlen((yyvsp[0].string)) * BITS_PER_BYTE,
								(yyvsp[0].string));
				xfree((yyvsp[0].string));
				(yyval.prio_spec) = spec;
			}
#line 9867 "parser_bison.tab.c"
    break;

  case 376: /* extended_prio_spec: extended_prio_name "+" "number"  */
#line 2491 "../../nft/nftables/src/parser_bison.y"
                        {
				struct prio_spec spec = {0};

				char str[NFT_NAME_MAXLEN];
				snprintf(str, sizeof(str), "%s + %" PRIu64, (yyvsp[-2].string), (yyvsp[0].val));
				spec.expr = constant_expr_alloc(&(yyloc), &string_type,
								BYTEORDER_HOST_ENDIAN,
								strlen(str) * BITS_PER_BYTE,
								str);
				xfree((yyvsp[-2].string));
				(yyval.prio_spec) = spec;
			}
#line 9884 "parser_bison.tab.c"
    break;

  case 377: /* extended_prio_spec: extended_prio_name "-" "number"  */
#line 2504 "../../nft/nftables/src/parser_bison.y"
                        {
				struct prio_spec spec = {0};
				char str[NFT_NAME_MAXLEN];

				snprintf(str, sizeof(str), "%s - %" PRIu64, (yyvsp[-2].string), (yyvsp[0].val));
				spec.expr = constant_expr_alloc(&(yyloc), &string_type,
								BYTEORDER_HOST_ENDIAN,
								strlen(str) * BITS_PER_BYTE,
								str);
				xfree((yyvsp[-2].string));
				(yyval.prio_spec) = spec;
			}
#line 9901 "parser_bison.tab.c"
    break;

  case 378: /* int_num: "number"  */
#line 2518 "../../nft/nftables/src/parser_bison.y"
                                                        { (yyval.val32) = (yyvsp[0].val); }
#line 9907 "parser_bison.tab.c"
    break;

  case 379: /* int_num: "-" "number"  */
#line 2519 "../../nft/nftables/src/parser_bison.y"
                                                        { (yyval.val32) = -(yyvsp[0].val); }
#line 9913 "parser_bison.tab.c"
    break;

  case 380: /* dev_spec: "device" string  */
#line 2523 "../../nft/nftables/src/parser_bison.y"
                        {
				struct expr *expr;

				expr = constant_expr_alloc(&(yyloc), &string_type,
							   BYTEORDER_HOST_ENDIAN,
							   strlen((yyvsp[0].string)) * BITS_PER_BYTE, (yyvsp[0].string));
				xfree((yyvsp[0].string));
				(yyval.expr) = compound_expr_alloc(&(yyloc), EXPR_LIST);
				compound_expr_add((yyval.expr), expr);

			}
#line 9929 "parser_bison.tab.c"
    break;

  case 381: /* dev_spec: "device" variable_expr  */
#line 2535 "../../nft/nftables/src/parser_bison.y"
                        {
				datatype_set((yyvsp[0].expr)->sym->expr, &ifname_type);
				(yyval.expr) = compound_expr_alloc(&(yyloc), EXPR_LIST);
				compound_expr_add((yyval.expr), (yyvsp[0].expr));
			}
#line 9939 "parser_bison.tab.c"
    break;

  case 382: /* dev_spec: "devices" '=' flowtable_expr  */
#line 2541 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = (yyvsp[0].expr);
			}
#line 9947 "parser_bison.tab.c"
    break;

  case 383: /* dev_spec: %empty  */
#line 2544 "../../nft/nftables/src/parser_bison.y"
                                                        { (yyval.expr) = NULL; }
#line 9953 "parser_bison.tab.c"
    break;

  case 384: /* flags_spec: "flags" "offload"  */
#line 2548 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[-2].chain)->flags |= CHAIN_F_HW_OFFLOAD;
			}
#line 9961 "parser_bison.tab.c"
    break;

  case 385: /* policy_spec: "policy" policy_expr close_scope_policy  */
#line 2554 "../../nft/nftables/src/parser_bison.y"
                        {
				if ((yyvsp[-3].chain)->policy) {
					erec_queue(error(&(yyloc), "you cannot set chain policy twice"),
						   state->msgs);
					expr_free((yyvsp[-1].expr));
					YYERROR;
				}
				(yyvsp[-3].chain)->policy		= (yyvsp[-1].expr);
				(yyvsp[-3].chain)->policy->location	= (yyloc);
			}
#line 9976 "parser_bison.tab.c"
    break;

  case 386: /* policy_expr: variable_expr  */
#line 2567 "../../nft/nftables/src/parser_bison.y"
                        {
				datatype_set((yyvsp[0].expr)->sym->expr, &policy_type);
				(yyval.expr) = (yyvsp[0].expr);
			}
#line 9985 "parser_bison.tab.c"
    break;

  case 387: /* policy_expr: chain_policy  */
#line 2572 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = constant_expr_alloc(&(yyloc), &integer_type,
							 BYTEORDER_HOST_ENDIAN,
							 sizeof(int) *
							 BITS_PER_BYTE, &(yyvsp[0].val32));
			}
#line 9996 "parser_bison.tab.c"
    break;

  case 388: /* chain_policy: "accept"  */
#line 2580 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val32) = NF_ACCEPT; }
#line 10002 "parser_bison.tab.c"
    break;

  case 389: /* chain_policy: "drop"  */
#line 2581 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val32) = NF_DROP;   }
#line 10008 "parser_bison.tab.c"
    break;

  case 394: /* time_spec: "string"  */
#line 2593 "../../nft/nftables/src/parser_bison.y"
                        {
				struct error_record *erec;
				uint64_t res;

				erec = time_parse(&(yylsp[0]), (yyvsp[0].string), &res);
				xfree((yyvsp[0].string));
				if (erec != NULL) {
					erec_queue(erec, state->msgs);
					YYERROR;
				}
				(yyval.val) = res;
			}
#line 10025 "parser_bison.tab.c"
    break;

  case 395: /* family_spec: %empty  */
#line 2607 "../../nft/nftables/src/parser_bison.y"
                                                        { (yyval.val) = NFPROTO_IPV4; }
#line 10031 "parser_bison.tab.c"
    break;

  case 397: /* family_spec_explicit: "ip" close_scope_ip  */
#line 2611 "../../nft/nftables/src/parser_bison.y"
                                                        { (yyval.val) = NFPROTO_IPV4; }
#line 10037 "parser_bison.tab.c"
    break;

  case 398: /* family_spec_explicit: "ip6" close_scope_ip6  */
#line 2612 "../../nft/nftables/src/parser_bison.y"
                                                        { (yyval.val) = NFPROTO_IPV6; }
#line 10043 "parser_bison.tab.c"
    break;

  case 399: /* family_spec_explicit: "inet"  */
#line 2613 "../../nft/nftables/src/parser_bison.y"
                                                        { (yyval.val) = NFPROTO_INET; }
#line 10049 "parser_bison.tab.c"
    break;

  case 400: /* family_spec_explicit: "arp" close_scope_arp  */
#line 2614 "../../nft/nftables/src/parser_bison.y"
                                                        { (yyval.val) = NFPROTO_ARP; }
#line 10055 "parser_bison.tab.c"
    break;

  case 401: /* family_spec_explicit: "bridge"  */
#line 2615 "../../nft/nftables/src/parser_bison.y"
                                                        { (yyval.val) = NFPROTO_BRIDGE; }
#line 10061 "parser_bison.tab.c"
    break;

  case 402: /* family_spec_explicit: "netdev"  */
#line 2616 "../../nft/nftables/src/parser_bison.y"
                                                        { (yyval.val) = NFPROTO_NETDEV; }
#line 10067 "parser_bison.tab.c"
    break;

  case 403: /* table_spec: family_spec identifier  */
#line 2620 "../../nft/nftables/src/parser_bison.y"
                        {
				memset(&(yyval.handle), 0, sizeof((yyval.handle)));
				(yyval.handle).family	= (yyvsp[-1].val);
				(yyval.handle).table.location = (yylsp[0]);
				(yyval.handle).table.name	= (yyvsp[0].string);
			}
#line 10078 "parser_bison.tab.c"
    break;

  case 404: /* tableid_spec: family_spec "handle" "number"  */
#line 2629 "../../nft/nftables/src/parser_bison.y"
                        {
				memset(&(yyval.handle), 0, sizeof((yyval.handle)));
				(yyval.handle).family 		= (yyvsp[-2].val);
				(yyval.handle).handle.id 		= (yyvsp[0].val);
				(yyval.handle).handle.location	= (yylsp[0]);
			}
#line 10089 "parser_bison.tab.c"
    break;

  case 405: /* chain_spec: table_spec identifier  */
#line 2638 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.handle)		= (yyvsp[-1].handle);
				(yyval.handle).chain.name	= (yyvsp[0].string);
				(yyval.handle).chain.location = (yylsp[0]);
			}
#line 10099 "parser_bison.tab.c"
    break;

  case 406: /* chainid_spec: table_spec "handle" "number"  */
#line 2646 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.handle) 			= (yyvsp[-2].handle);
				(yyval.handle).handle.location 	= (yylsp[0]);
				(yyval.handle).handle.id 		= (yyvsp[0].val);
			}
#line 10109 "parser_bison.tab.c"
    break;

  case 407: /* chain_identifier: identifier  */
#line 2654 "../../nft/nftables/src/parser_bison.y"
                        {
				memset(&(yyval.handle), 0, sizeof((yyval.handle)));
				(yyval.handle).chain.name		= (yyvsp[0].string);
				(yyval.handle).chain.location	= (yylsp[0]);
			}
#line 10119 "parser_bison.tab.c"
    break;

  case 408: /* set_spec: table_spec identifier  */
#line 2662 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.handle)		= (yyvsp[-1].handle);
				(yyval.handle).set.name	= (yyvsp[0].string);
				(yyval.handle).set.location	= (yylsp[0]);
			}
#line 10129 "parser_bison.tab.c"
    break;

  case 409: /* setid_spec: table_spec "handle" "number"  */
#line 2670 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.handle) 			= (yyvsp[-2].handle);
				(yyval.handle).handle.location 	= (yylsp[0]);
				(yyval.handle).handle.id 		= (yyvsp[0].val);
			}
#line 10139 "parser_bison.tab.c"
    break;

  case 410: /* set_identifier: identifier  */
#line 2678 "../../nft/nftables/src/parser_bison.y"
                        {
				memset(&(yyval.handle), 0, sizeof((yyval.handle)));
				(yyval.handle).set.name	= (yyvsp[0].string);
				(yyval.handle).set.location	= (yylsp[0]);
			}
#line 10149 "parser_bison.tab.c"
    break;

  case 411: /* flowtable_spec: table_spec identifier  */
#line 2686 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.handle)			= (yyvsp[-1].handle);
				(yyval.handle).flowtable.name	= (yyvsp[0].string);
				(yyval.handle).flowtable.location	= (yylsp[0]);
			}
#line 10159 "parser_bison.tab.c"
    break;

  case 412: /* flowtableid_spec: table_spec "handle" "number"  */
#line 2694 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.handle)			= (yyvsp[-2].handle);
				(yyval.handle).handle.location	= (yylsp[0]);
				(yyval.handle).handle.id		= (yyvsp[0].val);
			}
#line 10169 "parser_bison.tab.c"
    break;

  case 413: /* flowtable_identifier: identifier  */
#line 2702 "../../nft/nftables/src/parser_bison.y"
                        {
				memset(&(yyval.handle), 0, sizeof((yyval.handle)));
				(yyval.handle).flowtable.name	= (yyvsp[0].string);
				(yyval.handle).flowtable.location	= (yylsp[0]);
			}
#line 10179 "parser_bison.tab.c"
    break;

  case 414: /* obj_spec: table_spec identifier  */
#line 2710 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.handle)		= (yyvsp[-1].handle);
				(yyval.handle).obj.name	= (yyvsp[0].string);
				(yyval.handle).obj.location	= (yylsp[0]);
			}
#line 10189 "parser_bison.tab.c"
    break;

  case 415: /* objid_spec: table_spec "handle" "number"  */
#line 2718 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.handle) 			= (yyvsp[-2].handle);
				(yyval.handle).handle.location	= (yylsp[0]);
				(yyval.handle).handle.id		= (yyvsp[0].val);
			}
#line 10199 "parser_bison.tab.c"
    break;

  case 416: /* obj_identifier: identifier  */
#line 2726 "../../nft/nftables/src/parser_bison.y"
                        {
				memset(&(yyval.handle), 0, sizeof((yyval.handle)));
				(yyval.handle).obj.name		= (yyvsp[0].string);
				(yyval.handle).obj.location		= (yylsp[0]);
			}
#line 10209 "parser_bison.tab.c"
    break;

  case 417: /* handle_spec: "handle" "number"  */
#line 2734 "../../nft/nftables/src/parser_bison.y"
                        {
				memset(&(yyval.handle), 0, sizeof((yyval.handle)));
				(yyval.handle).handle.location	= (yylsp[0]);
				(yyval.handle).handle.id		= (yyvsp[0].val);
			}
#line 10219 "parser_bison.tab.c"
    break;

  case 418: /* position_spec: "position" "number"  */
#line 2742 "../../nft/nftables/src/parser_bison.y"
                        {
				memset(&(yyval.handle), 0, sizeof((yyval.handle)));
				(yyval.handle).position.location	= (yyloc);
				(yyval.handle).position.id		= (yyvsp[0].val);
			}
#line 10229 "parser_bison.tab.c"
    break;

  case 419: /* index_spec: "index" "number"  */
#line 2750 "../../nft/nftables/src/parser_bison.y"
                        {
				memset(&(yyval.handle), 0, sizeof((yyval.handle)));
				(yyval.handle).index.location	= (yyloc);
				(yyval.handle).index.id		= (yyvsp[0].val) + 1;
			}
#line 10239 "parser_bison.tab.c"
    break;

  case 420: /* rule_position: chain_spec  */
#line 2758 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.handle) = (yyvsp[0].handle);
			}
#line 10247 "parser_bison.tab.c"
    break;

  case 421: /* rule_position: chain_spec position_spec  */
#line 2762 "../../nft/nftables/src/parser_bison.y"
                        {
				handle_merge(&(yyvsp[-1].handle), &(yyvsp[0].handle));
				(yyval.handle) = (yyvsp[-1].handle);
			}
#line 10256 "parser_bison.tab.c"
    break;

  case 422: /* rule_position: chain_spec handle_spec  */
#line 2767 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[0].handle).position.location = (yyvsp[0].handle).handle.location;
				(yyvsp[0].handle).position.id = (yyvsp[0].handle).handle.id;
				(yyvsp[0].handle).handle.id = 0;
				handle_merge(&(yyvsp[-1].handle), &(yyvsp[0].handle));
				(yyval.handle) = (yyvsp[-1].handle);
			}
#line 10268 "parser_bison.tab.c"
    break;

  case 423: /* rule_position: chain_spec index_spec  */
#line 2775 "../../nft/nftables/src/parser_bison.y"
                        {
				handle_merge(&(yyvsp[-1].handle), &(yyvsp[0].handle));
				(yyval.handle) = (yyvsp[-1].handle);
			}
#line 10277 "parser_bison.tab.c"
    break;

  case 424: /* ruleid_spec: chain_spec handle_spec  */
#line 2782 "../../nft/nftables/src/parser_bison.y"
                        {
				handle_merge(&(yyvsp[-1].handle), &(yyvsp[0].handle));
				(yyval.handle) = (yyvsp[-1].handle);
			}
#line 10286 "parser_bison.tab.c"
    break;

  case 425: /* comment_spec: "comment" string  */
#line 2789 "../../nft/nftables/src/parser_bison.y"
                        {
				if (strlen((yyvsp[0].string)) > NFTNL_UDATA_COMMENT_MAXLEN) {
					erec_queue(error(&(yylsp[0]), "comment too long, %d characters maximum allowed",
							 NFTNL_UDATA_COMMENT_MAXLEN),
						   state->msgs);
					xfree((yyvsp[0].string));
					YYERROR;
				}
				(yyval.string) = (yyvsp[0].string);
			}
#line 10301 "parser_bison.tab.c"
    break;

  case 426: /* ruleset_spec: %empty  */
#line 2802 "../../nft/nftables/src/parser_bison.y"
                        {
				memset(&(yyval.handle), 0, sizeof((yyval.handle)));
				(yyval.handle).family	= NFPROTO_UNSPEC;
			}
#line 10310 "parser_bison.tab.c"
    break;

  case 427: /* ruleset_spec: family_spec_explicit  */
#line 2807 "../../nft/nftables/src/parser_bison.y"
                        {
				memset(&(yyval.handle), 0, sizeof((yyval.handle)));
				(yyval.handle).family	= (yyvsp[0].val);
			}
#line 10319 "parser_bison.tab.c"
    break;

  case 428: /* rule: rule_alloc  */
#line 2814 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.rule)->comment = NULL;
			}
#line 10327 "parser_bison.tab.c"
    break;

  case 429: /* rule: rule_alloc comment_spec  */
#line 2818 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.rule)->comment = (yyvsp[0].string);
			}
#line 10335 "parser_bison.tab.c"
    break;

  case 430: /* rule_alloc: stmt_list  */
#line 2824 "../../nft/nftables/src/parser_bison.y"
                        {
				struct stmt *i;

				(yyval.rule) = rule_alloc(&(yyloc), NULL);
				list_for_each_entry(i, (yyvsp[0].list), list)
					(yyval.rule)->num_stmts++;
				list_splice_tail((yyvsp[0].list), &(yyval.rule)->stmts);
				xfree((yyvsp[0].list));
			}
#line 10349 "parser_bison.tab.c"
    break;

  case 431: /* stmt_list: stmt  */
#line 2836 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.list) = xmalloc(sizeof(*(yyval.list)));
				init_list_head((yyval.list));
				list_add_tail(&(yyvsp[0].stmt)->list, (yyval.list));
			}
#line 10359 "parser_bison.tab.c"
    break;

  case 432: /* stmt_list: stmt_list stmt  */
#line 2842 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.list) = (yyvsp[-1].list);
				list_add_tail(&(yyvsp[0].stmt)->list, (yyvsp[-1].list));
			}
#line 10368 "parser_bison.tab.c"
    break;

  case 433: /* stateful_stmt_list: stateful_stmt  */
#line 2849 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.list) = xmalloc(sizeof(*(yyval.list)));
				init_list_head((yyval.list));
				list_add_tail(&(yyvsp[0].stmt)->list, (yyval.list));
			}
#line 10378 "parser_bison.tab.c"
    break;

  case 434: /* stateful_stmt_list: stateful_stmt_list stateful_stmt  */
#line 2855 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.list) = (yyvsp[-1].list);
				list_add_tail(&(yyvsp[0].stmt)->list, (yyvsp[-1].list));
			}
#line 10387 "parser_bison.tab.c"
    break;

  case 461: /* xt_stmt: "xt" "string" "string"  */
#line 2892 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.stmt) = NULL;
				xfree((yyvsp[-1].string));
				xfree((yyvsp[0].string));
				erec_queue(error(&(yyloc), "unsupported xtables compat expression, use iptables-nft with this ruleset"),
					   state->msgs);
				YYERROR;
			}
#line 10400 "parser_bison.tab.c"
    break;

  case 462: /* chain_stmt_type: "jump"  */
#line 2902 "../../nft/nftables/src/parser_bison.y"
                                        { (yyval.val) = NFT_JUMP; }
#line 10406 "parser_bison.tab.c"
    break;

  case 463: /* chain_stmt_type: "goto"  */
#line 2903 "../../nft/nftables/src/parser_bison.y"
                                        { (yyval.val) = NFT_GOTO; }
#line 10412 "parser_bison.tab.c"
    break;

  case 464: /* chain_stmt: chain_stmt_type chain_block_alloc '{' subchain_block '}'  */
#line 2907 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[-3].chain)->location = (yylsp[-3]);
				close_scope(state);
				(yyvsp[-1].chain)->location = (yylsp[-1]);
				(yyval.stmt) = chain_stmt_alloc(&(yyloc), (yyvsp[-1].chain), (yyvsp[-4].val));
			}
#line 10423 "parser_bison.tab.c"
    break;

  case 465: /* verdict_stmt: verdict_expr  */
#line 2916 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.stmt) = verdict_stmt_alloc(&(yyloc), (yyvsp[0].expr));
			}
#line 10431 "parser_bison.tab.c"
    break;

  case 466: /* verdict_stmt: verdict_map_stmt  */
#line 2920 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.stmt) = verdict_stmt_alloc(&(yyloc), (yyvsp[0].expr));
			}
#line 10439 "parser_bison.tab.c"
    break;

  case 467: /* verdict_map_stmt: concat_expr "vmap" verdict_map_expr  */
#line 2926 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = map_expr_alloc(&(yyloc), (yyvsp[-2].expr), (yyvsp[0].expr));
			}
#line 10447 "parser_bison.tab.c"
    break;

  case 468: /* verdict_map_expr: '{' verdict_map_list_expr '}'  */
#line 2932 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[-1].expr)->location = (yyloc);
				(yyval.expr) = (yyvsp[-1].expr);
			}
#line 10456 "parser_bison.tab.c"
    break;

  case 470: /* verdict_map_list_expr: verdict_map_list_member_expr  */
#line 2940 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = set_expr_alloc(&(yyloc), NULL);
				compound_expr_add((yyval.expr), (yyvsp[0].expr));
			}
#line 10465 "parser_bison.tab.c"
    break;

  case 471: /* verdict_map_list_expr: verdict_map_list_expr "comma" verdict_map_list_member_expr  */
#line 2945 "../../nft/nftables/src/parser_bison.y"
                        {
				compound_expr_add((yyvsp[-2].expr), (yyvsp[0].expr));
				(yyval.expr) = (yyvsp[-2].expr);
			}
#line 10474 "parser_bison.tab.c"
    break;

  case 473: /* verdict_map_list_member_expr: opt_newline set_elem_expr "colon" verdict_expr opt_newline  */
#line 2953 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = mapping_expr_alloc(&(yylsp[-3]), (yyvsp[-3].expr), (yyvsp[-1].expr));
			}
#line 10482 "parser_bison.tab.c"
    break;

  case 474: /* connlimit_stmt: "ct" "count" "number" close_scope_ct  */
#line 2959 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.stmt) = connlimit_stmt_alloc(&(yyloc));
				(yyval.stmt)->connlimit.count	= (yyvsp[-1].val);
			}
#line 10491 "parser_bison.tab.c"
    break;

  case 475: /* connlimit_stmt: "ct" "count" "over" "number" close_scope_ct  */
#line 2964 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.stmt) = connlimit_stmt_alloc(&(yyloc));
				(yyval.stmt)->connlimit.count = (yyvsp[-1].val);
				(yyval.stmt)->connlimit.flags = NFT_CONNLIMIT_F_INV;
			}
#line 10501 "parser_bison.tab.c"
    break;

  case 478: /* counter_stmt_alloc: "counter"  */
#line 2975 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.stmt) = counter_stmt_alloc(&(yyloc));
			}
#line 10509 "parser_bison.tab.c"
    break;

  case 479: /* counter_stmt_alloc: "counter" "name" stmt_expr  */
#line 2979 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.stmt) = objref_stmt_alloc(&(yyloc));
				(yyval.stmt)->objref.type = NFT_OBJECT_COUNTER;
				(yyval.stmt)->objref.expr = (yyvsp[0].expr);
			}
#line 10519 "parser_bison.tab.c"
    break;

  case 480: /* counter_args: counter_arg  */
#line 2987 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.stmt)	= (yyvsp[-1].stmt);
			}
#line 10527 "parser_bison.tab.c"
    break;

  case 482: /* counter_arg: "packets" "number"  */
#line 2994 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[-2].stmt)->counter.packets = (yyvsp[0].val);
			}
#line 10535 "parser_bison.tab.c"
    break;

  case 483: /* counter_arg: "bytes" "number"  */
#line 2998 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[-2].stmt)->counter.bytes	 = (yyvsp[0].val);
			}
#line 10543 "parser_bison.tab.c"
    break;

  case 486: /* log_stmt_alloc: "log"  */
#line 3008 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.stmt) = log_stmt_alloc(&(yyloc));
			}
#line 10551 "parser_bison.tab.c"
    break;

  case 487: /* log_args: log_arg  */
#line 3014 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.stmt)	= (yyvsp[-1].stmt);
			}
#line 10559 "parser_bison.tab.c"
    break;

  case 489: /* log_arg: "prefix" string  */
#line 3021 "../../nft/nftables/src/parser_bison.y"
                        {
				struct scope *scope = current_scope(state);
				bool done = false, another_var = false;
				char *start, *end, scratch = '\0';
				struct expr *expr, *item;
				struct symbol *sym;
				enum {
					PARSE_TEXT,
					PARSE_VAR,
				} prefix_state;

				/* No variables in log prefix, skip. */
				if (!strchr((yyvsp[0].string), '$')) {
					expr = constant_expr_alloc(&(yyloc), &string_type,
								   BYTEORDER_HOST_ENDIAN,
								   (strlen((yyvsp[0].string)) + 1) * BITS_PER_BYTE, (yyvsp[0].string));
					xfree((yyvsp[0].string));
					(yyvsp[-2].stmt)->log.prefix = expr;
					(yyvsp[-2].stmt)->log.flags |= STMT_LOG_PREFIX;
					break;
				}

				/* Parse variables in log prefix string using a
				 * state machine parser with two states. This
				 * parser creates list of expressions composed
				 * of constant and variable expressions.
				 */
				expr = compound_expr_alloc(&(yyloc), EXPR_LIST);

				start = (char *)(yyvsp[0].string);

				if (*start != '$') {
					prefix_state = PARSE_TEXT;
				} else {
					prefix_state = PARSE_VAR;
					start++;
				}
				end = start;

				/* Not nice, but works. */
				while (!done) {
					switch (prefix_state) {
					case PARSE_TEXT:
						while (*end != '\0' && *end != '$')
							end++;

						if (*end == '\0')
							done = true;

						*end = '\0';
						item = constant_expr_alloc(&(yyloc), &string_type,
									   BYTEORDER_HOST_ENDIAN,
									   (strlen(start) + 1) * BITS_PER_BYTE,
									   start);
						compound_expr_add(expr, item);

						if (done)
							break;

						start = end + 1;
						end = start;

						/* fall through */
					case PARSE_VAR:
						while (isalnum(*end) || *end == '_')
							end++;

						if (*end == '\0')
							done = true;
						else if (*end == '$')
							another_var = true;
						else
							scratch = *end;

						*end = '\0';

						sym = symbol_get(scope, start);
						if (!sym) {
							sym = symbol_lookup_fuzzy(scope, start);
							if (sym) {
								erec_queue(error(&(yylsp[0]), "unknown identifier '%s'; "
										 "did you mean identifier ‘%s’?",
										 start, sym->identifier),
									   state->msgs);
							} else {
								erec_queue(error(&(yylsp[0]), "unknown identifier '%s'",
										 start),
									   state->msgs);
							}
							expr_free(expr);
							xfree((yyvsp[0].string));
							YYERROR;
						}
						item = variable_expr_alloc(&(yyloc), scope, sym);
						compound_expr_add(expr, item);

						if (done)
							break;

						/* Restore original byte after
						 * symbol lookup.
						 */
						if (scratch) {
							*end = scratch;
							scratch = '\0';
						}

						start = end;
						if (another_var) {
							another_var = false;
							start++;
							prefix_state = PARSE_VAR;
						} else {
							prefix_state = PARSE_TEXT;
						}
						end = start;
						break;
					}
				}

				xfree((yyvsp[0].string));
				(yyvsp[-2].stmt)->log.prefix	 = expr;
				(yyvsp[-2].stmt)->log.flags 	|= STMT_LOG_PREFIX;
			}
#line 10688 "parser_bison.tab.c"
    break;

  case 490: /* log_arg: "group" "number"  */
#line 3146 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[-2].stmt)->log.group	 = (yyvsp[0].val);
				(yyvsp[-2].stmt)->log.flags 	|= STMT_LOG_GROUP;
			}
#line 10697 "parser_bison.tab.c"
    break;

  case 491: /* log_arg: "snaplen" "number"  */
#line 3151 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[-2].stmt)->log.snaplen	 = (yyvsp[0].val);
				(yyvsp[-2].stmt)->log.flags 	|= STMT_LOG_SNAPLEN;
			}
#line 10706 "parser_bison.tab.c"
    break;

  case 492: /* log_arg: "queue-threshold" "number"  */
#line 3156 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[-2].stmt)->log.qthreshold = (yyvsp[0].val);
				(yyvsp[-2].stmt)->log.flags 	|= STMT_LOG_QTHRESHOLD;
			}
#line 10715 "parser_bison.tab.c"
    break;

  case 493: /* log_arg: "level" level_type  */
#line 3161 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[-2].stmt)->log.level	= (yyvsp[0].val);
				(yyvsp[-2].stmt)->log.flags 	|= STMT_LOG_LEVEL;
			}
#line 10724 "parser_bison.tab.c"
    break;

  case 494: /* log_arg: "flags" log_flags  */
#line 3166 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[-2].stmt)->log.logflags	|= (yyvsp[0].val);
			}
#line 10732 "parser_bison.tab.c"
    break;

  case 495: /* level_type: string  */
#line 3172 "../../nft/nftables/src/parser_bison.y"
                        {
				if (!strcmp("emerg", (yyvsp[0].string)))
					(yyval.val) = NFT_LOGLEVEL_EMERG;
				else if (!strcmp("alert", (yyvsp[0].string)))
					(yyval.val) = NFT_LOGLEVEL_ALERT;
				else if (!strcmp("crit", (yyvsp[0].string)))
					(yyval.val) = NFT_LOGLEVEL_CRIT;
				else if (!strcmp("err", (yyvsp[0].string)))
					(yyval.val) = NFT_LOGLEVEL_ERR;
				else if (!strcmp("warn", (yyvsp[0].string)))
					(yyval.val) = NFT_LOGLEVEL_WARNING;
				else if (!strcmp("notice", (yyvsp[0].string)))
					(yyval.val) = NFT_LOGLEVEL_NOTICE;
				else if (!strcmp("info", (yyvsp[0].string)))
					(yyval.val) = NFT_LOGLEVEL_INFO;
				else if (!strcmp("debug", (yyvsp[0].string)))
					(yyval.val) = NFT_LOGLEVEL_DEBUG;
				else if (!strcmp("audit", (yyvsp[0].string)))
					(yyval.val) = NFT_LOGLEVEL_AUDIT;
				else {
					erec_queue(error(&(yylsp[0]), "invalid log level"),
						   state->msgs);
					xfree((yyvsp[0].string));
					YYERROR;
				}
				xfree((yyvsp[0].string));
			}
#line 10764 "parser_bison.tab.c"
    break;

  case 496: /* log_flags: "tcp" log_flags_tcp close_scope_tcp  */
#line 3202 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.val) = (yyvsp[-1].val);
			}
#line 10772 "parser_bison.tab.c"
    break;

  case 497: /* log_flags: "ip" "options" close_scope_ip  */
#line 3206 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.val) = NF_LOG_IPOPT;
			}
#line 10780 "parser_bison.tab.c"
    break;

  case 498: /* log_flags: "skuid"  */
#line 3210 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.val) = NF_LOG_UID;
			}
#line 10788 "parser_bison.tab.c"
    break;

  case 499: /* log_flags: "ether" close_scope_eth  */
#line 3214 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.val) = NF_LOG_MACDECODE;
			}
#line 10796 "parser_bison.tab.c"
    break;

  case 500: /* log_flags: "all"  */
#line 3218 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.val) = NF_LOG_MASK;
			}
#line 10804 "parser_bison.tab.c"
    break;

  case 501: /* log_flags_tcp: log_flags_tcp "comma" log_flag_tcp  */
#line 3224 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.val) = (yyvsp[-2].val) | (yyvsp[0].val);
			}
#line 10812 "parser_bison.tab.c"
    break;

  case 503: /* log_flag_tcp: "seq"  */
#line 3231 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.val) = NF_LOG_TCPSEQ;
			}
#line 10820 "parser_bison.tab.c"
    break;

  case 504: /* log_flag_tcp: "options"  */
#line 3235 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.val) = NF_LOG_TCPOPT;
			}
#line 10828 "parser_bison.tab.c"
    break;

  case 505: /* limit_stmt: "limit" "rate" limit_mode limit_rate_pkts limit_burst_pkts close_scope_limit  */
#line 3241 "../../nft/nftables/src/parser_bison.y"
                        {
				if ((yyvsp[-1].val) == 0) {
					erec_queue(error(&(yylsp[-1]), "packet limit burst must be > 0"),
						   state->msgs);
					YYERROR;
				}
				(yyval.stmt) = limit_stmt_alloc(&(yyloc));
				(yyval.stmt)->limit.rate	= (yyvsp[-2].limit_rate).rate;
				(yyval.stmt)->limit.unit	= (yyvsp[-2].limit_rate).unit;
				(yyval.stmt)->limit.burst	= (yyvsp[-1].val);
				(yyval.stmt)->limit.type	= NFT_LIMIT_PKTS;
				(yyval.stmt)->limit.flags = (yyvsp[-3].val);
			}
#line 10846 "parser_bison.tab.c"
    break;

  case 506: /* limit_stmt: "limit" "rate" limit_mode limit_rate_bytes limit_burst_bytes close_scope_limit  */
#line 3255 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.stmt) = limit_stmt_alloc(&(yyloc));
				(yyval.stmt)->limit.rate	= (yyvsp[-2].limit_rate).rate;
				(yyval.stmt)->limit.unit	= (yyvsp[-2].limit_rate).unit;
				(yyval.stmt)->limit.burst	= (yyvsp[-1].val);
				(yyval.stmt)->limit.type	= NFT_LIMIT_PKT_BYTES;
				(yyval.stmt)->limit.flags = (yyvsp[-3].val);
			}
#line 10859 "parser_bison.tab.c"
    break;

  case 507: /* limit_stmt: "limit" "name" stmt_expr close_scope_limit  */
#line 3264 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.stmt) = objref_stmt_alloc(&(yyloc));
				(yyval.stmt)->objref.type = NFT_OBJECT_LIMIT;
				(yyval.stmt)->objref.expr = (yyvsp[-1].expr);
			}
#line 10869 "parser_bison.tab.c"
    break;

  case 508: /* quota_mode: "over"  */
#line 3271 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = NFT_QUOTA_F_INV; }
#line 10875 "parser_bison.tab.c"
    break;

  case 509: /* quota_mode: "until"  */
#line 3272 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = 0; }
#line 10881 "parser_bison.tab.c"
    break;

  case 510: /* quota_mode: %empty  */
#line 3273 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = 0; }
#line 10887 "parser_bison.tab.c"
    break;

  case 511: /* quota_unit: "bytes"  */
#line 3276 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.string) = xstrdup("bytes"); }
#line 10893 "parser_bison.tab.c"
    break;

  case 512: /* quota_unit: "string"  */
#line 3277 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.string) = (yyvsp[0].string); }
#line 10899 "parser_bison.tab.c"
    break;

  case 513: /* quota_used: %empty  */
#line 3280 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = 0; }
#line 10905 "parser_bison.tab.c"
    break;

  case 514: /* quota_used: "used" "number" quota_unit  */
#line 3282 "../../nft/nftables/src/parser_bison.y"
                        {
				struct error_record *erec;
				uint64_t rate;

				erec = data_unit_parse(&(yyloc), (yyvsp[0].string), &rate);
				xfree((yyvsp[0].string));
				if (erec != NULL) {
					erec_queue(erec, state->msgs);
					YYERROR;
				}
				(yyval.val) = (yyvsp[-1].val) * rate;
			}
#line 10922 "parser_bison.tab.c"
    break;

  case 515: /* quota_stmt: "quota" quota_mode "number" quota_unit quota_used close_scope_quota  */
#line 3297 "../../nft/nftables/src/parser_bison.y"
                        {
				struct error_record *erec;
				uint64_t rate;

				erec = data_unit_parse(&(yyloc), (yyvsp[-2].string), &rate);
				xfree((yyvsp[-2].string));
				if (erec != NULL) {
					erec_queue(erec, state->msgs);
					YYERROR;
				}
				(yyval.stmt) = quota_stmt_alloc(&(yyloc));
				(yyval.stmt)->quota.bytes	= (yyvsp[-3].val) * rate;
				(yyval.stmt)->quota.used = (yyvsp[-1].val);
				(yyval.stmt)->quota.flags	= (yyvsp[-4].val);
			}
#line 10942 "parser_bison.tab.c"
    break;

  case 516: /* quota_stmt: "quota" "name" stmt_expr close_scope_quota  */
#line 3313 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.stmt) = objref_stmt_alloc(&(yyloc));
				(yyval.stmt)->objref.type = NFT_OBJECT_QUOTA;
				(yyval.stmt)->objref.expr = (yyvsp[-1].expr);
			}
#line 10952 "parser_bison.tab.c"
    break;

  case 517: /* limit_mode: "over"  */
#line 3320 "../../nft/nftables/src/parser_bison.y"
                                                                { (yyval.val) = NFT_LIMIT_F_INV; }
#line 10958 "parser_bison.tab.c"
    break;

  case 518: /* limit_mode: "until"  */
#line 3321 "../../nft/nftables/src/parser_bison.y"
                                                                { (yyval.val) = 0; }
#line 10964 "parser_bison.tab.c"
    break;

  case 519: /* limit_mode: %empty  */
#line 3322 "../../nft/nftables/src/parser_bison.y"
                                                                { (yyval.val) = 0; }
#line 10970 "parser_bison.tab.c"
    break;

  case 520: /* limit_burst_pkts: %empty  */
#line 3325 "../../nft/nftables/src/parser_bison.y"
                                                                { (yyval.val) = 5; }
#line 10976 "parser_bison.tab.c"
    break;

  case 521: /* limit_burst_pkts: "burst" "number" "packets"  */
#line 3326 "../../nft/nftables/src/parser_bison.y"
                                                                { (yyval.val) = (yyvsp[-1].val); }
#line 10982 "parser_bison.tab.c"
    break;

  case 522: /* limit_rate_pkts: "number" "/" time_unit  */
#line 3330 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.limit_rate).rate = (yyvsp[-2].val);
				(yyval.limit_rate).unit = (yyvsp[0].val);
			}
#line 10991 "parser_bison.tab.c"
    break;

  case 523: /* limit_burst_bytes: %empty  */
#line 3336 "../../nft/nftables/src/parser_bison.y"
                                                                { (yyval.val) = 0; }
#line 10997 "parser_bison.tab.c"
    break;

  case 524: /* limit_burst_bytes: "burst" limit_bytes  */
#line 3337 "../../nft/nftables/src/parser_bison.y"
                                                                { (yyval.val) = (yyvsp[0].val); }
#line 11003 "parser_bison.tab.c"
    break;

  case 525: /* limit_rate_bytes: "number" "string"  */
#line 3341 "../../nft/nftables/src/parser_bison.y"
                        {
				struct error_record *erec;
				uint64_t rate, unit;

				erec = rate_parse(&(yyloc), (yyvsp[0].string), &rate, &unit);
				xfree((yyvsp[0].string));
				if (erec != NULL) {
					erec_queue(erec, state->msgs);
					YYERROR;
				}
				(yyval.limit_rate).rate = rate * (yyvsp[-1].val);
				(yyval.limit_rate).unit = unit;
			}
#line 11021 "parser_bison.tab.c"
    break;

  case 526: /* limit_rate_bytes: limit_bytes "/" time_unit  */
#line 3355 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.limit_rate).rate = (yyvsp[-2].val);
				(yyval.limit_rate).unit = (yyvsp[0].val);
			}
#line 11030 "parser_bison.tab.c"
    break;

  case 527: /* limit_bytes: "number" "bytes"  */
#line 3361 "../../nft/nftables/src/parser_bison.y"
                                                        { (yyval.val) = (yyvsp[-1].val); }
#line 11036 "parser_bison.tab.c"
    break;

  case 528: /* limit_bytes: "number" "string"  */
#line 3363 "../../nft/nftables/src/parser_bison.y"
                        {
				struct error_record *erec;
				uint64_t rate;

				erec = data_unit_parse(&(yyloc), (yyvsp[0].string), &rate);
				xfree((yyvsp[0].string));
				if (erec != NULL) {
					erec_queue(erec, state->msgs);
					YYERROR;
				}
				(yyval.val) = (yyvsp[-1].val) * rate;
			}
#line 11053 "parser_bison.tab.c"
    break;

  case 529: /* time_unit: "second"  */
#line 3377 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = 1ULL; }
#line 11059 "parser_bison.tab.c"
    break;

  case 530: /* time_unit: "minute"  */
#line 3378 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = 1ULL * 60; }
#line 11065 "parser_bison.tab.c"
    break;

  case 531: /* time_unit: "hour"  */
#line 3379 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = 1ULL * 60 * 60; }
#line 11071 "parser_bison.tab.c"
    break;

  case 532: /* time_unit: "day"  */
#line 3380 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = 1ULL * 60 * 60 * 24; }
#line 11077 "parser_bison.tab.c"
    break;

  case 533: /* time_unit: "week"  */
#line 3381 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = 1ULL * 60 * 60 * 24 * 7; }
#line 11083 "parser_bison.tab.c"
    break;

  case 535: /* reject_stmt_alloc: "reject"  */
#line 3388 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.stmt) = reject_stmt_alloc(&(yyloc));
			}
#line 11091 "parser_bison.tab.c"
    break;

  case 536: /* reject_with_expr: "string"  */
#line 3394 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = symbol_expr_alloc(&(yyloc), SYMBOL_VALUE,
						       current_scope(state), (yyvsp[0].string));
				xfree((yyvsp[0].string));
			}
#line 11101 "parser_bison.tab.c"
    break;

  case 537: /* reject_with_expr: integer_expr  */
#line 3399 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.expr) = (yyvsp[0].expr); }
#line 11107 "parser_bison.tab.c"
    break;

  case 538: /* reject_opts: %empty  */
#line 3403 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[0].stmt)->reject.type = -1;
				(yyvsp[0].stmt)->reject.icmp_code = -1;
			}
#line 11116 "parser_bison.tab.c"
    break;

  case 539: /* reject_opts: "with" "icmp" "type" reject_with_expr close_scope_type close_scope_icmp  */
#line 3408 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[-6].stmt)->reject.family = NFPROTO_IPV4;
				(yyvsp[-6].stmt)->reject.type = NFT_REJECT_ICMP_UNREACH;
				(yyvsp[-6].stmt)->reject.expr = (yyvsp[-2].expr);
				datatype_set((yyvsp[-6].stmt)->reject.expr, &icmp_code_type);
			}
#line 11127 "parser_bison.tab.c"
    break;

  case 540: /* reject_opts: "with" "icmp" reject_with_expr  */
#line 3415 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[-3].stmt)->reject.family = NFPROTO_IPV4;
				(yyvsp[-3].stmt)->reject.type = NFT_REJECT_ICMP_UNREACH;
				(yyvsp[-3].stmt)->reject.expr = (yyvsp[0].expr);
				datatype_set((yyvsp[-3].stmt)->reject.expr, &icmp_code_type);
			}
#line 11138 "parser_bison.tab.c"
    break;

  case 541: /* reject_opts: "with" "icmpv6" "type" reject_with_expr close_scope_type close_scope_icmp  */
#line 3422 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[-6].stmt)->reject.family = NFPROTO_IPV6;
				(yyvsp[-6].stmt)->reject.type = NFT_REJECT_ICMP_UNREACH;
				(yyvsp[-6].stmt)->reject.expr = (yyvsp[-2].expr);
				datatype_set((yyvsp[-6].stmt)->reject.expr, &icmpv6_code_type);
			}
#line 11149 "parser_bison.tab.c"
    break;

  case 542: /* reject_opts: "with" "icmpv6" reject_with_expr  */
#line 3429 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[-3].stmt)->reject.family = NFPROTO_IPV6;
				(yyvsp[-3].stmt)->reject.type = NFT_REJECT_ICMP_UNREACH;
				(yyvsp[-3].stmt)->reject.expr = (yyvsp[0].expr);
				datatype_set((yyvsp[-3].stmt)->reject.expr, &icmpv6_code_type);
			}
#line 11160 "parser_bison.tab.c"
    break;

  case 543: /* reject_opts: "with" "icmpx" "type" reject_with_expr close_scope_type  */
#line 3436 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[-5].stmt)->reject.type = NFT_REJECT_ICMPX_UNREACH;
				(yyvsp[-5].stmt)->reject.expr = (yyvsp[-1].expr);
				datatype_set((yyvsp[-5].stmt)->reject.expr, &icmpx_code_type);
			}
#line 11170 "parser_bison.tab.c"
    break;

  case 544: /* reject_opts: "with" "icmpx" reject_with_expr  */
#line 3442 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[-3].stmt)->reject.type = NFT_REJECT_ICMPX_UNREACH;
				(yyvsp[-3].stmt)->reject.expr = (yyvsp[0].expr);
				datatype_set((yyvsp[-3].stmt)->reject.expr, &icmpx_code_type);
			}
#line 11180 "parser_bison.tab.c"
    break;

  case 545: /* reject_opts: "with" "tcp" close_scope_tcp "reset" close_scope_reset  */
#line 3448 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[-5].stmt)->reject.type = NFT_REJECT_TCP_RST;
			}
#line 11188 "parser_bison.tab.c"
    break;

  case 547: /* nat_stmt_alloc: "snat"  */
#line 3456 "../../nft/nftables/src/parser_bison.y"
                                        { (yyval.stmt) = nat_stmt_alloc(&(yyloc), NFT_NAT_SNAT); }
#line 11194 "parser_bison.tab.c"
    break;

  case 548: /* nat_stmt_alloc: "dnat"  */
#line 3457 "../../nft/nftables/src/parser_bison.y"
                                        { (yyval.stmt) = nat_stmt_alloc(&(yyloc), NFT_NAT_DNAT); }
#line 11200 "parser_bison.tab.c"
    break;

  case 549: /* tproxy_stmt: "tproxy" "to" stmt_expr  */
#line 3461 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.stmt) = tproxy_stmt_alloc(&(yyloc));
				(yyval.stmt)->tproxy.family = NFPROTO_UNSPEC;
				(yyval.stmt)->tproxy.addr = (yyvsp[0].expr);
			}
#line 11210 "parser_bison.tab.c"
    break;

  case 550: /* tproxy_stmt: "tproxy" nf_key_proto "to" stmt_expr  */
#line 3467 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.stmt) = tproxy_stmt_alloc(&(yyloc));
				(yyval.stmt)->tproxy.family = (yyvsp[-2].val);
				(yyval.stmt)->tproxy.addr = (yyvsp[0].expr);
			}
#line 11220 "parser_bison.tab.c"
    break;

  case 551: /* tproxy_stmt: "tproxy" "to" "colon" stmt_expr  */
#line 3473 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.stmt) = tproxy_stmt_alloc(&(yyloc));
				(yyval.stmt)->tproxy.family = NFPROTO_UNSPEC;
				(yyval.stmt)->tproxy.port = (yyvsp[0].expr);
			}
#line 11230 "parser_bison.tab.c"
    break;

  case 552: /* tproxy_stmt: "tproxy" "to" stmt_expr "colon" stmt_expr  */
#line 3479 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.stmt) = tproxy_stmt_alloc(&(yyloc));
				(yyval.stmt)->tproxy.family = NFPROTO_UNSPEC;
				(yyval.stmt)->tproxy.addr = (yyvsp[-2].expr);
				(yyval.stmt)->tproxy.port = (yyvsp[0].expr);
			}
#line 11241 "parser_bison.tab.c"
    break;

  case 553: /* tproxy_stmt: "tproxy" nf_key_proto "to" stmt_expr "colon" stmt_expr  */
#line 3486 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.stmt) = tproxy_stmt_alloc(&(yyloc));
				(yyval.stmt)->tproxy.family = (yyvsp[-4].val);
				(yyval.stmt)->tproxy.addr = (yyvsp[-2].expr);
				(yyval.stmt)->tproxy.port = (yyvsp[0].expr);
			}
#line 11252 "parser_bison.tab.c"
    break;

  case 554: /* tproxy_stmt: "tproxy" nf_key_proto "to" "colon" stmt_expr  */
#line 3493 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.stmt) = tproxy_stmt_alloc(&(yyloc));
				(yyval.stmt)->tproxy.family = (yyvsp[-3].val);
				(yyval.stmt)->tproxy.port = (yyvsp[0].expr);
			}
#line 11262 "parser_bison.tab.c"
    break;

  case 557: /* synproxy_stmt_alloc: "synproxy"  */
#line 3505 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.stmt) = synproxy_stmt_alloc(&(yyloc));
			}
#line 11270 "parser_bison.tab.c"
    break;

  case 558: /* synproxy_stmt_alloc: "synproxy" "name" stmt_expr  */
#line 3509 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.stmt) = objref_stmt_alloc(&(yyloc));
				(yyval.stmt)->objref.type = NFT_OBJECT_SYNPROXY;
				(yyval.stmt)->objref.expr = (yyvsp[0].expr);
			}
#line 11280 "parser_bison.tab.c"
    break;

  case 559: /* synproxy_args: synproxy_arg  */
#line 3517 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.stmt)	= (yyvsp[-1].stmt);
			}
#line 11288 "parser_bison.tab.c"
    break;

  case 561: /* synproxy_arg: "mss" "number"  */
#line 3524 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[-2].stmt)->synproxy.mss = (yyvsp[0].val);
				(yyvsp[-2].stmt)->synproxy.flags |= NF_SYNPROXY_OPT_MSS;
			}
#line 11297 "parser_bison.tab.c"
    break;

  case 562: /* synproxy_arg: "wscale" "number"  */
#line 3529 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[-2].stmt)->synproxy.wscale = (yyvsp[0].val);
				(yyvsp[-2].stmt)->synproxy.flags |= NF_SYNPROXY_OPT_WSCALE;
			}
#line 11306 "parser_bison.tab.c"
    break;

  case 563: /* synproxy_arg: "timestamp"  */
#line 3534 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[-1].stmt)->synproxy.flags |= NF_SYNPROXY_OPT_TIMESTAMP;
			}
#line 11314 "parser_bison.tab.c"
    break;

  case 564: /* synproxy_arg: "sack-permitted"  */
#line 3538 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[-1].stmt)->synproxy.flags |= NF_SYNPROXY_OPT_SACK_PERM;
			}
#line 11322 "parser_bison.tab.c"
    break;

  case 565: /* synproxy_config: "mss" "number" "wscale" "number" synproxy_ts synproxy_sack  */
#line 3544 "../../nft/nftables/src/parser_bison.y"
                        {
				struct synproxy *synproxy;
				uint32_t flags = 0;

				synproxy = &(yyvsp[-6].obj)->synproxy;
				synproxy->mss = (yyvsp[-4].val);
				flags |= NF_SYNPROXY_OPT_MSS;
				synproxy->wscale = (yyvsp[-2].val);
				flags |= NF_SYNPROXY_OPT_WSCALE;
				if ((yyvsp[-1].val))
					flags |= (yyvsp[-1].val);
				if ((yyvsp[0].val))
					flags |= (yyvsp[0].val);
				synproxy->flags = flags;
			}
#line 11342 "parser_bison.tab.c"
    break;

  case 566: /* synproxy_config: "mss" "number" stmt_separator "wscale" "number" stmt_separator synproxy_ts synproxy_sack  */
#line 3560 "../../nft/nftables/src/parser_bison.y"
                        {
				struct synproxy *synproxy;
				uint32_t flags = 0;

				synproxy = &(yyvsp[-8].obj)->synproxy;
				synproxy->mss = (yyvsp[-6].val);
				flags |= NF_SYNPROXY_OPT_MSS;
				synproxy->wscale = (yyvsp[-3].val);
				flags |= NF_SYNPROXY_OPT_WSCALE;
				if ((yyvsp[-1].val))
					flags |= (yyvsp[-1].val);
				if ((yyvsp[0].val))
					flags |= (yyvsp[0].val);
				synproxy->flags = flags;
			}
#line 11362 "parser_bison.tab.c"
    break;

  case 567: /* synproxy_obj: %empty  */
#line 3578 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.obj) = obj_alloc(&(yyloc));
				(yyval.obj)->type = NFT_OBJECT_SYNPROXY;
			}
#line 11371 "parser_bison.tab.c"
    break;

  case 568: /* synproxy_ts: %empty  */
#line 3584 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = 0; }
#line 11377 "parser_bison.tab.c"
    break;

  case 569: /* synproxy_ts: "timestamp"  */
#line 3586 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.val) = NF_SYNPROXY_OPT_TIMESTAMP;
			}
#line 11385 "parser_bison.tab.c"
    break;

  case 570: /* synproxy_sack: %empty  */
#line 3591 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = 0; }
#line 11391 "parser_bison.tab.c"
    break;

  case 571: /* synproxy_sack: "sack-permitted"  */
#line 3593 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.val) = NF_SYNPROXY_OPT_SACK_PERM;
			}
#line 11399 "parser_bison.tab.c"
    break;

  case 572: /* primary_stmt_expr: symbol_expr  */
#line 3598 "../../nft/nftables/src/parser_bison.y"
                                                                { (yyval.expr) = (yyvsp[0].expr); }
#line 11405 "parser_bison.tab.c"
    break;

  case 573: /* primary_stmt_expr: integer_expr  */
#line 3599 "../../nft/nftables/src/parser_bison.y"
                                                                { (yyval.expr) = (yyvsp[0].expr); }
#line 11411 "parser_bison.tab.c"
    break;

  case 574: /* primary_stmt_expr: boolean_expr  */
#line 3600 "../../nft/nftables/src/parser_bison.y"
                                                                { (yyval.expr) = (yyvsp[0].expr); }
#line 11417 "parser_bison.tab.c"
    break;

  case 575: /* primary_stmt_expr: meta_expr  */
#line 3601 "../../nft/nftables/src/parser_bison.y"
                                                                { (yyval.expr) = (yyvsp[0].expr); }
#line 11423 "parser_bison.tab.c"
    break;

  case 576: /* primary_stmt_expr: rt_expr  */
#line 3602 "../../nft/nftables/src/parser_bison.y"
                                                                { (yyval.expr) = (yyvsp[0].expr); }
#line 11429 "parser_bison.tab.c"
    break;

  case 577: /* primary_stmt_expr: ct_expr  */
#line 3603 "../../nft/nftables/src/parser_bison.y"
                                                                { (yyval.expr) = (yyvsp[0].expr); }
#line 11435 "parser_bison.tab.c"
    break;

  case 578: /* primary_stmt_expr: numgen_expr  */
#line 3604 "../../nft/nftables/src/parser_bison.y"
                                                                { (yyval.expr) = (yyvsp[0].expr); }
#line 11441 "parser_bison.tab.c"
    break;

  case 579: /* primary_stmt_expr: hash_expr  */
#line 3605 "../../nft/nftables/src/parser_bison.y"
                                                                { (yyval.expr) = (yyvsp[0].expr); }
#line 11447 "parser_bison.tab.c"
    break;

  case 580: /* primary_stmt_expr: payload_expr  */
#line 3606 "../../nft/nftables/src/parser_bison.y"
                                                                { (yyval.expr) = (yyvsp[0].expr); }
#line 11453 "parser_bison.tab.c"
    break;

  case 581: /* primary_stmt_expr: keyword_expr  */
#line 3607 "../../nft/nftables/src/parser_bison.y"
                                                                { (yyval.expr) = (yyvsp[0].expr); }
#line 11459 "parser_bison.tab.c"
    break;

  case 582: /* primary_stmt_expr: socket_expr  */
#line 3608 "../../nft/nftables/src/parser_bison.y"
                                                                { (yyval.expr) = (yyvsp[0].expr); }
#line 11465 "parser_bison.tab.c"
    break;

  case 583: /* primary_stmt_expr: osf_expr  */
#line 3609 "../../nft/nftables/src/parser_bison.y"
                                                                { (yyval.expr) = (yyvsp[0].expr); }
#line 11471 "parser_bison.tab.c"
    break;

  case 584: /* primary_stmt_expr: '(' basic_stmt_expr ')'  */
#line 3610 "../../nft/nftables/src/parser_bison.y"
                                                                { (yyval.expr) = (yyvsp[-1].expr); }
#line 11477 "parser_bison.tab.c"
    break;

  case 586: /* shift_stmt_expr: shift_stmt_expr "<<" primary_stmt_expr  */
#line 3615 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = binop_expr_alloc(&(yyloc), OP_LSHIFT, (yyvsp[-2].expr), (yyvsp[0].expr));
			}
#line 11485 "parser_bison.tab.c"
    break;

  case 587: /* shift_stmt_expr: shift_stmt_expr ">>" primary_stmt_expr  */
#line 3619 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = binop_expr_alloc(&(yyloc), OP_RSHIFT, (yyvsp[-2].expr), (yyvsp[0].expr));
			}
#line 11493 "parser_bison.tab.c"
    break;

  case 589: /* and_stmt_expr: and_stmt_expr "&" shift_stmt_expr  */
#line 3626 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = binop_expr_alloc(&(yyloc), OP_AND, (yyvsp[-2].expr), (yyvsp[0].expr));
			}
#line 11501 "parser_bison.tab.c"
    break;

  case 591: /* exclusive_or_stmt_expr: exclusive_or_stmt_expr "^" and_stmt_expr  */
#line 3633 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = binop_expr_alloc(&(yyloc), OP_XOR, (yyvsp[-2].expr), (yyvsp[0].expr));
			}
#line 11509 "parser_bison.tab.c"
    break;

  case 593: /* inclusive_or_stmt_expr: inclusive_or_stmt_expr '|' exclusive_or_stmt_expr  */
#line 3640 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = binop_expr_alloc(&(yyloc), OP_OR, (yyvsp[-2].expr), (yyvsp[0].expr));
			}
#line 11517 "parser_bison.tab.c"
    break;

  case 596: /* concat_stmt_expr: concat_stmt_expr "." primary_stmt_expr  */
#line 3650 "../../nft/nftables/src/parser_bison.y"
                        {
				struct location rhs[] = {
					[1]	= (yylsp[-1]),
					[2]	= (yylsp[0]),
				};

				(yyval.expr) = handle_concat_expr(&(yyloc), (yyval.expr), (yyvsp[-2].expr), (yyvsp[0].expr), rhs);
			}
#line 11530 "parser_bison.tab.c"
    break;

  case 599: /* map_stmt_expr: concat_stmt_expr "map" map_stmt_expr_set  */
#line 3665 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = map_expr_alloc(&(yyloc), (yyvsp[-2].expr), (yyvsp[0].expr));
			}
#line 11538 "parser_bison.tab.c"
    break;

  case 600: /* map_stmt_expr: concat_stmt_expr  */
#line 3668 "../../nft/nftables/src/parser_bison.y"
                                                        { (yyval.expr) = (yyvsp[0].expr); }
#line 11544 "parser_bison.tab.c"
    break;

  case 601: /* prefix_stmt_expr: basic_stmt_expr "/" "number"  */
#line 3672 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = prefix_expr_alloc(&(yyloc), (yyvsp[-2].expr), (yyvsp[0].val));
			}
#line 11552 "parser_bison.tab.c"
    break;

  case 602: /* range_stmt_expr: basic_stmt_expr "-" basic_stmt_expr  */
#line 3678 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = range_expr_alloc(&(yyloc), (yyvsp[-2].expr), (yyvsp[0].expr));
			}
#line 11560 "parser_bison.tab.c"
    break;

  case 608: /* nat_stmt_args: stmt_expr  */
#line 3693 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[-1].stmt)->nat.addr = (yyvsp[0].expr);
			}
#line 11568 "parser_bison.tab.c"
    break;

  case 609: /* nat_stmt_args: "to" stmt_expr  */
#line 3697 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[-2].stmt)->nat.addr = (yyvsp[0].expr);
			}
#line 11576 "parser_bison.tab.c"
    break;

  case 610: /* nat_stmt_args: nf_key_proto "to" stmt_expr  */
#line 3701 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[-3].stmt)->nat.family = (yyvsp[-2].val);
				(yyvsp[-3].stmt)->nat.addr = (yyvsp[0].expr);
			}
#line 11585 "parser_bison.tab.c"
    break;

  case 611: /* nat_stmt_args: stmt_expr "colon" stmt_expr  */
#line 3706 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[-3].stmt)->nat.addr = (yyvsp[-2].expr);
				(yyvsp[-3].stmt)->nat.proto = (yyvsp[0].expr);
			}
#line 11594 "parser_bison.tab.c"
    break;

  case 612: /* nat_stmt_args: "to" stmt_expr "colon" stmt_expr  */
#line 3711 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[-4].stmt)->nat.addr = (yyvsp[-2].expr);
				(yyvsp[-4].stmt)->nat.proto = (yyvsp[0].expr);
			}
#line 11603 "parser_bison.tab.c"
    break;

  case 613: /* nat_stmt_args: nf_key_proto "to" stmt_expr "colon" stmt_expr  */
#line 3716 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[-5].stmt)->nat.family = (yyvsp[-4].val);
				(yyvsp[-5].stmt)->nat.addr = (yyvsp[-2].expr);
				(yyvsp[-5].stmt)->nat.proto = (yyvsp[0].expr);
			}
#line 11613 "parser_bison.tab.c"
    break;

  case 614: /* nat_stmt_args: "colon" stmt_expr  */
#line 3722 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[-2].stmt)->nat.proto = (yyvsp[0].expr);
			}
#line 11621 "parser_bison.tab.c"
    break;

  case 615: /* nat_stmt_args: "to" "colon" stmt_expr  */
#line 3726 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[-3].stmt)->nat.proto = (yyvsp[0].expr);
			}
#line 11629 "parser_bison.tab.c"
    break;

  case 616: /* nat_stmt_args: nat_stmt_args nf_nat_flags  */
#line 3730 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[-2].stmt)->nat.flags = (yyvsp[0].val);
			}
#line 11637 "parser_bison.tab.c"
    break;

  case 617: /* nat_stmt_args: nf_key_proto "addr" "." "port" "to" stmt_expr  */
#line 3734 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[-6].stmt)->nat.family = (yyvsp[-5].val);
				(yyvsp[-6].stmt)->nat.addr = (yyvsp[0].expr);
				(yyvsp[-6].stmt)->nat.type_flags = STMT_NAT_F_CONCAT;
			}
#line 11647 "parser_bison.tab.c"
    break;

  case 618: /* nat_stmt_args: nf_key_proto "interval" "to" stmt_expr  */
#line 3740 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[-4].stmt)->nat.family = (yyvsp[-3].val);
				(yyvsp[-4].stmt)->nat.addr = (yyvsp[0].expr);
			}
#line 11656 "parser_bison.tab.c"
    break;

  case 619: /* nat_stmt_args: "interval" "to" stmt_expr  */
#line 3745 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[-3].stmt)->nat.addr = (yyvsp[0].expr);
			}
#line 11664 "parser_bison.tab.c"
    break;

  case 620: /* nat_stmt_args: nf_key_proto "prefix" "to" stmt_expr  */
#line 3749 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[-4].stmt)->nat.family = (yyvsp[-3].val);
				(yyvsp[-4].stmt)->nat.addr = (yyvsp[0].expr);
				(yyvsp[-4].stmt)->nat.type_flags =
						STMT_NAT_F_PREFIX;
				(yyvsp[-4].stmt)->nat.flags |= NF_NAT_RANGE_NETMAP;
			}
#line 11676 "parser_bison.tab.c"
    break;

  case 621: /* nat_stmt_args: "prefix" "to" stmt_expr  */
#line 3757 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[-3].stmt)->nat.addr = (yyvsp[0].expr);
				(yyvsp[-3].stmt)->nat.type_flags =
						STMT_NAT_F_PREFIX;
				(yyvsp[-3].stmt)->nat.flags |= NF_NAT_RANGE_NETMAP;
			}
#line 11687 "parser_bison.tab.c"
    break;

  case 624: /* masq_stmt_alloc: "masquerade"  */
#line 3769 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.stmt) = nat_stmt_alloc(&(yyloc), NFT_NAT_MASQ); }
#line 11693 "parser_bison.tab.c"
    break;

  case 625: /* masq_stmt_args: "to" "colon" stmt_expr  */
#line 3773 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[-3].stmt)->nat.proto = (yyvsp[0].expr);
			}
#line 11701 "parser_bison.tab.c"
    break;

  case 626: /* masq_stmt_args: "to" "colon" stmt_expr nf_nat_flags  */
#line 3777 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[-4].stmt)->nat.proto = (yyvsp[-1].expr);
				(yyvsp[-4].stmt)->nat.flags = (yyvsp[0].val);
			}
#line 11710 "parser_bison.tab.c"
    break;

  case 627: /* masq_stmt_args: nf_nat_flags  */
#line 3782 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[-1].stmt)->nat.flags = (yyvsp[0].val);
			}
#line 11718 "parser_bison.tab.c"
    break;

  case 630: /* redir_stmt_alloc: "redirect"  */
#line 3791 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.stmt) = nat_stmt_alloc(&(yyloc), NFT_NAT_REDIR); }
#line 11724 "parser_bison.tab.c"
    break;

  case 631: /* redir_stmt_arg: "to" stmt_expr  */
#line 3795 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[-2].stmt)->nat.proto = (yyvsp[0].expr);
			}
#line 11732 "parser_bison.tab.c"
    break;

  case 632: /* redir_stmt_arg: "to" "colon" stmt_expr  */
#line 3799 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[-3].stmt)->nat.proto = (yyvsp[0].expr);
			}
#line 11740 "parser_bison.tab.c"
    break;

  case 633: /* redir_stmt_arg: nf_nat_flags  */
#line 3803 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[-1].stmt)->nat.flags = (yyvsp[0].val);
			}
#line 11748 "parser_bison.tab.c"
    break;

  case 634: /* redir_stmt_arg: "to" stmt_expr nf_nat_flags  */
#line 3807 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[-3].stmt)->nat.proto = (yyvsp[-1].expr);
				(yyvsp[-3].stmt)->nat.flags = (yyvsp[0].val);
			}
#line 11757 "parser_bison.tab.c"
    break;

  case 635: /* redir_stmt_arg: "to" "colon" stmt_expr nf_nat_flags  */
#line 3812 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[-4].stmt)->nat.proto = (yyvsp[-1].expr);
				(yyvsp[-4].stmt)->nat.flags = (yyvsp[0].val);
			}
#line 11766 "parser_bison.tab.c"
    break;

  case 636: /* dup_stmt: "dup" "to" stmt_expr  */
#line 3819 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.stmt) = dup_stmt_alloc(&(yyloc));
				(yyval.stmt)->dup.to = (yyvsp[0].expr);
			}
#line 11775 "parser_bison.tab.c"
    break;

  case 637: /* dup_stmt: "dup" "to" stmt_expr "device" stmt_expr  */
#line 3824 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.stmt) = dup_stmt_alloc(&(yyloc));
				(yyval.stmt)->dup.to = (yyvsp[-2].expr);
				(yyval.stmt)->dup.dev = (yyvsp[0].expr);
			}
#line 11785 "parser_bison.tab.c"
    break;

  case 638: /* fwd_stmt: "fwd" "to" stmt_expr  */
#line 3832 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.stmt) = fwd_stmt_alloc(&(yyloc));
				(yyval.stmt)->fwd.dev = (yyvsp[0].expr);
			}
#line 11794 "parser_bison.tab.c"
    break;

  case 639: /* fwd_stmt: "fwd" nf_key_proto "to" stmt_expr "device" stmt_expr  */
#line 3837 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.stmt) = fwd_stmt_alloc(&(yyloc));
				(yyval.stmt)->fwd.family = (yyvsp[-4].val);
				(yyval.stmt)->fwd.addr = (yyvsp[-2].expr);
				(yyval.stmt)->fwd.dev = (yyvsp[0].expr);
			}
#line 11805 "parser_bison.tab.c"
    break;

  case 641: /* nf_nat_flags: nf_nat_flags "comma" nf_nat_flag  */
#line 3847 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.val) = (yyvsp[-2].val) | (yyvsp[0].val);
			}
#line 11813 "parser_bison.tab.c"
    break;

  case 642: /* nf_nat_flag: "random"  */
#line 3852 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = NF_NAT_RANGE_PROTO_RANDOM; }
#line 11819 "parser_bison.tab.c"
    break;

  case 643: /* nf_nat_flag: "fully-random"  */
#line 3853 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = NF_NAT_RANGE_PROTO_RANDOM_FULLY; }
#line 11825 "parser_bison.tab.c"
    break;

  case 644: /* nf_nat_flag: "persistent"  */
#line 3854 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = NF_NAT_RANGE_PERSISTENT; }
#line 11831 "parser_bison.tab.c"
    break;

  case 646: /* queue_stmt: "queue" "to" queue_stmt_expr close_scope_queue  */
#line 3859 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.stmt) = queue_stmt_alloc(&(yyloc), (yyvsp[-1].expr), 0);
			}
#line 11839 "parser_bison.tab.c"
    break;

  case 647: /* queue_stmt: "queue" "flags" queue_stmt_flags "to" queue_stmt_expr close_scope_queue  */
#line 3863 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.stmt) = queue_stmt_alloc(&(yyloc), (yyvsp[-1].expr), (yyvsp[-3].val));
			}
#line 11847 "parser_bison.tab.c"
    break;

  case 648: /* queue_stmt: "queue" "flags" queue_stmt_flags "num" queue_stmt_expr_simple close_scope_queue  */
#line 3867 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.stmt) = queue_stmt_alloc(&(yyloc), (yyvsp[-1].expr), (yyvsp[-3].val));
			}
#line 11855 "parser_bison.tab.c"
    break;

  case 651: /* queue_stmt_alloc: "queue"  */
#line 3877 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.stmt) = queue_stmt_alloc(&(yyloc), NULL, 0);
			}
#line 11863 "parser_bison.tab.c"
    break;

  case 652: /* queue_stmt_args: queue_stmt_arg  */
#line 3883 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.stmt)	= (yyvsp[-1].stmt);
			}
#line 11871 "parser_bison.tab.c"
    break;

  case 654: /* queue_stmt_arg: "num" queue_stmt_expr_simple  */
#line 3890 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[-2].stmt)->queue.queue = (yyvsp[0].expr);
				(yyvsp[-2].stmt)->queue.queue->location = (yyloc);
			}
#line 11880 "parser_bison.tab.c"
    break;

  case 655: /* queue_stmt_arg: queue_stmt_flags  */
#line 3895 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[-1].stmt)->queue.flags |= (yyvsp[0].val);
			}
#line 11888 "parser_bison.tab.c"
    break;

  case 660: /* queue_stmt_expr_simple: queue_expr "-" queue_expr  */
#line 3907 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = range_expr_alloc(&(yyloc), (yyvsp[-2].expr), (yyvsp[0].expr));
			}
#line 11896 "parser_bison.tab.c"
    break;

  case 666: /* queue_stmt_flags: queue_stmt_flags "comma" queue_stmt_flag  */
#line 3920 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.val) = (yyvsp[-2].val) | (yyvsp[0].val);
			}
#line 11904 "parser_bison.tab.c"
    break;

  case 667: /* queue_stmt_flag: "bypass"  */
#line 3925 "../../nft/nftables/src/parser_bison.y"
                                        { (yyval.val) = NFT_QUEUE_FLAG_BYPASS; }
#line 11910 "parser_bison.tab.c"
    break;

  case 668: /* queue_stmt_flag: "fanout"  */
#line 3926 "../../nft/nftables/src/parser_bison.y"
                                        { (yyval.val) = NFT_QUEUE_FLAG_CPU_FANOUT; }
#line 11916 "parser_bison.tab.c"
    break;

  case 671: /* set_elem_expr_stmt_alloc: concat_expr  */
#line 3934 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = set_elem_expr_alloc(&(yylsp[0]), (yyvsp[0].expr));
			}
#line 11924 "parser_bison.tab.c"
    break;

  case 672: /* set_stmt: "set" set_stmt_op set_elem_expr_stmt set_ref_expr  */
#line 3940 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.stmt) = set_stmt_alloc(&(yyloc));
				(yyval.stmt)->set.op  = (yyvsp[-2].val);
				(yyval.stmt)->set.key = (yyvsp[-1].expr);
				(yyval.stmt)->set.set = (yyvsp[0].expr);
			}
#line 11935 "parser_bison.tab.c"
    break;

  case 673: /* set_stmt: set_stmt_op set_ref_expr '{' set_elem_expr_stmt '}'  */
#line 3947 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.stmt) = set_stmt_alloc(&(yyloc));
				(yyval.stmt)->set.op  = (yyvsp[-4].val);
				(yyval.stmt)->set.key = (yyvsp[-1].expr);
				(yyval.stmt)->set.set = (yyvsp[-3].expr);
			}
#line 11946 "parser_bison.tab.c"
    break;

  case 674: /* set_stmt: set_stmt_op set_ref_expr '{' set_elem_expr_stmt stateful_stmt_list '}'  */
#line 3954 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.stmt) = set_stmt_alloc(&(yyloc));
				(yyval.stmt)->set.op  = (yyvsp[-5].val);
				(yyval.stmt)->set.key = (yyvsp[-2].expr);
				(yyval.stmt)->set.set = (yyvsp[-4].expr);
				list_splice_tail((yyvsp[-1].list), &(yyval.stmt)->set.stmt_list);
				free((yyvsp[-1].list));
			}
#line 11959 "parser_bison.tab.c"
    break;

  case 675: /* set_stmt_op: "add"  */
#line 3964 "../../nft/nftables/src/parser_bison.y"
                                        { (yyval.val) = NFT_DYNSET_OP_ADD; }
#line 11965 "parser_bison.tab.c"
    break;

  case 676: /* set_stmt_op: "update"  */
#line 3965 "../../nft/nftables/src/parser_bison.y"
                                        { (yyval.val) = NFT_DYNSET_OP_UPDATE; }
#line 11971 "parser_bison.tab.c"
    break;

  case 677: /* set_stmt_op: "delete"  */
#line 3966 "../../nft/nftables/src/parser_bison.y"
                                        { (yyval.val) = NFT_DYNSET_OP_DELETE; }
#line 11977 "parser_bison.tab.c"
    break;

  case 678: /* map_stmt: set_stmt_op set_ref_expr '{' set_elem_expr_stmt "colon" set_elem_expr_stmt '}'  */
#line 3970 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.stmt) = map_stmt_alloc(&(yyloc));
				(yyval.stmt)->map.op  = (yyvsp[-6].val);
				(yyval.stmt)->map.key = (yyvsp[-3].expr);
				(yyval.stmt)->map.data = (yyvsp[-1].expr);
				(yyval.stmt)->map.set = (yyvsp[-5].expr);
			}
#line 11989 "parser_bison.tab.c"
    break;

  case 679: /* map_stmt: set_stmt_op set_ref_expr '{' set_elem_expr_stmt stateful_stmt_list "colon" set_elem_expr_stmt '}'  */
#line 3978 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.stmt) = map_stmt_alloc(&(yyloc));
				(yyval.stmt)->map.op  = (yyvsp[-7].val);
				(yyval.stmt)->map.key = (yyvsp[-4].expr);
				(yyval.stmt)->map.data = (yyvsp[-1].expr);
				(yyval.stmt)->map.set = (yyvsp[-6].expr);
				list_splice_tail((yyvsp[-3].list), &(yyval.stmt)->map.stmt_list);
				free((yyvsp[-3].list));
			}
#line 12003 "parser_bison.tab.c"
    break;

  case 680: /* meter_stmt: flow_stmt_legacy_alloc flow_stmt_opts '{' meter_key_expr stmt '}'  */
#line 3990 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[-5].stmt)->meter.key  = (yyvsp[-2].expr);
				(yyvsp[-5].stmt)->meter.stmt = (yyvsp[-1].stmt);
				(yyval.stmt)->location  = (yyloc);
				(yyval.stmt) = (yyvsp[-5].stmt);
			}
#line 12014 "parser_bison.tab.c"
    break;

  case 681: /* meter_stmt: meter_stmt_alloc  */
#line 3996 "../../nft/nftables/src/parser_bison.y"
                                                                { (yyval.stmt) = (yyvsp[0].stmt); }
#line 12020 "parser_bison.tab.c"
    break;

  case 682: /* flow_stmt_legacy_alloc: "flow"  */
#line 4000 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.stmt) = meter_stmt_alloc(&(yyloc));
			}
#line 12028 "parser_bison.tab.c"
    break;

  case 683: /* flow_stmt_opts: flow_stmt_opt  */
#line 4006 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.stmt)	= (yyvsp[-1].stmt);
			}
#line 12036 "parser_bison.tab.c"
    break;

  case 685: /* flow_stmt_opt: "table" identifier  */
#line 4013 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[-2].stmt)->meter.name = (yyvsp[0].string);
			}
#line 12044 "parser_bison.tab.c"
    break;

  case 686: /* meter_stmt_alloc: "meter" identifier '{' meter_key_expr stmt '}'  */
#line 4019 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.stmt) = meter_stmt_alloc(&(yyloc));
				(yyval.stmt)->meter.name = (yyvsp[-4].string);
				(yyval.stmt)->meter.size = 0;
				(yyval.stmt)->meter.key  = (yyvsp[-2].expr);
				(yyval.stmt)->meter.stmt = (yyvsp[-1].stmt);
				(yyval.stmt)->location  = (yyloc);
			}
#line 12057 "parser_bison.tab.c"
    break;

  case 687: /* meter_stmt_alloc: "meter" identifier "size" "number" '{' meter_key_expr stmt '}'  */
#line 4028 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.stmt) = meter_stmt_alloc(&(yyloc));
				(yyval.stmt)->meter.name = (yyvsp[-6].string);
				(yyval.stmt)->meter.size = (yyvsp[-4].val);
				(yyval.stmt)->meter.key  = (yyvsp[-2].expr);
				(yyval.stmt)->meter.stmt = (yyvsp[-1].stmt);
				(yyval.stmt)->location  = (yyloc);
			}
#line 12070 "parser_bison.tab.c"
    break;

  case 688: /* match_stmt: relational_expr  */
#line 4039 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.stmt) = expr_stmt_alloc(&(yyloc), (yyvsp[0].expr));
			}
#line 12078 "parser_bison.tab.c"
    break;

  case 689: /* variable_expr: '$' identifier  */
#line 4045 "../../nft/nftables/src/parser_bison.y"
                        {
				struct scope *scope = current_scope(state);
				struct symbol *sym;

				sym = symbol_get(scope, (yyvsp[0].string));
				if (!sym) {
					sym = symbol_lookup_fuzzy(scope, (yyvsp[0].string));
					if (sym) {
						erec_queue(error(&(yylsp[0]), "unknown identifier '%s'; "
								      "did you mean identifier ‘%s’?",
								      (yyvsp[0].string), sym->identifier),
							   state->msgs);
					} else {
						erec_queue(error(&(yylsp[0]), "unknown identifier '%s'", (yyvsp[0].string)),
							   state->msgs);
					}
					xfree((yyvsp[0].string));
					YYERROR;
				}

				(yyval.expr) = variable_expr_alloc(&(yyloc), scope, sym);
				xfree((yyvsp[0].string));
			}
#line 12106 "parser_bison.tab.c"
    break;

  case 691: /* symbol_expr: string  */
#line 4072 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = symbol_expr_alloc(&(yyloc), SYMBOL_VALUE,
						       current_scope(state),
						       (yyvsp[0].string));
				xfree((yyvsp[0].string));
			}
#line 12117 "parser_bison.tab.c"
    break;

  case 694: /* set_ref_symbol_expr: "@" identifier close_scope_at  */
#line 4085 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = symbol_expr_alloc(&(yyloc), SYMBOL_SET,
						       current_scope(state),
						       (yyvsp[-1].string));
				xfree((yyvsp[-1].string));
			}
#line 12128 "parser_bison.tab.c"
    break;

  case 695: /* integer_expr: "number"  */
#line 4094 "../../nft/nftables/src/parser_bison.y"
                        {
				char str[64];

				snprintf(str, sizeof(str), "%" PRIu64, (yyvsp[0].val));
				(yyval.expr) = symbol_expr_alloc(&(yyloc), SYMBOL_VALUE,
						       current_scope(state),
						       str);
			}
#line 12141 "parser_bison.tab.c"
    break;

  case 696: /* primary_expr: symbol_expr  */
#line 4104 "../../nft/nftables/src/parser_bison.y"
                                                                { (yyval.expr) = (yyvsp[0].expr); }
#line 12147 "parser_bison.tab.c"
    break;

  case 697: /* primary_expr: integer_expr  */
#line 4105 "../../nft/nftables/src/parser_bison.y"
                                                                { (yyval.expr) = (yyvsp[0].expr); }
#line 12153 "parser_bison.tab.c"
    break;

  case 698: /* primary_expr: payload_expr  */
#line 4106 "../../nft/nftables/src/parser_bison.y"
                                                                { (yyval.expr) = (yyvsp[0].expr); }
#line 12159 "parser_bison.tab.c"
    break;

  case 699: /* primary_expr: exthdr_expr  */
#line 4107 "../../nft/nftables/src/parser_bison.y"
                                                                { (yyval.expr) = (yyvsp[0].expr); }
#line 12165 "parser_bison.tab.c"
    break;

  case 700: /* primary_expr: exthdr_exists_expr  */
#line 4108 "../../nft/nftables/src/parser_bison.y"
                                                                { (yyval.expr) = (yyvsp[0].expr); }
#line 12171 "parser_bison.tab.c"
    break;

  case 701: /* primary_expr: meta_expr  */
#line 4109 "../../nft/nftables/src/parser_bison.y"
                                                                { (yyval.expr) = (yyvsp[0].expr); }
#line 12177 "parser_bison.tab.c"
    break;

  case 702: /* primary_expr: socket_expr  */
#line 4110 "../../nft/nftables/src/parser_bison.y"
                                                                { (yyval.expr) = (yyvsp[0].expr); }
#line 12183 "parser_bison.tab.c"
    break;

  case 703: /* primary_expr: rt_expr  */
#line 4111 "../../nft/nftables/src/parser_bison.y"
                                                                { (yyval.expr) = (yyvsp[0].expr); }
#line 12189 "parser_bison.tab.c"
    break;

  case 704: /* primary_expr: ct_expr  */
#line 4112 "../../nft/nftables/src/parser_bison.y"
                                                                { (yyval.expr) = (yyvsp[0].expr); }
#line 12195 "parser_bison.tab.c"
    break;

  case 705: /* primary_expr: numgen_expr  */
#line 4113 "../../nft/nftables/src/parser_bison.y"
                                                                { (yyval.expr) = (yyvsp[0].expr); }
#line 12201 "parser_bison.tab.c"
    break;

  case 706: /* primary_expr: hash_expr  */
#line 4114 "../../nft/nftables/src/parser_bison.y"
                                                                { (yyval.expr) = (yyvsp[0].expr); }
#line 12207 "parser_bison.tab.c"
    break;

  case 707: /* primary_expr: fib_expr  */
#line 4115 "../../nft/nftables/src/parser_bison.y"
                                                                { (yyval.expr) = (yyvsp[0].expr); }
#line 12213 "parser_bison.tab.c"
    break;

  case 708: /* primary_expr: osf_expr  */
#line 4116 "../../nft/nftables/src/parser_bison.y"
                                                                { (yyval.expr) = (yyvsp[0].expr); }
#line 12219 "parser_bison.tab.c"
    break;

  case 709: /* primary_expr: xfrm_expr  */
#line 4117 "../../nft/nftables/src/parser_bison.y"
                                                                { (yyval.expr) = (yyvsp[0].expr); }
#line 12225 "parser_bison.tab.c"
    break;

  case 710: /* primary_expr: '(' basic_expr ')'  */
#line 4118 "../../nft/nftables/src/parser_bison.y"
                                                                { (yyval.expr) = (yyvsp[-1].expr); }
#line 12231 "parser_bison.tab.c"
    break;

  case 711: /* fib_expr: "fib" fib_tuple fib_result close_scope_fib  */
#line 4122 "../../nft/nftables/src/parser_bison.y"
                        {
				if (((yyvsp[-2].val) & (NFTA_FIB_F_SADDR|NFTA_FIB_F_DADDR)) == 0) {
					erec_queue(error(&(yylsp[-2]), "fib: need either saddr or daddr"), state->msgs);
					YYERROR;
				}

				if (((yyvsp[-2].val) & (NFTA_FIB_F_SADDR|NFTA_FIB_F_DADDR)) ==
					  (NFTA_FIB_F_SADDR|NFTA_FIB_F_DADDR)) {
					erec_queue(error(&(yylsp[-2]), "fib: saddr and daddr are mutually exclusive"), state->msgs);
					YYERROR;
				}

				if (((yyvsp[-2].val) & (NFTA_FIB_F_IIF|NFTA_FIB_F_OIF)) ==
					  (NFTA_FIB_F_IIF|NFTA_FIB_F_OIF)) {
					erec_queue(error(&(yylsp[-2]), "fib: iif and oif are mutually exclusive"), state->msgs);
					YYERROR;
				}

				(yyval.expr) = fib_expr_alloc(&(yyloc), (yyvsp[-2].val), (yyvsp[-1].val));
			}
#line 12256 "parser_bison.tab.c"
    break;

  case 712: /* fib_result: "oif"  */
#line 4144 "../../nft/nftables/src/parser_bison.y"
                                        { (yyval.val) =NFT_FIB_RESULT_OIF; }
#line 12262 "parser_bison.tab.c"
    break;

  case 713: /* fib_result: "oifname"  */
#line 4145 "../../nft/nftables/src/parser_bison.y"
                                        { (yyval.val) =NFT_FIB_RESULT_OIFNAME; }
#line 12268 "parser_bison.tab.c"
    break;

  case 714: /* fib_result: "type" close_scope_type  */
#line 4146 "../../nft/nftables/src/parser_bison.y"
                                                                { (yyval.val) =NFT_FIB_RESULT_ADDRTYPE; }
#line 12274 "parser_bison.tab.c"
    break;

  case 715: /* fib_flag: "saddr"  */
#line 4149 "../../nft/nftables/src/parser_bison.y"
                                        { (yyval.val) = NFTA_FIB_F_SADDR; }
#line 12280 "parser_bison.tab.c"
    break;

  case 716: /* fib_flag: "daddr"  */
#line 4150 "../../nft/nftables/src/parser_bison.y"
                                        { (yyval.val) = NFTA_FIB_F_DADDR; }
#line 12286 "parser_bison.tab.c"
    break;

  case 717: /* fib_flag: "mark"  */
#line 4151 "../../nft/nftables/src/parser_bison.y"
                                        { (yyval.val) = NFTA_FIB_F_MARK; }
#line 12292 "parser_bison.tab.c"
    break;

  case 718: /* fib_flag: "iif"  */
#line 4152 "../../nft/nftables/src/parser_bison.y"
                                        { (yyval.val) = NFTA_FIB_F_IIF; }
#line 12298 "parser_bison.tab.c"
    break;

  case 719: /* fib_flag: "oif"  */
#line 4153 "../../nft/nftables/src/parser_bison.y"
                                        { (yyval.val) = NFTA_FIB_F_OIF; }
#line 12304 "parser_bison.tab.c"
    break;

  case 720: /* fib_tuple: fib_flag "." fib_tuple  */
#line 4157 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.val) = (yyvsp[-2].val) | (yyvsp[0].val);
			}
#line 12312 "parser_bison.tab.c"
    break;

  case 722: /* osf_expr: "osf" osf_ttl "version" close_scope_osf  */
#line 4164 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = osf_expr_alloc(&(yyloc), (yyvsp[-2].val), NFT_OSF_F_VERSION);
			}
#line 12320 "parser_bison.tab.c"
    break;

  case 723: /* osf_expr: "osf" osf_ttl "name" close_scope_osf  */
#line 4168 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = osf_expr_alloc(&(yyloc), (yyvsp[-2].val), 0);
			}
#line 12328 "parser_bison.tab.c"
    break;

  case 724: /* osf_ttl: %empty  */
#line 4174 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.val) = NF_OSF_TTL_TRUE;
			}
#line 12336 "parser_bison.tab.c"
    break;

  case 725: /* osf_ttl: "ttl" "string"  */
#line 4178 "../../nft/nftables/src/parser_bison.y"
                        {
				if (!strcmp((yyvsp[0].string), "loose"))
					(yyval.val) = NF_OSF_TTL_LESS;
				else if (!strcmp((yyvsp[0].string), "skip"))
					(yyval.val) = NF_OSF_TTL_NOCHECK;
				else {
					erec_queue(error(&(yylsp[0]), "invalid ttl option"),
						   state->msgs);
					xfree((yyvsp[0].string));
					YYERROR;
				}
				xfree((yyvsp[0].string));
			}
#line 12354 "parser_bison.tab.c"
    break;

  case 727: /* shift_expr: shift_expr "<<" primary_rhs_expr  */
#line 4195 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = binop_expr_alloc(&(yyloc), OP_LSHIFT, (yyvsp[-2].expr), (yyvsp[0].expr));
			}
#line 12362 "parser_bison.tab.c"
    break;

  case 728: /* shift_expr: shift_expr ">>" primary_rhs_expr  */
#line 4199 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = binop_expr_alloc(&(yyloc), OP_RSHIFT, (yyvsp[-2].expr), (yyvsp[0].expr));
			}
#line 12370 "parser_bison.tab.c"
    break;

  case 730: /* and_expr: and_expr "&" shift_rhs_expr  */
#line 4206 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = binop_expr_alloc(&(yyloc), OP_AND, (yyvsp[-2].expr), (yyvsp[0].expr));
			}
#line 12378 "parser_bison.tab.c"
    break;

  case 732: /* exclusive_or_expr: exclusive_or_expr "^" and_rhs_expr  */
#line 4213 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = binop_expr_alloc(&(yyloc), OP_XOR, (yyvsp[-2].expr), (yyvsp[0].expr));
			}
#line 12386 "parser_bison.tab.c"
    break;

  case 734: /* inclusive_or_expr: inclusive_or_expr '|' exclusive_or_rhs_expr  */
#line 4220 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = binop_expr_alloc(&(yyloc), OP_OR, (yyvsp[-2].expr), (yyvsp[0].expr));
			}
#line 12394 "parser_bison.tab.c"
    break;

  case 737: /* concat_expr: concat_expr "." basic_expr  */
#line 4230 "../../nft/nftables/src/parser_bison.y"
                        {
				struct location rhs[] = {
					[1]	= (yylsp[-1]),
					[2]	= (yylsp[0]),
				};

				(yyval.expr) = handle_concat_expr(&(yyloc), (yyval.expr), (yyvsp[-2].expr), (yyvsp[0].expr), rhs);
			}
#line 12407 "parser_bison.tab.c"
    break;

  case 738: /* prefix_rhs_expr: basic_rhs_expr "/" "number"  */
#line 4241 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = prefix_expr_alloc(&(yyloc), (yyvsp[-2].expr), (yyvsp[0].val));
			}
#line 12415 "parser_bison.tab.c"
    break;

  case 739: /* range_rhs_expr: basic_rhs_expr "-" basic_rhs_expr  */
#line 4247 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = range_expr_alloc(&(yyloc), (yyvsp[-2].expr), (yyvsp[0].expr));
			}
#line 12423 "parser_bison.tab.c"
    break;

  case 742: /* map_expr: concat_expr "map" rhs_expr  */
#line 4257 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = map_expr_alloc(&(yyloc), (yyvsp[-2].expr), (yyvsp[0].expr));
			}
#line 12431 "parser_bison.tab.c"
    break;

  case 746: /* set_expr: '{' set_list_expr '}'  */
#line 4268 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[-1].expr)->location = (yyloc);
				(yyval.expr) = (yyvsp[-1].expr);
			}
#line 12440 "parser_bison.tab.c"
    break;

  case 747: /* set_list_expr: set_list_member_expr  */
#line 4275 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = set_expr_alloc(&(yyloc), NULL);
				compound_expr_add((yyval.expr), (yyvsp[0].expr));
			}
#line 12449 "parser_bison.tab.c"
    break;

  case 748: /* set_list_expr: set_list_expr "comma" set_list_member_expr  */
#line 4280 "../../nft/nftables/src/parser_bison.y"
                        {
				compound_expr_add((yyvsp[-2].expr), (yyvsp[0].expr));
				(yyval.expr) = (yyvsp[-2].expr);
			}
#line 12458 "parser_bison.tab.c"
    break;

  case 750: /* set_list_member_expr: opt_newline set_expr opt_newline  */
#line 4288 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = (yyvsp[-1].expr);
			}
#line 12466 "parser_bison.tab.c"
    break;

  case 751: /* set_list_member_expr: opt_newline set_elem_expr opt_newline  */
#line 4292 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = (yyvsp[-1].expr);
			}
#line 12474 "parser_bison.tab.c"
    break;

  case 752: /* set_list_member_expr: opt_newline set_elem_expr "colon" set_rhs_expr opt_newline  */
#line 4296 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = mapping_expr_alloc(&(yylsp[-3]), (yyvsp[-3].expr), (yyvsp[-1].expr));
			}
#line 12482 "parser_bison.tab.c"
    break;

  case 754: /* meter_key_expr: meter_key_expr_alloc set_elem_options  */
#line 4303 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr)->location = (yyloc);
				(yyval.expr) = (yyvsp[-1].expr);
			}
#line 12491 "parser_bison.tab.c"
    break;

  case 755: /* meter_key_expr_alloc: concat_expr  */
#line 4310 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = set_elem_expr_alloc(&(yylsp[0]), (yyvsp[0].expr));
			}
#line 12499 "parser_bison.tab.c"
    break;

  case 758: /* set_elem_key_expr: set_lhs_expr  */
#line 4319 "../../nft/nftables/src/parser_bison.y"
                                                        { (yyval.expr) = (yyvsp[0].expr); }
#line 12505 "parser_bison.tab.c"
    break;

  case 759: /* set_elem_key_expr: "*"  */
#line 4320 "../../nft/nftables/src/parser_bison.y"
                                                        { (yyval.expr) = set_elem_catchall_expr_alloc(&(yylsp[0])); }
#line 12511 "parser_bison.tab.c"
    break;

  case 760: /* set_elem_expr_alloc: set_elem_key_expr set_elem_stmt_list  */
#line 4324 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = set_elem_expr_alloc(&(yylsp[-1]), (yyvsp[-1].expr));
				list_splice_tail((yyvsp[0].list), &(yyval.expr)->stmt_list);
				xfree((yyvsp[0].list));
			}
#line 12521 "parser_bison.tab.c"
    break;

  case 761: /* set_elem_expr_alloc: set_elem_key_expr  */
#line 4330 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = set_elem_expr_alloc(&(yylsp[0]), (yyvsp[0].expr));
			}
#line 12529 "parser_bison.tab.c"
    break;

  case 762: /* set_elem_options: set_elem_option  */
#line 4336 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr)	= (yyvsp[-1].expr);
			}
#line 12537 "parser_bison.tab.c"
    break;

  case 764: /* set_elem_option: "timeout" time_spec  */
#line 4343 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[-2].expr)->timeout = (yyvsp[0].val);
			}
#line 12545 "parser_bison.tab.c"
    break;

  case 765: /* set_elem_option: "expires" time_spec  */
#line 4347 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[-2].expr)->expiration = (yyvsp[0].val);
			}
#line 12553 "parser_bison.tab.c"
    break;

  case 766: /* set_elem_option: comment_spec  */
#line 4351 "../../nft/nftables/src/parser_bison.y"
                        {
				if (already_set((yyvsp[-1].expr)->comment, &(yylsp[0]), state)) {
					xfree((yyvsp[0].string));
					YYERROR;
				}
				(yyvsp[-1].expr)->comment = (yyvsp[0].string);
			}
#line 12565 "parser_bison.tab.c"
    break;

  case 767: /* set_elem_expr_options: set_elem_expr_option  */
#line 4361 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr)	= (yyvsp[-1].expr);
			}
#line 12573 "parser_bison.tab.c"
    break;

  case 769: /* set_elem_stmt_list: set_elem_stmt  */
#line 4368 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.list) = xmalloc(sizeof(*(yyval.list)));
				init_list_head((yyval.list));
				list_add_tail(&(yyvsp[0].stmt)->list, (yyval.list));
			}
#line 12583 "parser_bison.tab.c"
    break;

  case 770: /* set_elem_stmt_list: set_elem_stmt_list set_elem_stmt  */
#line 4374 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.list) = (yyvsp[-1].list);
				list_add_tail(&(yyvsp[0].stmt)->list, (yyvsp[-1].list));
			}
#line 12592 "parser_bison.tab.c"
    break;

  case 771: /* set_elem_stmt: "counter" close_scope_counter  */
#line 4381 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.stmt) = counter_stmt_alloc(&(yyloc));
			}
#line 12600 "parser_bison.tab.c"
    break;

  case 772: /* set_elem_stmt: "counter" "packets" "number" "bytes" "number" close_scope_counter  */
#line 4385 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.stmt) = counter_stmt_alloc(&(yyloc));
				(yyval.stmt)->counter.packets = (yyvsp[-3].val);
				(yyval.stmt)->counter.bytes = (yyvsp[-1].val);
			}
#line 12610 "parser_bison.tab.c"
    break;

  case 773: /* set_elem_stmt: "limit" "rate" limit_mode limit_rate_pkts limit_burst_pkts close_scope_limit  */
#line 4391 "../../nft/nftables/src/parser_bison.y"
                        {
				if ((yyvsp[-1].val) == 0) {
					erec_queue(error(&(yylsp[-1]), "limit burst must be > 0"),
						   state->msgs);
					YYERROR;
				}
				(yyval.stmt) = limit_stmt_alloc(&(yyloc));
				(yyval.stmt)->limit.rate  = (yyvsp[-2].limit_rate).rate;
				(yyval.stmt)->limit.unit  = (yyvsp[-2].limit_rate).unit;
				(yyval.stmt)->limit.burst = (yyvsp[-1].val);
				(yyval.stmt)->limit.type  = NFT_LIMIT_PKTS;
				(yyval.stmt)->limit.flags = (yyvsp[-3].val);
			}
#line 12628 "parser_bison.tab.c"
    break;

  case 774: /* set_elem_stmt: "limit" "rate" limit_mode limit_rate_bytes limit_burst_bytes close_scope_limit  */
#line 4405 "../../nft/nftables/src/parser_bison.y"
                        {
				if ((yyvsp[-1].val) == 0) {
					erec_queue(error(&(yylsp[0]), "limit burst must be > 0"),
						   state->msgs);
					YYERROR;
				}
				(yyval.stmt) = limit_stmt_alloc(&(yyloc));
				(yyval.stmt)->limit.rate  = (yyvsp[-2].limit_rate).rate;
				(yyval.stmt)->limit.unit  = (yyvsp[-2].limit_rate).unit;
				(yyval.stmt)->limit.burst = (yyvsp[-1].val);
				(yyval.stmt)->limit.type  = NFT_LIMIT_PKT_BYTES;
				(yyval.stmt)->limit.flags = (yyvsp[-3].val);
			}
#line 12646 "parser_bison.tab.c"
    break;

  case 775: /* set_elem_stmt: "ct" "count" "number" close_scope_ct  */
#line 4419 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.stmt) = connlimit_stmt_alloc(&(yyloc));
				(yyval.stmt)->connlimit.count	= (yyvsp[-1].val);
			}
#line 12655 "parser_bison.tab.c"
    break;

  case 776: /* set_elem_stmt: "ct" "count" "over" "number" close_scope_ct  */
#line 4424 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.stmt) = connlimit_stmt_alloc(&(yyloc));
				(yyval.stmt)->connlimit.count = (yyvsp[-1].val);
				(yyval.stmt)->connlimit.flags = NFT_CONNLIMIT_F_INV;
			}
#line 12665 "parser_bison.tab.c"
    break;

  case 777: /* set_elem_expr_option: "timeout" time_spec  */
#line 4432 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[-2].expr)->timeout = (yyvsp[0].val);
			}
#line 12673 "parser_bison.tab.c"
    break;

  case 778: /* set_elem_expr_option: "expires" time_spec  */
#line 4436 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[-2].expr)->expiration = (yyvsp[0].val);
			}
#line 12681 "parser_bison.tab.c"
    break;

  case 779: /* set_elem_expr_option: comment_spec  */
#line 4440 "../../nft/nftables/src/parser_bison.y"
                        {
				if (already_set((yyvsp[-1].expr)->comment, &(yylsp[0]), state)) {
					xfree((yyvsp[0].string));
					YYERROR;
				}
				(yyvsp[-1].expr)->comment = (yyvsp[0].string);
			}
#line 12693 "parser_bison.tab.c"
    break;

  case 785: /* initializer_expr: '{' '}'  */
#line 4458 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.expr) = compound_expr_alloc(&(yyloc), EXPR_SET); }
#line 12699 "parser_bison.tab.c"
    break;

  case 786: /* initializer_expr: "-" "number"  */
#line 4460 "../../nft/nftables/src/parser_bison.y"
                        {
				int32_t num = -(yyvsp[0].val);

				(yyval.expr) = constant_expr_alloc(&(yyloc), &integer_type,
							 BYTEORDER_HOST_ENDIAN,
							 sizeof(num) * BITS_PER_BYTE,
							 &num);
			}
#line 12712 "parser_bison.tab.c"
    break;

  case 787: /* counter_config: "packets" "number" "bytes" "number"  */
#line 4471 "../../nft/nftables/src/parser_bison.y"
                        {
				struct counter *counter;

				counter = &(yyvsp[-4].obj)->counter;
				counter->packets = (yyvsp[-2].val);
				counter->bytes = (yyvsp[0].val);
			}
#line 12724 "parser_bison.tab.c"
    break;

  case 788: /* counter_obj: %empty  */
#line 4481 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.obj) = obj_alloc(&(yyloc));
				(yyval.obj)->type = NFT_OBJECT_COUNTER;
			}
#line 12733 "parser_bison.tab.c"
    break;

  case 789: /* quota_config: quota_mode "number" quota_unit quota_used  */
#line 4488 "../../nft/nftables/src/parser_bison.y"
                        {
				struct error_record *erec;
				struct quota *quota;
				uint64_t rate;

				erec = data_unit_parse(&(yyloc), (yyvsp[-1].string), &rate);
				xfree((yyvsp[-1].string));
				if (erec != NULL) {
					erec_queue(erec, state->msgs);
					YYERROR;
				}

				quota = &(yyvsp[-4].obj)->quota;
				quota->bytes	= (yyvsp[-2].val) * rate;
				quota->used	= (yyvsp[0].val);
				quota->flags	= (yyvsp[-3].val);
			}
#line 12755 "parser_bison.tab.c"
    break;

  case 790: /* quota_obj: %empty  */
#line 4508 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.obj) = obj_alloc(&(yyloc));
				(yyval.obj)->type = NFT_OBJECT_QUOTA;
			}
#line 12764 "parser_bison.tab.c"
    break;

  case 791: /* secmark_config: string  */
#line 4515 "../../nft/nftables/src/parser_bison.y"
                        {
				int ret;
				struct secmark *secmark;

				secmark = &(yyvsp[-1].obj)->secmark;
				ret = snprintf(secmark->ctx, sizeof(secmark->ctx), "%s", (yyvsp[0].string));
				if (ret <= 0 || ret >= (int)sizeof(secmark->ctx)) {
					erec_queue(error(&(yylsp[0]), "invalid context '%s', max length is %u\n", (yyvsp[0].string), (int)sizeof(secmark->ctx)), state->msgs);
					xfree((yyvsp[0].string));
					YYERROR;
				}
				xfree((yyvsp[0].string));
			}
#line 12782 "parser_bison.tab.c"
    break;

  case 792: /* secmark_obj: %empty  */
#line 4531 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.obj) = obj_alloc(&(yyloc));
				(yyval.obj)->type = NFT_OBJECT_SECMARK;
			}
#line 12791 "parser_bison.tab.c"
    break;

  case 793: /* ct_obj_type: "helper"  */
#line 4537 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = NFT_OBJECT_CT_HELPER; }
#line 12797 "parser_bison.tab.c"
    break;

  case 794: /* ct_obj_type: "timeout"  */
#line 4538 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = NFT_OBJECT_CT_TIMEOUT; }
#line 12803 "parser_bison.tab.c"
    break;

  case 795: /* ct_obj_type: "expectation"  */
#line 4539 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = NFT_OBJECT_CT_EXPECT; }
#line 12809 "parser_bison.tab.c"
    break;

  case 796: /* ct_cmd_type: "helpers"  */
#line 4542 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = CMD_OBJ_CT_HELPERS; }
#line 12815 "parser_bison.tab.c"
    break;

  case 797: /* ct_cmd_type: "timeout"  */
#line 4543 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = CMD_OBJ_CT_TIMEOUT; }
#line 12821 "parser_bison.tab.c"
    break;

  case 798: /* ct_cmd_type: "expectation"  */
#line 4544 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = CMD_OBJ_CT_EXPECT; }
#line 12827 "parser_bison.tab.c"
    break;

  case 799: /* ct_l4protoname: "tcp" close_scope_tcp  */
#line 4547 "../../nft/nftables/src/parser_bison.y"
                                                        { (yyval.val) = IPPROTO_TCP; }
#line 12833 "parser_bison.tab.c"
    break;

  case 800: /* ct_l4protoname: "udp" close_scope_udp  */
#line 4548 "../../nft/nftables/src/parser_bison.y"
                                                        { (yyval.val) = IPPROTO_UDP; }
#line 12839 "parser_bison.tab.c"
    break;

  case 801: /* ct_helper_config: "type" "quoted string" "protocol" ct_l4protoname stmt_separator close_scope_type  */
#line 4552 "../../nft/nftables/src/parser_bison.y"
                        {
				struct ct_helper *ct;
				int ret;

				ct = &(yyvsp[-6].obj)->ct_helper;

				ret = snprintf(ct->name, sizeof(ct->name), "%s", (yyvsp[-4].string));
				if (ret <= 0 || ret >= (int)sizeof(ct->name)) {
					erec_queue(error(&(yylsp[-4]), "invalid name '%s', max length is %u\n", (yyvsp[-4].string), (int)sizeof(ct->name)), state->msgs);
					YYERROR;
				}
				xfree((yyvsp[-4].string));

				ct->l4proto = (yyvsp[-2].val);
			}
#line 12859 "parser_bison.tab.c"
    break;

  case 802: /* ct_helper_config: "l3proto" family_spec_explicit stmt_separator  */
#line 4568 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[-3].obj)->ct_helper.l3proto = (yyvsp[-1].val);
			}
#line 12867 "parser_bison.tab.c"
    break;

  case 803: /* timeout_states: timeout_state  */
#line 4574 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.list) = xmalloc(sizeof(*(yyval.list)));
				init_list_head((yyval.list));
				list_add_tail((yyvsp[0].list), (yyval.list));
			}
#line 12877 "parser_bison.tab.c"
    break;

  case 804: /* timeout_states: timeout_states "comma" timeout_state  */
#line 4580 "../../nft/nftables/src/parser_bison.y"
                        {
				list_add_tail((yyvsp[0].list), (yyvsp[-2].list));
				(yyval.list) = (yyvsp[-2].list);
			}
#line 12886 "parser_bison.tab.c"
    break;

  case 805: /* timeout_state: "string" "colon" "number"  */
#line 4588 "../../nft/nftables/src/parser_bison.y"
                        {
				struct timeout_state *ts;

				ts = xzalloc(sizeof(*ts));
				ts->timeout_str = (yyvsp[-2].string);
				ts->timeout_value = (yyvsp[0].val);
				ts->location = (yylsp[-2]);
				init_list_head(&ts->head);
				(yyval.list) = &ts->head;
			}
#line 12901 "parser_bison.tab.c"
    break;

  case 806: /* ct_timeout_config: "protocol" ct_l4protoname stmt_separator  */
#line 4601 "../../nft/nftables/src/parser_bison.y"
                        {
				struct ct_timeout *ct;
				int l4proto = (yyvsp[-1].val);

				ct = &(yyvsp[-3].obj)->ct_timeout;
				ct->l4proto = l4proto;
			}
#line 12913 "parser_bison.tab.c"
    break;

  case 807: /* ct_timeout_config: "policy" '=' '{' timeout_states '}' stmt_separator close_scope_policy  */
#line 4609 "../../nft/nftables/src/parser_bison.y"
                        {
				struct ct_timeout *ct;

				ct = &(yyvsp[-7].obj)->ct_timeout;
				list_splice_tail((yyvsp[-3].list), &ct->timeout_list);
				xfree((yyvsp[-3].list));
			}
#line 12925 "parser_bison.tab.c"
    break;

  case 808: /* ct_timeout_config: "l3proto" family_spec_explicit stmt_separator  */
#line 4617 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[-3].obj)->ct_timeout.l3proto = (yyvsp[-1].val);
			}
#line 12933 "parser_bison.tab.c"
    break;

  case 809: /* ct_expect_config: "protocol" ct_l4protoname stmt_separator  */
#line 4623 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[-3].obj)->ct_expect.l4proto = (yyvsp[-1].val);
			}
#line 12941 "parser_bison.tab.c"
    break;

  case 810: /* ct_expect_config: "dport" "number" stmt_separator  */
#line 4627 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[-3].obj)->ct_expect.dport = (yyvsp[-1].val);
			}
#line 12949 "parser_bison.tab.c"
    break;

  case 811: /* ct_expect_config: "timeout" time_spec stmt_separator  */
#line 4631 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[-3].obj)->ct_expect.timeout = (yyvsp[-1].val);
			}
#line 12957 "parser_bison.tab.c"
    break;

  case 812: /* ct_expect_config: "size" "number" stmt_separator  */
#line 4635 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[-3].obj)->ct_expect.size = (yyvsp[-1].val);
			}
#line 12965 "parser_bison.tab.c"
    break;

  case 813: /* ct_expect_config: "l3proto" family_spec_explicit stmt_separator  */
#line 4639 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[-3].obj)->ct_expect.l3proto = (yyvsp[-1].val);
			}
#line 12973 "parser_bison.tab.c"
    break;

  case 814: /* ct_obj_alloc: %empty  */
#line 4645 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.obj) = obj_alloc(&(yyloc));
			}
#line 12981 "parser_bison.tab.c"
    break;

  case 815: /* limit_config: "rate" limit_mode limit_rate_pkts limit_burst_pkts  */
#line 4651 "../../nft/nftables/src/parser_bison.y"
                        {
				struct limit *limit;

				limit = &(yyvsp[-4].obj)->limit;
				limit->rate	= (yyvsp[-1].limit_rate).rate;
				limit->unit	= (yyvsp[-1].limit_rate).unit;
				limit->burst	= (yyvsp[0].val);
				limit->type	= NFT_LIMIT_PKTS;
				limit->flags	= (yyvsp[-2].val);
			}
#line 12996 "parser_bison.tab.c"
    break;

  case 816: /* limit_config: "rate" limit_mode limit_rate_bytes limit_burst_bytes  */
#line 4662 "../../nft/nftables/src/parser_bison.y"
                        {
				struct limit *limit;

				limit = &(yyvsp[-4].obj)->limit;
				limit->rate	= (yyvsp[-1].limit_rate).rate;
				limit->unit	= (yyvsp[-1].limit_rate).unit;
				limit->burst	= (yyvsp[0].val);
				limit->type	= NFT_LIMIT_PKT_BYTES;
				limit->flags	= (yyvsp[-2].val);
			}
#line 13011 "parser_bison.tab.c"
    break;

  case 817: /* limit_obj: %empty  */
#line 4675 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.obj) = obj_alloc(&(yyloc));
				(yyval.obj)->type = NFT_OBJECT_LIMIT;
			}
#line 13020 "parser_bison.tab.c"
    break;

  case 818: /* relational_expr: expr rhs_expr  */
#line 4682 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = relational_expr_alloc(&(yyloc), OP_IMPLICIT, (yyvsp[-1].expr), (yyvsp[0].expr));
			}
#line 13028 "parser_bison.tab.c"
    break;

  case 819: /* relational_expr: expr list_rhs_expr  */
#line 4686 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = relational_expr_alloc(&(yyloc), OP_IMPLICIT, (yyvsp[-1].expr), (yyvsp[0].expr));
			}
#line 13036 "parser_bison.tab.c"
    break;

  case 820: /* relational_expr: expr basic_rhs_expr "/" list_rhs_expr  */
#line 4690 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = flagcmp_expr_alloc(&(yyloc), OP_EQ, (yyvsp[-3].expr), (yyvsp[0].expr), (yyvsp[-2].expr));
			}
#line 13044 "parser_bison.tab.c"
    break;

  case 821: /* relational_expr: expr list_rhs_expr "/" list_rhs_expr  */
#line 4694 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = flagcmp_expr_alloc(&(yyloc), OP_EQ, (yyvsp[-3].expr), (yyvsp[0].expr), (yyvsp[-2].expr));
			}
#line 13052 "parser_bison.tab.c"
    break;

  case 822: /* relational_expr: expr relational_op basic_rhs_expr "/" list_rhs_expr  */
#line 4698 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = flagcmp_expr_alloc(&(yyloc), (yyvsp[-3].val), (yyvsp[-4].expr), (yyvsp[0].expr), (yyvsp[-2].expr));
			}
#line 13060 "parser_bison.tab.c"
    break;

  case 823: /* relational_expr: expr relational_op list_rhs_expr "/" list_rhs_expr  */
#line 4702 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = flagcmp_expr_alloc(&(yyloc), (yyvsp[-3].val), (yyvsp[-4].expr), (yyvsp[0].expr), (yyvsp[-2].expr));
			}
#line 13068 "parser_bison.tab.c"
    break;

  case 824: /* relational_expr: expr relational_op rhs_expr  */
#line 4706 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = relational_expr_alloc(&(yylsp[-1]), (yyvsp[-1].val), (yyvsp[-2].expr), (yyvsp[0].expr));
			}
#line 13076 "parser_bison.tab.c"
    break;

  case 825: /* relational_expr: expr relational_op list_rhs_expr  */
#line 4710 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = relational_expr_alloc(&(yylsp[-1]), (yyvsp[-1].val), (yyvsp[-2].expr), (yyvsp[0].expr));
			}
#line 13084 "parser_bison.tab.c"
    break;

  case 826: /* list_rhs_expr: basic_rhs_expr "comma" basic_rhs_expr  */
#line 4716 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = list_expr_alloc(&(yyloc));
				compound_expr_add((yyval.expr), (yyvsp[-2].expr));
				compound_expr_add((yyval.expr), (yyvsp[0].expr));
			}
#line 13094 "parser_bison.tab.c"
    break;

  case 827: /* list_rhs_expr: list_rhs_expr "comma" basic_rhs_expr  */
#line 4722 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[-2].expr)->location = (yyloc);
				compound_expr_add((yyvsp[-2].expr), (yyvsp[0].expr));
				(yyval.expr) = (yyvsp[-2].expr);
			}
#line 13104 "parser_bison.tab.c"
    break;

  case 828: /* rhs_expr: concat_rhs_expr  */
#line 4729 "../../nft/nftables/src/parser_bison.y"
                                                        { (yyval.expr) = (yyvsp[0].expr); }
#line 13110 "parser_bison.tab.c"
    break;

  case 829: /* rhs_expr: set_expr  */
#line 4730 "../../nft/nftables/src/parser_bison.y"
                                                        { (yyval.expr) = (yyvsp[0].expr); }
#line 13116 "parser_bison.tab.c"
    break;

  case 830: /* rhs_expr: set_ref_symbol_expr  */
#line 4731 "../../nft/nftables/src/parser_bison.y"
                                                        { (yyval.expr) = (yyvsp[0].expr); }
#line 13122 "parser_bison.tab.c"
    break;

  case 832: /* shift_rhs_expr: shift_rhs_expr "<<" primary_rhs_expr  */
#line 4736 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = binop_expr_alloc(&(yyloc), OP_LSHIFT, (yyvsp[-2].expr), (yyvsp[0].expr));
			}
#line 13130 "parser_bison.tab.c"
    break;

  case 833: /* shift_rhs_expr: shift_rhs_expr ">>" primary_rhs_expr  */
#line 4740 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = binop_expr_alloc(&(yyloc), OP_RSHIFT, (yyvsp[-2].expr), (yyvsp[0].expr));
			}
#line 13138 "parser_bison.tab.c"
    break;

  case 835: /* and_rhs_expr: and_rhs_expr "&" shift_rhs_expr  */
#line 4747 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = binop_expr_alloc(&(yyloc), OP_AND, (yyvsp[-2].expr), (yyvsp[0].expr));
			}
#line 13146 "parser_bison.tab.c"
    break;

  case 837: /* exclusive_or_rhs_expr: exclusive_or_rhs_expr "^" and_rhs_expr  */
#line 4754 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = binop_expr_alloc(&(yyloc), OP_XOR, (yyvsp[-2].expr), (yyvsp[0].expr));
			}
#line 13154 "parser_bison.tab.c"
    break;

  case 839: /* inclusive_or_rhs_expr: inclusive_or_rhs_expr '|' exclusive_or_rhs_expr  */
#line 4761 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = binop_expr_alloc(&(yyloc), OP_OR, (yyvsp[-2].expr), (yyvsp[0].expr));
			}
#line 13162 "parser_bison.tab.c"
    break;

  case 843: /* concat_rhs_expr: concat_rhs_expr "." multiton_rhs_expr  */
#line 4772 "../../nft/nftables/src/parser_bison.y"
                        {
				struct location rhs[] = {
					[1]	= (yylsp[-1]),
					[2]	= (yylsp[0]),
				};

				(yyval.expr) = handle_concat_expr(&(yyloc), (yyval.expr), (yyvsp[-2].expr), (yyvsp[0].expr), rhs);
			}
#line 13175 "parser_bison.tab.c"
    break;

  case 844: /* concat_rhs_expr: concat_rhs_expr "." basic_rhs_expr  */
#line 4781 "../../nft/nftables/src/parser_bison.y"
                        {
				struct location rhs[] = {
					[1]	= (yylsp[-1]),
					[2]	= (yylsp[0]),
				};

				(yyval.expr) = handle_concat_expr(&(yyloc), (yyval.expr), (yyvsp[-2].expr), (yyvsp[0].expr), rhs);
			}
#line 13188 "parser_bison.tab.c"
    break;

  case 845: /* boolean_keys: "exists"  */
#line 4791 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val8) = true; }
#line 13194 "parser_bison.tab.c"
    break;

  case 846: /* boolean_keys: "missing"  */
#line 4792 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val8) = false; }
#line 13200 "parser_bison.tab.c"
    break;

  case 847: /* boolean_expr: boolean_keys  */
#line 4796 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = constant_expr_alloc(&(yyloc), &boolean_type,
							 BYTEORDER_HOST_ENDIAN,
							 sizeof((yyvsp[0].val8)) * BITS_PER_BYTE, &(yyvsp[0].val8));
			}
#line 13210 "parser_bison.tab.c"
    break;

  case 848: /* keyword_expr: "ether" close_scope_eth  */
#line 4803 "../../nft/nftables/src/parser_bison.y"
                                                        { (yyval.expr) = symbol_value(&(yyloc), "ether"); }
#line 13216 "parser_bison.tab.c"
    break;

  case 849: /* keyword_expr: "ip" close_scope_ip  */
#line 4804 "../../nft/nftables/src/parser_bison.y"
                                                        { (yyval.expr) = symbol_value(&(yyloc), "ip"); }
#line 13222 "parser_bison.tab.c"
    break;

  case 850: /* keyword_expr: "ip6" close_scope_ip6  */
#line 4805 "../../nft/nftables/src/parser_bison.y"
                                                        { (yyval.expr) = symbol_value(&(yyloc), "ip6"); }
#line 13228 "parser_bison.tab.c"
    break;

  case 851: /* keyword_expr: "vlan" close_scope_vlan  */
#line 4806 "../../nft/nftables/src/parser_bison.y"
                                                         { (yyval.expr) = symbol_value(&(yyloc), "vlan"); }
#line 13234 "parser_bison.tab.c"
    break;

  case 852: /* keyword_expr: "arp" close_scope_arp  */
#line 4807 "../../nft/nftables/src/parser_bison.y"
                                                        { (yyval.expr) = symbol_value(&(yyloc), "arp"); }
#line 13240 "parser_bison.tab.c"
    break;

  case 853: /* keyword_expr: "dnat" close_scope_nat  */
#line 4808 "../../nft/nftables/src/parser_bison.y"
                                                        { (yyval.expr) = symbol_value(&(yyloc), "dnat"); }
#line 13246 "parser_bison.tab.c"
    break;

  case 854: /* keyword_expr: "snat" close_scope_nat  */
#line 4809 "../../nft/nftables/src/parser_bison.y"
                                                        { (yyval.expr) = symbol_value(&(yyloc), "snat"); }
#line 13252 "parser_bison.tab.c"
    break;

  case 855: /* keyword_expr: "ecn"  */
#line 4810 "../../nft/nftables/src/parser_bison.y"
                                                        { (yyval.expr) = symbol_value(&(yyloc), "ecn"); }
#line 13258 "parser_bison.tab.c"
    break;

  case 856: /* keyword_expr: "reset" close_scope_reset  */
#line 4811 "../../nft/nftables/src/parser_bison.y"
                                                                { (yyval.expr) = symbol_value(&(yyloc), "reset"); }
#line 13264 "parser_bison.tab.c"
    break;

  case 857: /* keyword_expr: "original"  */
#line 4812 "../../nft/nftables/src/parser_bison.y"
                                                        { (yyval.expr) = symbol_value(&(yyloc), "original"); }
#line 13270 "parser_bison.tab.c"
    break;

  case 858: /* keyword_expr: "reply"  */
#line 4813 "../../nft/nftables/src/parser_bison.y"
                                                        { (yyval.expr) = symbol_value(&(yyloc), "reply"); }
#line 13276 "parser_bison.tab.c"
    break;

  case 859: /* keyword_expr: "label"  */
#line 4814 "../../nft/nftables/src/parser_bison.y"
                                                        { (yyval.expr) = symbol_value(&(yyloc), "label"); }
#line 13282 "parser_bison.tab.c"
    break;

  case 860: /* primary_rhs_expr: symbol_expr  */
#line 4817 "../../nft/nftables/src/parser_bison.y"
                                                        { (yyval.expr) = (yyvsp[0].expr); }
#line 13288 "parser_bison.tab.c"
    break;

  case 861: /* primary_rhs_expr: integer_expr  */
#line 4818 "../../nft/nftables/src/parser_bison.y"
                                                        { (yyval.expr) = (yyvsp[0].expr); }
#line 13294 "parser_bison.tab.c"
    break;

  case 862: /* primary_rhs_expr: boolean_expr  */
#line 4819 "../../nft/nftables/src/parser_bison.y"
                                                        { (yyval.expr) = (yyvsp[0].expr); }
#line 13300 "parser_bison.tab.c"
    break;

  case 863: /* primary_rhs_expr: keyword_expr  */
#line 4820 "../../nft/nftables/src/parser_bison.y"
                                                        { (yyval.expr) = (yyvsp[0].expr); }
#line 13306 "parser_bison.tab.c"
    break;

  case 864: /* primary_rhs_expr: "tcp" close_scope_tcp  */
#line 4822 "../../nft/nftables/src/parser_bison.y"
                        {
				uint8_t data = IPPROTO_TCP;
				(yyval.expr) = constant_expr_alloc(&(yyloc), &inet_protocol_type,
							 BYTEORDER_HOST_ENDIAN,
							 sizeof(data) * BITS_PER_BYTE, &data);
			}
#line 13317 "parser_bison.tab.c"
    break;

  case 865: /* primary_rhs_expr: "udp" close_scope_udp  */
#line 4829 "../../nft/nftables/src/parser_bison.y"
                        {
				uint8_t data = IPPROTO_UDP;
				(yyval.expr) = constant_expr_alloc(&(yyloc), &inet_protocol_type,
							 BYTEORDER_HOST_ENDIAN,
							 sizeof(data) * BITS_PER_BYTE, &data);
			}
#line 13328 "parser_bison.tab.c"
    break;

  case 866: /* primary_rhs_expr: "udplite" close_scope_udplite  */
#line 4836 "../../nft/nftables/src/parser_bison.y"
                        {
				uint8_t data = IPPROTO_UDPLITE;
				(yyval.expr) = constant_expr_alloc(&(yyloc), &inet_protocol_type,
							 BYTEORDER_HOST_ENDIAN,
							 sizeof(data) * BITS_PER_BYTE, &data);
			}
#line 13339 "parser_bison.tab.c"
    break;

  case 867: /* primary_rhs_expr: "esp" close_scope_esp  */
#line 4843 "../../nft/nftables/src/parser_bison.y"
                        {
				uint8_t data = IPPROTO_ESP;
				(yyval.expr) = constant_expr_alloc(&(yyloc), &inet_protocol_type,
							 BYTEORDER_HOST_ENDIAN,
							 sizeof(data) * BITS_PER_BYTE, &data);
			}
#line 13350 "parser_bison.tab.c"
    break;

  case 868: /* primary_rhs_expr: "ah" close_scope_ah  */
#line 4850 "../../nft/nftables/src/parser_bison.y"
                        {
				uint8_t data = IPPROTO_AH;
				(yyval.expr) = constant_expr_alloc(&(yyloc), &inet_protocol_type,
							 BYTEORDER_HOST_ENDIAN,
							 sizeof(data) * BITS_PER_BYTE, &data);
			}
#line 13361 "parser_bison.tab.c"
    break;

  case 869: /* primary_rhs_expr: "icmp" close_scope_icmp  */
#line 4857 "../../nft/nftables/src/parser_bison.y"
                        {
				uint8_t data = IPPROTO_ICMP;
				(yyval.expr) = constant_expr_alloc(&(yyloc), &inet_protocol_type,
							 BYTEORDER_HOST_ENDIAN,
							 sizeof(data) * BITS_PER_BYTE, &data);
			}
#line 13372 "parser_bison.tab.c"
    break;

  case 870: /* primary_rhs_expr: "igmp"  */
#line 4864 "../../nft/nftables/src/parser_bison.y"
                        {
				uint8_t data = IPPROTO_IGMP;
				(yyval.expr) = constant_expr_alloc(&(yyloc), &inet_protocol_type,
							 BYTEORDER_HOST_ENDIAN,
							 sizeof(data) * BITS_PER_BYTE, &data);
			}
#line 13383 "parser_bison.tab.c"
    break;

  case 871: /* primary_rhs_expr: "icmpv6" close_scope_icmp  */
#line 4871 "../../nft/nftables/src/parser_bison.y"
                        {
				uint8_t data = IPPROTO_ICMPV6;
				(yyval.expr) = constant_expr_alloc(&(yyloc), &inet_protocol_type,
							 BYTEORDER_HOST_ENDIAN,
							 sizeof(data) * BITS_PER_BYTE, &data);
			}
#line 13394 "parser_bison.tab.c"
    break;

  case 872: /* primary_rhs_expr: "comp" close_scope_comp  */
#line 4878 "../../nft/nftables/src/parser_bison.y"
                        {
				uint8_t data = IPPROTO_COMP;
				(yyval.expr) = constant_expr_alloc(&(yyloc), &inet_protocol_type,
							 BYTEORDER_HOST_ENDIAN,
							 sizeof(data) * BITS_PER_BYTE, &data);
			}
#line 13405 "parser_bison.tab.c"
    break;

  case 873: /* primary_rhs_expr: "dccp" close_scope_dccp  */
#line 4885 "../../nft/nftables/src/parser_bison.y"
                        {
				uint8_t data = IPPROTO_DCCP;
				(yyval.expr) = constant_expr_alloc(&(yyloc), &inet_protocol_type,
							 BYTEORDER_HOST_ENDIAN,
							 sizeof(data) * BITS_PER_BYTE, &data);
			}
#line 13416 "parser_bison.tab.c"
    break;

  case 874: /* primary_rhs_expr: "sctp" close_scope_sctp  */
#line 4892 "../../nft/nftables/src/parser_bison.y"
                        {
				uint8_t data = IPPROTO_SCTP;
				(yyval.expr) = constant_expr_alloc(&(yyloc), &inet_protocol_type,
							 BYTEORDER_HOST_ENDIAN,
							 sizeof(data) * BITS_PER_BYTE, &data);
			}
#line 13427 "parser_bison.tab.c"
    break;

  case 875: /* primary_rhs_expr: "redirect" close_scope_nat  */
#line 4899 "../../nft/nftables/src/parser_bison.y"
                        {
				uint8_t data = ICMP_REDIRECT;
				(yyval.expr) = constant_expr_alloc(&(yyloc), &icmp_type_type,
							 BYTEORDER_HOST_ENDIAN,
							 sizeof(data) * BITS_PER_BYTE, &data);
			}
#line 13438 "parser_bison.tab.c"
    break;

  case 876: /* primary_rhs_expr: '(' basic_rhs_expr ')'  */
#line 4905 "../../nft/nftables/src/parser_bison.y"
                                                                { (yyval.expr) = (yyvsp[-1].expr); }
#line 13444 "parser_bison.tab.c"
    break;

  case 877: /* relational_op: "=="  */
#line 4908 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = OP_EQ; }
#line 13450 "parser_bison.tab.c"
    break;

  case 878: /* relational_op: "!="  */
#line 4909 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = OP_NEQ; }
#line 13456 "parser_bison.tab.c"
    break;

  case 879: /* relational_op: "<"  */
#line 4910 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = OP_LT; }
#line 13462 "parser_bison.tab.c"
    break;

  case 880: /* relational_op: ">"  */
#line 4911 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = OP_GT; }
#line 13468 "parser_bison.tab.c"
    break;

  case 881: /* relational_op: ">="  */
#line 4912 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = OP_GTE; }
#line 13474 "parser_bison.tab.c"
    break;

  case 882: /* relational_op: "<="  */
#line 4913 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = OP_LTE; }
#line 13480 "parser_bison.tab.c"
    break;

  case 883: /* relational_op: "!"  */
#line 4914 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = OP_NEG; }
#line 13486 "parser_bison.tab.c"
    break;

  case 884: /* verdict_expr: "accept"  */
#line 4918 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = verdict_expr_alloc(&(yyloc), NF_ACCEPT, NULL);
			}
#line 13494 "parser_bison.tab.c"
    break;

  case 885: /* verdict_expr: "drop"  */
#line 4922 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = verdict_expr_alloc(&(yyloc), NF_DROP, NULL);
			}
#line 13502 "parser_bison.tab.c"
    break;

  case 886: /* verdict_expr: "continue"  */
#line 4926 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = verdict_expr_alloc(&(yyloc), NFT_CONTINUE, NULL);
			}
#line 13510 "parser_bison.tab.c"
    break;

  case 887: /* verdict_expr: "jump" chain_expr  */
#line 4930 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = verdict_expr_alloc(&(yyloc), NFT_JUMP, (yyvsp[0].expr));
			}
#line 13518 "parser_bison.tab.c"
    break;

  case 888: /* verdict_expr: "goto" chain_expr  */
#line 4934 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = verdict_expr_alloc(&(yyloc), NFT_GOTO, (yyvsp[0].expr));
			}
#line 13526 "parser_bison.tab.c"
    break;

  case 889: /* verdict_expr: "return"  */
#line 4938 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = verdict_expr_alloc(&(yyloc), NFT_RETURN, NULL);
			}
#line 13534 "parser_bison.tab.c"
    break;

  case 891: /* chain_expr: identifier  */
#line 4945 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = constant_expr_alloc(&(yyloc), &string_type,
							 BYTEORDER_HOST_ENDIAN,
							 strlen((yyvsp[0].string)) * BITS_PER_BYTE,
							 (yyvsp[0].string));
				xfree((yyvsp[0].string));
			}
#line 13546 "parser_bison.tab.c"
    break;

  case 892: /* meta_expr: "meta" meta_key close_scope_meta  */
#line 4955 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = meta_expr_alloc(&(yyloc), (yyvsp[-1].val));
			}
#line 13554 "parser_bison.tab.c"
    break;

  case 893: /* meta_expr: meta_key_unqualified  */
#line 4959 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = meta_expr_alloc(&(yyloc), (yyvsp[0].val));
			}
#line 13562 "parser_bison.tab.c"
    break;

  case 894: /* meta_expr: "meta" "string" close_scope_meta  */
#line 4963 "../../nft/nftables/src/parser_bison.y"
                        {
				struct error_record *erec;
				unsigned int key;

				erec = meta_key_parse(&(yyloc), (yyvsp[-1].string), &key);
				xfree((yyvsp[-1].string));
				if (erec != NULL) {
					erec_queue(erec, state->msgs);
					YYERROR;
				}

				(yyval.expr) = meta_expr_alloc(&(yyloc), key);
			}
#line 13580 "parser_bison.tab.c"
    break;

  case 897: /* meta_key_qualified: "length"  */
#line 4982 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = NFT_META_LEN; }
#line 13586 "parser_bison.tab.c"
    break;

  case 898: /* meta_key_qualified: "protocol"  */
#line 4983 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = NFT_META_PROTOCOL; }
#line 13592 "parser_bison.tab.c"
    break;

  case 899: /* meta_key_qualified: "priority"  */
#line 4984 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = NFT_META_PRIORITY; }
#line 13598 "parser_bison.tab.c"
    break;

  case 900: /* meta_key_qualified: "random"  */
#line 4985 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = NFT_META_PRANDOM; }
#line 13604 "parser_bison.tab.c"
    break;

  case 901: /* meta_key_qualified: "secmark" close_scope_secmark  */
#line 4986 "../../nft/nftables/src/parser_bison.y"
                                                            { (yyval.val) = NFT_META_SECMARK; }
#line 13610 "parser_bison.tab.c"
    break;

  case 902: /* meta_key_unqualified: "mark"  */
#line 4989 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = NFT_META_MARK; }
#line 13616 "parser_bison.tab.c"
    break;

  case 903: /* meta_key_unqualified: "iif"  */
#line 4990 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = NFT_META_IIF; }
#line 13622 "parser_bison.tab.c"
    break;

  case 904: /* meta_key_unqualified: "iifname"  */
#line 4991 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = NFT_META_IIFNAME; }
#line 13628 "parser_bison.tab.c"
    break;

  case 905: /* meta_key_unqualified: "iiftype"  */
#line 4992 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = NFT_META_IIFTYPE; }
#line 13634 "parser_bison.tab.c"
    break;

  case 906: /* meta_key_unqualified: "oif"  */
#line 4993 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = NFT_META_OIF; }
#line 13640 "parser_bison.tab.c"
    break;

  case 907: /* meta_key_unqualified: "oifname"  */
#line 4994 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = NFT_META_OIFNAME; }
#line 13646 "parser_bison.tab.c"
    break;

  case 908: /* meta_key_unqualified: "oiftype"  */
#line 4995 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = NFT_META_OIFTYPE; }
#line 13652 "parser_bison.tab.c"
    break;

  case 909: /* meta_key_unqualified: "skuid"  */
#line 4996 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = NFT_META_SKUID; }
#line 13658 "parser_bison.tab.c"
    break;

  case 910: /* meta_key_unqualified: "skgid"  */
#line 4997 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = NFT_META_SKGID; }
#line 13664 "parser_bison.tab.c"
    break;

  case 911: /* meta_key_unqualified: "nftrace"  */
#line 4998 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = NFT_META_NFTRACE; }
#line 13670 "parser_bison.tab.c"
    break;

  case 912: /* meta_key_unqualified: "rtclassid"  */
#line 4999 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = NFT_META_RTCLASSID; }
#line 13676 "parser_bison.tab.c"
    break;

  case 913: /* meta_key_unqualified: "ibriport"  */
#line 5000 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = NFT_META_BRI_IIFNAME; }
#line 13682 "parser_bison.tab.c"
    break;

  case 914: /* meta_key_unqualified: "obriport"  */
#line 5001 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = NFT_META_BRI_OIFNAME; }
#line 13688 "parser_bison.tab.c"
    break;

  case 915: /* meta_key_unqualified: "ibrname"  */
#line 5002 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = NFT_META_BRI_IIFNAME; }
#line 13694 "parser_bison.tab.c"
    break;

  case 916: /* meta_key_unqualified: "obrname"  */
#line 5003 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = NFT_META_BRI_OIFNAME; }
#line 13700 "parser_bison.tab.c"
    break;

  case 917: /* meta_key_unqualified: "pkttype"  */
#line 5004 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = NFT_META_PKTTYPE; }
#line 13706 "parser_bison.tab.c"
    break;

  case 918: /* meta_key_unqualified: "cpu"  */
#line 5005 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = NFT_META_CPU; }
#line 13712 "parser_bison.tab.c"
    break;

  case 919: /* meta_key_unqualified: "iifgroup"  */
#line 5006 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = NFT_META_IIFGROUP; }
#line 13718 "parser_bison.tab.c"
    break;

  case 920: /* meta_key_unqualified: "oifgroup"  */
#line 5007 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = NFT_META_OIFGROUP; }
#line 13724 "parser_bison.tab.c"
    break;

  case 921: /* meta_key_unqualified: "cgroup"  */
#line 5008 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = NFT_META_CGROUP; }
#line 13730 "parser_bison.tab.c"
    break;

  case 922: /* meta_key_unqualified: "ipsec" close_scope_ipsec  */
#line 5009 "../../nft/nftables/src/parser_bison.y"
                                                          { (yyval.val) = NFT_META_SECPATH; }
#line 13736 "parser_bison.tab.c"
    break;

  case 923: /* meta_key_unqualified: "time"  */
#line 5010 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = NFT_META_TIME_NS; }
#line 13742 "parser_bison.tab.c"
    break;

  case 924: /* meta_key_unqualified: "day"  */
#line 5011 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = NFT_META_TIME_DAY; }
#line 13748 "parser_bison.tab.c"
    break;

  case 925: /* meta_key_unqualified: "hour"  */
#line 5012 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = NFT_META_TIME_HOUR; }
#line 13754 "parser_bison.tab.c"
    break;

  case 926: /* meta_stmt: "meta" meta_key "set" stmt_expr close_scope_meta  */
#line 5016 "../../nft/nftables/src/parser_bison.y"
                        {
				switch ((yyvsp[-3].val)) {
				case NFT_META_SECMARK:
					switch ((yyvsp[-1].expr)->etype) {
					case EXPR_CT:
						(yyval.stmt) = meta_stmt_alloc(&(yyloc), (yyvsp[-3].val), (yyvsp[-1].expr));
						break;
					default:
						(yyval.stmt) = objref_stmt_alloc(&(yyloc));
						(yyval.stmt)->objref.type = NFT_OBJECT_SECMARK;
						(yyval.stmt)->objref.expr = (yyvsp[-1].expr);
						break;
					}
					break;
				default:
					(yyval.stmt) = meta_stmt_alloc(&(yyloc), (yyvsp[-3].val), (yyvsp[-1].expr));
					break;
				}
			}
#line 13778 "parser_bison.tab.c"
    break;

  case 927: /* meta_stmt: meta_key_unqualified "set" stmt_expr  */
#line 5036 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.stmt) = meta_stmt_alloc(&(yyloc), (yyvsp[-2].val), (yyvsp[0].expr));
			}
#line 13786 "parser_bison.tab.c"
    break;

  case 928: /* meta_stmt: "meta" "string" "set" stmt_expr close_scope_meta  */
#line 5040 "../../nft/nftables/src/parser_bison.y"
                        {
				struct error_record *erec;
				unsigned int key;

				erec = meta_key_parse(&(yyloc), (yyvsp[-3].string), &key);
				xfree((yyvsp[-3].string));
				if (erec != NULL) {
					erec_queue(erec, state->msgs);
					YYERROR;
				}

				(yyval.stmt) = meta_stmt_alloc(&(yyloc), key, (yyvsp[-1].expr));
			}
#line 13804 "parser_bison.tab.c"
    break;

  case 929: /* meta_stmt: "notrack"  */
#line 5054 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.stmt) = notrack_stmt_alloc(&(yyloc));
			}
#line 13812 "parser_bison.tab.c"
    break;

  case 930: /* meta_stmt: "flow" "offload" "@" string close_scope_at  */
#line 5058 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.stmt) = flow_offload_stmt_alloc(&(yyloc), (yyvsp[-1].string));
			}
#line 13820 "parser_bison.tab.c"
    break;

  case 931: /* meta_stmt: "flow" "add" "@" string close_scope_at  */
#line 5062 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.stmt) = flow_offload_stmt_alloc(&(yyloc), (yyvsp[-1].string));
			}
#line 13828 "parser_bison.tab.c"
    break;

  case 932: /* socket_expr: "socket" socket_key close_scope_socket  */
#line 5068 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = socket_expr_alloc(&(yyloc), (yyvsp[-1].val), 0);
			}
#line 13836 "parser_bison.tab.c"
    break;

  case 933: /* socket_expr: "socket" "cgroupv2" "level" "number" close_scope_socket  */
#line 5072 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = socket_expr_alloc(&(yyloc), NFT_SOCKET_CGROUPV2, (yyvsp[-1].val));
			}
#line 13844 "parser_bison.tab.c"
    break;

  case 934: /* socket_key: "transparent"  */
#line 5077 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = NFT_SOCKET_TRANSPARENT; }
#line 13850 "parser_bison.tab.c"
    break;

  case 935: /* socket_key: "mark"  */
#line 5078 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = NFT_SOCKET_MARK; }
#line 13856 "parser_bison.tab.c"
    break;

  case 936: /* socket_key: "wildcard"  */
#line 5079 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = NFT_SOCKET_WILDCARD; }
#line 13862 "parser_bison.tab.c"
    break;

  case 937: /* offset_opt: %empty  */
#line 5082 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = 0; }
#line 13868 "parser_bison.tab.c"
    break;

  case 938: /* offset_opt: "offset" "number"  */
#line 5083 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = (yyvsp[0].val); }
#line 13874 "parser_bison.tab.c"
    break;

  case 939: /* numgen_type: "inc"  */
#line 5086 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = NFT_NG_INCREMENTAL; }
#line 13880 "parser_bison.tab.c"
    break;

  case 940: /* numgen_type: "random"  */
#line 5087 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = NFT_NG_RANDOM; }
#line 13886 "parser_bison.tab.c"
    break;

  case 941: /* numgen_expr: "numgen" numgen_type "mod" "number" offset_opt close_scope_numgen  */
#line 5091 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = numgen_expr_alloc(&(yyloc), (yyvsp[-4].val), (yyvsp[-2].val), (yyvsp[-1].val));
			}
#line 13894 "parser_bison.tab.c"
    break;

  case 942: /* xfrm_spnum: "spnum" "number"  */
#line 5096 "../../nft/nftables/src/parser_bison.y"
                                            { (yyval.val) = (yyvsp[0].val); }
#line 13900 "parser_bison.tab.c"
    break;

  case 943: /* xfrm_spnum: %empty  */
#line 5097 "../../nft/nftables/src/parser_bison.y"
                                            { (yyval.val) = 0; }
#line 13906 "parser_bison.tab.c"
    break;

  case 944: /* xfrm_dir: "in"  */
#line 5100 "../../nft/nftables/src/parser_bison.y"
                                        { (yyval.val) = XFRM_POLICY_IN; }
#line 13912 "parser_bison.tab.c"
    break;

  case 945: /* xfrm_dir: "out"  */
#line 5101 "../../nft/nftables/src/parser_bison.y"
                                        { (yyval.val) = XFRM_POLICY_OUT; }
#line 13918 "parser_bison.tab.c"
    break;

  case 946: /* xfrm_state_key: "spi"  */
#line 5104 "../../nft/nftables/src/parser_bison.y"
                                    { (yyval.val) = NFT_XFRM_KEY_SPI; }
#line 13924 "parser_bison.tab.c"
    break;

  case 947: /* xfrm_state_key: "reqid"  */
#line 5105 "../../nft/nftables/src/parser_bison.y"
                                      { (yyval.val) = NFT_XFRM_KEY_REQID; }
#line 13930 "parser_bison.tab.c"
    break;

  case 948: /* xfrm_state_proto_key: "daddr"  */
#line 5108 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = NFT_XFRM_KEY_DADDR_IP4; }
#line 13936 "parser_bison.tab.c"
    break;

  case 949: /* xfrm_state_proto_key: "saddr"  */
#line 5109 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = NFT_XFRM_KEY_SADDR_IP4; }
#line 13942 "parser_bison.tab.c"
    break;

  case 950: /* xfrm_expr: "ipsec" xfrm_dir xfrm_spnum xfrm_state_key close_scope_ipsec  */
#line 5113 "../../nft/nftables/src/parser_bison.y"
                        {
				if ((yyvsp[-2].val) > 255) {
					erec_queue(error(&(yylsp[-2]), "value too large"), state->msgs);
					YYERROR;
				}
				(yyval.expr) = xfrm_expr_alloc(&(yyloc), (yyvsp[-3].val), (yyvsp[-2].val), (yyvsp[-1].val));
			}
#line 13954 "parser_bison.tab.c"
    break;

  case 951: /* xfrm_expr: "ipsec" xfrm_dir xfrm_spnum nf_key_proto xfrm_state_proto_key close_scope_ipsec  */
#line 5121 "../../nft/nftables/src/parser_bison.y"
                        {
				enum nft_xfrm_keys xfrmk = (yyvsp[-1].val);

				switch ((yyvsp[-2].val)) {
				case NFPROTO_IPV4:
					break;
				case NFPROTO_IPV6:
					if ((yyvsp[-1].val) == NFT_XFRM_KEY_SADDR_IP4)
						xfrmk = NFT_XFRM_KEY_SADDR_IP6;
					else if ((yyvsp[-1].val) == NFT_XFRM_KEY_DADDR_IP4)
						xfrmk = NFT_XFRM_KEY_DADDR_IP6;
					break;
				default:
					YYERROR;
					break;
				}

				if ((yyvsp[-3].val) > 255) {
					erec_queue(error(&(yylsp[-3]), "value too large"), state->msgs);
					YYERROR;
				}

				(yyval.expr) = xfrm_expr_alloc(&(yyloc), (yyvsp[-4].val), (yyvsp[-3].val), xfrmk);
			}
#line 13983 "parser_bison.tab.c"
    break;

  case 952: /* hash_expr: "jhash" expr "mod" "number" "seed" "number" offset_opt close_scope_hash  */
#line 5148 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = hash_expr_alloc(&(yyloc), (yyvsp[-4].val), true, (yyvsp[-2].val), (yyvsp[-1].val), NFT_HASH_JENKINS);
				(yyval.expr)->hash.expr = (yyvsp[-6].expr);
			}
#line 13992 "parser_bison.tab.c"
    break;

  case 953: /* hash_expr: "jhash" expr "mod" "number" offset_opt close_scope_hash  */
#line 5153 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = hash_expr_alloc(&(yyloc), (yyvsp[-2].val), false, 0, (yyvsp[-1].val), NFT_HASH_JENKINS);
				(yyval.expr)->hash.expr = (yyvsp[-4].expr);
			}
#line 14001 "parser_bison.tab.c"
    break;

  case 954: /* hash_expr: "symhash" "mod" "number" offset_opt close_scope_hash  */
#line 5158 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = hash_expr_alloc(&(yyloc), (yyvsp[-2].val), false, 0, (yyvsp[-1].val), NFT_HASH_SYM);
			}
#line 14009 "parser_bison.tab.c"
    break;

  case 955: /* nf_key_proto: "ip" close_scope_ip  */
#line 5163 "../../nft/nftables/src/parser_bison.y"
                                                       { (yyval.val) = NFPROTO_IPV4; }
#line 14015 "parser_bison.tab.c"
    break;

  case 956: /* nf_key_proto: "ip6" close_scope_ip6  */
#line 5164 "../../nft/nftables/src/parser_bison.y"
                                                        { (yyval.val) = NFPROTO_IPV6; }
#line 14021 "parser_bison.tab.c"
    break;

  case 957: /* rt_expr: "rt" rt_key close_scope_rt  */
#line 5168 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = rt_expr_alloc(&(yyloc), (yyvsp[-1].val), true);
			}
#line 14029 "parser_bison.tab.c"
    break;

  case 958: /* rt_expr: "rt" nf_key_proto rt_key close_scope_rt  */
#line 5172 "../../nft/nftables/src/parser_bison.y"
                        {
				enum nft_rt_keys rtk = (yyvsp[-1].val);

				switch ((yyvsp[-2].val)) {
				case NFPROTO_IPV4:
					break;
				case NFPROTO_IPV6:
					if ((yyvsp[-1].val) == NFT_RT_NEXTHOP4)
						rtk = NFT_RT_NEXTHOP6;
					break;
				default:
					YYERROR;
					break;
				}

				(yyval.expr) = rt_expr_alloc(&(yyloc), rtk, false);
			}
#line 14051 "parser_bison.tab.c"
    break;

  case 959: /* rt_key: "classid"  */
#line 5191 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = NFT_RT_CLASSID; }
#line 14057 "parser_bison.tab.c"
    break;

  case 960: /* rt_key: "nexthop"  */
#line 5192 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = NFT_RT_NEXTHOP4; }
#line 14063 "parser_bison.tab.c"
    break;

  case 961: /* rt_key: "mtu"  */
#line 5193 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = NFT_RT_TCPMSS; }
#line 14069 "parser_bison.tab.c"
    break;

  case 962: /* rt_key: "ipsec" close_scope_ipsec  */
#line 5194 "../../nft/nftables/src/parser_bison.y"
                                                          { (yyval.val) = NFT_RT_XFRM; }
#line 14075 "parser_bison.tab.c"
    break;

  case 963: /* ct_expr: "ct" ct_key close_scope_ct  */
#line 5198 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = ct_expr_alloc(&(yyloc), (yyvsp[-1].val), -1);
			}
#line 14083 "parser_bison.tab.c"
    break;

  case 964: /* ct_expr: "ct" ct_dir ct_key_dir close_scope_ct  */
#line 5202 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = ct_expr_alloc(&(yyloc), (yyvsp[-1].val), (yyvsp[-2].val));
			}
#line 14091 "parser_bison.tab.c"
    break;

  case 965: /* ct_expr: "ct" ct_dir ct_key_proto_field close_scope_ct  */
#line 5206 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = ct_expr_alloc(&(yyloc), (yyvsp[-1].val), (yyvsp[-2].val));
			}
#line 14099 "parser_bison.tab.c"
    break;

  case 966: /* ct_dir: "original"  */
#line 5211 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = IP_CT_DIR_ORIGINAL; }
#line 14105 "parser_bison.tab.c"
    break;

  case 967: /* ct_dir: "reply"  */
#line 5212 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = IP_CT_DIR_REPLY; }
#line 14111 "parser_bison.tab.c"
    break;

  case 968: /* ct_key: "l3proto"  */
#line 5215 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = NFT_CT_L3PROTOCOL; }
#line 14117 "parser_bison.tab.c"
    break;

  case 969: /* ct_key: "protocol"  */
#line 5216 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = NFT_CT_PROTOCOL; }
#line 14123 "parser_bison.tab.c"
    break;

  case 970: /* ct_key: "mark"  */
#line 5217 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = NFT_CT_MARK; }
#line 14129 "parser_bison.tab.c"
    break;

  case 971: /* ct_key: "state"  */
#line 5218 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = NFT_CT_STATE; }
#line 14135 "parser_bison.tab.c"
    break;

  case 972: /* ct_key: "direction"  */
#line 5219 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = NFT_CT_DIRECTION; }
#line 14141 "parser_bison.tab.c"
    break;

  case 973: /* ct_key: "status"  */
#line 5220 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = NFT_CT_STATUS; }
#line 14147 "parser_bison.tab.c"
    break;

  case 974: /* ct_key: "expiration"  */
#line 5221 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = NFT_CT_EXPIRATION; }
#line 14153 "parser_bison.tab.c"
    break;

  case 975: /* ct_key: "helper"  */
#line 5222 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = NFT_CT_HELPER; }
#line 14159 "parser_bison.tab.c"
    break;

  case 976: /* ct_key: "saddr"  */
#line 5223 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = NFT_CT_SRC; }
#line 14165 "parser_bison.tab.c"
    break;

  case 977: /* ct_key: "daddr"  */
#line 5224 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = NFT_CT_DST; }
#line 14171 "parser_bison.tab.c"
    break;

  case 978: /* ct_key: "proto-src"  */
#line 5225 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = NFT_CT_PROTO_SRC; }
#line 14177 "parser_bison.tab.c"
    break;

  case 979: /* ct_key: "proto-dst"  */
#line 5226 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = NFT_CT_PROTO_DST; }
#line 14183 "parser_bison.tab.c"
    break;

  case 980: /* ct_key: "label"  */
#line 5227 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = NFT_CT_LABELS; }
#line 14189 "parser_bison.tab.c"
    break;

  case 981: /* ct_key: "event"  */
#line 5228 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = NFT_CT_EVENTMASK; }
#line 14195 "parser_bison.tab.c"
    break;

  case 982: /* ct_key: "secmark" close_scope_secmark  */
#line 5229 "../../nft/nftables/src/parser_bison.y"
                                                            { (yyval.val) = NFT_CT_SECMARK; }
#line 14201 "parser_bison.tab.c"
    break;

  case 983: /* ct_key: "id"  */
#line 5230 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = NFT_CT_ID; }
#line 14207 "parser_bison.tab.c"
    break;

  case 985: /* ct_key_dir: "saddr"  */
#line 5234 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = NFT_CT_SRC; }
#line 14213 "parser_bison.tab.c"
    break;

  case 986: /* ct_key_dir: "daddr"  */
#line 5235 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = NFT_CT_DST; }
#line 14219 "parser_bison.tab.c"
    break;

  case 987: /* ct_key_dir: "l3proto"  */
#line 5236 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = NFT_CT_L3PROTOCOL; }
#line 14225 "parser_bison.tab.c"
    break;

  case 988: /* ct_key_dir: "protocol"  */
#line 5237 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = NFT_CT_PROTOCOL; }
#line 14231 "parser_bison.tab.c"
    break;

  case 989: /* ct_key_dir: "proto-src"  */
#line 5238 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = NFT_CT_PROTO_SRC; }
#line 14237 "parser_bison.tab.c"
    break;

  case 990: /* ct_key_dir: "proto-dst"  */
#line 5239 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = NFT_CT_PROTO_DST; }
#line 14243 "parser_bison.tab.c"
    break;

  case 992: /* ct_key_proto_field: "ip" "saddr" close_scope_ip  */
#line 5243 "../../nft/nftables/src/parser_bison.y"
                                                               { (yyval.val) = NFT_CT_SRC_IP; }
#line 14249 "parser_bison.tab.c"
    break;

  case 993: /* ct_key_proto_field: "ip" "daddr" close_scope_ip  */
#line 5244 "../../nft/nftables/src/parser_bison.y"
                                                               { (yyval.val) = NFT_CT_DST_IP; }
#line 14255 "parser_bison.tab.c"
    break;

  case 994: /* ct_key_proto_field: "ip6" "saddr" close_scope_ip6  */
#line 5245 "../../nft/nftables/src/parser_bison.y"
                                                                { (yyval.val) = NFT_CT_SRC_IP6; }
#line 14261 "parser_bison.tab.c"
    break;

  case 995: /* ct_key_proto_field: "ip6" "daddr" close_scope_ip6  */
#line 5246 "../../nft/nftables/src/parser_bison.y"
                                                                { (yyval.val) = NFT_CT_DST_IP6; }
#line 14267 "parser_bison.tab.c"
    break;

  case 996: /* ct_key_dir_optional: "bytes"  */
#line 5249 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = NFT_CT_BYTES; }
#line 14273 "parser_bison.tab.c"
    break;

  case 997: /* ct_key_dir_optional: "packets"  */
#line 5250 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = NFT_CT_PKTS; }
#line 14279 "parser_bison.tab.c"
    break;

  case 998: /* ct_key_dir_optional: "avgpkt"  */
#line 5251 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = NFT_CT_AVGPKT; }
#line 14285 "parser_bison.tab.c"
    break;

  case 999: /* ct_key_dir_optional: "zone"  */
#line 5252 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = NFT_CT_ZONE; }
#line 14291 "parser_bison.tab.c"
    break;

  case 1002: /* list_stmt_expr: symbol_stmt_expr "comma" symbol_stmt_expr  */
#line 5260 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = list_expr_alloc(&(yyloc));
				compound_expr_add((yyval.expr), (yyvsp[-2].expr));
				compound_expr_add((yyval.expr), (yyvsp[0].expr));
			}
#line 14301 "parser_bison.tab.c"
    break;

  case 1003: /* list_stmt_expr: list_stmt_expr "comma" symbol_stmt_expr  */
#line 5266 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyvsp[-2].expr)->location = (yyloc);
				compound_expr_add((yyvsp[-2].expr), (yyvsp[0].expr));
				(yyval.expr) = (yyvsp[-2].expr);
			}
#line 14311 "parser_bison.tab.c"
    break;

  case 1004: /* ct_stmt: "ct" ct_key "set" stmt_expr close_scope_ct  */
#line 5274 "../../nft/nftables/src/parser_bison.y"
                        {
				switch ((yyvsp[-3].val)) {
				case NFT_CT_HELPER:
					(yyval.stmt) = objref_stmt_alloc(&(yyloc));
					(yyval.stmt)->objref.type = NFT_OBJECT_CT_HELPER;
					(yyval.stmt)->objref.expr = (yyvsp[-1].expr);
					break;
				default:
					(yyval.stmt) = ct_stmt_alloc(&(yyloc), (yyvsp[-3].val), -1, (yyvsp[-1].expr));
					break;
				}
			}
#line 14328 "parser_bison.tab.c"
    break;

  case 1005: /* ct_stmt: "ct" "timeout" "set" stmt_expr close_scope_ct  */
#line 5287 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.stmt) = objref_stmt_alloc(&(yyloc));
				(yyval.stmt)->objref.type = NFT_OBJECT_CT_TIMEOUT;
				(yyval.stmt)->objref.expr = (yyvsp[-1].expr);

			}
#line 14339 "parser_bison.tab.c"
    break;

  case 1006: /* ct_stmt: "ct" "expectation" "set" stmt_expr close_scope_ct  */
#line 5294 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.stmt) = objref_stmt_alloc(&(yyloc));
				(yyval.stmt)->objref.type = NFT_OBJECT_CT_EXPECT;
				(yyval.stmt)->objref.expr = (yyvsp[-1].expr);
			}
#line 14349 "parser_bison.tab.c"
    break;

  case 1007: /* ct_stmt: "ct" ct_dir ct_key_dir_optional "set" stmt_expr close_scope_ct  */
#line 5300 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.stmt) = ct_stmt_alloc(&(yyloc), (yyvsp[-3].val), (yyvsp[-4].val), (yyvsp[-1].expr));
			}
#line 14357 "parser_bison.tab.c"
    break;

  case 1008: /* payload_stmt: payload_expr "set" stmt_expr  */
#line 5306 "../../nft/nftables/src/parser_bison.y"
                        {
				if ((yyvsp[-2].expr)->etype == EXPR_EXTHDR)
					(yyval.stmt) = exthdr_stmt_alloc(&(yyloc), (yyvsp[-2].expr), (yyvsp[0].expr));
				else
					(yyval.stmt) = payload_stmt_alloc(&(yyloc), (yyvsp[-2].expr), (yyvsp[0].expr));
			}
#line 14368 "parser_bison.tab.c"
    break;

  case 1027: /* payload_raw_expr: "@" payload_base_spec "comma" "number" "comma" "number" close_scope_at  */
#line 5335 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = payload_expr_alloc(&(yyloc), NULL, 0);
				payload_init_raw((yyval.expr), (yyvsp[-5].val), (yyvsp[-3].val), (yyvsp[-1].val));
				(yyval.expr)->byteorder		= BYTEORDER_BIG_ENDIAN;
				(yyval.expr)->payload.is_raw	= true;
			}
#line 14379 "parser_bison.tab.c"
    break;

  case 1028: /* payload_base_spec: "ll"  */
#line 5343 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = PROTO_BASE_LL_HDR; }
#line 14385 "parser_bison.tab.c"
    break;

  case 1029: /* payload_base_spec: "nh"  */
#line 5344 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = PROTO_BASE_NETWORK_HDR; }
#line 14391 "parser_bison.tab.c"
    break;

  case 1030: /* payload_base_spec: "th" close_scope_th  */
#line 5345 "../../nft/nftables/src/parser_bison.y"
                                                                { (yyval.val) = PROTO_BASE_TRANSPORT_HDR; }
#line 14397 "parser_bison.tab.c"
    break;

  case 1031: /* payload_base_spec: "string"  */
#line 5347 "../../nft/nftables/src/parser_bison.y"
                        {
				if (!strcmp((yyvsp[0].string), "ih")) {
					(yyval.val) = PROTO_BASE_INNER_HDR;
				} else {
					erec_queue(error(&(yylsp[0]), "unknown raw payload base"), state->msgs);
					xfree((yyvsp[0].string));
					YYERROR;
				}
				xfree((yyvsp[0].string));
			}
#line 14412 "parser_bison.tab.c"
    break;

  case 1032: /* eth_hdr_expr: "ether" eth_hdr_field close_scope_eth  */
#line 5360 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = payload_expr_alloc(&(yyloc), &proto_eth, (yyvsp[-1].val));
			}
#line 14420 "parser_bison.tab.c"
    break;

  case 1033: /* eth_hdr_field: "saddr"  */
#line 5365 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = ETHHDR_SADDR; }
#line 14426 "parser_bison.tab.c"
    break;

  case 1034: /* eth_hdr_field: "daddr"  */
#line 5366 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = ETHHDR_DADDR; }
#line 14432 "parser_bison.tab.c"
    break;

  case 1035: /* eth_hdr_field: "type" close_scope_type  */
#line 5367 "../../nft/nftables/src/parser_bison.y"
                                                                        { (yyval.val) = ETHHDR_TYPE; }
#line 14438 "parser_bison.tab.c"
    break;

  case 1036: /* vlan_hdr_expr: "vlan" vlan_hdr_field close_scope_vlan  */
#line 5371 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = payload_expr_alloc(&(yyloc), &proto_vlan, (yyvsp[-1].val));
			}
#line 14446 "parser_bison.tab.c"
    break;

  case 1037: /* vlan_hdr_field: "id"  */
#line 5376 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = VLANHDR_VID; }
#line 14452 "parser_bison.tab.c"
    break;

  case 1038: /* vlan_hdr_field: "cfi"  */
#line 5377 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = VLANHDR_CFI; }
#line 14458 "parser_bison.tab.c"
    break;

  case 1039: /* vlan_hdr_field: "dei"  */
#line 5378 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = VLANHDR_DEI; }
#line 14464 "parser_bison.tab.c"
    break;

  case 1040: /* vlan_hdr_field: "pcp"  */
#line 5379 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = VLANHDR_PCP; }
#line 14470 "parser_bison.tab.c"
    break;

  case 1041: /* vlan_hdr_field: "type" close_scope_type  */
#line 5380 "../../nft/nftables/src/parser_bison.y"
                                                                        { (yyval.val) = VLANHDR_TYPE; }
#line 14476 "parser_bison.tab.c"
    break;

  case 1042: /* arp_hdr_expr: "arp" arp_hdr_field close_scope_arp  */
#line 5384 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = payload_expr_alloc(&(yyloc), &proto_arp, (yyvsp[-1].val));
			}
#line 14484 "parser_bison.tab.c"
    break;

  case 1043: /* arp_hdr_field: "htype"  */
#line 5389 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = ARPHDR_HRD; }
#line 14490 "parser_bison.tab.c"
    break;

  case 1044: /* arp_hdr_field: "ptype"  */
#line 5390 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = ARPHDR_PRO; }
#line 14496 "parser_bison.tab.c"
    break;

  case 1045: /* arp_hdr_field: "hlen"  */
#line 5391 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = ARPHDR_HLN; }
#line 14502 "parser_bison.tab.c"
    break;

  case 1046: /* arp_hdr_field: "plen"  */
#line 5392 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = ARPHDR_PLN; }
#line 14508 "parser_bison.tab.c"
    break;

  case 1047: /* arp_hdr_field: "operation"  */
#line 5393 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = ARPHDR_OP; }
#line 14514 "parser_bison.tab.c"
    break;

  case 1048: /* arp_hdr_field: "saddr" "ether" close_scope_eth  */
#line 5394 "../../nft/nftables/src/parser_bison.y"
                                                                { (yyval.val) = ARPHDR_SADDR_ETHER; }
#line 14520 "parser_bison.tab.c"
    break;

  case 1049: /* arp_hdr_field: "daddr" "ether" close_scope_eth  */
#line 5395 "../../nft/nftables/src/parser_bison.y"
                                                                { (yyval.val) = ARPHDR_DADDR_ETHER; }
#line 14526 "parser_bison.tab.c"
    break;

  case 1050: /* arp_hdr_field: "saddr" "ip" close_scope_ip  */
#line 5396 "../../nft/nftables/src/parser_bison.y"
                                                                { (yyval.val) = ARPHDR_SADDR_IP; }
#line 14532 "parser_bison.tab.c"
    break;

  case 1051: /* arp_hdr_field: "daddr" "ip" close_scope_ip  */
#line 5397 "../../nft/nftables/src/parser_bison.y"
                                                                { (yyval.val) = ARPHDR_DADDR_IP; }
#line 14538 "parser_bison.tab.c"
    break;

  case 1052: /* ip_hdr_expr: "ip" ip_hdr_field close_scope_ip  */
#line 5401 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = payload_expr_alloc(&(yyloc), &proto_ip, (yyvsp[-1].val));
			}
#line 14546 "parser_bison.tab.c"
    break;

  case 1053: /* ip_hdr_expr: "ip" "option" ip_option_type ip_option_field close_scope_ip  */
#line 5405 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = ipopt_expr_alloc(&(yyloc), (yyvsp[-2].val), (yyvsp[-1].val));
				if (!(yyval.expr)) {
					erec_queue(error(&(yylsp[-4]), "unknown ip option type/field"), state->msgs);
					YYERROR;
				}
			}
#line 14558 "parser_bison.tab.c"
    break;

  case 1054: /* ip_hdr_expr: "ip" "option" ip_option_type close_scope_ip  */
#line 5413 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = ipopt_expr_alloc(&(yyloc), (yyvsp[-1].val), IPOPT_FIELD_TYPE);
				(yyval.expr)->exthdr.flags = NFT_EXTHDR_F_PRESENT;
			}
#line 14567 "parser_bison.tab.c"
    break;

  case 1055: /* ip_hdr_field: "version"  */
#line 5419 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = IPHDR_VERSION; }
#line 14573 "parser_bison.tab.c"
    break;

  case 1056: /* ip_hdr_field: "hdrlength"  */
#line 5420 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = IPHDR_HDRLENGTH; }
#line 14579 "parser_bison.tab.c"
    break;

  case 1057: /* ip_hdr_field: "dscp"  */
#line 5421 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = IPHDR_DSCP; }
#line 14585 "parser_bison.tab.c"
    break;

  case 1058: /* ip_hdr_field: "ecn"  */
#line 5422 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = IPHDR_ECN; }
#line 14591 "parser_bison.tab.c"
    break;

  case 1059: /* ip_hdr_field: "length"  */
#line 5423 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = IPHDR_LENGTH; }
#line 14597 "parser_bison.tab.c"
    break;

  case 1060: /* ip_hdr_field: "id"  */
#line 5424 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = IPHDR_ID; }
#line 14603 "parser_bison.tab.c"
    break;

  case 1061: /* ip_hdr_field: "frag-off"  */
#line 5425 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = IPHDR_FRAG_OFF; }
#line 14609 "parser_bison.tab.c"
    break;

  case 1062: /* ip_hdr_field: "ttl"  */
#line 5426 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = IPHDR_TTL; }
#line 14615 "parser_bison.tab.c"
    break;

  case 1063: /* ip_hdr_field: "protocol"  */
#line 5427 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = IPHDR_PROTOCOL; }
#line 14621 "parser_bison.tab.c"
    break;

  case 1064: /* ip_hdr_field: "checksum"  */
#line 5428 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = IPHDR_CHECKSUM; }
#line 14627 "parser_bison.tab.c"
    break;

  case 1065: /* ip_hdr_field: "saddr"  */
#line 5429 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = IPHDR_SADDR; }
#line 14633 "parser_bison.tab.c"
    break;

  case 1066: /* ip_hdr_field: "daddr"  */
#line 5430 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = IPHDR_DADDR; }
#line 14639 "parser_bison.tab.c"
    break;

  case 1067: /* ip_option_type: "lsrr"  */
#line 5433 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = IPOPT_LSRR; }
#line 14645 "parser_bison.tab.c"
    break;

  case 1068: /* ip_option_type: "rr"  */
#line 5434 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = IPOPT_RR; }
#line 14651 "parser_bison.tab.c"
    break;

  case 1069: /* ip_option_type: "ssrr"  */
#line 5435 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = IPOPT_SSRR; }
#line 14657 "parser_bison.tab.c"
    break;

  case 1070: /* ip_option_type: "ra"  */
#line 5436 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = IPOPT_RA; }
#line 14663 "parser_bison.tab.c"
    break;

  case 1071: /* ip_option_field: "type" close_scope_type  */
#line 5439 "../../nft/nftables/src/parser_bison.y"
                                                                        { (yyval.val) = IPOPT_FIELD_TYPE; }
#line 14669 "parser_bison.tab.c"
    break;

  case 1072: /* ip_option_field: "length"  */
#line 5440 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = IPOPT_FIELD_LENGTH; }
#line 14675 "parser_bison.tab.c"
    break;

  case 1073: /* ip_option_field: "value"  */
#line 5441 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = IPOPT_FIELD_VALUE; }
#line 14681 "parser_bison.tab.c"
    break;

  case 1074: /* ip_option_field: "ptr"  */
#line 5442 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = IPOPT_FIELD_PTR; }
#line 14687 "parser_bison.tab.c"
    break;

  case 1075: /* ip_option_field: "addr"  */
#line 5443 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = IPOPT_FIELD_ADDR_0; }
#line 14693 "parser_bison.tab.c"
    break;

  case 1076: /* icmp_hdr_expr: "icmp" icmp_hdr_field close_scope_icmp  */
#line 5447 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = payload_expr_alloc(&(yyloc), &proto_icmp, (yyvsp[-1].val));
			}
#line 14701 "parser_bison.tab.c"
    break;

  case 1077: /* icmp_hdr_field: "type" close_scope_type  */
#line 5452 "../../nft/nftables/src/parser_bison.y"
                                                                        { (yyval.val) = ICMPHDR_TYPE; }
#line 14707 "parser_bison.tab.c"
    break;

  case 1078: /* icmp_hdr_field: "code"  */
#line 5453 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = ICMPHDR_CODE; }
#line 14713 "parser_bison.tab.c"
    break;

  case 1079: /* icmp_hdr_field: "checksum"  */
#line 5454 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = ICMPHDR_CHECKSUM; }
#line 14719 "parser_bison.tab.c"
    break;

  case 1080: /* icmp_hdr_field: "id"  */
#line 5455 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = ICMPHDR_ID; }
#line 14725 "parser_bison.tab.c"
    break;

  case 1081: /* icmp_hdr_field: "seq"  */
#line 5456 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = ICMPHDR_SEQ; }
#line 14731 "parser_bison.tab.c"
    break;

  case 1082: /* icmp_hdr_field: "gateway"  */
#line 5457 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = ICMPHDR_GATEWAY; }
#line 14737 "parser_bison.tab.c"
    break;

  case 1083: /* icmp_hdr_field: "mtu"  */
#line 5458 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = ICMPHDR_MTU; }
#line 14743 "parser_bison.tab.c"
    break;

  case 1084: /* igmp_hdr_expr: "igmp" igmp_hdr_field close_scope_igmp  */
#line 5462 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = payload_expr_alloc(&(yyloc), &proto_igmp, (yyvsp[-1].val));
			}
#line 14751 "parser_bison.tab.c"
    break;

  case 1085: /* igmp_hdr_field: "type" close_scope_type  */
#line 5467 "../../nft/nftables/src/parser_bison.y"
                                                                        { (yyval.val) = IGMPHDR_TYPE; }
#line 14757 "parser_bison.tab.c"
    break;

  case 1086: /* igmp_hdr_field: "checksum"  */
#line 5468 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = IGMPHDR_CHECKSUM; }
#line 14763 "parser_bison.tab.c"
    break;

  case 1087: /* igmp_hdr_field: "mrt"  */
#line 5469 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = IGMPHDR_MRT; }
#line 14769 "parser_bison.tab.c"
    break;

  case 1088: /* igmp_hdr_field: "group"  */
#line 5470 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = IGMPHDR_GROUP; }
#line 14775 "parser_bison.tab.c"
    break;

  case 1089: /* ip6_hdr_expr: "ip6" ip6_hdr_field close_scope_ip6  */
#line 5474 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = payload_expr_alloc(&(yyloc), &proto_ip6, (yyvsp[-1].val));
			}
#line 14783 "parser_bison.tab.c"
    break;

  case 1090: /* ip6_hdr_field: "version"  */
#line 5479 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = IP6HDR_VERSION; }
#line 14789 "parser_bison.tab.c"
    break;

  case 1091: /* ip6_hdr_field: "dscp"  */
#line 5480 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = IP6HDR_DSCP; }
#line 14795 "parser_bison.tab.c"
    break;

  case 1092: /* ip6_hdr_field: "ecn"  */
#line 5481 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = IP6HDR_ECN; }
#line 14801 "parser_bison.tab.c"
    break;

  case 1093: /* ip6_hdr_field: "flowlabel"  */
#line 5482 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = IP6HDR_FLOWLABEL; }
#line 14807 "parser_bison.tab.c"
    break;

  case 1094: /* ip6_hdr_field: "length"  */
#line 5483 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = IP6HDR_LENGTH; }
#line 14813 "parser_bison.tab.c"
    break;

  case 1095: /* ip6_hdr_field: "nexthdr"  */
#line 5484 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = IP6HDR_NEXTHDR; }
#line 14819 "parser_bison.tab.c"
    break;

  case 1096: /* ip6_hdr_field: "hoplimit"  */
#line 5485 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = IP6HDR_HOPLIMIT; }
#line 14825 "parser_bison.tab.c"
    break;

  case 1097: /* ip6_hdr_field: "saddr"  */
#line 5486 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = IP6HDR_SADDR; }
#line 14831 "parser_bison.tab.c"
    break;

  case 1098: /* ip6_hdr_field: "daddr"  */
#line 5487 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = IP6HDR_DADDR; }
#line 14837 "parser_bison.tab.c"
    break;

  case 1099: /* icmp6_hdr_expr: "icmpv6" icmp6_hdr_field close_scope_icmp  */
#line 5490 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = payload_expr_alloc(&(yyloc), &proto_icmp6, (yyvsp[-1].val));
			}
#line 14845 "parser_bison.tab.c"
    break;

  case 1100: /* icmp6_hdr_field: "type" close_scope_type  */
#line 5495 "../../nft/nftables/src/parser_bison.y"
                                                                        { (yyval.val) = ICMP6HDR_TYPE; }
#line 14851 "parser_bison.tab.c"
    break;

  case 1101: /* icmp6_hdr_field: "code"  */
#line 5496 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = ICMP6HDR_CODE; }
#line 14857 "parser_bison.tab.c"
    break;

  case 1102: /* icmp6_hdr_field: "checksum"  */
#line 5497 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = ICMP6HDR_CHECKSUM; }
#line 14863 "parser_bison.tab.c"
    break;

  case 1103: /* icmp6_hdr_field: "param-problem"  */
#line 5498 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = ICMP6HDR_PPTR; }
#line 14869 "parser_bison.tab.c"
    break;

  case 1104: /* icmp6_hdr_field: "mtu"  */
#line 5499 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = ICMP6HDR_MTU; }
#line 14875 "parser_bison.tab.c"
    break;

  case 1105: /* icmp6_hdr_field: "id"  */
#line 5500 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = ICMP6HDR_ID; }
#line 14881 "parser_bison.tab.c"
    break;

  case 1106: /* icmp6_hdr_field: "seq"  */
#line 5501 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = ICMP6HDR_SEQ; }
#line 14887 "parser_bison.tab.c"
    break;

  case 1107: /* icmp6_hdr_field: "max-delay"  */
#line 5502 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = ICMP6HDR_MAXDELAY; }
#line 14893 "parser_bison.tab.c"
    break;

  case 1108: /* auth_hdr_expr: "ah" auth_hdr_field close_scope_ah  */
#line 5506 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = payload_expr_alloc(&(yyloc), &proto_ah, (yyvsp[-1].val));
			}
#line 14901 "parser_bison.tab.c"
    break;

  case 1109: /* auth_hdr_field: "nexthdr"  */
#line 5511 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = AHHDR_NEXTHDR; }
#line 14907 "parser_bison.tab.c"
    break;

  case 1110: /* auth_hdr_field: "hdrlength"  */
#line 5512 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = AHHDR_HDRLENGTH; }
#line 14913 "parser_bison.tab.c"
    break;

  case 1111: /* auth_hdr_field: "reserved"  */
#line 5513 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = AHHDR_RESERVED; }
#line 14919 "parser_bison.tab.c"
    break;

  case 1112: /* auth_hdr_field: "spi"  */
#line 5514 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = AHHDR_SPI; }
#line 14925 "parser_bison.tab.c"
    break;

  case 1113: /* auth_hdr_field: "seq"  */
#line 5515 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = AHHDR_SEQUENCE; }
#line 14931 "parser_bison.tab.c"
    break;

  case 1114: /* esp_hdr_expr: "esp" esp_hdr_field close_scope_esp  */
#line 5519 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = payload_expr_alloc(&(yyloc), &proto_esp, (yyvsp[-1].val));
			}
#line 14939 "parser_bison.tab.c"
    break;

  case 1115: /* esp_hdr_field: "spi"  */
#line 5524 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = ESPHDR_SPI; }
#line 14945 "parser_bison.tab.c"
    break;

  case 1116: /* esp_hdr_field: "seq"  */
#line 5525 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = ESPHDR_SEQUENCE; }
#line 14951 "parser_bison.tab.c"
    break;

  case 1117: /* comp_hdr_expr: "comp" comp_hdr_field close_scope_comp  */
#line 5529 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = payload_expr_alloc(&(yyloc), &proto_comp, (yyvsp[-1].val));
			}
#line 14959 "parser_bison.tab.c"
    break;

  case 1118: /* comp_hdr_field: "nexthdr"  */
#line 5534 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = COMPHDR_NEXTHDR; }
#line 14965 "parser_bison.tab.c"
    break;

  case 1119: /* comp_hdr_field: "flags"  */
#line 5535 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = COMPHDR_FLAGS; }
#line 14971 "parser_bison.tab.c"
    break;

  case 1120: /* comp_hdr_field: "cpi"  */
#line 5536 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = COMPHDR_CPI; }
#line 14977 "parser_bison.tab.c"
    break;

  case 1121: /* udp_hdr_expr: "udp" udp_hdr_field close_scope_udp  */
#line 5540 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = payload_expr_alloc(&(yyloc), &proto_udp, (yyvsp[-1].val));
			}
#line 14985 "parser_bison.tab.c"
    break;

  case 1122: /* udp_hdr_field: "sport"  */
#line 5545 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = UDPHDR_SPORT; }
#line 14991 "parser_bison.tab.c"
    break;

  case 1123: /* udp_hdr_field: "dport"  */
#line 5546 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = UDPHDR_DPORT; }
#line 14997 "parser_bison.tab.c"
    break;

  case 1124: /* udp_hdr_field: "length"  */
#line 5547 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = UDPHDR_LENGTH; }
#line 15003 "parser_bison.tab.c"
    break;

  case 1125: /* udp_hdr_field: "checksum"  */
#line 5548 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = UDPHDR_CHECKSUM; }
#line 15009 "parser_bison.tab.c"
    break;

  case 1126: /* udplite_hdr_expr: "udplite" udplite_hdr_field close_scope_udplite  */
#line 5552 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = payload_expr_alloc(&(yyloc), &proto_udplite, (yyvsp[-1].val));
			}
#line 15017 "parser_bison.tab.c"
    break;

  case 1127: /* udplite_hdr_field: "sport"  */
#line 5557 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = UDPHDR_SPORT; }
#line 15023 "parser_bison.tab.c"
    break;

  case 1128: /* udplite_hdr_field: "dport"  */
#line 5558 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = UDPHDR_DPORT; }
#line 15029 "parser_bison.tab.c"
    break;

  case 1129: /* udplite_hdr_field: "csumcov"  */
#line 5559 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = UDPHDR_LENGTH; }
#line 15035 "parser_bison.tab.c"
    break;

  case 1130: /* udplite_hdr_field: "checksum"  */
#line 5560 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = UDPHDR_CHECKSUM; }
#line 15041 "parser_bison.tab.c"
    break;

  case 1131: /* tcp_hdr_expr: "tcp" tcp_hdr_field  */
#line 5564 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = payload_expr_alloc(&(yyloc), &proto_tcp, (yyvsp[0].val));
			}
#line 15049 "parser_bison.tab.c"
    break;

  case 1132: /* tcp_hdr_expr: "tcp" "option" tcp_hdr_option_type  */
#line 5568 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = tcpopt_expr_alloc(&(yyloc), (yyvsp[0].val), TCPOPT_COMMON_KIND);
				(yyval.expr)->exthdr.flags = NFT_EXTHDR_F_PRESENT;
			}
#line 15058 "parser_bison.tab.c"
    break;

  case 1133: /* tcp_hdr_expr: "tcp" "option" tcp_hdr_option_kind_and_field  */
#line 5573 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = tcpopt_expr_alloc(&(yyloc), (yyvsp[0].tcp_kind_field).kind, (yyvsp[0].tcp_kind_field).field);
			}
#line 15066 "parser_bison.tab.c"
    break;

  case 1134: /* tcp_hdr_expr: "tcp" "option" "@" close_scope_at tcp_hdr_option_type "comma" "number" "comma" "number"  */
#line 5577 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = tcpopt_expr_alloc(&(yyloc), (yyvsp[-4].val), 0);
				tcpopt_init_raw((yyval.expr), (yyvsp[-4].val), (yyvsp[-2].val), (yyvsp[0].val), 0);
			}
#line 15075 "parser_bison.tab.c"
    break;

  case 1135: /* optstrip_stmt: "reset" "tcp" "option" tcp_hdr_option_type close_scope_tcp  */
#line 5584 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.stmt) = optstrip_stmt_alloc(&(yyloc), tcpopt_expr_alloc(&(yyloc),
										(yyvsp[-1].val), TCPOPT_COMMON_KIND));
			}
#line 15084 "parser_bison.tab.c"
    break;

  case 1136: /* tcp_hdr_field: "sport"  */
#line 5590 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = TCPHDR_SPORT; }
#line 15090 "parser_bison.tab.c"
    break;

  case 1137: /* tcp_hdr_field: "dport"  */
#line 5591 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = TCPHDR_DPORT; }
#line 15096 "parser_bison.tab.c"
    break;

  case 1138: /* tcp_hdr_field: "seq"  */
#line 5592 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = TCPHDR_SEQ; }
#line 15102 "parser_bison.tab.c"
    break;

  case 1139: /* tcp_hdr_field: "ackseq"  */
#line 5593 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = TCPHDR_ACKSEQ; }
#line 15108 "parser_bison.tab.c"
    break;

  case 1140: /* tcp_hdr_field: "doff"  */
#line 5594 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = TCPHDR_DOFF; }
#line 15114 "parser_bison.tab.c"
    break;

  case 1141: /* tcp_hdr_field: "reserved"  */
#line 5595 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = TCPHDR_RESERVED; }
#line 15120 "parser_bison.tab.c"
    break;

  case 1142: /* tcp_hdr_field: "flags"  */
#line 5596 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = TCPHDR_FLAGS; }
#line 15126 "parser_bison.tab.c"
    break;

  case 1143: /* tcp_hdr_field: "window"  */
#line 5597 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = TCPHDR_WINDOW; }
#line 15132 "parser_bison.tab.c"
    break;

  case 1144: /* tcp_hdr_field: "checksum"  */
#line 5598 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = TCPHDR_CHECKSUM; }
#line 15138 "parser_bison.tab.c"
    break;

  case 1145: /* tcp_hdr_field: "urgptr"  */
#line 5599 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = TCPHDR_URGPTR; }
#line 15144 "parser_bison.tab.c"
    break;

  case 1146: /* tcp_hdr_option_kind_and_field: "mss" tcpopt_field_maxseg  */
#line 5603 "../../nft/nftables/src/parser_bison.y"
                                {
					struct tcp_kind_field kind_field = { .kind = TCPOPT_KIND_MAXSEG, .field = (yyvsp[0].val) };
					(yyval.tcp_kind_field) = kind_field;
				}
#line 15153 "parser_bison.tab.c"
    break;

  case 1147: /* tcp_hdr_option_kind_and_field: tcp_hdr_option_sack tcpopt_field_sack  */
#line 5608 "../../nft/nftables/src/parser_bison.y"
                                {
					struct tcp_kind_field kind_field = { .kind = (yyvsp[-1].val), .field = (yyvsp[0].val) };
					(yyval.tcp_kind_field) = kind_field;
				}
#line 15162 "parser_bison.tab.c"
    break;

  case 1148: /* tcp_hdr_option_kind_and_field: "window" tcpopt_field_window  */
#line 5613 "../../nft/nftables/src/parser_bison.y"
                                {
					struct tcp_kind_field kind_field = { .kind = TCPOPT_KIND_WINDOW, .field = (yyvsp[0].val) };
					(yyval.tcp_kind_field) = kind_field;
				}
#line 15171 "parser_bison.tab.c"
    break;

  case 1149: /* tcp_hdr_option_kind_and_field: "timestamp" tcpopt_field_tsopt  */
#line 5618 "../../nft/nftables/src/parser_bison.y"
                                {
					struct tcp_kind_field kind_field = { .kind = TCPOPT_KIND_TIMESTAMP, .field = (yyvsp[0].val) };
					(yyval.tcp_kind_field) = kind_field;
				}
#line 15180 "parser_bison.tab.c"
    break;

  case 1150: /* tcp_hdr_option_kind_and_field: tcp_hdr_option_type "length"  */
#line 5623 "../../nft/nftables/src/parser_bison.y"
                                {
					struct tcp_kind_field kind_field = { .kind = (yyvsp[-1].val), .field = TCPOPT_COMMON_LENGTH };
					(yyval.tcp_kind_field) = kind_field;
				}
#line 15189 "parser_bison.tab.c"
    break;

  case 1151: /* tcp_hdr_option_kind_and_field: "mptcp" tcpopt_field_mptcp  */
#line 5628 "../../nft/nftables/src/parser_bison.y"
                                {
					struct tcp_kind_field kind_field = { .kind = TCPOPT_KIND_MPTCP, .field = (yyvsp[0].val) };
					(yyval.tcp_kind_field) = kind_field;
				}
#line 15198 "parser_bison.tab.c"
    break;

  case 1152: /* tcp_hdr_option_sack: "sack"  */
#line 5634 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = TCPOPT_KIND_SACK; }
#line 15204 "parser_bison.tab.c"
    break;

  case 1153: /* tcp_hdr_option_sack: "sack0"  */
#line 5635 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = TCPOPT_KIND_SACK; }
#line 15210 "parser_bison.tab.c"
    break;

  case 1154: /* tcp_hdr_option_sack: "sack1"  */
#line 5636 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = TCPOPT_KIND_SACK1; }
#line 15216 "parser_bison.tab.c"
    break;

  case 1155: /* tcp_hdr_option_sack: "sack2"  */
#line 5637 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = TCPOPT_KIND_SACK2; }
#line 15222 "parser_bison.tab.c"
    break;

  case 1156: /* tcp_hdr_option_sack: "sack3"  */
#line 5638 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = TCPOPT_KIND_SACK3; }
#line 15228 "parser_bison.tab.c"
    break;

  case 1157: /* tcp_hdr_option_type: "echo"  */
#line 5641 "../../nft/nftables/src/parser_bison.y"
                                                        { (yyval.val) = TCPOPT_KIND_ECHO; }
#line 15234 "parser_bison.tab.c"
    break;

  case 1158: /* tcp_hdr_option_type: "eol"  */
#line 5642 "../../nft/nftables/src/parser_bison.y"
                                                        { (yyval.val) = TCPOPT_KIND_EOL; }
#line 15240 "parser_bison.tab.c"
    break;

  case 1159: /* tcp_hdr_option_type: "fastopen"  */
#line 5643 "../../nft/nftables/src/parser_bison.y"
                                                        { (yyval.val) = TCPOPT_KIND_FASTOPEN; }
#line 15246 "parser_bison.tab.c"
    break;

  case 1160: /* tcp_hdr_option_type: "md5sig"  */
#line 5644 "../../nft/nftables/src/parser_bison.y"
                                                        { (yyval.val) = TCPOPT_KIND_MD5SIG; }
#line 15252 "parser_bison.tab.c"
    break;

  case 1161: /* tcp_hdr_option_type: "mptcp"  */
#line 5645 "../../nft/nftables/src/parser_bison.y"
                                                        { (yyval.val) = TCPOPT_KIND_MPTCP; }
#line 15258 "parser_bison.tab.c"
    break;

  case 1162: /* tcp_hdr_option_type: "mss"  */
#line 5646 "../../nft/nftables/src/parser_bison.y"
                                                        { (yyval.val) = TCPOPT_KIND_MAXSEG; }
#line 15264 "parser_bison.tab.c"
    break;

  case 1163: /* tcp_hdr_option_type: "nop"  */
#line 5647 "../../nft/nftables/src/parser_bison.y"
                                                        { (yyval.val) = TCPOPT_KIND_NOP; }
#line 15270 "parser_bison.tab.c"
    break;

  case 1164: /* tcp_hdr_option_type: "sack-permitted"  */
#line 5648 "../../nft/nftables/src/parser_bison.y"
                                                        { (yyval.val) = TCPOPT_KIND_SACK_PERMITTED; }
#line 15276 "parser_bison.tab.c"
    break;

  case 1165: /* tcp_hdr_option_type: "timestamp"  */
#line 5649 "../../nft/nftables/src/parser_bison.y"
                                                        { (yyval.val) = TCPOPT_KIND_TIMESTAMP; }
#line 15282 "parser_bison.tab.c"
    break;

  case 1166: /* tcp_hdr_option_type: "window"  */
#line 5650 "../../nft/nftables/src/parser_bison.y"
                                                        { (yyval.val) = TCPOPT_KIND_WINDOW; }
#line 15288 "parser_bison.tab.c"
    break;

  case 1167: /* tcp_hdr_option_type: tcp_hdr_option_sack  */
#line 5651 "../../nft/nftables/src/parser_bison.y"
                                                        { (yyval.val) = (yyvsp[0].val); }
#line 15294 "parser_bison.tab.c"
    break;

  case 1168: /* tcp_hdr_option_type: "number"  */
#line 5652 "../../nft/nftables/src/parser_bison.y"
                                                        {
				if ((yyvsp[0].val) > 255) {
					erec_queue(error(&(yylsp[0]), "value too large"), state->msgs);
					YYERROR;
				}
				(yyval.val) = (yyvsp[0].val);
			}
#line 15306 "parser_bison.tab.c"
    break;

  case 1169: /* tcpopt_field_sack: "left"  */
#line 5661 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = TCPOPT_SACK_LEFT; }
#line 15312 "parser_bison.tab.c"
    break;

  case 1170: /* tcpopt_field_sack: "right"  */
#line 5662 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = TCPOPT_SACK_RIGHT; }
#line 15318 "parser_bison.tab.c"
    break;

  case 1171: /* tcpopt_field_window: "count"  */
#line 5665 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = TCPOPT_WINDOW_COUNT; }
#line 15324 "parser_bison.tab.c"
    break;

  case 1172: /* tcpopt_field_tsopt: "tsval"  */
#line 5668 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = TCPOPT_TS_TSVAL; }
#line 15330 "parser_bison.tab.c"
    break;

  case 1173: /* tcpopt_field_tsopt: "tsecr"  */
#line 5669 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = TCPOPT_TS_TSECR; }
#line 15336 "parser_bison.tab.c"
    break;

  case 1174: /* tcpopt_field_maxseg: "size"  */
#line 5672 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = TCPOPT_MAXSEG_SIZE; }
#line 15342 "parser_bison.tab.c"
    break;

  case 1175: /* tcpopt_field_mptcp: "subtype"  */
#line 5675 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = TCPOPT_MPTCP_SUBTYPE; }
#line 15348 "parser_bison.tab.c"
    break;

  case 1176: /* dccp_hdr_expr: "dccp" dccp_hdr_field close_scope_dccp  */
#line 5679 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = payload_expr_alloc(&(yyloc), &proto_dccp, (yyvsp[-1].val));
			}
#line 15356 "parser_bison.tab.c"
    break;

  case 1177: /* dccp_hdr_field: "sport"  */
#line 5684 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = DCCPHDR_SPORT; }
#line 15362 "parser_bison.tab.c"
    break;

  case 1178: /* dccp_hdr_field: "dport"  */
#line 5685 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = DCCPHDR_DPORT; }
#line 15368 "parser_bison.tab.c"
    break;

  case 1179: /* dccp_hdr_field: "type" close_scope_type  */
#line 5686 "../../nft/nftables/src/parser_bison.y"
                                                                        { (yyval.val) = DCCPHDR_TYPE; }
#line 15374 "parser_bison.tab.c"
    break;

  case 1180: /* sctp_chunk_type: "data"  */
#line 5689 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = SCTP_CHUNK_TYPE_DATA; }
#line 15380 "parser_bison.tab.c"
    break;

  case 1181: /* sctp_chunk_type: "init"  */
#line 5690 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = SCTP_CHUNK_TYPE_INIT; }
#line 15386 "parser_bison.tab.c"
    break;

  case 1182: /* sctp_chunk_type: "init-ack"  */
#line 5691 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = SCTP_CHUNK_TYPE_INIT_ACK; }
#line 15392 "parser_bison.tab.c"
    break;

  case 1183: /* sctp_chunk_type: "sack"  */
#line 5692 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = SCTP_CHUNK_TYPE_SACK; }
#line 15398 "parser_bison.tab.c"
    break;

  case 1184: /* sctp_chunk_type: "heartbeat"  */
#line 5693 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = SCTP_CHUNK_TYPE_HEARTBEAT; }
#line 15404 "parser_bison.tab.c"
    break;

  case 1185: /* sctp_chunk_type: "heartbeat-ack"  */
#line 5694 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = SCTP_CHUNK_TYPE_HEARTBEAT_ACK; }
#line 15410 "parser_bison.tab.c"
    break;

  case 1186: /* sctp_chunk_type: "abort"  */
#line 5695 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = SCTP_CHUNK_TYPE_ABORT; }
#line 15416 "parser_bison.tab.c"
    break;

  case 1187: /* sctp_chunk_type: "shutdown"  */
#line 5696 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = SCTP_CHUNK_TYPE_SHUTDOWN; }
#line 15422 "parser_bison.tab.c"
    break;

  case 1188: /* sctp_chunk_type: "shutdown-ack"  */
#line 5697 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = SCTP_CHUNK_TYPE_SHUTDOWN_ACK; }
#line 15428 "parser_bison.tab.c"
    break;

  case 1189: /* sctp_chunk_type: "error"  */
#line 5698 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = SCTP_CHUNK_TYPE_ERROR; }
#line 15434 "parser_bison.tab.c"
    break;

  case 1190: /* sctp_chunk_type: "cookie-echo"  */
#line 5699 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = SCTP_CHUNK_TYPE_COOKIE_ECHO; }
#line 15440 "parser_bison.tab.c"
    break;

  case 1191: /* sctp_chunk_type: "cookie-ack"  */
#line 5700 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = SCTP_CHUNK_TYPE_COOKIE_ACK; }
#line 15446 "parser_bison.tab.c"
    break;

  case 1192: /* sctp_chunk_type: "ecne"  */
#line 5701 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = SCTP_CHUNK_TYPE_ECNE; }
#line 15452 "parser_bison.tab.c"
    break;

  case 1193: /* sctp_chunk_type: "cwr"  */
#line 5702 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = SCTP_CHUNK_TYPE_CWR; }
#line 15458 "parser_bison.tab.c"
    break;

  case 1194: /* sctp_chunk_type: "shutdown-complete"  */
#line 5703 "../../nft/nftables/src/parser_bison.y"
                                                  { (yyval.val) = SCTP_CHUNK_TYPE_SHUTDOWN_COMPLETE; }
#line 15464 "parser_bison.tab.c"
    break;

  case 1195: /* sctp_chunk_type: "asconf-ack"  */
#line 5704 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = SCTP_CHUNK_TYPE_ASCONF_ACK; }
#line 15470 "parser_bison.tab.c"
    break;

  case 1196: /* sctp_chunk_type: "forward-tsn"  */
#line 5705 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = SCTP_CHUNK_TYPE_FORWARD_TSN; }
#line 15476 "parser_bison.tab.c"
    break;

  case 1197: /* sctp_chunk_type: "asconf"  */
#line 5706 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = SCTP_CHUNK_TYPE_ASCONF; }
#line 15482 "parser_bison.tab.c"
    break;

  case 1198: /* sctp_chunk_common_field: "type" close_scope_type  */
#line 5709 "../../nft/nftables/src/parser_bison.y"
                                                                { (yyval.val) = SCTP_CHUNK_COMMON_TYPE; }
#line 15488 "parser_bison.tab.c"
    break;

  case 1199: /* sctp_chunk_common_field: "flags"  */
#line 5710 "../../nft/nftables/src/parser_bison.y"
                                        { (yyval.val) = SCTP_CHUNK_COMMON_FLAGS; }
#line 15494 "parser_bison.tab.c"
    break;

  case 1200: /* sctp_chunk_common_field: "length"  */
#line 5711 "../../nft/nftables/src/parser_bison.y"
                                        { (yyval.val) = SCTP_CHUNK_COMMON_LENGTH; }
#line 15500 "parser_bison.tab.c"
    break;

  case 1201: /* sctp_chunk_data_field: "tsn"  */
#line 5714 "../../nft/nftables/src/parser_bison.y"
                                        { (yyval.val) = SCTP_CHUNK_DATA_TSN; }
#line 15506 "parser_bison.tab.c"
    break;

  case 1202: /* sctp_chunk_data_field: "stream"  */
#line 5715 "../../nft/nftables/src/parser_bison.y"
                                        { (yyval.val) = SCTP_CHUNK_DATA_STREAM; }
#line 15512 "parser_bison.tab.c"
    break;

  case 1203: /* sctp_chunk_data_field: "ssn"  */
#line 5716 "../../nft/nftables/src/parser_bison.y"
                                        { (yyval.val) = SCTP_CHUNK_DATA_SSN; }
#line 15518 "parser_bison.tab.c"
    break;

  case 1204: /* sctp_chunk_data_field: "ppid"  */
#line 5717 "../../nft/nftables/src/parser_bison.y"
                                        { (yyval.val) = SCTP_CHUNK_DATA_PPID; }
#line 15524 "parser_bison.tab.c"
    break;

  case 1205: /* sctp_chunk_init_field: "init-tag"  */
#line 5720 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = SCTP_CHUNK_INIT_TAG; }
#line 15530 "parser_bison.tab.c"
    break;

  case 1206: /* sctp_chunk_init_field: "a-rwnd"  */
#line 5721 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = SCTP_CHUNK_INIT_RWND; }
#line 15536 "parser_bison.tab.c"
    break;

  case 1207: /* sctp_chunk_init_field: "num-outbound-streams"  */
#line 5722 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = SCTP_CHUNK_INIT_OSTREAMS; }
#line 15542 "parser_bison.tab.c"
    break;

  case 1208: /* sctp_chunk_init_field: "num-inbound-streams"  */
#line 5723 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = SCTP_CHUNK_INIT_ISTREAMS; }
#line 15548 "parser_bison.tab.c"
    break;

  case 1209: /* sctp_chunk_init_field: "initial-tsn"  */
#line 5724 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = SCTP_CHUNK_INIT_TSN; }
#line 15554 "parser_bison.tab.c"
    break;

  case 1210: /* sctp_chunk_sack_field: "cum-tsn-ack"  */
#line 5727 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = SCTP_CHUNK_SACK_CTSN_ACK; }
#line 15560 "parser_bison.tab.c"
    break;

  case 1211: /* sctp_chunk_sack_field: "a-rwnd"  */
#line 5728 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = SCTP_CHUNK_SACK_RWND; }
#line 15566 "parser_bison.tab.c"
    break;

  case 1212: /* sctp_chunk_sack_field: "num-gap-ack-blocks"  */
#line 5729 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = SCTP_CHUNK_SACK_GACK_BLOCKS; }
#line 15572 "parser_bison.tab.c"
    break;

  case 1213: /* sctp_chunk_sack_field: "num-dup-tsns"  */
#line 5730 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = SCTP_CHUNK_SACK_DUP_TSNS; }
#line 15578 "parser_bison.tab.c"
    break;

  case 1214: /* sctp_chunk_alloc: sctp_chunk_type  */
#line 5734 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = sctp_chunk_expr_alloc(&(yyloc), (yyvsp[0].val), SCTP_CHUNK_COMMON_TYPE);
				(yyval.expr)->exthdr.flags = NFT_EXTHDR_F_PRESENT;
			}
#line 15587 "parser_bison.tab.c"
    break;

  case 1215: /* sctp_chunk_alloc: sctp_chunk_type sctp_chunk_common_field  */
#line 5739 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = sctp_chunk_expr_alloc(&(yyloc), (yyvsp[-1].val), (yyvsp[0].val));
			}
#line 15595 "parser_bison.tab.c"
    break;

  case 1216: /* sctp_chunk_alloc: "data" sctp_chunk_data_field  */
#line 5743 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = sctp_chunk_expr_alloc(&(yyloc), SCTP_CHUNK_TYPE_DATA, (yyvsp[0].val));
			}
#line 15603 "parser_bison.tab.c"
    break;

  case 1217: /* sctp_chunk_alloc: "init" sctp_chunk_init_field  */
#line 5747 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = sctp_chunk_expr_alloc(&(yyloc), SCTP_CHUNK_TYPE_INIT, (yyvsp[0].val));
			}
#line 15611 "parser_bison.tab.c"
    break;

  case 1218: /* sctp_chunk_alloc: "init-ack" sctp_chunk_init_field  */
#line 5751 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = sctp_chunk_expr_alloc(&(yyloc), SCTP_CHUNK_TYPE_INIT_ACK, (yyvsp[0].val));
			}
#line 15619 "parser_bison.tab.c"
    break;

  case 1219: /* sctp_chunk_alloc: "sack" sctp_chunk_sack_field  */
#line 5755 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = sctp_chunk_expr_alloc(&(yyloc), SCTP_CHUNK_TYPE_SACK, (yyvsp[0].val));
			}
#line 15627 "parser_bison.tab.c"
    break;

  case 1220: /* sctp_chunk_alloc: "shutdown" "cum-tsn-ack"  */
#line 5759 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = sctp_chunk_expr_alloc(&(yyloc), SCTP_CHUNK_TYPE_SHUTDOWN,
							   SCTP_CHUNK_SHUTDOWN_CTSN_ACK);
			}
#line 15636 "parser_bison.tab.c"
    break;

  case 1221: /* sctp_chunk_alloc: "ecne" "lowest-tsn"  */
#line 5764 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = sctp_chunk_expr_alloc(&(yyloc), SCTP_CHUNK_TYPE_ECNE,
							   SCTP_CHUNK_ECNE_CWR_MIN_TSN);
			}
#line 15645 "parser_bison.tab.c"
    break;

  case 1222: /* sctp_chunk_alloc: "cwr" "lowest-tsn"  */
#line 5769 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = sctp_chunk_expr_alloc(&(yyloc), SCTP_CHUNK_TYPE_CWR,
							   SCTP_CHUNK_ECNE_CWR_MIN_TSN);
			}
#line 15654 "parser_bison.tab.c"
    break;

  case 1223: /* sctp_chunk_alloc: "asconf-ack" "seqno"  */
#line 5774 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = sctp_chunk_expr_alloc(&(yyloc), SCTP_CHUNK_TYPE_ASCONF_ACK,
							   SCTP_CHUNK_ASCONF_SEQNO);
			}
#line 15663 "parser_bison.tab.c"
    break;

  case 1224: /* sctp_chunk_alloc: "forward-tsn" "new-cum-tsn"  */
#line 5779 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = sctp_chunk_expr_alloc(&(yyloc), SCTP_CHUNK_TYPE_FORWARD_TSN,
							   SCTP_CHUNK_FORWARD_TSN_NCTSN);
			}
#line 15672 "parser_bison.tab.c"
    break;

  case 1225: /* sctp_chunk_alloc: "asconf" "seqno"  */
#line 5784 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = sctp_chunk_expr_alloc(&(yyloc), SCTP_CHUNK_TYPE_ASCONF,
							   SCTP_CHUNK_ASCONF_SEQNO);
			}
#line 15681 "parser_bison.tab.c"
    break;

  case 1226: /* sctp_hdr_expr: "sctp" sctp_hdr_field close_scope_sctp  */
#line 5791 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = payload_expr_alloc(&(yyloc), &proto_sctp, (yyvsp[-1].val));
			}
#line 15689 "parser_bison.tab.c"
    break;

  case 1227: /* sctp_hdr_expr: "sctp" "chunk" sctp_chunk_alloc close_scope_sctp_chunk close_scope_sctp  */
#line 5795 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = (yyvsp[-2].expr);
			}
#line 15697 "parser_bison.tab.c"
    break;

  case 1228: /* sctp_hdr_field: "sport"  */
#line 5800 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = SCTPHDR_SPORT; }
#line 15703 "parser_bison.tab.c"
    break;

  case 1229: /* sctp_hdr_field: "dport"  */
#line 5801 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = SCTPHDR_DPORT; }
#line 15709 "parser_bison.tab.c"
    break;

  case 1230: /* sctp_hdr_field: "vtag"  */
#line 5802 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = SCTPHDR_VTAG; }
#line 15715 "parser_bison.tab.c"
    break;

  case 1231: /* sctp_hdr_field: "checksum"  */
#line 5803 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = SCTPHDR_CHECKSUM; }
#line 15721 "parser_bison.tab.c"
    break;

  case 1232: /* th_hdr_expr: "th" th_hdr_field close_scope_th  */
#line 5807 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = payload_expr_alloc(&(yyloc), &proto_th, (yyvsp[-1].val));
				if ((yyval.expr))
					(yyval.expr)->payload.is_raw = true;
			}
#line 15731 "parser_bison.tab.c"
    break;

  case 1233: /* th_hdr_field: "sport"  */
#line 5814 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = THDR_SPORT; }
#line 15737 "parser_bison.tab.c"
    break;

  case 1234: /* th_hdr_field: "dport"  */
#line 5815 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = THDR_DPORT; }
#line 15743 "parser_bison.tab.c"
    break;

  case 1243: /* hbh_hdr_expr: "hbh" hbh_hdr_field close_scope_hbh  */
#line 5829 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = exthdr_expr_alloc(&(yyloc), &exthdr_hbh, (yyvsp[-1].val));
			}
#line 15751 "parser_bison.tab.c"
    break;

  case 1244: /* hbh_hdr_field: "nexthdr"  */
#line 5834 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = HBHHDR_NEXTHDR; }
#line 15757 "parser_bison.tab.c"
    break;

  case 1245: /* hbh_hdr_field: "hdrlength"  */
#line 5835 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = HBHHDR_HDRLENGTH; }
#line 15763 "parser_bison.tab.c"
    break;

  case 1246: /* rt_hdr_expr: "rt" rt_hdr_field close_scope_rt  */
#line 5839 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = exthdr_expr_alloc(&(yyloc), &exthdr_rt, (yyvsp[-1].val));
			}
#line 15771 "parser_bison.tab.c"
    break;

  case 1247: /* rt_hdr_field: "nexthdr"  */
#line 5844 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = RTHDR_NEXTHDR; }
#line 15777 "parser_bison.tab.c"
    break;

  case 1248: /* rt_hdr_field: "hdrlength"  */
#line 5845 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = RTHDR_HDRLENGTH; }
#line 15783 "parser_bison.tab.c"
    break;

  case 1249: /* rt_hdr_field: "type" close_scope_type  */
#line 5846 "../../nft/nftables/src/parser_bison.y"
                                                                        { (yyval.val) = RTHDR_TYPE; }
#line 15789 "parser_bison.tab.c"
    break;

  case 1250: /* rt_hdr_field: "seg-left"  */
#line 5847 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = RTHDR_SEG_LEFT; }
#line 15795 "parser_bison.tab.c"
    break;

  case 1251: /* rt0_hdr_expr: "rt0" rt0_hdr_field close_scope_rt  */
#line 5851 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = exthdr_expr_alloc(&(yyloc), &exthdr_rt0, (yyvsp[-1].val));
			}
#line 15803 "parser_bison.tab.c"
    break;

  case 1252: /* rt0_hdr_field: "addr" '[' "number" ']'  */
#line 5857 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.val) = RT0HDR_ADDR_1 + (yyvsp[-1].val) - 1;
			}
#line 15811 "parser_bison.tab.c"
    break;

  case 1253: /* rt2_hdr_expr: "rt2" rt2_hdr_field close_scope_rt  */
#line 5863 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = exthdr_expr_alloc(&(yyloc), &exthdr_rt2, (yyvsp[-1].val));
			}
#line 15819 "parser_bison.tab.c"
    break;

  case 1254: /* rt2_hdr_field: "addr"  */
#line 5868 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = RT2HDR_ADDR; }
#line 15825 "parser_bison.tab.c"
    break;

  case 1255: /* rt4_hdr_expr: "srh" rt4_hdr_field close_scope_rt  */
#line 5872 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = exthdr_expr_alloc(&(yyloc), &exthdr_rt4, (yyvsp[-1].val));
			}
#line 15833 "parser_bison.tab.c"
    break;

  case 1256: /* rt4_hdr_field: "last-entry"  */
#line 5877 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = RT4HDR_LASTENT; }
#line 15839 "parser_bison.tab.c"
    break;

  case 1257: /* rt4_hdr_field: "flags"  */
#line 5878 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = RT4HDR_FLAGS; }
#line 15845 "parser_bison.tab.c"
    break;

  case 1258: /* rt4_hdr_field: "tag"  */
#line 5879 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = RT4HDR_TAG; }
#line 15851 "parser_bison.tab.c"
    break;

  case 1259: /* rt4_hdr_field: "sid" '[' "number" ']'  */
#line 5881 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.val) = RT4HDR_SID_1 + (yyvsp[-1].val) - 1;
			}
#line 15859 "parser_bison.tab.c"
    break;

  case 1260: /* frag_hdr_expr: "frag" frag_hdr_field close_scope_frag  */
#line 5887 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = exthdr_expr_alloc(&(yyloc), &exthdr_frag, (yyvsp[-1].val));
			}
#line 15867 "parser_bison.tab.c"
    break;

  case 1261: /* frag_hdr_field: "nexthdr"  */
#line 5892 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = FRAGHDR_NEXTHDR; }
#line 15873 "parser_bison.tab.c"
    break;

  case 1262: /* frag_hdr_field: "reserved"  */
#line 5893 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = FRAGHDR_RESERVED; }
#line 15879 "parser_bison.tab.c"
    break;

  case 1263: /* frag_hdr_field: "frag-off"  */
#line 5894 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = FRAGHDR_FRAG_OFF; }
#line 15885 "parser_bison.tab.c"
    break;

  case 1264: /* frag_hdr_field: "reserved2"  */
#line 5895 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = FRAGHDR_RESERVED2; }
#line 15891 "parser_bison.tab.c"
    break;

  case 1265: /* frag_hdr_field: "more-fragments"  */
#line 5896 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = FRAGHDR_MFRAGS; }
#line 15897 "parser_bison.tab.c"
    break;

  case 1266: /* frag_hdr_field: "id"  */
#line 5897 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = FRAGHDR_ID; }
#line 15903 "parser_bison.tab.c"
    break;

  case 1267: /* dst_hdr_expr: "dst" dst_hdr_field close_scope_dst  */
#line 5901 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = exthdr_expr_alloc(&(yyloc), &exthdr_dst, (yyvsp[-1].val));
			}
#line 15911 "parser_bison.tab.c"
    break;

  case 1268: /* dst_hdr_field: "nexthdr"  */
#line 5906 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = DSTHDR_NEXTHDR; }
#line 15917 "parser_bison.tab.c"
    break;

  case 1269: /* dst_hdr_field: "hdrlength"  */
#line 5907 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = DSTHDR_HDRLENGTH; }
#line 15923 "parser_bison.tab.c"
    break;

  case 1270: /* mh_hdr_expr: "mh" mh_hdr_field close_scope_mh  */
#line 5911 "../../nft/nftables/src/parser_bison.y"
                        {
				(yyval.expr) = exthdr_expr_alloc(&(yyloc), &exthdr_mh, (yyvsp[-1].val));
			}
#line 15931 "parser_bison.tab.c"
    break;

  case 1271: /* mh_hdr_field: "nexthdr"  */
#line 5916 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = MHHDR_NEXTHDR; }
#line 15937 "parser_bison.tab.c"
    break;

  case 1272: /* mh_hdr_field: "hdrlength"  */
#line 5917 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = MHHDR_HDRLENGTH; }
#line 15943 "parser_bison.tab.c"
    break;

  case 1273: /* mh_hdr_field: "type" close_scope_type  */
#line 5918 "../../nft/nftables/src/parser_bison.y"
                                                                        { (yyval.val) = MHHDR_TYPE; }
#line 15949 "parser_bison.tab.c"
    break;

  case 1274: /* mh_hdr_field: "reserved"  */
#line 5919 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = MHHDR_RESERVED; }
#line 15955 "parser_bison.tab.c"
    break;

  case 1275: /* mh_hdr_field: "checksum"  */
#line 5920 "../../nft/nftables/src/parser_bison.y"
                                                { (yyval.val) = MHHDR_CHECKSUM; }
#line 15961 "parser_bison.tab.c"
    break;

  case 1276: /* exthdr_exists_expr: "exthdr" exthdr_key  */
#line 5924 "../../nft/nftables/src/parser_bison.y"
                        {
				const struct exthdr_desc *desc;

				desc = exthdr_find_proto((yyvsp[0].val));

				/* Assume that NEXTHDR template is always
				 * the fist one in list of templates.
				 */
				(yyval.expr) = exthdr_expr_alloc(&(yyloc), desc, 1);
				(yyval.expr)->exthdr.flags = NFT_EXTHDR_F_PRESENT;
			}
#line 15977 "parser_bison.tab.c"
    break;

  case 1277: /* exthdr_key: "hbh" close_scope_hbh  */
#line 5937 "../../nft/nftables/src/parser_bison.y"
                                                        { (yyval.val) = IPPROTO_HOPOPTS; }
#line 15983 "parser_bison.tab.c"
    break;

  case 1278: /* exthdr_key: "rt" close_scope_rt  */
#line 5938 "../../nft/nftables/src/parser_bison.y"
                                                        { (yyval.val) = IPPROTO_ROUTING; }
#line 15989 "parser_bison.tab.c"
    break;

  case 1279: /* exthdr_key: "frag" close_scope_frag  */
#line 5939 "../../nft/nftables/src/parser_bison.y"
                                                                { (yyval.val) = IPPROTO_FRAGMENT; }
#line 15995 "parser_bison.tab.c"
    break;

  case 1280: /* exthdr_key: "dst" close_scope_dst  */
#line 5940 "../../nft/nftables/src/parser_bison.y"
                                                        { (yyval.val) = IPPROTO_DSTOPTS; }
#line 16001 "parser_bison.tab.c"
    break;

  case 1281: /* exthdr_key: "mh" close_scope_mh  */
#line 5941 "../../nft/nftables/src/parser_bison.y"
                                                        { (yyval.val) = IPPROTO_MH; }
#line 16007 "parser_bison.tab.c"
    break;


#line 16011 "parser_bison.tab.c"

      default: break;
    }
  /* User semantic actions sometimes alter yychar, and that requires
     that yytoken be updated with the new translation.  We take the
     approach of translating immediately before every use of yytoken.
     One alternative is translating here after every semantic action,
     but that translation would be missed if the semantic action invokes
     YYABORT, YYACCEPT, or YYERROR immediately after altering yychar or
     if it invokes YYBACKUP.  In the case of YYABORT or YYACCEPT, an
     incorrect destructor might then be invoked immediately.  In the
     case of YYERROR or YYBACKUP, subsequent parser actions might lead
     to an incorrect destructor call or verbose syntax error message
     before the lookahead is translated.  */
  YY_SYMBOL_PRINT ("-> $$ =", YY_CAST (yysymbol_kind_t, yyr1[yyn]), &yyval, &yyloc);

  YYPOPSTACK (yylen);
  yylen = 0;

  *++yyvsp = yyval;
  *++yylsp = yyloc;

  /* Now 'shift' the result of the reduction.  Determine what state
     that goes to, based on the state we popped back to and the rule
     number reduced by.  */
  {
    const int yylhs = yyr1[yyn] - YYNTOKENS;
    const int yyi = yypgoto[yylhs] + *yyssp;
    yystate = (0 <= yyi && yyi <= YYLAST && yycheck[yyi] == *yyssp
               ? yytable[yyi]
               : yydefgoto[yylhs]);
  }

  goto yynewstate;


/*--------------------------------------.
| yyerrlab -- here on detecting error.  |
`--------------------------------------*/
yyerrlab:
  /* Make sure we have latest lookahead translation.  See comments at
     user semantic actions for why this is necessary.  */
  yytoken = yychar == NFT_EMPTY ? YYSYMBOL_YYEMPTY : YYTRANSLATE (yychar);
  /* If not already recovering from an error, report this error.  */
  if (!yyerrstatus)
    {
      ++yynerrs;
      {
        yypcontext_t yyctx
          = {yyssp, yytoken, &yylloc};
        char const *yymsgp = YY_("syntax error");
        int yysyntax_error_status;
        yysyntax_error_status = yysyntax_error (&yymsg_alloc, &yymsg, &yyctx);
        if (yysyntax_error_status == 0)
          yymsgp = yymsg;
        else if (yysyntax_error_status == -1)
          {
            if (yymsg != yymsgbuf)
              YYSTACK_FREE (yymsg);
            yymsg = YY_CAST (char *,
                             YYSTACK_ALLOC (YY_CAST (YYSIZE_T, yymsg_alloc)));
            if (yymsg)
              {
                yysyntax_error_status
                  = yysyntax_error (&yymsg_alloc, &yymsg, &yyctx);
                yymsgp = yymsg;
              }
            else
              {
                yymsg = yymsgbuf;
                yymsg_alloc = sizeof yymsgbuf;
                yysyntax_error_status = YYENOMEM;
              }
          }
        yyerror (&yylloc, nft, scanner, state, yymsgp);
        if (yysyntax_error_status == YYENOMEM)
          YYNOMEM;
      }
    }

  yyerror_range[1] = yylloc;
  if (yyerrstatus == 3)
    {
      /* If just tried and failed to reuse lookahead token after an
         error, discard it.  */

      if (yychar <= TOKEN_EOF)
        {
          /* Return failure if at end of input.  */
          if (yychar == TOKEN_EOF)
            YYABORT;
        }
      else
        {
          yydestruct ("Error: discarding",
                      yytoken, &yylval, &yylloc, nft, scanner, state);
          yychar = NFT_EMPTY;
        }
    }

  /* Else will try to reuse lookahead token after shifting the error
     token.  */
  goto yyerrlab1;


/*---------------------------------------------------.
| yyerrorlab -- error raised explicitly by YYERROR.  |
`---------------------------------------------------*/
yyerrorlab:
  /* Pacify compilers when the user code never invokes YYERROR and the
     label yyerrorlab therefore never appears in user code.  */
  if (0)
    YYERROR;
  ++yynerrs;

  /* Do not reclaim the symbols of the rule whose action triggered
     this YYERROR.  */
  YYPOPSTACK (yylen);
  yylen = 0;
  YY_STACK_PRINT (yyss, yyssp);
  yystate = *yyssp;
  goto yyerrlab1;


/*-------------------------------------------------------------.
| yyerrlab1 -- common code for both syntax error and YYERROR.  |
`-------------------------------------------------------------*/
yyerrlab1:
  yyerrstatus = 3;      /* Each real token shifted decrements this.  */

  /* Pop stack until we find a state that shifts the error token.  */
  for (;;)
    {
      yyn = yypact[yystate];
      if (!yypact_value_is_default (yyn))
        {
          yyn += YYSYMBOL_YYerror;
          if (0 <= yyn && yyn <= YYLAST && yycheck[yyn] == YYSYMBOL_YYerror)
            {
              yyn = yytable[yyn];
              if (0 < yyn)
                break;
            }
        }

      /* Pop the current state because it cannot handle the error token.  */
      if (yyssp == yyss)
        YYABORT;

      yyerror_range[1] = *yylsp;
      yydestruct ("Error: popping",
                  YY_ACCESSING_SYMBOL (yystate), yyvsp, yylsp, nft, scanner, state);
      YYPOPSTACK (1);
      yystate = *yyssp;
      YY_STACK_PRINT (yyss, yyssp);
    }

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  *++yyvsp = yylval;
  YY_IGNORE_MAYBE_UNINITIALIZED_END

  yyerror_range[2] = yylloc;
  ++yylsp;
  YYLLOC_DEFAULT (*yylsp, yyerror_range, 2);

  /* Shift the error token.  */
  YY_SYMBOL_PRINT ("Shifting", YY_ACCESSING_SYMBOL (yyn), yyvsp, yylsp);

  yystate = yyn;
  goto yynewstate;


/*-------------------------------------.
| yyacceptlab -- YYACCEPT comes here.  |
`-------------------------------------*/
yyacceptlab:
  yyresult = 0;
  goto yyreturnlab;


/*-----------------------------------.
| yyabortlab -- YYABORT comes here.  |
`-----------------------------------*/
yyabortlab:
  yyresult = 1;
  goto yyreturnlab;


/*-----------------------------------------------------------.
| yyexhaustedlab -- YYNOMEM (memory exhaustion) comes here.  |
`-----------------------------------------------------------*/
yyexhaustedlab:
  yyerror (&yylloc, nft, scanner, state, YY_("memory exhausted"));
  yyresult = 2;
  goto yyreturnlab;


/*----------------------------------------------------------.
| yyreturnlab -- parsing is finished, clean up and return.  |
`----------------------------------------------------------*/
yyreturnlab:
  if (yychar != NFT_EMPTY)
    {
      /* Make sure we have latest lookahead translation.  See comments at
         user semantic actions for why this is necessary.  */
      yytoken = YYTRANSLATE (yychar);
      yydestruct ("Cleanup: discarding lookahead",
                  yytoken, &yylval, &yylloc, nft, scanner, state);
    }
  /* Do not reclaim the symbols of the rule whose action triggered
     this YYABORT or YYACCEPT.  */
  YYPOPSTACK (yylen);
  YY_STACK_PRINT (yyss, yyssp);
  while (yyssp != yyss)
    {
      yydestruct ("Cleanup: popping",
                  YY_ACCESSING_SYMBOL (+*yyssp), yyvsp, yylsp, nft, scanner, state);
      YYPOPSTACK (1);
    }
#ifndef yyoverflow
  if (yyss != yyssa)
    YYSTACK_FREE (yyss);
#endif
  if (yymsg != yymsgbuf)
    YYSTACK_FREE (yymsg);
  return yyresult;
}

#line 5944 "../../nft/nftables/src/parser_bison.y"

