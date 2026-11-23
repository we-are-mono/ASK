// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright 2018 NXP
 */


/******************************************************************************
 @File          fm_cc_dbg.h

 @Description   FM Coarse Classifier debug
 *//***************************************************************************/

#include <linux/slab.h>
#include "fm_pcd_ext.h"
//enable prints from FMD
//#define FM_CC_DEBUG 		1

// Host-command MURAM prints are opt-in via this dir's Makefile: set the
// FMAN_DEBUG env to '-DFM_CC_MURAM_DEBUG=1'. Not hard-enabled here.
//table descriptor structure
struct generic_5_off_ic_gmask {
	union {
		struct {
			uint32_t cc_adbase:24;
			uint32_t key_length:6;
			uint32_t type:2;
		}__attribute__((packed));
		uint32_t word_0;
	};
	union {
		struct {
			uint32_t match_table_ptr:23;
			uint32_t LM:1;
			uint32_t match_table_entries_num:8;	
		}__attribute__((packed));
		uint32_t word_1;
	};
	union {	
		struct {
			uint32_t op_code:8;
			uint32_t reserved:8;
			uint32_t offset:8;
			uint32_t offset_from_parse_result:8;
		}__attribute__((packed));
		uint32_t word_2;
	};
	uint32_t age_mask;
}__attribute__((packed));

//new class result descriptor structure
struct new_class_res_desc {
	union {
		uint32_t word_0;
		struct {
			uint32_t fqid:24;
			uint32_t rspid:6;
			uint32_t type:2;
		}__attribute__((packed));
	};
	union {
		uint32_t word_1;
		struct {
			uint32_t next_ad_index:16;	
			uint32_t policer_profile:8;	
			uint32_t vspe:1;	
			uint32_t resv:1;	
			uint32_t nenq:1;	
			uint32_t cwd:1;	
			uint32_t nl:1;	
			uint32_t fwd:1;	
			uint32_t ebad:1;	
			uint32_t ebd:1;	

		}__attribute__((packed));
	};
	union {
		uint32_t word_2;
		struct {
			uint32_t fpm_nia:24;
			uint32_t ovom:1;
			uint32_t no_cspen:1;
			uint32_t resv_2:1;
			uint32_t fr:1;
			uint32_t resv_1:1;
			uint32_t naden:1;
			uint32_t stats_en:1;
			uint32_t extended_mode:1;
		}__attribute__((packed));
	};
	uint32_t word_3;
};

//statistics table descriptor structure
struct stats_table_desc {
	union {
		uint32_t word_0;
		struct {
			uint32_t stats_prof_tbl_addr:24;
			uint32_t reserved:8;
			uint32_t type:2;
		}__attribute__((packed));
	};
	uint32_t word_1;
	union {
		uint32_t word_2;
		struct {
			uint32_t opcode:8;
			uint32_t reserved_1:5;
			uint32_t cond_en:1;
			uint32_t flr_en:1;
			uint32_t nad_en:1;
			uint32_t next_ad_index:16;
		}__attribute__((packed));
	};
	union {
		uint32_t word_3;
		struct {
			uint32_t stats_tbl_addr:24;
			uint32_t reserved_2:8;
		}__attribute__((packed));
	};
};

//keep classification results descriptor structure
struct keep_class_res_desc_ad {
	union {
		struct {
			uint32_t reserved_1:29;
			uint32_t PD:1;
			uint32_t type:2;
		}__attribute__((packed));
		uint32_t word_0;
	};
	union {
		struct {
			uint32_t next_action_desc_index:16;
			uint32_t reserved_2:16;
		}__attribute__((packed));
		uint32_t word_1;
	};
	union {
		struct {
			uint32_t fpm_nia:24;
			uint32_t reserved_3:1;
			uint32_t no_vspe:1;
			uint32_t reserved_4:3;
			uint32_t naden:1;
			uint32_t statistics_enable:1;
			uint32_t extended_mode:1;
		}__attribute__((packed));
		uint32_t word_2;
	};
	uint32_t statistic_counter;
};

//header modification table desc
struct hmt_desc {
	union {
		struct {
			uint32_t reserved_2:21;
			uint32_t naden:1;
			uint32_t pahm:1;
			uint32_t reserved_1:7;
			uint32_t type:2;
		}__attribute__((packed));
		uint32_t word_0;
	};
	union {
		struct {
			uint32_t internal_hmt_ptr:24;
			uint32_t reserved_3:8;
		}__attribute__((packed));
		uint32_t word_1;
	};
	union {
		struct {
			uint32_t opcode:8;
			uint32_t reserved_4:8;
			uint32_t nextdescindex:16;
		}__attribute__((packed));
		uint32_t word_2;
	};
	uint32_t word_3;
};

//header removal header manipulation command
struct hdr_removal_hmc {
	union {
		uint32_t word;
		struct {
			uint32_t hdrrmvoffset:8;
			uint32_t hdrrmvsize:8;
			uint32_t reserved:7;
			uint32_t last:1;
			uint32_t opcode:8;
		}__attribute__((packed));
	};
};

//header insert header manipulation command
struct hdr_insert_hmc {
	union {
		uint32_t word;
		struct {
			uint32_t hdrinsoffset:8;
			uint32_t hdrinssize:8;
			uint32_t reserved:7;
			uint32_t last:1;
			uint32_t opcode:8;
		}__attribute__((packed));
	};
};

//header replace header manipulation command
#define hdr_replace_hmc hdr_insert_hmc

//internal header insert header manipulation command
struct internal_hdr_insert_hmc {
	union {
		uint32_t word_0;
		struct {
			uint32_t hdrinsoffset:8;
			uint32_t hdrinssize:8;
			uint32_t reserved:7;
			uint32_t last:1;
			uint32_t opcode:8;
		}__attribute__((packed));
	};
	union {
		uint32_t word_1;
		struct {
			uint32_t hdrinsptr:24;
			uint32_t reserved_1:8;
		}__attribute__((packed));
	};
};
//internal header replace header manipulation command
#define internal_hdr_replace_hmc internal_hdr_insert_hmc

//protocol specific header removal header manipulation command
struct proto_specific_hdr_removal_hmc {
	union {
                uint32_t word;
                struct {
                        uint32_t reserved_1:16;
                        uint32_t protospec_hdr_rmv_mode:4;
                        uint32_t reserved:3;
                        uint32_t last:1;
                        uint32_t opcode:8;
                }__attribute__((packed));
        };
};

//protocol specific header insert header manipulation command
struct proto_specific_hdr_insert_hmc {
        union {
                uint32_t word_0;
                struct {
                        uint32_t reserved_1:16;
                        uint32_t protospec_hdr_ins_mode:4;
                        uint32_t reserved:3;
                        uint32_t last:1;
                        uint32_t opcode:8;
                }__attribute__((packed));
        };
        union {
                uint32_t word_1;
                struct {
                        uint32_t inthdrptr:24;
                        uint32_t hdrinssize:8;
                }__attribute__((packed));
        };


};

//vlan priority update header manipulation command
struct vlan_priority_update_hmc {
        union {
                uint32_t word_0;
	        struct {
                        uint32_t vpri_def_value:3;
                        uint32_t reserved_1:13;
                        uint32_t vprihdr_rep_mode:3;
                        uint32_t reserved:4;
                        uint32_t last:1;
                        uint32_t opcode:8;
                }__attribute__((packed));
        };
        union {
                uint32_t word_1;
	        struct {
			uint32_t int_hdr_rep_ptr:24;
			uint32_t reserved_2:8;
                }__attribute__((packed));
        };
};

//local ipv4 update header manipulation command
struct local_ipv4_update_hmc {
        union {
                uint32_t word;
                struct {
                        uint32_t ip_ttl:1;
                        uint32_t ip_tos_mode:2;
                        uint32_t reserved_1:2;
                        uint32_t ip_dst:1;
                        uint32_t ip_src:1;
                        uint32_t ip_id_mode:1;
                        uint32_t ip_tos:8;
                        uint32_t reserved:7;
                        uint32_t last:1;
                        uint32_t opcode:8;
                }__attribute__((packed));
        };
};


//local tcp udp update header manipulation command
struct local_tcp_udp_update_hmc {
        union {
                uint32_t word_0;
                struct {
                        uint32_t reserved:14;
                        uint32_t tcp_udp_dst:1;
                        uint32_t tcp_udp_src:1;
                        uint32_t reserved_1:7;
                        uint32_t last:1;
                        uint32_t opcode:8;
                }__attribute__((packed));
        };
        union {
                uint32_t word_1;
		struct {
			uint32_t dst_port:16;
			uint32_t src_port:16;
		}__attribute__((packed));
	};
};


//ipv6 header update header manipulation command
struct ipv6_update_hmc {
	union {
		uint32_t word;
		struct {
			int32_t ip_hop_limit:1;
			uint32_t ip_traffic_class_mode:2;
			uint32_t reserved_1:3;
			uint32_t ipdst:1;
			uint32_t ipsrc:1;
			uint32_t iptraffic_class:8;
			uint32_t reserved:7;
			uint32_t last:1;
			uint32_t opcode:8;
		}__attribute__((packed));;
	};
};

//internal ipheader replace header manipulation command
struct internal_iphdr_replace_hmc {
	union {
		uint32_t word_0;
		struct {
			uint32_t reserved:16;
			uint32_t inl3smode:2;
			uint32_t reserved_1:3;
			int32_t ttl_hop_limit:1;
			uint32_t ipid_mode:1;
			uint32_t last:1;
			uint32_t opcode:8;
		}__attribute__((packed));
	};
	union {
		uint32_t word_1;
		struct {
			uint32_t l3hdr_ptr:24;
			uint32_t l3hdr_ins_size:8;
		}__attribute__((packed));;
	};
	union {
		uint32_t word_2;
		struct {
			uint32_t id_hdr_ptr:24;
			uint32_t reserved_2:8;
		}__attribute__((packed));
	};
};

extern void *FmMurambaseAddr;
void display_cc_node(void *handle, const char *func_name);

static inline uint32_t swap_word(uint32_t *ptr)
{
	uint32_t val;
	val =  ((*ptr >> 24) | (*ptr << 24) | 
			((*ptr >> 8) & 0x0000ff00) |
			((*ptr << 8) & 0xff0000));
	return val;
}

#define display_cc_node(x, y)
#define disp_ht_params(x)


#define display_pcd_cc_hc(x, y, z);

