/*
 *
 *  Copyright (C) 2007 Mindspeed Technologies, Inc.
 *  Copyright 2014-2016 Freescale Semiconductor, Inc.
 *  Copyright 2017,2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 *
 */

#ifdef WIFI_ENABLE
#include "cmm.h"
#include "itf.h"

//#include <net/if.h>
#include <linux/sockios.h>
//#include <linux/wireless.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <module_wifi.h>

//static unsigned char wifi_sysctl[128];	
#define SIOCVAPUPDATE (0x6401)
#define WIFI_FF_MASTER_IF "/dev/vwd0"

extern struct wifi_ff_entry glbl_wifi_ff_ifs[MAX_WIFI_FF_IFS];
void __cmmGetWiFi(int fd, struct interface *itf)
{
	int ii;
		
	itf->itf_flags &= ~ITF_WIFI;

	//if( ioctl(fd, SIOCGIWMODE, &pwrq) < 0 )
	//{
	//	return;
	//}

	for( ii = 0; ii < MAX_WIFI_FF_IFS; ii++ )
	{
		if ( glbl_wifi_ff_ifs[ii].used  )
			if( !strcmp(glbl_wifi_ff_ifs[ii].ifname, itf->ifname) )
			{
				cmm_print(DEBUG_INFO, "%s: wifi if is up %s \n", __func__, itf->ifname);
				cmm_print(DEBUG_INFO, "%s: mac:%s:%d %x:%x:%x:%x:%x:%x \n", __func__, 
					itf->ifname, itf->macaddr_len, itf->macaddr[0], itf->macaddr[1], 
					itf->macaddr[2],itf->macaddr[3],itf->macaddr[4],itf->macaddr[5]  );

				itf->itf_flags |= ITF_WIFI;
				itf->wifi_if = &glbl_wifi_ff_ifs[ii];
				memcpy(glbl_wifi_ff_ifs[ii].macaddr, itf->macaddr, 6);
			}
	}
	
	return;		
}

static int cmmResetVWD()
{
        vwd_cmd_t cmd;
	int sfd;

        memset(&cmd, 0, sizeof(cmd));
	sfd = open(WIFI_FF_MASTER_IF, O_RDONLY);

	if ( sfd <= 0 )
	{
		cmm_print(DEBUG_ERROR, "%s: failed to open vwd device: %s\n", __func__, strerror(errno));
		return -1;
	}

        cmd.action = FPP_VWD_VAP_RESET;

        if ( ioctl(sfd, SIOCVAPUPDATE, &cmd) < 0)
        {
		close(sfd);
		cmm_print(DEBUG_ERROR, "%s::%d: ioctl() %s\n", __func__, __LINE__, strerror(errno));
                return -1;
        }

	close(sfd);
        return 0;
}

static int cmmUpdateVWD(struct interface *itf, int req)
{
        vwd_cmd_t cmd;
       // struct ifreq ifr;
	int sfd;

        memset(&cmd, 0, sizeof(cmd));

	sfd = open(WIFI_FF_MASTER_IF, O_RDONLY);
	
	if ( sfd <= 0 )
	{
        	cmm_print(DEBUG_ERROR, "%s: failed to open vwd device: %s\n", __func__, strerror(errno));
		return -1;
	}

	cmd.action = req;
	cmd.ifindex = itf->ifindex;

	if (____itf_get_name(itf, cmd.ifname, sizeof(cmd.ifname)) < 0)
	{
		cmm_print(DEBUG_ERROR, "%s: ____itf_get_name(%d) failed\n", __func__, itf->ifindex);
		return -1;
	}

	memcpy( cmd.macaddr, itf->macaddr, 6);
	
	cmd.vap_id = itf->wifi_if->vapid;	
	cmd.direct_path_rx = itf->wifi_if->direct_path_rx;	
	cmd.no_l2_itf = itf->wifi_if->no_l2_itf;
	cmm_print(DEBUG_INFO, "%s: no_l2_itf: %d, mac:%s:%d %x:%x:%x:%x:%x:%x \n", __func__,
						cmd.no_l2_itf,
                                        itf->ifname, itf->ifindex, itf->macaddr[0], itf->macaddr[1],
                                       itf->macaddr[2],itf->macaddr[3],itf->macaddr[4],itf->macaddr[5]  );

        if ( ioctl(sfd, SIOCVAPUPDATE, &cmd) < 0)
        {
		close(sfd);
                cmm_print(DEBUG_ERROR, "%s::%d: ioctl() %s\n", __func__, __LINE__, strerror(errno));
                return -1;
        }

	close(sfd);
        return 0;
}


int cmmFeWiFiAddInterface(struct wifi_ff_entry *wifi_if, int vapid)
{
	vwd_cmd_t cmd;
	int sfd;

	memset(&cmd, 0, sizeof(cmd));
	sfd = open(WIFI_FF_MASTER_IF, O_RDONLY);

	if ( sfd <= 0 )
	{
		cmm_print(DEBUG_ERROR, "%s: failed to open vwd device: %s\n", __func__, strerror(errno));
		return -1;
	}
	cmm_print(DEBUG_INFO, "Send VAP %s configure\n", wifi_if->ifname);

	cmd.action = FPP_VWD_VAP_CONFIGURE;
	strcpy(cmd.ifname, wifi_if->ifname);
	cmd.vap_id = vapid;
	cmd.direct_path_rx = wifi_if->direct_path_rx;

	if ( ioctl(sfd, SIOCVAPUPDATE, &cmd) < 0)
	{
		close(sfd);
		cmm_print(DEBUG_ERROR, "%s::%d: ioctl() %s\n", __func__, __LINE__, strerror(errno));
		return -1;
	}

	close(sfd);

	return 0;

}

int cmmFeWiFiUpdate(FCI_CLIENT *fci_handle, int fd, int request, struct interface *itf)
{
	struct fpp_wifi_cmd cmd;
        short ret = 0;
        int action;

	memset(&cmd, 0, sizeof(cmd));
	switch (request)
	{
	default:
	case ADD:
		if ((itf->flags & (FPP_PROGRAMMED | FPP_NEEDS_UPDATE)) == FPP_PROGRAMMED)
			goto out;

		if ((itf->flags & (FPP_PROGRAMMED | FPP_NEEDS_UPDATE)) == (FPP_PROGRAMMED | FPP_NEEDS_UPDATE))
		{
			cmm_print(DEBUG_ERROR, "%s: trying to update wifi interface(%d)\n", __func__, itf->ifindex);
			ret = -1;
			goto out;
		}
		action = FPP_VWD_VAP_ADD;
		

		break;

	case UPDATE:
		if (!(itf->flags & FPP_PROGRAMMED))
		{
			cmm_print(DEBUG_ERROR, "%s: trying to update non FF iface(%s)\n", __func__, itf->ifname);
			goto out;
		}            

		action = FPP_VWD_VAP_UPDATE;

		break;

	case REMOVE:
		if (!(itf->flags & FPP_PROGRAMMED))
		{
			cmm_print( DEBUG_ERROR, "%s: Called remove, but not programmed\n", __func__);
			goto out;
		}

		action = FPP_VWD_VAP_REMOVE;
		
		break;
	}
	
	cmd.action = action;
	cmd.vap_id = itf->wifi_if->vapid;	
	cmd.wifi_guest_flag = itf->wifi_if->wifi_guest;
	
	if (____itf_get_name(itf, cmd.ifname, sizeof(cmd.ifname)) < 0)
	{
		cmm_print(DEBUG_ERROR, "%s: ____itf_get_name(%d) failed\n", __func__, itf->ifindex);

		goto out;
	}
        
	memcpy( cmd.mac_addr, itf->macaddr, 6);
	
        //cmm_print(DEBUG_ERROR, "%s: mac:%s:%d %x:%x:%x:%x:%x:%x \n", __func__,
        //                                cmd.ifname, cmd.vap_id,cmd.mac_addr[0], cmd.mac_addr[1],
        //                                cmd.mac_addr[2],cmd.mac_addr[3],cmd.mac_addr[4],cmd.mac_addr[5]  );
	//Send VAP entry command to FPP
	ret = fci_write(fci_handle, FPP_CMD_WIFI_VAP_ENTRY, 
				sizeof(fpp_wifi_cmd_t), &cmd); 

	if ( ret != FPP_ERR_OK )
	{	
		cmm_print(DEBUG_ERROR, "%s: Failed command FPP_CMD_WIFI_VAP_ENTRY, action:error %d:%d\n",
                         __func__, action, ret);
		goto out;
	}
	


	if( ! cmmUpdateVWD(itf, action) )
	{
		switch (action)
		{
			case FPP_VWD_VAP_UPDATE:
			case FPP_VWD_VAP_ADD:
				itf->flags |= FPP_PROGRAMMED;
				itf->flags &= ~FPP_NEEDS_UPDATE;
				break;

			case FPP_VWD_VAP_REMOVE:
				itf->flags &= ~FPP_PROGRAMMED;
				itf->flags &= ~FPP_NEEDS_UPDATE;
				break;
			
	
		}
	}
	else {
		/* FIXME : Roll back the changes in PPFE on VAP addition failed in VWD. This implementation is
		 *  with assumption that, REMOVE/UPDATE commands will never failed in VWD.
                 */
		if (cmd.action == FPP_VWD_VAP_ADD) {
			cmd.action = FPP_VWD_VAP_REMOVE;
			ret = fci_write(fci_handle, FPP_CMD_WIFI_VAP_ENTRY, 
				sizeof(fpp_wifi_cmd_t), &cmd); 
			if ( ret != FPP_ERR_OK )
			{	
				cmm_print(DEBUG_ERROR, "%s: %d Failed command FPP_CMD_WIFI_VAP_ENTRY, action:error %d:%d\n",
						__func__, __LINE__, action, ret);
				goto out;
			}

		}
	} 	

out:
	return ret;
	
}

	
/*****************************************************************
* cmmWiFiReset
* 
*
*
******************************************************************/
void cmmWiFiReset(FCI_CLIENT *fci_handle)
{
	struct list_head *entry;
	struct interface *itf;
	short ret;
	int i;

	// Send message to forward engine
	cmm_print(DEBUG_COMMAND, "Send CMD_WIFI_VAP_RESET\n");

	__pthread_mutex_lock(&itf_table.lock);

	ret = fci_write(fci_handle, FPP_CMD_WIFI_VAP_RESET, 0, NULL); 
	if (ret == FPP_ERR_OK)
	{
		if (!cmmResetVWD()) {
			/* Configure the WiFi interfaces agin*/
			for( i = 0; i < MAX_WIFI_FF_IFS; i++ )
			{
				cmm_print(DEBUG_INFO, "Configuring WiFi VAP\n");
				if (glbl_wifi_ff_ifs[i].used)
					if (cmmFeWiFiAddInterface(&glbl_wifi_ff_ifs[i], i))
						cmm_print(DEBUG_ERROR, "%s: Failed to configure VAP (%s)\n", __func__, glbl_wifi_ff_ifs[i].ifname);
			}

		}
		else
			cmm_print(DEBUG_ERROR, "%s: Failed to reset VAPs with VWD\n", __func__);


		for (i = 0; i < ITF_HASH_TABLE_SIZE; i++)
		{
			for (entry = list_first(&itf_table.hash[i]); entry != &itf_table.hash[i]; entry = list_next(entry))
			{
				itf = container_of(entry, struct interface, list);

				if (!__itf_is_wifi(itf))
					continue;

				itf->flags &= ~FPP_PROGRAMMED;
			}
		}
	}
	else
	{
		cmm_print(DEBUG_ERROR, "%s: Error %d while sending CMD_WIFI_VAP_RESET\n", __func__, ret);
	}

	__pthread_mutex_unlock(&itf_table.lock);
}

#endif //WIFI_ENABLE
