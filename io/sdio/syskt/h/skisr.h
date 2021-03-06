/**
 *
 * Name:	skisr.h
 * Project:	Wireless LAN, Bus driver for SDIO interface
 * Version:	$Revision: 1.1 $
 * Date:	$Date: 2007/01/18 09:26:19 $
 * Purpose:	This module handles the interrupts.
 *
 *
 * Copyright (C) 2003-2009, Marvell International Ltd.
 *
 * This software file (the "File") is distributed by Marvell International 
 * Ltd. under the terms of the GNU General Public License Version 2, June 1991 
 * (the "License").  You may use, redistribute and/or modify this File in 
 * accordance with the terms and conditions of the License, a copy of which 
 * is available by writing to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA or on the
 * worldwide web at http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.
 *
 * THE FILE IS DISTRIBUTED AS-IS, WITHOUT WARRANTY OF ANY KIND, AND THE 
 * IMPLIED WARRANTIES OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE 
 * ARE EXPRESSLY DISCLAIMED.  The License provides additional details about 
 * this warranty disclaimer.
 *
 */

/******************************************************************************
 *
 * History:
 *
 *	$Log: skisr.h,v $
 *	Revision 1.1  2007/01/18 09:26:19  pweber
 *	Put under CVS control
 *	
 *	
 ******************************************************************************/

void SDIOBus_Dpc(unsigned long arg);

irqreturn_t SDIOBus_Isr(int irq, void *dev_id, struct pt_regs *regs);
