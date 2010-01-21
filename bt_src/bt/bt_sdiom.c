/** @file bt_sdiom.c
 *  @brief This file contains SDIO IF (interface) module
 *  related functions.
 * 
 * Copyright (C) 2007-2008, Marvell International Ltd.
 *
 * This software file (the "File") is distributed by Marvell International 
 * Ltd. under the terms of the GNU General Public License Version 2, June 1991 
 * (the "License").  You may use, redistribute and/or modify this File in 
 * accordance with the terms and conditions of the License, a copy of which 
 * is available along with the File in the gpl.txt file or by writing to 
 * the Free Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 
 * 02111-1307 or on the worldwide web at http://www.gnu.org/licenses/gpl.txt.
 *
 * THE FILE IS DISTRIBUTED AS-IS, WITHOUT WARRANTY OF ANY KIND, AND THE 
 * IMPLIED WARRANTIES OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE 
 * ARE EXPRESSLY DISCLAIMED.  The License provides additional details about 
 * this warranty disclaimer.
 *
 */

#include "include.h"

/** define marvell vendor id */
#define MARVELL_VENDOR_ID 0x02df

/** Max retry number of CMD53 write */
#define MAX_WRITE_IOMEM_RETRY	2
/** Firmware name */
char *fw_name = NULL;
/** Default firmware name */
#define DEFAULT_FW_NAME "mrvl/sd8787.bin"

/** Device ID for SD8787 */
#define SD_DEVICE_ID_8787   0x911A

static sd_device_id bt_ids[] = {
    {MARVELL_VENDOR_ID, SD_DEVICE_ID_8787, SD_CLASS_ANY, FN2},
    {}
};

/********************************************************
		Global Variables
********************************************************/

/** 
 *  @brief This function get rx_unit value
 *  
 *  @param priv    A pointer to bt_private structure
 *  @return 	   BT_STATUS_SUCCESS or BT_STATUS_FAILURE
 */
int
sd_get_rx_unit(bt_private * priv)
{
    int ret = BT_STATUS_SUCCESS;
    u8 reg;
    ENTER();
    ret =
        sdio_read_ioreg(priv->bt_dev.card, priv->bt_dev.fn, CARD_RX_UNIT_REG,
                        &reg);
    if (ret == BT_STATUS_SUCCESS)
        priv->bt_dev.rx_unit = reg;
    LEAVE();
    return ret;
}

/** 
 *  @brief This function reads fwstatus registers
 *  
 *  @param priv    A pointer to bt_private structure
 *  @param dat	   A pointer to keep returned data
 *  @return 	   BT_STATUS_SUCCESS or BT_STATUS_FAILURE
 */
static int
sd_read_firmware_status(bt_private * priv, u16 * dat)
{
    int ret = BT_STATUS_SUCCESS;
    u8 fws0;
    u8 fws1;
    ENTER();
    ret =
        sdio_read_ioreg(priv->bt_dev.card, priv->bt_dev.fn, CARD_FW_STATUS0_REG,
                        &fws0);

    if (ret < 0)
        return BT_STATUS_FAILURE;

    ret =
        sdio_read_ioreg(priv->bt_dev.card, priv->bt_dev.fn, CARD_FW_STATUS1_REG,
                        &fws1);
    if (ret < 0)
        return BT_STATUS_FAILURE;

    *dat = (((u16) fws1) << 8) | fws0;

    LEAVE();
    return BT_STATUS_SUCCESS;
}

/** 
 *  @brief This function reads rx length
 *  
 *  @param priv    A pointer to bt_private structure
 *  @param dat	   A pointer to keep returned data
 *  @return 	   BT_STATUS_SUCCESS or BT_STATUS_FAILURE
 */
static int
sd_read_rx_len(bt_private * priv, u16 * dat)
{
    int ret = BT_STATUS_SUCCESS;
    u8 reg;
    ret =
        sdio_read_ioreg(priv->bt_dev.card, priv->bt_dev.fn, CARD_RX_LEN_REG,
                        &reg);
    if (ret == BT_STATUS_SUCCESS)
        *dat = (u16) reg << priv->bt_dev.rx_unit;

    return ret;
}

/** 
 *  @brief This function polls the card status register.
 *  
 *  @param priv    	A pointer to bt_private structure
 *  @param fn   	function number
 *  @param bits    	the bit mask
 *  @return 	   	BT_STATUS_SUCCESS or BT_STATUS_FAILURE
 */
static int
sd_poll_card_status(bt_private * priv, u8 fn, u8 bits)
{
    int tries;
    int rval;
    u8 cs;
    ENTER();

    for (tries = 0; tries < MAX_POLL_TRIES * 1000; tries++) {
        rval = sdio_read_ioreg(priv->bt_dev.card, fn, CARD_STATUS_REG, &cs);
        if (rval != 0)
            break;
        if (rval == 0 && (cs & bits) == bits) {
            LEAVE();
            return BT_STATUS_SUCCESS;
        }
        udelay(1);
    }
    PRINTM(WARN, "mv_sdio_poll_card_status: FAILED!:%d\n", rval);
    LEAVE();
    return BT_STATUS_FAILURE;
}

/** 
 *  @brief This function probe the card
 *  
 *  @param dev     A pointer to structure _sd_device
 *  @param id	   A pointer to structure sd_device_id	
 *  @return 	   BT_STATUS_SUCCESS or BT_STATUS_FAILURE
 */
int
sd_probe_card(struct _sd_device *dev, sd_device_id * id)
{
    int ret = BT_STATUS_SUCCESS;
    bt_private *priv = NULL;
    u8 bic;
    ENTER();
    PRINTM(INFO, "vendor=%x,fn=%d,device=%x,class=%d\n", id->vendor, id->fn,
           id->device, id->class);
    if ((id->vendor != bt_ids[0].vendor) || (id->fn != bt_ids[0].fn)) {
        PRINTM(ERROR, "Ignoring a non-Marvell SDIO card %x...\n", ret);
        ret = BT_STATUS_FAILURE;
        goto done;
    }
    PRINTM(INFO, "Marvell SDIO card detected!\n");
    dev->pCurrent_Ids = id;

    /* enable async interrupt mode */
    ret = sdio_read_ioreg(dev, FN0, BUS_INTERFACE_CONTROL_REG, &bic);
    if (ret < 0) {
        ret = BT_STATUS_FAILURE;
        goto done;
    }
    bic |= ASYNC_INT_MODE;
    ret = sdio_write_ioreg(dev, FN0, BUS_INTERFACE_CONTROL_REG, bic);
    if (ret < 0) {
        ret = BT_STATUS_FAILURE;
        goto done;
    }
    priv = bt_add_card(dev);
    dev->priv = priv;
    if (!priv)
        ret = BT_STATUS_FAILURE;
  done:
    LEAVE();
    return ret;
}

/** 
 *  @brief This function checks if the firmware is ready to accept
 *  command or not.
 *  
 *  @param priv    A pointer to bt_private structure
 *  @param pollnum  number of times to polling fw status 
 *  @return 	   BT_STATUS_SUCCESS or BT_STATUS_FAILURE
 */
int
sd_verify_fw_download(bt_private * priv, int pollnum)
{
    int ret = BT_STATUS_SUCCESS;
    u16 firmwarestat;
    int tries;

    ENTER();
    /* Wait for firmware initialization event */
    for (tries = 0; tries < pollnum; tries++) {
        if (sd_read_firmware_status(priv, &firmwarestat) < 0)
            continue;
        if (firmwarestat == FIRMWARE_READY) {
            ret = BT_STATUS_SUCCESS;
            break;
        } else {
            mdelay(10);
            ret = BT_STATUS_FAILURE;
        }
    }
    if (ret < 0)
        goto done;

    ret = BT_STATUS_SUCCESS;
  done:
    LEAVE();
    return ret;
}

/** 
 *  @brief This function downloads firmware image to the card.
 *  
 *  @param priv    	A pointer to bt_private structure
 *  @param fn 		function number
 *  @param ioport	ioport for cmd53
 *  @return 	   	BT_STATUS_SUCCESS or BT_STATUS_FAILURE
 */
int
sd_download_firmware_w_helper(bt_private * priv, u8 fn, u32 ioport)
{
    const struct firmware *fw_firmware = NULL;
    u8 *firmware = NULL;
    int firmwarelen;
    u8 base0;
    u8 base1;
    int ret = BT_STATUS_SUCCESS;
    int offset;
    void *tmpfwbuf = NULL;
    int tmpfwbufsz;
    u8 *fwbuf;
    u16 len;
    int txlen = 0;
    int tx_blocks = 0;
    int i = 0;
    int tries = 0;
#ifdef FW_DOWNLOAD_SPEED
    u32 tv1, tv2;
#endif

    ENTER();
    if ((ret =
         request_firmware(&fw_firmware, fw_name, priv->hotplug_device)) < 0) {
        PRINTM(FATAL, "request_firmware() failed, error code = %#x\n", ret);
        goto done;
    }

    if (fw_firmware) {
        firmware = (u8 *) fw_firmware->data;
        firmwarelen = fw_firmware->size;
    } else {
        PRINTM(MSG, "No firmware image found! Terminating download\n");
        ret = BT_STATUS_FAILURE;
        goto done;
    }

    PRINTM(INFO, "Downloading FW image (%d bytes)\n", firmwarelen);

#ifdef FW_DOWNLOAD_SPEED
    tv1 = get_utimeofday();
#endif

    tmpfwbufsz = BT_UPLD_SIZE;
    tmpfwbuf = kmalloc(tmpfwbufsz, GFP_KERNEL);
    if (!tmpfwbuf) {
        PRINTM(ERROR,
               "Unable to allocate buffer for firmware. Terminating download\n");
        ret = BT_STATUS_FAILURE;
        goto done;
    }
    memset(tmpfwbuf, 0, tmpfwbufsz);

    fwbuf = (u8 *) tmpfwbuf;

    /* Perform firmware data transfer */
    offset = 0;
    do {
        /* The host polls for the DN_LD_CARD_RDY and CARD_IO_READY bits */
        ret = sd_poll_card_status(priv, fn, CARD_IO_READY | DN_LD_CARD_RDY);
        if (ret < 0) {
            PRINTM(FATAL, "FW download with helper poll status timeout @ %d\n",
                   offset);
            goto done;
        }

        /* More data? */
        if (offset >= firmwarelen)
            break;

        for (tries = 0; tries < MAX_POLL_TRIES; tries++) {
            if ((ret = sdio_read_ioreg(priv->bt_dev.card, fn,
                                       SQ_READ_BASE_ADDRESS_A0_REG,
                                       &base0)) < 0) {
                PRINTM(WARN,
                       "Dev BASE0 register read failed:"
                       " base0=0x%04X(%d). Terminating download\n", base0,
                       base0);
                ret = BT_STATUS_FAILURE;
                goto done;
            }
            if ((ret = sdio_read_ioreg(priv->bt_dev.card, fn,
                                       SQ_READ_BASE_ADDRESS_A1_REG,
                                       &base1)) < 0) {
                PRINTM(WARN,
                       "Dev BASE1 register read failed:"
                       " base1=0x%04X(%d). Terminating download\n", base1,
                       base1);
                ret = BT_STATUS_FAILURE;
                goto done;
            }
            len = (((u16) base1) << 8) | base0;

            if (len != 0)
                break;
            udelay(10);
        }

        if (len == 0)
            break;
        else if (len > BT_UPLD_SIZE) {
            PRINTM(FATAL, "FW download failure @ %d, invalid length %d\n",
                   offset, len);
            ret = BT_STATUS_FAILURE;
            goto done;
        }

        txlen = len;

        if (len & BIT(0)) {
            i++;
            if (i > MAX_WRITE_IOMEM_RETRY) {
                PRINTM(FATAL,
                       "FW download failure @ %d, over max retry count\n",
                       offset);
                ret = BT_STATUS_FAILURE;
                goto done;
            }
            PRINTM(ERROR, "FW CRC error indicated by the helper:"
                   " len = 0x%04X, txlen = %d\n", len, txlen);
            len &= ~BIT(0);
            /* Setting this to 0 to resend from same offset */
            txlen = 0;
        } else {
            i = 0;

            /* Set blocksize to transfer - checking for last block */
            if (firmwarelen - offset < txlen) {
                txlen = firmwarelen - offset;
            }
            PRINTM(INFO, ".");

            tx_blocks = (txlen + SD_BLOCK_SIZE_FW_DL - 1) / SD_BLOCK_SIZE_FW_DL;

            /* Copy payload to buffer */
            memcpy(fwbuf, &firmware[offset], txlen);
        }

        /* Send data */
        ret =
            sdio_write_iomem(priv->bt_dev.card, fn, ioport, BLOCK_MODE,
                             FIXED_ADDRESS, tx_blocks, SD_BLOCK_SIZE_FW_DL,
                             fwbuf);

        if (ret < 0) {
            PRINTM(ERROR, "FW download, write iomem (%d) failed @ %d\n", i,
                   offset);
            if (sdio_write_ioreg(priv->bt_dev.card, fn, CONFIGURATION_REG, 0x04)
                < 0) {
                PRINTM(ERROR, "write ioreg failed (func = %d CFG)\n", fn);
            }
        }

        offset += txlen;
    } while (TRUE);

    PRINTM(INFO, "\nFW download over, size %d bytes\n", offset);

    ret = BT_STATUS_SUCCESS;
  done:
#ifdef FW_DOWNLOAD_SPEED
    tv2 = get_utimeofday();
    PRINTM(INFO, "FW: %ld.%03ld.%03ld ", tv1 / 1000000,
           (tv1 % 1000000) / 1000, tv1 % 1000);
    PRINTM(INFO, " -> %ld.%03ld.%03ld ", tv2 / 1000000,
           (tv2 % 1000000) / 1000, tv2 % 1000);
    tv2 -= tv1;
    PRINTM(INFO, " == %ld.%03ld.%03ld\n", tv2 / 1000000,
           (tv2 % 1000000) / 1000, tv2 % 1000);
#endif
    if (tmpfwbuf)
        kfree(tmpfwbuf);
    if (fw_firmware)
        release_firmware(fw_firmware);
    LEAVE();
    return ret;
}

/** 
 *  @brief This function reads data from the card.
 *  
 *  @param priv    	A pointer to bt_private structure
 *  @return 	   	BT_STATUS_SUCCESS or BT_STATUS_FAILURE
 */
static int
sd_card_to_host(bt_private * priv)
{
    int ret = BT_STATUS_SUCCESS;
    u16 buf_len = 0;
    int buf_block_len;
    int blksz;
    struct sk_buff *skb = NULL;
    u32 type;
    u8 *payload = NULL;
    struct hci_dev *hdev = priv->bt_dev.hcidev;

    ENTER();
    /* Read the length of data to be transferred */
    ret = sd_read_rx_len(priv, &buf_len);
    if (ret < 0) {
        PRINTM(ERROR, "card_to_host, read scratch reg failed\n");
        ret = BT_STATUS_FAILURE;
        goto exit;
    }

    /* Allocate buffer */
    blksz = SD_BLOCK_SIZE;
    buf_block_len = (buf_len + blksz - 1) / blksz;
    if (buf_len <= BT_HEADER_LEN || (buf_block_len * blksz) > ALLOC_BUF_SIZE) {
        PRINTM(ERROR, "card_to_host, invalid packet length: %d\n", buf_len);
        ret = BT_STATUS_FAILURE;
        goto exit;
    }
    skb = bt_skb_alloc(buf_block_len * blksz, GFP_ATOMIC);
    if (skb == NULL) {
        PRINTM(WARN, "No free skb\n");
        goto exit;
    }
    payload = skb->tail;
    ret =
        sdio_read_iomem(priv->bt_dev.card, priv->bt_dev.fn, priv->bt_dev.ioport,
                        BLOCK_MODE, FIXED_ADDRESS, buf_block_len, blksz,
                        payload);
    if (ret < 0) {
        PRINTM(ERROR, "card_to_host, read iomem failed: %d\n", ret);
        ret = BT_STATUS_FAILURE;
        goto exit;
    }
    DBG_HEXDUMP(DBG_DATA, "SDIO Blk Rd", payload, blksz * buf_block_len);
    /* This is SDIO specific header length: byte[2][1][0], type: byte[3]
       (HCI_COMMAND = 1, ACL_DATA = 2, SCO_DATA = 3, 0xFE = Vendor) */
    buf_len = payload[0];
    buf_len |= (u16) payload[1] << 8;
    type = payload[3];
    switch (type) {
    case HCI_ACLDATA_PKT:
    case HCI_SCODATA_PKT:
    case HCI_EVENT_PKT:
        bt_cb(skb)->pkt_type = type;
        skb->dev = (void *) hdev;
        skb_put(skb, buf_len);
        skb_pull(skb, BT_HEADER_LEN);
        if (type == HCI_EVENT_PKT)
            check_evtpkt(priv, skb);
        hci_recv_frame(skb);
        hdev->stat.byte_rx += buf_len;
        break;
    case MRVL_VENDOR_PKT:
        bt_cb(skb)->pkt_type = HCI_VENDOR_PKT;
        skb->dev = (void *) hdev;
        skb_put(skb, buf_len);
        skb_pull(skb, BT_HEADER_LEN);
        if (BT_STATUS_SUCCESS != bt_process_event(priv, skb))
            hci_recv_frame(skb);
        hdev->stat.byte_rx += buf_len;
        break;
    default:
        /* Driver specified event and command resp should be handle here */
        PRINTM(INFO, "Unknown PKT type:%d\n", type);
        kfree_skb(skb);
        skb = NULL;
        break;
    }
  exit:
    if (ret) {
        hdev->stat.err_rx++;
        if (skb)
            kfree_skb(skb);
    }
    LEAVE();
    return ret;
}

#ifdef CONFIG_PM
/** 
 *  @brief This function handle the suspend function
 *  
 *  @param dev    A pointer to _sd_device structure
 *  @return	   BT_STATUS_SUCCESS
 */
int
sd_suspend(struct _sd_device *dev)
{
    struct hci_dev *hcidev;
    bt_private *priv = NULL;

    ENTER();
    priv = (bt_private *) dev->priv;
    if (!priv) {
        LEAVE();
        return BT_STATUS_SUCCESS;
    }
    if (priv->adapter->hs_state != HS_ACTIVATED) {
        if (BT_STATUS_SUCCESS != bt_enable_hs(priv)) {
            LEAVE();
            return BT_STATUS_FAILURE;
        }
    }
    hcidev = priv->bt_dev.hcidev;
    hci_suspend_dev(hcidev);
    skb_queue_purge(&priv->adapter->tx_queue);

    LEAVE();
    return BT_STATUS_SUCCESS;
}

/** 
 *  @brief This function handle the resume function
 *  
 *  @param dev    A pointer to _sd_device structure
 *  @return	  BT_STATUS_SUCCESS
 */
int
sd_resume(struct _sd_device *dev)
{
    struct hci_dev *hcidev;
    bt_private *priv = NULL;

    ENTER();
    priv = (bt_private *) dev->priv;
    if (!priv) {
        LEAVE();
        return BT_STATUS_SUCCESS;
    }
    hcidev = priv->bt_dev.hcidev;
    hci_resume_dev(hcidev);
    /* if (is_bt_the_wakeup_src()){ */
    {
        PRINTM(MSG, "WAKEUP SRC: BT\n");
        if ((priv->bt_dev.gpio_gap & 0x00ff) == 0xff) {
            sbi_wakeup_firmware(priv);
            priv->adapter->hs_state = HS_DEACTIVATED;
        }
    }

    LEAVE();
    return BT_STATUS_SUCCESS;
}
#endif

/** 
 *  @brief This function removes the card
 *  
 *  @param dev     A pointer to the device
 *  @return 	   BT_STATUS_SUCCESS or BT_STATUS_FAILURE
 */
int
sd_remove_card(struct _sd_device *dev)
{
    bt_private *priv = NULL;
    int ret = BT_STATUS_SUCCESS;

    ENTER();
    if (dev) {
        priv = (bt_private *) dev->priv;
        if (dev->dev == NULL) {
            PRINTM(INFO, "card removed from sd slot\n");
            if (priv)
                priv->adapter->SurpriseRemoved = TRUE;
        }
        ret = bt_remove_card(dev);
    }
    LEAVE();
    return ret;
}

/** 
 *  @brief This function handles the interrupt.
 *  
 *  @param dev 	   A pointer to device
 *  @param id      A pointer to device id
 *  @param context A pointer to context
 *  @return 	   n/a
 */
void
sd_interrupt(void *dev, sd_device_id * id, void *context)
{
    bt_private *priv = (bt_private *) context;
    struct hci_dev *hcidev = priv->bt_dev.hcidev;
    ENTER();
    bt_interrupt(hcidev);
    LEAVE();
}

/** 
 *  @brief This function checks if the interface is ready to download
 *  or not while other download interfaces are present
 *  
 *  @param priv   A pointer to bt_private structure
 *  @return       BT_STATUS_SUCCESS or BT_STATUS_FAILURE
 *                UPON BT_STATUS_SUCCESS the calling interface
 *                is winner
 */
int
sd_check_winner_status(bt_private * priv)
{

    int ret = BT_STATUS_SUCCESS;
    u8 winner_status = 0;
    psd_device cardp = (psd_device) priv->bt_dev.card;

    ENTER();

    if (BT_STATUS_SUCCESS !=
        sdio_read_ioreg(cardp, priv->bt_dev.fn, CARD_FW_STATUS0_REG,
                        &winner_status)) {
        LEAVE();
        return BT_STATUS_FAILURE;
    }

    if (winner_status != 0)
        ret = BT_STATUS_FAILURE;
    else
        ret = BT_STATUS_SUCCESS;

    LEAVE();
    return ret;
}

/********************************************************
		Global Functions
********************************************************/
static sd_driver sdio_bt = {
    .name = "sdio_bt",
    .ids = bt_ids,
    .probe = sd_probe_card,
    .remove = sd_remove_card,
#ifdef CONFIG_PM
    .suspend = sd_suspend,
    .resume = sd_resume,
#endif
};

/** ISR function */
sd_function bt_isr_fn = {
    .int_handler = sd_interrupt,
    .context = NULL
};

/** 
 *  @brief This function registers the bt module in bus driver.
 *  
 *  @return	   An int pointer that keeps returned value
 */
int *
sbi_register(void)
{
    int *ret;
    ENTER();
    if (sd_driver_register(&sdio_bt) != 0) {
        PRINTM(FATAL, "SD Driver Registration Failed \n");
        return NULL;
    } else
        ret = (int *) 1;
    LEAVE();
    return ret;
}

/** 
 *  @brief This function de-registers the bt module in bus driver.
 *  
 *  @return 	   n/a
 */
void
sbi_unregister(void)
{
    ENTER();
    if (sd_driver_unregister(&sdio_bt) != 0) {
        PRINTM(FATAL, "SD Driver unregister Failed \n");
    }
    LEAVE();
}

/** 
 *  @brief This function registers the device.
 *  
 *  @param priv    A pointer to bt_private structure
 *  @return 	   BT_STATUS_SUCCESS or BT_STATUS_FAILURE
 */
int
sbi_register_dev(bt_private * priv)
{
    int ret = BT_STATUS_SUCCESS;
    u8 reg;
    psd_device card = (psd_device) priv->bt_dev.card;

    ENTER();
    priv->hotplug_device = card->dev;
    if (fw_name == NULL)
        fw_name = DEFAULT_FW_NAME;

    /* Initialize the private structure */
    strncpy(priv->bt_dev.name, "bt_sdio0", sizeof(priv->bt_dev.name));
    priv->bt_dev.ioport = 0;
    priv->bt_dev.fn = card->pCurrent_Ids->fn;

    if (sdio_read_ioreg
        (card, priv->bt_dev.fn, CARD_REVISION_REG, &card->chiprev) < 0) {
        PRINTM(FATAL, "cannot read CARD_REVISION_REG\n");
        goto failed;
    } else {
        PRINTM(INFO, "revsion=0x%x\n", card->chiprev);
    }

    /* Read the IO port */
    ret = sdio_read_ioreg(card, priv->bt_dev.fn, IO_PORT_0_REG, &reg);
    if (ret < 0)
        goto failed;
    else
        priv->bt_dev.ioport |= reg;

    ret = sdio_read_ioreg(card, priv->bt_dev.fn, IO_PORT_1_REG, &reg);
    if (ret < 0)
        goto failed;
    else
        priv->bt_dev.ioport |= (reg << 8);

    ret = sdio_read_ioreg(card, priv->bt_dev.fn, IO_PORT_2_REG, &reg);
    if (ret < 0)
        goto failed;
    else
        priv->bt_dev.ioport |= (reg << 16);

    PRINTM(INFO, "SDIO FUNC%d IO port: 0x%x\n", priv->bt_dev.fn,
           priv->bt_dev.ioport);

    /* Disable host interrupt first. */
    if ((ret = sbi_disable_host_int(priv)) < 0) {
        PRINTM(WARN, "Warning: unable to disable host interrupt!\n");
    }

    /* Request the SDIO IRQ */
    PRINTM(INFO, "Before request_irq Address is if==>%p\n", sd_interrupt);
    bt_isr_fn.context = priv;
    if (sd_request_int(priv->bt_dev.card, card->pCurrent_Ids, &bt_isr_fn)) {
        PRINTM(FATAL, "Failed to request IRQ on SDIO bus\n");
        goto failed;
    }
    priv->adapter->chip_rev = card->chiprev;
    LEAVE();
    return BT_STATUS_SUCCESS;
  failed:
    priv->bt_dev.card = NULL;
    LEAVE();
    return BT_STATUS_FAILURE;
}

/** 
 *  @brief This function de-registers the device.
 *  
 *  @param priv    A pointer to  bt_private structure
 *  @return 	   BT_STATUS_SUCCESS
 */
int
sbi_unregister_dev(bt_private * priv)
{
    psd_device card;
    ENTER();
    if (priv->bt_dev.card != NULL) {
        card = (psd_device) priv->bt_dev.card;
        /* Release the SDIO IRQ */
        sd_release_int(priv->bt_dev.card, card->pCurrent_Ids);
        PRINTM(WARN, "Making the sdio dev card as NULL\n");
    }
    LEAVE();
    return BT_STATUS_SUCCESS;
}

/** 
 *  @brief This function enables the host interrupts.
 *  
 *  @param priv    A pointer to bt_private structure
 *  @return 	   BT_STATUS_SUCCESS or BT_STATUS_FAILURE
 */
int
sbi_enable_host_int(bt_private * priv)
{
    int ret;
    psd_device card = (psd_device) priv->bt_dev.card;

    ENTER();
    sd_get_rx_unit(priv);
    ret =
        sdio_write_ioreg(card, priv->bt_dev.fn, HOST_INT_MASK_REG, HIM_ENABLE);
    if (!ret)
        ret = sd_enable_int(card, card->pCurrent_Ids);
    LEAVE();
    return ret;
}

/** 
 *  @brief This function disables the host interrupts.
 *  
 *  @param priv    A pointer to bt_private structure
 *  @return 	   BT_STATUS_SUCCESS or BT_STATUS_FAILURE
 */
int
sbi_disable_host_int(bt_private * priv)
{
    int ret;
    psd_device card = (psd_device) priv->bt_dev.card;

    ENTER();
    ret =
        sdio_write_ioreg(card, priv->bt_dev.fn, HOST_INT_MASK_REG,
                         (u8) ~ HIM_DISABLE);
    if (!ret)
        ret = sd_disable_int(card, card->pCurrent_Ids);
    LEAVE();
    return ret;
}

/**  
 *  @brief This function sends data to the card.
 *  
 *  @param priv    A pointer to bt_private structure
 *  @param payload A pointer to the data/cmd buffer
 *  @param nb	   the length of data/cmd
 *  @return 	   BT_STATUS_SUCCESS or BT_STATUS_FAILURE
 */
int
sbi_host_to_card(bt_private * priv, u8 * payload, u16 nb)
{
    int ret = BT_STATUS_SUCCESS;
    int buf_block_len;
    int blksz;
    int i = 0;
    ENTER();

    /* Allocate buffer and copy payload */
    blksz = SD_BLOCK_SIZE;
    buf_block_len = (nb + blksz - 1) / blksz;
#define MAX_WRITE_IOMEM_RETRY	2
    do {
        /* Transfer data to card */
        ret =
            sdio_write_iomem(priv->bt_dev.card, priv->bt_dev.fn,
                             priv->bt_dev.ioport, BLOCK_MODE, FIXED_ADDRESS,
                             buf_block_len, blksz, payload);
        if (ret < 0) {
            i++;
            PRINTM(ERROR, "host_to_card, write iomem (%d) failed: %d\n", i,
                   ret);
            ret = BT_STATUS_FAILURE;
            if (i > MAX_WRITE_IOMEM_RETRY)
                goto exit;
        } else {
            DBG_HEXDUMP(DBG_DATA, "SDIO Blk Wr", payload, nb);
        }
    } while (ret == BT_STATUS_FAILURE);
    priv->bt_dev.tx_dnld_rdy = FALSE;
  exit:
    LEAVE();
    return ret;
}

/** 
 *  @brief This function initializes firmware
 *  
 *  @param priv    A pointer to bt_private structure
 *  @return 	   BT_STATUS_SUCCESS or BT_STATUS_FAILURE
 */
int
sbi_dowload_fw(bt_private * priv)
{
    int ret = BT_STATUS_SUCCESS;
    int poll_num = MAX_FIRMWARE_POLL_TRIES;

    ENTER();

    if (BT_STATUS_SUCCESS == sd_verify_fw_download(priv, 1)) {
        PRINTM(INFO, "Firmware already downloaded!\n");
        goto done;
    }
    /* Check if other interface is downloading */
    ret = sd_check_winner_status(priv);
    if (ret == BT_STATUS_FAILURE) {
        PRINTM(INFO, "winner interface already running! Skip FW download\n");
        poll_num = MAX_MULTI_INTERFACE_POLL_TRIES;
        goto poll_fw;
    }

    /* Download the main firmware via the helper firmware */
    if (sd_download_firmware_w_helper
        (priv, priv->bt_dev.fn, priv->bt_dev.ioport)) {
        PRINTM(INFO, "Bluetooth FW download failed!\n");
        ret = BT_STATUS_FAILURE;
        goto done;
    }
  poll_fw:
    /* check if the fimware is downloaded successfully or not */
    if (sd_verify_fw_download(priv, poll_num)) {
        PRINTM(INFO, "FW failed to be active in time!\n");
        ret = BT_STATUS_FAILURE;
        goto done;
    }
  done:
    LEAVE();
    return ret;
}

/** 
 *  @brief This function checks the interrupt status and handle it accordingly.
 *  
 *  @param priv    A pointer to bt_private structure
 *  @param ireg    A pointer to variable that keeps returned value
 *  @return 	   BT_STATUS_SUCCESS or BT_STATUS_FAILURE
 */
int
sbi_get_int_status(bt_private * priv, u8 * ireg)
{
    int ret = BT_STATUS_SUCCESS;
    u8 sdio_ireg = 0;
    psd_device card = (psd_device) priv->bt_dev.card;
    ENTER();
    *ireg = 0;
    if ((ret =
         sdio_read_ioreg(priv->bt_dev.card, priv->bt_dev.fn, HOST_INTSTATUS_REG,
                         &sdio_ireg))) {
        PRINTM(WARN, "sdio_read_ioreg: read int status register failed\n");
        ret = BT_STATUS_FAILURE;
        goto done;
    }
    if (sdio_ireg != 0) {
        /* 
         * DN_LD_HOST_INT_STATUS and/or UP_LD_HOST_INT_STATUS
         * Clear the interrupt status register and re-enable the interrupt
         */
        PRINTM(INFO, "sdio_ireg = 0x%x\n", sdio_ireg);
        priv->adapter->irq_recv = sdio_ireg;
        priv->adapter->irq_done = sdio_ireg;
        if ((ret =
             sdio_write_ioreg(priv->bt_dev.card, priv->bt_dev.fn,
                              HOST_INTSTATUS_REG,
                              ~(sdio_ireg) & (DN_LD_HOST_INT_STATUS |
                                              UP_LD_HOST_INT_STATUS))) < 0) {
            PRINTM(WARN,
                   "sdio_write_ioreg: clear int status register failed\n");
            ret = BT_STATUS_FAILURE;
            goto done;
        }
    }
    sd_unmask((sd_device *) priv->bt_dev.card, card->pCurrent_Ids);
    if (sdio_ireg & DN_LD_HOST_INT_STATUS) {    /* tx_done INT */
        if (priv->bt_dev.tx_dnld_rdy) { /* tx_done already received */
            PRINTM(INFO,
                   "warning: tx_done already received: tx_dnld_rdy=0x%x int status=0x%x\n",
                   priv->bt_dev.tx_dnld_rdy, sdio_ireg);
        } else {
            priv->bt_dev.tx_dnld_rdy = TRUE;
        }
    }
    if (sdio_ireg & UP_LD_HOST_INT_STATUS) {
        sd_card_to_host(priv);
    }
    *ireg = sdio_ireg;
    ret = BT_STATUS_SUCCESS;
  done:
    LEAVE();
    return ret;
}

/** 
 *  @brief This function wakeup firmware
 *  
 *  @param priv    A pointer to bt_private structure
 *  @return 	   BT_STATUS_SUCCESS or BT_STATUS_FAILURE
 */
int
sbi_wakeup_firmware(bt_private * priv)
{
    int ret = BT_STATUS_SUCCESS;
    ENTER();
    ret =
        sdio_write_ioreg(priv->bt_dev.card, priv->bt_dev.fn, CONFIGURATION_REG,
                         HOST_POWER_UP);
    PRINTM(CMD, "wake up firmware\n");
    LEAVE();
    return ret;
}

module_param(fw_name, charp, 0);
MODULE_PARM_DESC(fw_name, "Firmware name");
