#ifndef __MODEM_H__
#define __MODEM_H__

#include "global.h"

/* GC Modem registers */
#define MODEM_IRQ_MASK      0x01
#define MODEM_IRQ_REASON    0x02
#define MODEM_HAYES_CMD     0x03
#define MODEM_HAYES_PENDING 0x04
#define MODEM_HAYES_RESP    0x05
#define MODEM_SERIAL_IO     0x08
#define MODEM_SEND_LEN_HI   0x09
#define MODEM_SEND_LEN_LO   0x0A
#define MODEM_RECV_LEN_HI   0x0B
#define MODEM_RECV_LEN_LO   0x0C

/* IRQ Reasons */
#define MODEM_IRQ_CONN      0x02
#define MODEM_IRQ_RECV      0x20

int modem_init(void);
int modem_shutdown(void);

int modem_write_cmd(u32 data, int len);
int modem_cmd_len(void);

int modem_read_resp(u32 addr, int len);
int modem_resp_len(void);

void modem_write_reg(u8 regnum, u8 value);
u8 modem_read_reg(u8 regnum);

void modem_reset_serial(void);
int modem_write_serial(u32 data, int len, int total);
int modem_poll(void);
int modem_read_serial(u32 addr, int len);

#endif /* !__MODEM_H__ */
