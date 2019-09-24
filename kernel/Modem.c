#include "Modem.h"
#include "vsprintf.h"
#include "debug.h"
#include "alloc.h"
#include "network.h"
#include "EXI.h"

/* Aught to be long enough... */
static char modem_cmd[0x80];
static char modem_resp[0x80];

static u8 regs[0x20];

static int modem_cmd_pos = 0;
static int modem_resp_pos = 0;
static int modem_resp_sz = 0;

static s32 sock = -1;
static int initted = 0;
static int connecting = 0;
static int connection_status = 0;

static u8 outbuf[1514];
static u8 inbuf[1514];
static int out_pos = 0;
static int in_pos = 0, read_in = 0;

#define CONN_CONNECTED      1
#define CONN_FAILED         2

static int _isdigit(char c) {
    return c >= '0' && c <= '9';
}

static u64 read_phonenumber(void) {
    char *pos = modem_cmd + 3;  /* Skip ATD */
    int p = 3;
    u64 rv = 0;

    if(*pos == 'T' || *pos == 'P') {
        ++pos;                  /* Skip T/P */
        ++p;
    }

    while(p < modem_cmd_pos) {
        if(*pos == '\0')
            return rv;
        else if(!_isdigit(*pos)) {
            return -1;
        }

        rv *= 10;
        rv += *pos - '0';
        ++pos;
        ++p;
    }

    return rv;
}

int modem_init(void) {
    if(net_init()) {
        dbgprintf("Failed to init network\n");
        return -1;
    }

    initted = 1;
    connection_status = 0;
    connecting = 0;
    sock = -1;

    dbgprintf("Initialized modem\n");
    return 0;
}

int modem_shutdown(void) {
    if(!initted)
        return 0;

    net_close(sock);
    net_deinit();
    initted = 0;
    connection_status = 0;

    return 0;
}

static void assert_irq(u8 lines) {
    regs[MODEM_IRQ_REASON] |= lines;

    if((regs[MODEM_IRQ_REASON] & regs[MODEM_IRQ_MASK])) {
        if(!(lines & MODEM_IRQ_RECV))
            EXIModemInterrupt();
        else
            EXIModemInterruptPktIn();
    }
}

static int modem_process_cmd(void) {
    u32 addr;
    u16 port;
    u64 pn;

    if(modem_cmd[0] != 'A' || modem_cmd[1] != 'T') {
        dbgprintf("Modem: Invalid command (doesn't start with AT)\n");
        strcpy(modem_resp + modem_resp_sz, "ERROR\r\n\r");
        modem_resp_sz += 8;
        modem_cmd[0] = '\0';
        modem_cmd_pos = 0;
        return 0;
    }

    /* Process the submitted command... */
    /* XXXX: Should we really assume only one command at a time? */
    switch(modem_cmd[2]) {
        case 'Z':   /* Reset Modem */
        case '+':   /* Settings we don't care about. */
        case 'E':   /* Echo on/off -- Hopefully it's always off. */
        case 'W':   /* More settings that we don't really care about... */
        case 'S':   /* Set modem registers, once again, don't care... */
            strcpy(modem_resp + modem_resp_sz, "OK");
            modem_resp_sz += 2;
            modem_cmd[0] = '\0';
            modem_cmd_pos = 0;
            connection_status = 0;
            break;

        case 'H':   /* Hang up */
            if(sock >= 0)
                net_close(sock);

            strcpy(modem_resp + modem_resp_sz, "OK");
            modem_resp_sz += 2;
            modem_cmd[0] = '\0';
            modem_cmd_pos = 0;
            connection_status = 0;
            assert_irq(MODEM_IRQ_CONN);
            return 0;

        case 'D':   /* Dial */
            /* Parse out the address first. */
            pn = read_phonenumber();
            if(pn == (u64)-1) {
                dbgprintf("Modem: Invalid phone number\n");
                strcpy(modem_resp + modem_resp_sz, "NO CARRIER\r\n");
                modem_resp_sz += 12;
                modem_cmd[0] = '\0';
                modem_cmd_pos = 0;
                connecting = 1;
                connection_status = CONN_FAILED;
                assert_irq(MODEM_IRQ_CONN);
                return 0;
            }

            addr = (u32)(pn >> 16);
            port = (u16)(pn);
            dbgprintf("Modem: Parsed phone number to: %08x:%d\n", addr,
                      (int)port);

            /* Create the socket. */
            if((sock = net_socket(PF_INET, SOCK_STREAM, 0)) < 0) {
                dbgprintf("Modem: Couldn't create socket (%d)\n", sock);
                strcpy(modem_resp + modem_resp_sz, "NO CARRIER\r\n");
                modem_resp_sz += 12;
                modem_cmd[0] = '\0';
                modem_cmd_pos = 0;
                connecting = 1;
                connection_status = CONN_FAILED;
                assert_irq(MODEM_IRQ_CONN);
                return 0;
            }

            /* Connect to the server. */
            struct sockaddr_in sa;
            sa.sin_family = AF_INET;
            sa.sin_addr.s_addr = htonl(addr);
            sa.sin_port = htons(port);
            s32 err = net_connect(sock, (struct sockaddr *)&sa,
                                  sizeof(struct sockaddr_in));
            if(err) {
                dbgprintf("Modem: Couldn't connect to server\n");
                net_close(sock);
                strcpy(modem_resp + modem_resp_sz, "NO CARRIER\r\n");
                modem_resp_sz += 12;
                modem_cmd[0] = '\0';
                modem_cmd_pos = 0;
                connecting = 1;
                connection_status = CONN_FAILED;
                assert_irq(MODEM_IRQ_CONN);
                return 0;
            }

            /* Set the socket to be non-blocking... */
            u32 flags = net_fcntl(sock, F_GETFL, 0);
            err = net_fcntl(sock, F_SETFL, flags | IOS_O_NONBLOCK);
            if(err < 0) {
                dbgprintf("Modem: Couldn't set socket to non-blocking mode\n");
                net_close(sock);
                strcpy(modem_resp + modem_resp_sz, "NO CARRIER\r\n");
                modem_resp_sz += 12;
                modem_cmd[0] = '\0';
                modem_cmd_pos = 0;
                connecting = 1;
                connection_status = CONN_FAILED;
                assert_irq(MODEM_IRQ_CONN);
                return 0;
            }

            dbgprintf("Modem: Connected to server!\n");
            strcpy(modem_resp + modem_resp_sz, "CONNECT 57600\r\n\r");
            modem_resp_sz += 16;
            modem_cmd[0] = '\0';
            modem_cmd_pos = 0;
            connecting = 1;
            connection_status = CONN_CONNECTED;
            assert_irq(MODEM_IRQ_CONN);
            return 0;
    }

    return 0;
}

void modem_write_reg(u8 regnum, u8 value) {
    if(regnum > 0x20) {
        dbgprintf("Modem: Ignoring write to unknown register: %d (%02x)\n",
                  regnum, value);
        return;
    }

    /* XXXX: Probably should protect against writing to read-only registers. */
    dbgprintf("Modem: Write %02x to register %d\n", value, regnum);
    regs[regnum] = value;

    /* Connecting from the start requires two IRQs. The first is probably to say
       that it's going from idle -> connecting, and the second from connecting
       to either connected or failed... This hack fixes that up so that we get
       both the requisite IRQs. */
    if(connecting && regnum == MODEM_IRQ_MASK && (value & 0x02)) {
        if(connection_status == CONN_CONNECTED) {
            strcpy(modem_resp + modem_resp_sz, "CONNECT 57600\r\n\r");
            modem_resp_sz += 16;
        }
        else {
            strcpy(modem_resp + modem_resp_sz, "NO CARRIER\r\n");
            modem_resp_sz += 12;
        }

        connecting = 0;
        regs[MODEM_IRQ_REASON] |= MODEM_IRQ_CONN;
        EXIModemInterrupt();
        return;
    }

    /* If we're setting the IRQ mask, see if we have any pending reasons to
       fire an IRQ, and if so, do it. */
    if(regnum == MODEM_IRQ_MASK && (value & regs[MODEM_IRQ_REASON])) {
        EXIModemInterrupt();
    }
}

u8 modem_read_reg(u8 regnum) {
    switch(regnum) {
        case MODEM_IRQ_REASON:
            /* Grab the IRQ reason, and clear the register before returning. */
            regnum = regs[MODEM_IRQ_REASON];
            regs[MODEM_IRQ_REASON] = 0;
            return regnum;

        case MODEM_HAYES_PENDING:
            return modem_cmd_len();
        case MODEM_HAYES_RESP:
            return modem_resp_len();

        case MODEM_SEND_LEN_HI:
            dbgprintf("outbuf hi: %d\n", out_pos);
            return (u8)(out_pos >> 8);
        case MODEM_SEND_LEN_LO:
            dbgprintf("outbuf lo: %d\n", out_pos);
            return (u8)out_pos;

        case MODEM_RECV_LEN_HI:
            dbgprintf("inbuf hi: %d\n", in_pos);
            return (u8)(in_pos >> 8);
        case MODEM_RECV_LEN_LO:
            dbgprintf("inbuf lo: %d\n", in_pos);
            return (u8)in_pos;

        default:
            return regs[regnum];
    }
}

int modem_write_cmd(u32 data, int len) {
    char *eoc;

    if(!initted)
        return -1;

    if(len + modem_cmd_pos >= 0x80) {
        dbgprintf("Modem: Command input overflow!");
        strcpy(modem_resp + modem_resp_sz, "ERROR\r\n\r");
        modem_resp_sz += 8;
        modem_cmd_pos = 0;
        modem_cmd[0] = '\0';
        return 0;
    }

    /* Copy over any bytes. */
    while(len) {
        modem_cmd[modem_cmd_pos++] = (char)((data >> 24) & 0xFF);
        --len;
        data <<= 8;
    }

    /* Did we copy over a carriage return character? */
    if((eoc = strchr(modem_cmd, '\r'))) {
        *eoc = '\0';
        dbgprintf("Modem: Input command: %s\n", modem_cmd);
        return modem_process_cmd();
    }

    return 0;
}

int modem_write_serial(u32 data, int len, int total) {
    if(connection_status != CONN_CONNECTED)
        return -1;

    if(total >= 1514)
        return -1;

    /* Copy over any bytes. */
    if(len <= 4) {
        /* Immediate mode */
        while(len) {
            outbuf[out_pos++] = (char)((data >> 24) & 0xFF);
            //++out_pos;
            --len;
            data <<= 8;
        }
    }
    else {
        /* DMA */
        sync_before_read((void *)data, len);
        memcpy(outbuf + out_pos, (void *)data, len);
        out_pos += len;
    }

    /* Do we have everything? */
    if(out_pos >= total) {
        dbgprintf("Modem: Sending frame of length %d\n", total);
        net_sendto(sock, outbuf, total, 0, NULL, 0);
        out_pos = 0;
        return 1;
    }

    return 0;
}

void modem_reset_serial(void) {
    out_pos = 0;
}

int modem_poll(void) {
    if(connection_status != CONN_CONNECTED)
        return 0;

    if(in_pos >= 1514)
        return -1;

    /* Poll the socket for any new data. */
    s32 sz = net_recvfrom(sock, inbuf + in_pos, 1514 - in_pos, 0, NULL, NULL);

    if(sz < 0)
        /* XXXX: This should usually be EAGAIN. If it's not, we should probably
           signal a connection error. */
        return 0;

    dbgprintf("Modem: Got %d bytes from socket\n", sz);
    in_pos += sz;

    /* Signal an IRQ saying that we got something... */
    assert_irq(MODEM_IRQ_RECV);

    return 0;
}

int modem_cmd_len(void) {
    return modem_cmd_pos;
}

int modem_read_resp(u32 addr, int len) {
    u32 resp;

    if(!initted)
        return -1;

    if(len == 1) {
        resp = modem_resp[modem_resp_pos++];
    }
    else if(len == 2) {
        resp = (modem_resp[modem_resp_pos] << 8) |
               (modem_resp[modem_resp_pos + 1]);
        modem_resp_pos += 2;
    }
    else if(len == 3) {
        resp = (modem_resp[modem_resp_pos] << 16) |
               (modem_resp[modem_resp_pos + 1] << 8) |
               (modem_resp[modem_resp_pos + 2]);
        modem_resp_pos += 3;
    }
    else if(len == 4) {
        resp = (modem_resp[modem_resp_pos] << 24) |
               (modem_resp[modem_resp_pos + 1] << 16) |
               (modem_resp[modem_resp_pos + 2] << 8) |
               (modem_resp[modem_resp_pos + 3]);
        modem_resp_pos += 4;
    }
    else {
        resp = 0;
    }

    write32(addr, resp);

    if(modem_resp_pos >= modem_resp_sz) {
        modem_resp_pos = modem_resp_sz = 0;
        modem_resp[0] = '\0';
    }

    return 0;
}

int modem_resp_len(void) {
    return modem_resp_sz - modem_resp_pos;
}

int modem_read_serial(u32 addr, int len) {
    u32 resp = 0;
    int rv = 0;

    if(!initted)
        return -1;

    if(len > in_pos - read_in)
        return -1;

    if(len <= 4) {
        /* Immediate mode. */
        if(len == 1) {
            resp = inbuf[read_in++];
        }
        else if(len == 2) {
            resp = (inbuf[read_in] << 8) |
                   (inbuf[read_in + 1]);
            read_in += 2;
        }
        else if(len == 3) {
            resp = (inbuf[read_in] << 16) |
                   (inbuf[read_in + 1] << 8) |
                   (inbuf[read_in + 2]);
            read_in += 3;
        }
        else if(len == 4) {
            resp = (inbuf[read_in] << 24) |
                   (inbuf[read_in + 1] << 16) |
                   (inbuf[read_in + 2] << 8) |
                   (inbuf[read_in + 3]);
            read_in += 4;
        }

        write32(addr, resp);
    }
    else {
        /* DMA */
        if(len > in_pos - read_in) {
            len = in_pos - read_in;
        }

        memcpy((void *)addr, inbuf + read_in, len);
        sync_after_write((void *)addr, len);
        read_in += len;
    }

    if(read_in >= in_pos) {
        read_in = in_pos = 0;
        rv = 1;
    }

    return rv;
}
