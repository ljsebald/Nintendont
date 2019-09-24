/*

Nintendont (Kernel) - Playing Gamecubes in Wii mode on a Wii U

Copyright (C) 2013  crediar

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation version 2.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

*/
#include "global.h"
#include "EXI.h"
#include "DI.h"
#include "common.h"
#include "vsprintf.h"
#include "alloc.h"
#include "Patch.h"
#include "Config.h"
#include "debug.h"
#include "SRAM.h"
#include "Modem.h"

#include "ff_utf8.h"

#define EXI_IRQ_INSTANT		0		// as soon as possible
#define EXI_IRQ_DEFAULT		1900	// about 1000 times a second
#define EXI_IRQ_SLOW		3800	// about 500 times a second

static u32 CurrentTiming = EXI_IRQ_DEFAULT;

extern vu32 useipl;

static u32 Device = 0;
static u32 SRAMWriteCount = 0;
static u32 EXICommand = 0;
static u32 BlockOff= 0;
static bool changed = false;
static u32 BlockOffLow = 0xFFFFFFFF;
static u32 BlockOffHigh = 0x00000000;
static u8 *const MCard = (u8*)(0x11000000);
static u8 *const FontBuf = (u8*)(0x13100000);
static u32 CARDWriteCount = 0;
static u32 IPLReadOffset;
static FIL MemCard;
bool EXI_IRQ = false;
static u32 IRQ_Timer = 0;
static u32 IRQ_Cause = 0;
static u32 IRQ_Cause2= 0;
static char MemCardName[0x20];

static u32 TRIBackupOffset= 0;
static u32 EXI2IRQ			= 0;
static u32 EXI2IRQStatus	= 0;

static bool Modem_IRQ = false;

static u8 *ambbBackupMem;

void EXIInit( void )
{
	dbgprintf("EXIInit Start\r\n");
	u32 wrote, ret;

	//some important memory for triforce
	ambbBackupMem = malloca(0x10000, 0x40);
	memset32(ambbBackupMem, 0xFF, 0x10000);

	memset32((void*)EXI_BASE, 0, 0x20);
	sync_after_write((void*)EXI_BASE, 0x20);

	const u32 GameID = ConfigGetGameID();
	if( ConfigGetConfig(NIN_CFG_MEMCARDEMU) )
	{
		memset32(MemCardName, 0, 0x20);
		memcpy(MemCardName, "/saves/", 7);
		if ( ConfigGetConfig(NIN_CFG_MC_MULTI) )
		{
			// "Multi" mode is enabled.
			// Use one memory card for USA/PAL games,
			// and another memory card for JPN games.
			switch (BI2region)
			{
				case BI2_REGION_JAPAN:
				case BI2_REGION_SOUTH_KOREA:
				default:
					// JPN games.
					memcpy(MemCardName+7, "ninmemj.raw", 11);
					break;

				case BI2_REGION_USA:
				case BI2_REGION_PAL:
					// USA/PAL games.
					memcpy(MemCardName+7, "ninmem.raw", 10);
					break;
			}
		}
		else
		{
			memcpy(MemCardName+7, &GameID, 4);
			memcpy(MemCardName+11, ".raw", 4);
		}
		sync_after_write(MemCardName, 0x20);

		dbgprintf("Trying to open %s\r\n", MemCardName);
		ret = f_open_char( &MemCard, MemCardName, FA_READ );
		if( ret != FR_OK || MemCard.obj.objsize == 0 )
		{
#ifdef DEBUG_EXI
			dbgprintf("EXI: Failed to open %s:%u\r\n", MemCardName, ret );
#endif
			Shutdown();
		}

#ifdef DEBUG_EXI
		dbgprintf("EXI: Loading memory card...");
#endif

		u32 FindBlocks = 0;
		for (FindBlocks = 0; FindBlocks <= MEM_CARD_MAX; FindBlocks++)
			if (MEM_CARD_SIZE(FindBlocks) == MemCard.obj.objsize)
				break;
		if (FindBlocks > MEM_CARD_MAX)
		{
			dbgprintf("EXI: Memcard unexpected size %s:%u\r\n", MemCardName, MemCard.obj.objsize );
			Shutdown();
		}
		ConfigSetMemcardBlocks(FindBlocks);
		f_lseek(&MemCard, 0);
		f_read( &MemCard, MCard, ConfigGetMemcardSize(), &wrote );
		f_close( &MemCard );
#ifdef DEBUG_EXI
		dbgprintf("EXI: Loaded memory card size %d\r\n", ConfigGetMemcardSize());
		dbgprintf("done\r\n");
#endif
		sync_after_write( MCard, ConfigGetMemcardSize() );

		// Set the flash ID in SRAM.
		// FIXME: This doesn't fix the problem with first-party
		// memory card images, and it might be causing problems
		// with Ikaruga (PAL).
		//SRAM_SetFlashID( MCard, 0 );
	}

	// Initialize SRAM.
	SRAM_Init();
}

extern vu32 TRIGame;

/**
 * Set EXI timings based on the game ID.
 * @param TitleID Game ID, rshifted by 8.
 * @param Region Region byte from Game ID.
 */
void EXISetTimings(u32 TitleID, u32 Region)
{
	//GC BIOS, Trifoce Game, X-Men Legends 2, Rainbow Six 3 or Starfox Assault (NTSC-U)
	if(useipl || TRIGame != TRI_NONE || TitleID == 0x475832 || TitleID == 0x473633 ||
		(TitleID == 0x474637 && Region == REGION_ID_USA))
	{
		CurrentTiming = EXI_IRQ_INSTANT;
	}
	else if(TitleID == 0x474C4D) //Luigis Mansion (stabilize)
	{
		CurrentTiming = EXI_IRQ_SLOW;
	}
	else
	{
		CurrentTiming = EXI_IRQ_DEFAULT;
	}
#ifdef DEBUG_PATCH
	dbgprintf("Patch:Using a EXI Timing of %i\n", CurrentTiming);
#endif
}

bool EXICheckTimer(void)
{
	return TimerDiffTicks(IRQ_Timer) > CurrentTiming;
}
void EXIInterrupt(void)
{
	write32( 0x10, IRQ_Cause );
	write32( 0x18, IRQ_Cause2 );
	sync_after_write( (void*)0, 0x20 );
	write32( EXI_INT, 0x10 ); // EXI IRQ
	sync_after_write( (void*)EXI_INT, 0x20 );
	write32( HW_IPC_ARMCTRL, (1<<0) | (1<<4) ); //throw irq
	//dbgprintf("EXI Interrupt\r\n");
	EXI_IRQ = false;
	IRQ_Timer = 0;
	IRQ_Cause = 0;
	IRQ_Cause2 = 0;
}

bool EXICheckCard(void)
{
	if(changed == true)
	{
		changed = false;
		return true;
	}
	return false;
}

void EXISaveCard(void)
{
	if(TRIGame)
		return;

	u32 wrote;

	if (BlockOffLow < BlockOffHigh)
	{
//#ifdef DEBUG_EXI
		//dbgprintf("EXI: Saving memory card...");
//#endif
		s32 ret = f_open_char( &MemCard, MemCardName, FA_WRITE );
		if( ret == FR_OK )
		{
			sync_before_read(MCard, ConfigGetMemcardSize());
			f_lseek(&MemCard, BlockOffLow);
			f_write(&MemCard, MCard + BlockOffLow, BlockOffHigh - BlockOffLow, &wrote);
			f_close(&MemCard);
//#ifdef DEBUG_EXI
			//dbgprintf("Done!\r\n");
		}
		//else
			//dbgprintf("\r\nUnable to open memory card file:%u\r\n", ret );
//#endif
		BlockOffLow = 0xFFFFFFFF;
		BlockOffHigh = 0x00000000;
	}
}

void EXIShutdown( void )
{
	if(TRIGame)
		return;

	u32 wrote;

//#ifdef DEBUG_EXI
	dbgprintf("EXI: Saving memory card...");
//#endif

	sync_before_read( MCard, ConfigGetMemcardSize() );
	s32 ret = f_open_char( &MemCard, MemCardName, FA_WRITE );
	if( ret == FR_OK )
	{
		f_lseek( &MemCard, 0 );
		f_write( &MemCard, MCard, ConfigGetMemcardSize(), &wrote );
		f_close( &MemCard );
	}
	else
		dbgprintf("\r\nUnable to open memory card file:%u\r\n", ret );
//#ifdef DEBUG_EXI
	dbgprintf("Done!\r\n");
//#endif
}
u32 EXIDeviceMemoryCard( u8 *Data, u32 Length, u32 Mode )
{
	u32 EXIOK = 1;
	//u32 read, wrote;

	if( Mode == 1 )		// Write
	{
		switch( Length )
		{
			case 1:
			{
				if( EXICommand == MEM_BLOCK_READ || EXICommand == MEM_BLOCK_WRITE )
					break;

				switch( (u32)Data >> 24 )
				{
					case 0x00:
					{
						EXICommand = MEM_READ_ID_NINTENDO;
#ifdef DEBUG_EXI
						dbgprintf("EXI: CARDGetDeviceIDNintendo()\r\n");
#endif
					} break;
#ifdef DEBUG_EXI
					case 0x89:
					{
						dbgprintf("EXI: CARDClearStatus()\r\n");
					} break;
#endif
				}
			} break;
			case 2:
			{
				switch( (u32)Data >> 16 )
				{
					case 0x0000:
					{
						EXICommand = MEM_READ_ID;
#ifdef DEBUG_EXI
						dbgprintf("EXI: CARDGetDeviceID()\r\n");
#endif
					} break;
					case 0x8300:	//
					{
						EXICommand = MEM_READ_STATUS;
#ifdef DEBUG_EXI
						dbgprintf("EXI: CARDReadStatus()\r\n");
#endif
					} break;
#ifdef DEBUG_EXI
					case 0x8101:
					{
						dbgprintf("EXI: CARDIRQEnable()\r\n");
					} break;
					case 0x8100:
					{
						dbgprintf("EXI: CARDIRQDisable()\r\n");
					} break;
#endif
				}
			} break;
			case 3:
			{
				switch( (u32)Data >> 24 )
				{
					case 0xF1:
					{
						BlockOff = (((u32)Data>>16)&0xFF)  << 17;
						BlockOff|= (((u32)Data>> 8)&0xFF)  << 9;
#ifdef DEBUG_EXI
						dbgprintf("EXI: CARDErasePage(%08X)\r\n", BlockOff );
#endif
						EXICommand = MEM_BLOCK_ERASE;
						CARDWriteCount = 0;
						IRQ_Cause = 2;			// EXI IRQ
						EXIOK = 2;
					} break;
				}
			} break;
			case 4:
			{
				if( EXICommand == MEM_BLOCK_READ || EXICommand == MEM_BLOCK_WRITE )
					break;

				switch( (u32)Data >> 24 )
				{
					case 0xF1:
					{
						BlockOff = (((u32)Data>>16)&0xFF)  << 17;
						BlockOff|= (((u32)Data>> 8)&0xFF)  << 9;
						BlockOff|= (((u32)Data&0xFF) & 3 ) << 7;
#ifdef DEBUG_EXI
						dbgprintf("EXI: CARDErasePage(%08X)\r\n", BlockOff );
#endif
						EXICommand = MEM_BLOCK_ERASE;
						CARDWriteCount = 0;
						IRQ_Cause = 2;			// EXI IRQ
						EXIOK = 2;
					} break;
					case 0xF2:
					{
						BlockOff = (((u32)Data>>16)&0xFF)  << 17;
						BlockOff|= (((u32)Data>> 8)&0xFF)  << 9;
						BlockOff|= (((u32)Data&0xFF) & 3 ) << 7;
#ifdef DEBUG_EXI
						dbgprintf("EXI: CARDWritePage(%08X)\r\n", BlockOff );
#endif
						EXICommand = MEM_BLOCK_WRITE;
					} break;
					case 0x52:
					{
						BlockOff = (((u32)Data>>16)&0xFF)  << 17;
						BlockOff|= (((u32)Data>> 8)&0xFF)  << 9;
						BlockOff|= (((u32)Data&0xFF) & 3 ) << 7;
#ifdef DEBUG_EXI
						dbgprintf("EXI: CARDReadPage(%08X)\r\n", BlockOff );
#endif

						EXICommand = MEM_BLOCK_READ;
					} break;
#ifdef DEBUG_EXI
					default:
					{
						dbgprintf("EXI: Unknown:%08x Line:%u\r\n", (u32)Data, __LINE__ );
					//	Shutdown();
					} break;
#endif
				}
			} break;
			default:
			{
				switch( EXICommand )
				{
					case MEM_BLOCK_WRITE:
					{
						if(BlockOff < BlockOffLow)
							BlockOffLow = BlockOff;
						if(BlockOff + Length > BlockOffHigh)
							BlockOffHigh = BlockOff + Length;
						changed = true;
						sync_before_read( Data, Length );

						memcpy( MCard+BlockOff, Data, Length );

						sync_after_write( MCard+BlockOff, Length );

						IRQ_Cause = 10;	// TC(8) & EXI(2) IRQ
						EXIOK = 2;
					} break;
				}
			} break;
		}

	} else {			// Read

		switch( EXICommand )
		{
			case MEM_READ_ID_NINTENDO:
			case MEM_READ_ID:
			{
				if( ConfigGetConfig(NIN_CFG_MEMCARDEMU) && (TRIGame == TRI_NONE) )
				{
					write32( EXI_CMD_1, ConfigGetMemcardCode() );
				} else {
					write32( EXI_CMD_1, 0x00000000 ); //no memory card
				}
#ifdef DEBUG_EXI
				dbgprintf("EXI: CARDReadID(%X)\r\n", read32(EXI_CMD_1) );
#endif
			} break;
			case MEM_READ_STATUS:
			{
				write32( EXI_CMD_1, 0x41 );	// Unlocked(0x40) and Ready(0x01)
#ifdef DEBUG_EXI
				dbgprintf("EXI: CARDReadStatus(%X)\r\n", read32(EXI_CMD_1) );
#endif
			} break;
			case MEM_BLOCK_READ:
			{
			//	f_lseek( &MemCard, BlockOff );
			//	f_read( &MemCard, Data, Length, &read );
				sync_before_read( MCard+BlockOff, Length );

				memcpy( Data, MCard+BlockOff, Length );

				sync_after_write( Data, Length );

				IRQ_Cause = 8;		// TC IRQ

				EXIOK = 2;
			} break;
		}
	}
	//dbgprintf("%08x %08x %08x %08x\r\n", (u32)Data >> 16, Mode, Length, EXICommand);
	write32( EXI_CMD_0, 0 ); //exit EXIDMA / EXIImm
	sync_after_write( (void*)EXI_BASE, 0x20 );

	if( EXIOK == 2 )
	{
		EXI_IRQ = true;
		IRQ_Timer = read32(HW_TIMER);
	}
	return 1;
}

u32 EXIDevice_ROM_RTC_SRAM_UART( u8 *Data, u32 Length, u32 Mode )
{
	if( Mode == 1 )		// Write
	{
		switch( Length )
		{
			case 4:
			{
				if( EXICommand == SRAM_WRITE )
				{
					*(u32*)(((u8*)&sram)+SRAMWriteCount) = (u32)Data;

					SRAMWriteCount += Length;

					break;
				}

				if( (u32)Data == 0x20000000 )
				{
					EXICommand = RTC_READ;
#ifdef DEBUG_SRAM
					dbgprintf("EXI: RTCRead()\r\n");
#endif
					break;
				}

				if( (u32)Data == 0x20000100 )
				{
					EXICommand = SRAM_READ;
#ifdef DEBUG_SRAM
					dbgprintf("EXI: SRAMRead()\r\n");
#endif
					break;
				}

				if( (u32)Data == 0x20010000 )
				{
					EXICommand = UART_READ;
#ifdef DEBUG_SRAM
					dbgprintf("EXI: UARTRead()\r\n");
#endif
					break;
				}

				if( (u32)Data == 0xA0000100 || (u32)Data == 0xA0000600 )
				{
					EXICommand = SRAM_WRITE;
					SRAMWriteCount = 0;
#ifdef DEBUG_SRAM
					dbgprintf("EXI: SRAMWrite()\r\n");
#endif
					break;
				}
				u32 PossibleIPLOffset = (u32)Data >> 6;
				if( PossibleIPLOffset >= IPL_ROM_FONT_SJIS && PossibleIPLOffset < IPL_ROM_END_OFFSET )
				{
					EXICommand = IPL_READ_FONT;
#ifdef DEBUG_SRAM
					dbgprintf("EXI: IPLReadFont()\r\n");
#endif
					IPLReadOffset = PossibleIPLOffset;
					break;
				}

			} break;
		}

	} else {

		switch( EXICommand )
		{
			case IPL_READ_FONT:
			{
//#ifdef DEBUG_SRAM
				dbgprintf("EXI: IPLRead( %p, %08X, %u), No ReadROM Patch?\r\n", Data, IPLReadOffset, Length );
//#endif
				EXIReadFontFile(Data, Length);
			} break;
			case RTC_READ:
			{
				Data = (u8*)P2C((u32)Data); //too small size so do it manually
#ifdef DEBUG_SRAM
				dbgprintf("EXI: RTCRead( %p, %u)\r\n", Data, Length );
#endif			//???
				sync_before_read_align32( Data, Length );
				memset( Data, 0, Length );
				sync_after_write_align32( Data, Length );
			} break;
			case SRAM_READ:
			{
#ifdef DEBUG_SRAM
				dbgprintf("EXI: SRAMRead(%p,%u)\r\n", Data, Length );
#endif
				memcpy( Data, &sram, Length );
				sync_after_write( Data, Length );
			} break;
			case UART_READ:
			{
				Data = (u8*)P2C((u32)Data); //too small size so do it manually
#ifdef DEBUG_SRAM
				dbgprintf("EXI: UARTRead( %p, %u)\r\n", Data, Length );
#endif			//???
				sync_before_read_align32( Data, Length );
				memset( Data, 0, Length );
				sync_after_write_align32( Data, Length );
			} break;
			default:
			{
				dbgprintf("EXI: Unknown:%08x Line:%u\r\n", (u32)Data, __LINE__ );
				Shutdown();
			} break;
		}
	}

	write32( EXI_CMD_0, 0 );
	sync_after_write( (void*)EXI_BASE, 0x20 );
	return 1;
}
u32 EXIDeviceSP1( u8 *Data, u32 Length, u32 Mode )
{
	u32 EXIOK = 0;

	if( Mode == 1 )		// Write
	{

		switch( Length )
		{
			/*
				0: command
			1-2: arg
			  3: checksum
			*/
			case 4:
			{
				switch( (u32)Data >> 24 )
				{
					case 0x01:
					{
						TRIBackupOffset = ((u32)Data >> 8) & 0xFFFF;
						EXICommand = AMBB_BACKUP_OFFSET;
					} break;
					case 0x02:
					{
						ambbBackupMem[TRIBackupOffset] = ((u32)Data >> 16) & 0xFF;
						EXICommand = AMBB_BACKUP_WRITE;
					} break;
					case 0x03:
					{
						EXICommand = AMBB_BACKUP_READ;
					} break;
					case 0x82:
					{
#ifdef DEBUG_GCAM
						dbgprintf("EXI:ISRRead()\n");
#endif
						EXICommand = AMBB_ISR_READ;
					} break;
					case 0x83:
					{
#ifdef DEBUG_GCAM
						dbgprintf("EXI:0x83()\n");
#endif
						EXICommand = AMBB_UNKNOWN;
					} break;
					case 0x86:
					{
#ifdef DEBUG_GCAM
						dbgprintf("EXI:IMRRead()\n");
#endif
						EXICommand = AMBB_IMR_READ;
					} break;
					case 0x87:
					{
#ifdef DEBUG_GCAM
						dbgprintf("EXI:IMRWrite(%04X)\n", ((u32)Data >> 8) & 0xFFFF );
#endif
						EXICommand = AMBB_IMR_WRITE;
					} break;
					case 0xFF:
					{
#ifdef DEBUG_GCAM
						dbgprintf("EXI:LANCNTWrite(%04X)\n", ((u32)Data >> 8) & 0xFFFF );
#endif
						if( (((u32)Data >> 8) & 0xFFFF) == 0x0201 )
						{
							EXI2IRQStatus = 0;

						} else if ((((u32)Data >> 8) & 0xFFFF) == 0 )
						{
							EXI2IRQ = 1;
							EXI2IRQStatus = 2;
						}
						EXICommand = AMBB_LANCNT_WRITE;
					} break;
				}
			} break;
			case 2:
			{
				switch( (u32)Data >>16 )
				{
					case 0x0000:
					{
						EXICommand = MEM_READ_ID;
					} break;
				}
			} break;
		}

	} else {

		switch(EXICommand)
		{
			/* 0x02 */
			case AMBB_BACKUP_WRITE:
			/* 0x01 */
			case AMBB_BACKUP_OFFSET:
			{
				write32( EXI_CMD_1, 0x01 );
			} break;
			/* 0x03 */
			case AMBB_BACKUP_READ:
			{
				write32( EXI_CMD_1, 0x0100 | ambbBackupMem[TRIBackupOffset] );
			} break;
			/* 0x87 */
			case AMBB_IMR_WRITE:
			/* 0x83 */
			case AMBB_UNKNOWN:
			{
				write32( EXI_CMD_1, 0x04 );
			} break;
			/* 0x82 */
			case AMBB_ISR_READ:
			{
				if( Length == 1 )
				{
					write32( EXI_CMD_1, 0x04 );
				} else {
					write32( EXI_CMD_1, EXI2IRQStatus );
					EXI2IRQ = 0;
				}
			} break;
			/* 0x86 */
			case AMBB_IMR_READ:
			{
				if( Length == 1 )
				{
					write32( EXI_CMD_1, 0x04 );
				} else {
					write32( EXI_CMD_1, 0x0000 );
				}
			} break;
			/* 0xFF */
			case AMBB_LANCNT_WRITE:
			{
				if( EXI2IRQ )
				{
					EXIOK = 2;
				}
				write32( EXI_CMD_1, 0x04 );
			} break;
			case MEM_READ_ID:
			{
				write32( EXI_CMD_1, EXI_DEVTYPE_BASEBOARD );
			} break;
		}
	}

	write32( EXI_CMD_0, 0 );
	sync_after_write((void*)EXI_BASE, 0x20);

	if( EXIOK == 2 )
	{
		//dbgprintf("EXI: Triforce IRQ\r\n");
		IRQ_Cause = 8;
		IRQ_Cause2 = 2;
		EXI_IRQ = true;
		IRQ_Timer = read32(HW_TIMER);
	}
	return 0;
}

void EXIModemInterrupt(void) {
    Modem_IRQ = true;
}

void EXIModemInterruptPktIn(void) {
    dbgprintf("EXI: Modem Pkt IRQ\r\n");
    IRQ_Cause2 = 2;
    EXI_IRQ = true;
    Modem_IRQ = false;
    IRQ_Timer = read32(HW_TIMER);
}

u32 EXIDeviceModem(u8 *Data, u32 Length, u32 Mode, int dma) {
    static u8 regnum = 0;
    static u16 blocklen = 0;
    u32 tmp;
    int transfer_irq = 0;

    dbgprintf("Modem access: %p %u %u (%d %d %d %d)\n", Data, Length, Mode, EXICommand, regnum, blocklen, dma);

    if(Mode == 1) { /* Write */
        tmp = (u32)Data;

        if(EXICommand == MODEM_WRITE_BLOCK) {
            if(regnum == MODEM_HAYES_CMD) {
                /* Hayes command register -- always sent by Immediate mode. */
                modem_write_cmd(tmp, blocklen > 4 ? 4 : blocklen);

                if(blocklen >= 4) {
                    blocklen -= 4;
                }
                else {
                    blocklen = 0;
                    EXICommand = 0;
                }
            }
            else if(regnum == MODEM_SERIAL_IO) {
                if(modem_write_serial(tmp, Length, blocklen)) {
                    blocklen = 0;
                    EXICommand = 0;

                    if(dma)
                        transfer_irq = 1;
                }
            }
        }
        else {
            switch(Length) {
                case 1:
                    if(EXICommand != MODEM_WRITE_REG) {
                        dbgprintf("Modem: Write length 1, but not to register (%d)?\n", EXICommand);
                        break;
                    }

                    modem_write_reg(regnum, tmp >> 24);
                    break;

                case 2:
                    if((tmp >> 16) == 0) {
                        dbgprintf("Modem: Set command to read ID\n");
                        EXICommand = MEM_READ_ID;
                    }
                    else if(((tmp >> 24) & 0xE0) == 0x80) {
                        dbgprintf("Modem: Reset?\n");
                        EXICommand = 0;
                        regnum = 0;
                        blocklen = 0;
                        modem_init();
                    }
                    else if(((tmp >> 24) & 0xE0) == 0x40) {
                        EXICommand = MODEM_WRITE_REG;
                        regnum = ((tmp >> 24) & 0x1F);
                        dbgprintf("Modem: Set command to write register %d\n", (int)regnum);
                    }
                    else if(((tmp >> 24) & 0xE0) == 0x00) {
                        EXICommand = MODEM_READ_REG;
                        regnum = ((tmp >> 24) & 0x1F);
                        dbgprintf("Modem: Set command to read register %d\n", (int)regnum);
                    }
                    else {
                        dbgprintf("Ignoring unknown write\n");
                        EXICommand = 0;
                    }
                    break;

                case 4:
                    if(((tmp >> 24) & 0xE0) == 0x60) {
                        EXICommand = MODEM_WRITE_BLOCK;
                        regnum = ((tmp >> 24) & 0x1F);
                        blocklen = ((tmp >> 8) & 0xFFFF);
                        dbgprintf("Modem: Set command to write %d bytes to block %d\n", (int)blocklen, (int)regnum);

                        if(regnum == MODEM_SERIAL_IO)
                            modem_reset_serial();
                    }
                    else if(((tmp >> 24) & 0xE0) == 0x20) {
                        EXICommand = MODEM_READ_BLOCK;
                        regnum = ((tmp >> 24) & 0x1F);
                        blocklen = ((tmp >> 8) & 0xFFFF);
                        dbgprintf("Modem: Set command to read %d bytes from block %d\n", (int)blocklen, (int)regnum);
                    }
                    break;
            }
        }
	} else {
        //dbgprintf("Command: %u\n", EXICommand);

        switch(EXICommand)
        {
            case MEM_READ_ID:
                write32(EXI_CMD_1, EXI_DEVTYPE_MODEM);
                break;

            case MODEM_READ_REG:
                write32(EXI_CMD_1, modem_read_reg(regnum));
                break;

            case MODEM_READ_BLOCK:
                switch(regnum) {
                    case MODEM_HAYES_CMD:
                        modem_read_resp(EXI_CMD_1, Length);
                        break;

                    case MODEM_SERIAL_IO:
                        if(modem_read_serial(EXI_CMD_1, Length)) {
                            blocklen = 0;
                            EXICommand = 0;

                            if(dma)
                                transfer_irq = 1;
                        }
                        break;

                    default:
                        dbgprintf("Ignoring unknown block read.\n");
                }
                break;

            default:
                dbgprintf("Ignoring unknown read\n");
        }
    }

    write32(EXI_CMD_0, 0);
    sync_after_write((void*)EXI_BASE, 0x20);

    if(Modem_IRQ) {
        dbgprintf("EXI: Modem IRQ\r\n");
        IRQ_Cause2 = 2;

        if(transfer_irq)
            IRQ_Cause2 |= 8;

        EXI_IRQ = true;
        Modem_IRQ = false;
        IRQ_Timer = read32(HW_TIMER);
    }
    else if(transfer_irq) {
        dbgprintf("EXI: Modem Transfer IRQ\r\n");
        IRQ_Cause2 = 8;
        EXI_IRQ = true;
        IRQ_Timer = read32(HW_TIMER);
    }
    return 0;
}

void EXIUpdateRegistersNEW( void )
{
	if( EXI_IRQ == true ) //still working
		return;

    modem_poll();

	//u32 chn, dev, frq, ret, data, len, mode;
	u32 chn, dev, ret, data, len, mode;
	u8 *ptr;
	sync_before_read((void*)EXI_BASE, 0x20);
	u32 command = read32(EXI_CMD_0);

    //chn = read32(EXI_LOCKS);
    //dbgprintf("EXI: %08x\n", chn);

	if( command & 0xFF000000 )
	{
		switch( command >> 24 )
		{
			case 0x10:	// EXISelect
			{
				chn = command & 0xFF;
				dev = (command>>8) & 0xFF;
				//frq = (command>>16) & 0xFF;

				//dbgprintf("EXISelect( %u, %u, %u )\r\n", chn, dev, frq );
				ret = 1;

				switch( chn )
				{
					case 0:
					{
						switch( dev )
						{
							case 0:
							{
								Device = EXI_DEV_MEMCARD_A;
							} break;
							case 1:
							{
								Device = EXI_DEV_MASK_ROM_RTC_SRAM_UART;
							} break;
							case 2:
							{
								Device = EXI_DEV_SP1;
							} break;
						}
					} break;
					case 1:
					{
						Device = EXI_DEV_MEMCARD_B;
						ret = 0;
					} break;
					case 2:
					{
						Device = EXI_DEV_AD16;
						ret = 0;
					} break;
				}

				EXICommand = 0;
				write32( EXI_CMD_0, 0 );
				write32( EXI_CMD_1, ret );
				sync_after_write((void*)EXI_BASE, 0x20);
			} break;
			case 0x11:	// EXI_Imm( s32 nChn, void *pData, u32 nLen, u32 nMode, EXICallback tc_cb );
			{
				chn	=	(command >> 20) & 0xF;
				data=	read32(EXI_CMD_1);
				len	=	command& 0xFFFF;
				mode=	(command >> 16) & 0xF;

				if( len > 4 )
				{
					data = P2C(data);
				}

				//dbgprintf("EXIImm( %u, %p, %u, %u, Dev:%u EC:%u )\r\n", chn, data, len, mode, Device, EXICommand );
				switch( Device )
				{
					case EXI_DEV_MEMCARD_A:
					{
						EXIDeviceMemoryCard( (u8*)data, len, mode );
					} break;
					case EXI_DEV_MASK_ROM_RTC_SRAM_UART:
					{
						EXIDevice_ROM_RTC_SRAM_UART( (u8*)data, len, mode );
					} break;
					case EXI_DEV_SP1:
					{
						//EXIDeviceSP1( (u8*)data, len, mode );
                        EXIDeviceModem((u8*)data, len, mode, 0);
					} break;
					default:
					{
#ifdef DEBUG_SRAM
						dbgprintf("EXI: EXIImm: Unhandled device:%u\r\n", Device );
#endif
					} break;
				}

			} break;
			case 0x12:	// EXIDMA
			{
				chn	=	(command >> 20) & 0xF;
				ptr=	(u8*)P2C(read32(EXI_CMD_1));
				len	=	command& 0xFFFF;
				mode=	(command >> 16) & 0xF;

				//dbgprintf("EXIDMA( %u, %p, %u, %u )\r\n", chn, ptr, len, mode );
				switch( Device )
				{
					case EXI_DEV_MEMCARD_A:
					{
						EXIDeviceMemoryCard( ptr, len, mode );
                        EXICommand = 0;
					} break;
					case EXI_DEV_MASK_ROM_RTC_SRAM_UART:
					{
						EXIDevice_ROM_RTC_SRAM_UART( ptr, len, mode );
                        EXICommand = 0;
					} break;
					case EXI_DEV_SP1:
					{
#ifdef DEBUG_SRAM
						hexdump( ptr, len );
#endif
						//EXIDeviceSP1( ptr, len, mode );
                        EXIDeviceModem(ptr, len, mode, 1);
					} break;
					default:
					{
#ifdef DEBUG_SRAM
						dbgprintf("EXI: EXIDMA: Unhandled device:%u\r\n", Device );
#endif
					} break;
				}

				//EXICommand = 0;

			} break;
			default:
			{
			} break;
		}
	}
}

// FontBuf starts at IPL_ROM_FONT_SJIS
void EXIReadFontFile(u8* Data, u32 Length)
{
	memcpy(Data, FontBuf + IPLReadOffset - IPL_ROM_FONT_SJIS, Length);
	sync_after_write(Data, Length);
}

//SegaBoot 3.11 with Free Play enabled
static const unsigned int sb311block[54] =
{
    0x41434255, 0x30303031, 0x007D0512, 0x01000000, 0x00000311, 0x53424C4B,
    0x00000000, 0x63090400, 0x01010A01, 0x01010001, 0x01010101, 0x01010101,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000001,
    0x00000000, 0x00000000, 0x00000000, 0x00000001, 0x00000000, 0x00000000,
    0x00000000, 0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000001,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x200E1AFF,
    0xFFFF0000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
};

extern u32 arcadeMode;
static bool TRIGameStarted = false;
//make sure ambbBackupMem is filled correctly
void EXIPrepareTRIGameStart()
{
	if(TRIGameStarted)
		return;
	dbgprintf("TRI:Setting up AMBB memory\r\n");
	memset32(ambbBackupMem, 0, 0x400);
	memcpy(ambbBackupMem, sb311block, sizeof(sb311block));
	memcpy(ambbBackupMem + 0x200, sb311block, sizeof(sb311block));
	if(arcadeMode)
	{	//standard coin settings instead of free play
		ambbBackupMem[0x00B] = 8; ambbBackupMem[0x022] = 1; ambbBackupMem[0x023] = 0;
		ambbBackupMem[0x20B] = 8; ambbBackupMem[0x222] = 1; ambbBackupMem[0x223] = 0;
	}
	memset32(ambbBackupMem + 0x400, 0xFF, 0x10000 - 0x400);
	TRIGameStarted = true;
}
