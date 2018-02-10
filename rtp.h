/*
 **************************************************************************************
 *       Filename:  rtp.h
 *    Description:   header file
 *
 *        Version:  1.0
 *        Created:  2018-02-10 10:26:21
 *
 *       Revision:  initial draft;
 **************************************************************************************
 */

#ifndef RTP_H_INCLUDED
#define RTP_H_INCLUDED

#include <endian.h>
#include <inttypes.h>

typedef struct rtp_header
{
#if __BYTE_ORDER == __BIG_ENDIAN
	uint16_t version:2;
	uint16_t padding:1;
	uint16_t extension:1;
	uint16_t csrccount:4;
	uint16_t markerbit:1;
	uint16_t type:7;
#elif __BYTE_ORDER == __LITTLE_ENDIAN
	uint16_t csrccount:4;
	uint16_t extension:1;
	uint16_t padding:1;
	uint16_t version:2;
	uint16_t type:7;
	uint16_t markerbit:1;
#endif
	uint16_t seq_number;
	uint32_t timestamp;
	uint32_t ssrc;
	uint32_t csrc[16];
} rtp_header;

#endif /*RTP_H_INCLUDED*/
/********************************** END **********************************************/
