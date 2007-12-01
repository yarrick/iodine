#include <string.h>

#include "common.h"
#include "packet.h"

/**
 *	Is some part of this packet sent?
 */
int
packet_sending(struct packet *packet)
{
	return (packet->len != 0);
}

/**
 *	Acknowledge that the latest send was succesful
 */
void
packet_advance(struct packet *packet)
{
	packet->offset += packet->sentlen;
	if (packet->offset == packet->len) {
		/* Packet completed */
		packet->offset = 0;
		packet->len = 0;
		packet->sentlen = 0;
	}
}


/**
 *	The length to left to send
 */
int
packet_len_to_send(struct packet *packet)
{
	return packet->len - packet->offset;
}

/**
 *	Fill the packet with data
 */
int
packet_fill(struct packet *packet, char *data, unsigned long datalen)
{
	memcpy(packet->data, data, MIN(datalen, PKTSIZE));
	packet->sentlen = 0;
	packet->offset = 0;
	packet->len = datalen;
	
	return packet->len;
}

/**
 *	Mark len number of bytes as being sent
 */
void
packet_send_len(struct packet *packet, int len)
{
	packet->sentlen = len;
}

