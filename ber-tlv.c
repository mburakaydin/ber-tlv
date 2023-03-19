/*
 * ber-tlv.c
 *
 *  Created on: Jul 27, 2016
 *      Author: burak.aydin
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "ber-tlv.h"


#ifdef DEBUG
	#define DEBUG_PRINTF(...) printf(va_args); fflush(stdout);
#else
	#define DEBUG_PRINTF(...)
#endif

#define IS_CONSTRUCTED 0x20

void hd(char *description, unsigned char *data, int data_len) {
	int i = 0;
	DEBUG_PRINTF("%s[%d]:", description, data_len);
	for(i = 0; i < data_len; i++)
		DEBUG_PRINTF("%02x ", data[i]);
	DEBUG_PRINTF("\n");
}


/*!
 * Parses tag
 * private function
 */
static int bertlv_parsetag(unsigned char *input_buffer, int buffer_len, unsigned int *tag) {
	unsigned char *p = input_buffer;
	int octet_size = 1;

	if(buffer_len < 1)
		return 0;

	if((*p & 0x1F) == 0x1F) {
		octet_size++;
		p++;

		while (*p & 0x80) {
			/*error parsing*/
			if((p - input_buffer) > buffer_len) {
				return 0;
			}
			octet_size++;
			p++;
		}
	}

	int i = 0;
	*tag = 0;
	for(i = 0; i < octet_size; i++) {
		*tag += input_buffer[i] << (octet_size - i - 1) * 8;
	}


	return octet_size;
}

/*!
 * Parses len
 * private function
 */
static int bertlv_parselen(unsigned char *input_buffer,  int buffer_len, unsigned int *len) {
	unsigned char *p = input_buffer;
	int octet_size = 1;
	int extension_byte = 0;

	if(buffer_len < 1)
		return 0;

	if (*p & 0x80) {
		octet_size = *p & 0x7F;
		if(octet_size > 4) {
			DEBUG_PRINTF("%s() err octet size...%d\n", __FUNCTION__, octet_size);
			return 0;
		}
		extension_byte = 1;
		p++;
	}


	int i = 0;
	*len = 0;
	for(i = 0; i < octet_size; i++) {
		*len += p[i] << (octet_size - i - 1) * 8;
	}

	if(*len > buffer_len) {
		return 0;
	}

	return octet_size + extension_byte;
}

uint8_t bertlv_len_size(uint16_t len)
{
    uint8_t ret;

    if(len < 0x7F)          // From 0x00 to 0x7F
        ret = 1;
    else if(len < 0x0100)   // From 0x81 0x80 to 0x81 0xFF
        ret = 2;
    else                    // From 0x82 0x01 0x00 to 0x82 0xFF 0xFF
        ret = 3;

    return ret;
}

int bertlv_tag_size (uint32_t tag) {
	uint8_t tag_len = 1;
	if(tag > 0xFFFFFF) {
		tag_len = 4;
	} else if (tag > 0xFFFF) {
		tag_len = 3;
	} else if (tag > 0xFF) {
		tag_len = 2;
	} else {
		tag_len = 1;
	}

	return tag_len;
}

int bertlv_build_len(uint16_t len, uint8_t *buf, uint32_t *buflen) {
    uint8_t sLen;
    uint16_t i;

    uint8_t *bufPtr = buf;
    uint8_t writtenBytes = 0;

    sLen = bertlv_len_size(len);
    if(sLen > *buflen) {
    	DEBUG_PRINTF("Error buffer too short!\n");
    	return -1;
    }

    /* Now pack bytes in buffer starting by MSB */
    if(sLen > 1) {
        *bufPtr = (0x80 | (sLen - 1));
        (bufPtr)++;
        writtenBytes++;
        sLen--;      // number of bytes remaining in LEN field to pack
    }

    for(i = sLen; i > 0; i--) {
        *(bufPtr + i - 1) = (uint8_t)(len & 0xFF);
        len = len >> 8;
    }

    /* Update buffer pointer to point right after LEN bytes */
    writtenBytes += sLen;

    *buflen = writtenBytes;

    return 0;
}
unsigned char * bertlv_parse_tlv(unsigned char *input_buffer, int buffer_len, unsigned int *tag, unsigned int *len, unsigned char **data) {
	unsigned char *p = input_buffer;
	int entity_len = 0;

	unsigned int _tag = 0, _len = 0;

	do {
		entity_len = bertlv_parsetag(p, buffer_len, &_tag);
		if(entity_len == 0) {
			DEBUG_PRINTF("%s() bertlv_parsetag error!\n", __FUNCTION__);
			p = NULL;
			break;
		}
		p += entity_len;

		entity_len = bertlv_parselen(p, buffer_len - (p - input_buffer), &_len);
		if(entity_len == 0) {
			DEBUG_PRINTF("%s() bertlv_parselen error!\n", __FUNCTION__);
			//hd("tlv", input_buffer, buffer_len);
			p = NULL;
			break;
		}
		p += entity_len;
		*data = p;

		p += _len;

		*tag = _tag;
		*len = _len;


	} while(0);

	return p;
}

int bertlv_checktag_isconstructed(unsigned int tag) {
	while(tag > 0xFF) {
		tag = tag >> 8;
	}
//	DEBUG_PRINTF("%s() tag:%x\n", __FUNCTION__, tag);
	if(tag & IS_CONSTRUCTED) {
		//DEBUG_PRINTF("%s() %x is constructed...\n", __FUNCTION__, tag);
		return 1;
	} else {
//		DEBUG_PRINTF("%s() tag is primitive...\n", __FUNCTION__);

	}
	return 0;
}



int bertlv_parse_tlv_all (unsigned char *input_buffer, int buffer_len, tlv_callback_t cb, int depth, void *userdata) {
	unsigned char *p = input_buffer;
	unsigned int _tag = 0, _len = 0;
	unsigned char *_data = NULL;
	int ret;

	if(cb == NULL) {
		DEBUG_PRINTF("%s() callback is null!\n", __FUNCTION__);
		return -1;
	}

//	DEBUG_PRINTF("%s() [%d] input_buffer:%p p:%p diff:%d depth:%d\n", __FUNCTION__, __LINE__, input_buffer, p, p - input_buffer,depth);
	do {
		p = bertlv_parse_tlv(p, buffer_len, &_tag, &_len, &_data);
		if(p == NULL) {
			DEBUG_PRINTF("%s() bertlv_parse error!\n", __FUNCTION__);
			return -1;
		}
		//DEBUG_PRINTF("%s() [%d] input_buffer:%p p:%p diff:%d depth:%d\n", __FUNCTION__, __LINE__, input_buffer, p, p - input_buffer,depth);

		ret = cb(_tag, _len, _data, depth, userdata);
		if(ret < 0) {
			return ret;
		}
		if(bertlv_checktag_isconstructed(_tag) && (_len > 0)) {
			ret = bertlv_parse_tlv_all(_data, _len, cb, depth + 1, userdata);
			if(ret < 0) {
				return ret;
			}
		}
		//DEBUG_PRINTF("%s() [%d] input_buffer:%p p:%p diff:%d depth:%d\n", __FUNCTION__, __LINE__, input_buffer, p, p - input_buffer,depth);

	} while(p - input_buffer < buffer_len);

	return 0;
}

int bertlv_build_tag(unsigned int tag, unsigned char *buffer, unsigned int *buf_len) {
	uint8_t tag_size = bertlv_tag_size(tag);
	uint8_t *p = buffer;
	if(tag_size > *buf_len) {
		DEBUG_PRINTF("Buffer too short!\n");
		return -1;
	}

	if(tag > 0xFFFFFF) {
		p[0] = (tag >> 24) & 0xFF;
		p[1] = (tag >> 16) & 0xFF;
		p[2] = (tag >>  8) & 0xFF;
		p[3] = (tag >>  0) & 0xFF;
	} else if (tag > 0xFFFF) {
		p[0] = (tag >> 16) & 0xFF;
		p[1] = (tag >>  8) & 0xFF;
		p[2] = (tag >>  0) & 0xFF;
	} else if (tag > 0xFF) {
		p[0] = (tag >>  8) & 0xFF;
		p[1] = (tag >>  0) & 0xFF;
	} else {
		p[0] = (tag >>  0) & 0xFF;
	}

	*buf_len = tag_size;
	return 0;
}

int bertlv_construct_tlv(unsigned int tag, unsigned int len, unsigned char *data, unsigned char **to_buffer, unsigned int *buffer_len) {
	unsigned char *p = NULL;
	int tag_len = bertlv_tag_size(tag);
	int len_len = bertlv_len_size(len);
	unsigned int build_len = 0;
	int8_t ret = 0;


	if(*to_buffer == NULL) { // then there is static memory, the memory should be allocated.
		*to_buffer = (uint8_t *)malloc(tag_len + len_len + len);
		if(*to_buffer == NULL) {
			DEBUG_PRINTF("malloc error");
			return -1;
		}
		*buffer_len = tag_len + len_len + len;
	} else {
		if((tag_len + len_len + len) > *buffer_len) {
			DEBUG_PRINTF("error buffer too short!\n");
			return -1;
		}
	}

	p = *to_buffer;
	build_len = *buffer_len;
	ret = bertlv_build_tag(tag, p, &build_len); //
	if(ret != 0) {
		DEBUG_PRINTF("Tag build error!\n");
		return -1;
	}
	p += build_len; // build len is returned from function

	build_len = *buffer_len - tag_len;
	ret = bertlv_build_len(len, p, &build_len);
	if(ret != 0) {
		DEBUG_PRINTF("Len build error!\n");
		return -1;
	}
	p += build_len; // build len is returned from function

	memcpy(p, data, len);

	*buffer_len = tag_len + len_len + len;
	return 0;
}


int bertlv_construct_tlv2(unsigned int tag, unsigned int len, unsigned char *data_buffer, unsigned int *data_buffer_len) {
	unsigned char *p = NULL;
	int tag_len = bertlv_tag_size(tag);
	int len_len = bertlv_len_size(len);
	uint32_t build_len = 0;
	int8_t ret = 0;


	if((tag_len + len_len + len) > *data_buffer_len) {
		DEBUG_PRINTF("%s() error buffer too short!\n", __FUNCTION__);
		return -1;
	}

	memmove(&data_buffer[tag_len + len_len], data_buffer, len);

	p = data_buffer;
	build_len = *data_buffer_len;
	ret = bertlv_build_tag(tag, p, &build_len); //
	if(ret != 0) {
		DEBUG_PRINTF("Tag build error!\n");
		return -1;
	}
	p += build_len; // build len is returned from function

	build_len = *data_buffer_len - tag_len;
	ret = bertlv_build_len(len, p, &build_len);
	if(ret != 0) {
		DEBUG_PRINTF("Len build error!\n");
		return -1;
	}
	p += build_len; // build len is returned from function

	*data_buffer_len = tag_len + len_len + len;
	return 0;
}


unsigned char * bertlv_parse_dol(unsigned char *input_buffer, int buffer_len, unsigned int *tag, unsigned int *len) {
	unsigned char *p = input_buffer;
	int entity_len = 0;

	unsigned int _tag = 0, _len = 0;

	do {
		entity_len = bertlv_parsetag(p, buffer_len, &_tag);
		if(entity_len == 0) {
			DEBUG_PRINTF("%s() bertlv_parsetag error!\n", __FUNCTION__);
			p = NULL;
			break;
		}
		p += entity_len;

		entity_len = bertlv_parselen(p, buffer_len - (p - input_buffer), &_len);
		if(entity_len == 0) {
			DEBUG_PRINTF("%s() bertlv_parselen error!\n", __FUNCTION__);
			p = NULL;
			break;
		}
		p += entity_len;

		*tag = _tag;
		*len = _len;


	} while(0);

	return p;
}

int bertlv_parse_dol_all (unsigned char *input_buffer, int buffer_len, dol_callback_t cb, void *userdata) {
	unsigned char *p = input_buffer;
	unsigned int _tag = 0, _len = 0;

	if(cb == NULL) {
		DEBUG_PRINTF("%s() callback is null!\n", __FUNCTION__);
		return -1;
	}

//	DEBUG_PRINTF("%s() [%d] input_buffer:%p p:%p diff:%d depth:%d\n", __FUNCTION__, __LINE__, input_buffer, p, p - input_buffer,depth);
	do {
		p = bertlv_parse_dol(p, buffer_len, &_tag, &_len);
		if(p == NULL) {
			DEBUG_PRINTF("%s() bertlv_parse error!\n", __FUNCTION__);
			return -1;
		}
		//DEBUG_PRINTF("%s() [%d] input_buffer:%p p:%p diff:%d depth:%d\n", __FUNCTION__, __LINE__, input_buffer, p, p - input_buffer,depth);

		cb(_tag, _len, userdata);

	} while(p - input_buffer < buffer_len);

	return 0;
}

int bertlv_contruct_dol(unsigned int tag, unsigned int len, unsigned char *to_buffer, int buffer_len) {
	unsigned char *p = to_buffer;
	int tag_len = 0;
	int len_len = 0;

	if(tag > 0xFFFFFF) {
		p[0] = (tag >> 24) & 0xFF;
		p[1] = (tag >> 16) & 0xFF;
		p[2] = (tag >>  8) & 0xFF;
		p[3] = (tag >>  0) & 0xFF;
		tag_len = 4;
	} else if (tag > 0xFFFF) {
		p[0] = (tag >> 16) & 0xFF;
		p[1] = (tag >>  8) & 0xFF;
		p[2] = (tag >>  0) & 0xFF;
		tag_len = 3;
	} else if (tag > 0xFF) {
		p[0] = (tag >>  8) & 0xFF;
		p[1] = (tag >>  0) & 0xFF;
		tag_len = 2;
	} else {
		p[0] = (tag >>  0) & 0xFF;
		tag_len = 1;
	}

	p += tag_len;

	if(len > 127) {
		if(len > 0xFFFFFF) {
			len_len = 5;
			p[1] = (len >> 24) & 0xFF;
			p[2] = (len >> 16) & 0xFF;
			p[3] = (len >>  8) & 0xFF;
			p[4] = (len >>  0) & 0xFF;
		} else if (tag > 0xFFFF) {
			len_len = 4;
			p[1] = (len >> 16) & 0xFF;
			p[2] = (len >>  8) & 0xFF;
			p[3] = (len >>  0) & 0xFF;
		} else if (tag > 0xFF) {
			len_len = 3;
			p[1] = (len >>  8) & 0xFF;
			p[2] = (len >>  0) & 0xFF;
		} else {
			len_len = 2;
			p[1] = (len >>  0) & 0xFF;
		}
		p[0] = (len_len - 1)| 0x80; // do not count itself
	} else {
		p[0] = len;
		len_len = 1;
	}

	p += len_len;

	if((tag_len + len_len) > buffer_len) {
		DEBUG_PRINTF("%s() error buffer too short!\n", __FUNCTION__);
		return -1;
	}


	return tag_len + len_len;
}


int print_tlv(unsigned int tag, unsigned int len, unsigned char *data, int depth, void *userdata) {
	int i = 0;
	for(i = 0; i < depth; i++)
		DEBUG_PRINTF("\t");

	DEBUG_PRINTF("[%d] TAG:%x LEN:%02x ", depth, tag, len);
	hd("DATA:", data, len);
	return 0;
}

int print_dol(unsigned int tag, unsigned int len, void *userdata) {
	DEBUG_PRINTF("TAG:%x LEN:%x \n", tag, len);
	return 0;
}

int bertlv_unittest() {

//	unsigned char sample_data1[] = {0x30, 0x01, 0x00};
//	unsigned char sample_data2[] = {0x9F, 0x65, 0x02, 0x12, 0x34};
//	unsigned char sample_data3[] = {0x6F, 0x08, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34};
	unsigned char sample_data4[] = {0x6F, 0x30, 0x84 , 0x0E , 0x32 , 0x50 , 0x41 , 0x59 , 0x2E , 0x53 , 0x59 , 0x53 , 0x2E , 0x44 , 0x44 , 0x46 , 0x30 , 0x31 , 0xA5 , 0x1E , 0xBF , 0x0C , 0x1B , 0x61 , 0x19 , 0x4F , 0x07 , 0xA0 , 0x00 , 0x00 , 0x00 , 0x03 , 0x10 , 0x10, 0x50 , 0x0B , 0x56 , 0x49 , 0x53 , 0x41 , 0x20 , 0x43 , 0x52 , 0x45 , 0x44 , 0x49 , 0x54 , 0x87 , 0x01 , 0x00};

	unsigned char sample_dol[] = {0x9F,0x02, 0x06, 0x9F, 0x03, 0x06, 0x9F, 0x1A, 0x02, 0x95, 0x05, 0x5F, 0x2A, 0x02, 0x9A, 0x03, 0x9C, 0x01, 0x9F, 0x37, 0x04, 0x9F, 0x35, 0x01, 0x9F, 0x45, 0x02, 0x9F, 0x4C, 0x08, 0x9F, 0x34, 0x03, 0x9F, 0x21, 0x03, 0x9F, 0x7C, 0x14};

	unsigned int  len = 0;
//	unsigned char *data = NULL;

//	bertlv_parse(sample_data1, sizeof(sample_data1), &tag, &len, &data);
//	DEBUG_PRINTF("tag: %x, len:%x\n", tag, len);
//	hd("data", data, len);
//
//	bertlv_parse(sample_data2, sizeof(sample_data2), &tag, &len, &data);
//	DEBUG_PRINTF("tag: %x, len:%x\n", tag, len);
//	hd("data", data, len);
//
//	bertlv_parse(sample_data3, sizeof(sample_data3), &tag, &len, &data);
//	DEBUG_PRINTF("tag: %x, len:%x\n", tag, len);
//	hd("data", data, len);

	unsigned char buf[1024] = {0};
	//unsigned char tempdata[] = {0x61, 0x19, 0x4f, 0x07, 0xa0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10, 0x50, 0x0b, 0x56, 0x49, 0x53, 0x41, 0x20, 0x43, 0x52, 0x45, 0x44, 0x49, 0x54, 0x87, 0x01, 0x00};
	//len = bertlv_contruct_tlv(0x0c, 0x02, tempdata, buf, sizeof(buf));
	//hd("out", buf, len);

	bertlv_parse_tlv_all(sample_data4, sizeof(sample_data4), print_tlv, 0, "kentkart_test");



	bertlv_parse_dol_all(sample_dol, sizeof(sample_dol), print_dol, "kentkart_test");



	len = bertlv_contruct_dol(0x9f12, 55, buf, sizeof(buf));
	hd("out", buf, len);




	return 0;
}
