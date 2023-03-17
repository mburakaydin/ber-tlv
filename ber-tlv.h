/*
 * ber-tlv.h
 *
 *  Created on: 13 Oct 2016
 *      Author: burak.aydin
 */

#ifndef BER_TLV_H_
#define BER_TLV_H_


typedef int (*tlv_callback_t)(unsigned int tag, unsigned int len, unsigned char *data, int depth, void *userdata);

typedef int (*dol_callback_t)(unsigned int tag, unsigned int len, void *userdata);

extern int print_tlv(unsigned int tag, unsigned int len, unsigned char *data, int depth, void *userdata);


/*!
 * checks whether the tag is constructed or not
 * \returns 1 if constructed, else 0
 */
extern int bertlv_checktag_isconstructed(unsigned int tag);

/*!
 * bertlv_parse_tlv
 * parses tlv data into tag length and value.
 * No memory allocation exists in the function. Returned data is the address over input_buffer
 * \param[in] input_buffer Raw tlv data input
 * \param[in] buffer_len buffer length
 * \param[out] tag  tag of data
 * \param[out] len  length of data
 * \param[out] data pointer of data
 * \returns pointer to the end of the TLV object. NULL if there is a parsing problem
 */
extern unsigned char * bertlv_parse_tlv(unsigned char *input_buffer, int buffer_len, unsigned int *tag, unsigned int *len, unsigned char **data);

/*!
 * bertlv_parse_tlv_all
 */
extern int bertlv_parse_tlv_all (unsigned char *input_buffer, int buffer_len, tlv_callback_t cb, int depth, void *userdata);


/*!
 * bertlv_contruct_tlv
 */
extern int bertlv_construct_tlv(unsigned int tag, unsigned int len, unsigned char *data, unsigned char **to_buffer, unsigned int *buffer_len);

extern int bertlv_construct_tlv2(unsigned int tag, unsigned int len, unsigned char *data_buffer, unsigned int *data_buffer_len);


/*!
 * bertlv_parse_dol_all
 * \todo fill documentation
 */
extern int bertlv_parse_dol_all (unsigned char *input_buffer, int buffer_len, dol_callback_t cb, void *userdata);


extern int bertlv_buildlen(uint16_t len, uint8_t **bufPtr, uint8_t *endPtr, uint8_t *writtenBytes);


extern int bertlv_build_len(uint16_t len, uint8_t *buf, uint32_t *buflen);

extern int bertlv_build_tag(unsigned int tag, unsigned char *buffer, unsigned int *buf_len);

#endif /* BER_TLV_H_ */
