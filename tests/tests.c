#include <stdio.h>

#include "unity.h"
#include "../ber-tlv.h"

void setUp() {

}

void tearDown() {

}

void testParseBasicTLV() {
	unsigned char sample_input[] = {0x30, 0x01, 0x00};
	unsigned int  tag = 0;
	unsigned int  len = 0;
	unsigned char *data = NULL;

	bertlv_parse_tlv(sample_input, sizeof(sample_input), &tag, &len, &data);
	
	TEST_ASSERT_EQUAL_UINT(0x30, tag);
	TEST_ASSERT_EQUAL_UINT(1, len);
	TEST_ASSERT_EQUAL_UINT(0x00, data[0]);

}

void testParseExtendedTag() {
	unsigned char sample_input[] = {0x9F, 0x65, 0x02, 0x12, 0x34};
	unsigned char expected_data[] = {0x12, 0x34};
        unsigned int  tag = 0;
        unsigned int  len = 0;
        unsigned char *data = NULL;

        bertlv_parse_tlv(sample_input, sizeof(sample_input), &tag, &len, &data);

        TEST_ASSERT_EQUAL_UINT(0x9f65, tag);
        TEST_ASSERT_EQUAL_UINT(0x02, len);
        TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_data, data, 2);

}


int main() 
{
	UNITY_BEGIN();
	printf("Running Tests!\n");
	RUN_TEST(testParseBasicTLV);
	RUN_TEST(testParseExtendedTag);
	return UNITY_END();
}
