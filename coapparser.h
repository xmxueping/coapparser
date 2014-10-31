#ifndef COAP_MESSAGE_PARSER_H_
#define COAP_MESSAGE_PARSER_H_

#ifdef __cplusplus
extern "C"
{
#endif

typedef struct coap_message_parser_t
{
    unsigned char *buffer;
    unsigned int   size;
    unsigned int   option_offset;
    unsigned int   payload_offset;
}coap_message_parser_t,TCoapMessageParser;

int CoapMessageParser_Init(coap_message_parser_t *parser
                          ,unsigned char *buffer
                          ,unsigned int size);

unsigned int  CoapMessageParser_GetId(coap_message_parser_t *parser);
unsigned char CoapMessageParser_GetVersion(coap_message_parser_t *parser);
unsigned char CoapMessageParser_GetType(coap_message_parser_t *parser);
unsigned char CoapMessageParser_GetCode(coap_message_parser_t *parser);
unsigned char CoapMessageParser_GetTokenSize(coap_message_parser_t *parser);
unsigned char CoapMessageParser_GetToken(coap_message_parser_t *parser, void *buffer, unsigned char size);
unsigned int  CoapMessageParser_GetPayloadSize(coap_message_parser_t *parser);
unsigned int  CoapMessageParser_GetPayload(coap_message_parser_t *parser, void *buffer, unsigned int size);
void* CoapMessageParser_GetTokenPtr(coap_message_parser_t *parser,unsigned char *size);
void* CoapMessageParser_GetPayloadPtr(coap_message_parser_t *parser, unsigned int *size);

int   CoapMessageParser_GetIntOption(coap_message_parser_t *parser, unsigned int number, unsigned long *value);
char* CoapMessageParser_GetStringOption(coap_message_parser_t *parser, unsigned int number, unsigned int *length);
void* CoapMessageParser_GetBinaryOption(coap_message_parser_t *parser, unsigned int number, unsigned int *length);

typedef struct coap_option_iterator_t
{
    //rest size
    unsigned char  rest_size;
    //option info
    unsigned int   number;
    unsigned int   length;
    unsigned char *buffer;
}coap_option_iterator_t,TCoapOptionIterator;

int   CoapOptionIterator_GetFirst(coap_message_parser_t  *parser
                                 ,coap_option_iterator_t *iterator);
int   CoapOptionIterator_GetNext(coap_option_iterator_t *iterator);

unsigned int   CoapOptionIterator_GetNumber(coap_option_iterator_t *iterator);
unsigned int   CoapOptionIterator_GetLength(coap_option_iterator_t *iterator);
unsigned char* CoapOptionIterator_GetPointer(coap_option_iterator_t *iterator);
int            CoapOptionIterator_GetIntValue(coap_option_iterator_t *iterator, unsigned long *value);
unsigned long  CoapOptionIterator_GetInt(coap_option_iterator_t *iterator);

/*
 * init parser with buffer without CoAP header
 * should not call CoapMessageParser_Get*(Id,Version,Type,Code,TokenSize,Token) functions
 */
int CoapMessageParser_InitNoHeader(coap_message_parser_t *parser
                                  ,unsigned char *buffer
                                  ,unsigned int   size);

#ifdef __cplusplus
}
#endif

#endif //COAP_MESSAGE_PARSER_H_
