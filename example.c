#include "coapparser.h"

void TestCoapParser(char *buffer, unsigned int size)
{
    int ir;
    coap_message_parser_t parser;
    unsigned long port;
    unsigned int length;
    char *result;

    ir=CoapMessageParser_Init(&parser,buffer,size);
    if (ir>=0)
    {
        ir=CoapMessageParser_GetIntOption(&parser,COAP_OPTION_URI_PORT,&port);
        port=port;

        result=CoapMessageParser_GetStringOption(&parser,COAP_OPTION_URI_HOST,&length);
        result=(char *)CoapMessageParser_GetBinaryOption(&parser,COAP_OPTION_ETAG,&length);
        result=CoapMessageParser_GetStringOption(&parser,COAP_OPTION_ETAG,&length);
        result=CoapMessageParser_GetStringOption(&parser,COAP_OPTION_URI_QUERY,&length);
        result=CoapMessageParser_GetStringOption(&parser,COAP_OPTION_URI_PATH,&length);
        result=(char *)CoapMessageParser_GetBinaryOption(&parser,COAP_OPTION_IF_MATCH,&length);
        result=result;


        coap_option_iterator_t iterator;
        ir=CoapOptionIterator_GetFirst(&parser,&iterator);
        while (ir>=0)
        {
            unsigned int   number=CoapOptionIterator_GetNumber(&iterator);
            unsigned int   length=CoapOptionIterator_GetLength(&iterator);
            unsigned char* value=CoapOptionIterator_GetPointer(&iterator);

            ir=CoapOptionIterator_GetNext(&iterator);
        }

        char payload[128];
        unsigned int payload_size=CoapMessageParser_GetPayloadSize(&parser);
        char *payload_ptr=(char *)CoapMessageParser_GetPayloadPtr(&parser,NULL);
        payload_size=CoapMessageParser_GetPayload(&parser, payload, sizeof(payload));
        payload_size=payload_size;
    }

    return 0;
}
