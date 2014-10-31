/*
 *
 * Description:CoAP message parser
 *
 * Author: Liu Xueping <xmxueping@gmail.com>
 *
**/

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "coap.h"
#include "coapparser.h"

#define E_INVALID_ARGUMENT -1
#define E_NO_ENOUGH_BUFFER -2
#define E_BAD_FORMAT       -3
#define E_NOT_FOUND        -4

#ifndef MIN
#define MIN(a, b) ((a) < (b)? (a) : (b))
#endif /* MIN */

int CoapMessageParser_Init(coap_message_parser_t *parser
                          ,unsigned char *buffer
                          ,unsigned int   size)
{
    if (size < COAP_HEADER_LEN)
    {
        //printf("no enough bytes\r\n");
        return E_NO_ENOUGH_BUFFER;//no enough bytes
    }

    if (((COAP_HEADER_VERSION_MASK & buffer[0]) >> COAP_HEADER_VERSION_POSITION) != COAP_HEADER_VERSION)
    {
        //printf("bad version\r\n");
        return E_BAD_FORMAT;//bad version
    }

    if (((COAP_HEADER_TOKEN_LEN_MASK & buffer[0])>>COAP_HEADER_TOKEN_LEN_POSITION) > COAP_TOKEN_LEN)
    {
        //printf("bad token length\r\n");
        return E_BAD_FORMAT;//bad token length
    }

    if ((4+ ((COAP_HEADER_TOKEN_LEN_MASK & buffer[0])>>COAP_HEADER_TOKEN_LEN_POSITION)) > size)
    {
        //printf("bad token length2\r\n");
        return E_NO_ENOUGH_BUFFER;//bad token length
    }

    parser->buffer = buffer;
    parser->size = size;
    parser->option_offset = 4+((COAP_HEADER_TOKEN_LEN_MASK & buffer[0]) >> COAP_HEADER_TOKEN_LEN_POSITION);

    //iterator the options to found the payload offset
    buffer += parser->option_offset;
    size -= parser->option_offset;

#undef  ADVANCE_BUFFER
#define ADVANCE_BUFFER(step)\
    if (size < step)\
    {\
        size=0;\
        continue;\
    } else\
    {\
        size -= step;\
        buffer += + step;\
    }

    while (size>=1)
    {
        unsigned int option_delta;
        unsigned int option_length;

        if (*buffer == COAP_PAYLOAD_START)
        {
            size--;
            break;
        }

        option_delta = (*buffer & 0xf0) >> 4;
        option_length = *buffer & 0x0f;

        switch(option_delta)
        {
        case 15:
            //debug("ignored reserved option delta 15\n");
            return E_BAD_FORMAT;

        case 14:
            /* Handle two-byte value: First, the MSB + 269 is stored as delta value.
            * After that, the option pointer is advanced to the LSB which is handled
            * just like case delta == 13. */
            ADVANCE_BUFFER(1);
            option_delta = ((*buffer & 0xff) << 8) + 269;
            if (option_delta < 269)
            {
                //debug("delta too large\n");
                //printf("delta too large\r\n");
                return E_BAD_FORMAT;
            }
            /* fall through */

        case 13:
            ADVANCE_BUFFER(1);
            option_delta += *buffer & 0xff;
            break;

        default:
            ;
        }

        switch(option_length)
        {
        case 15:
            //debug("found reserved option length 15\n");
            //printf("found reserved option length 15\r\n");
            return E_BAD_FORMAT;

        case 14:
            /* Handle two-byte value: First, the MSB + 269 is stored as delta value.
            * After that, the option pointer is advanced to the LSB which is handled
            * just like case delta == 13. */
            ADVANCE_BUFFER(1);
            option_length = ((*buffer & 0xff) << 8) + 269;
            /* fall through */

        case 13:
            ADVANCE_BUFFER(1);
            option_length += *buffer & 0xff;
            break;

        default:
            ;
        }

        ADVANCE_BUFFER(1);
        /* buffer now points to value, if present */
        if (size < option_length)
        {
            //debug("invalid option length\n");
            //printf("invalid option length\r\n");
            return E_BAD_FORMAT;
        }

        ADVANCE_BUFFER(option_length);
        /* buffer now points to next option or payload, if present */
    }

    parser->payload_offset = parser->size - size;
#undef  ADVANCE_BUFFER

    return 0;
}

int CoapMessageParser_InitNoHeader(coap_message_parser_t *parser
                                  ,unsigned char *buffer
                                  ,unsigned int   size)
{
    parser->buffer = buffer;
    parser->size = size;
    parser->option_offset = 0;

    //iterator the options to found the payload offset
    buffer += parser->option_offset;
    size -= parser->option_offset;

#undef  ADVANCE_BUFFER
#define ADVANCE_BUFFER(step)\
    if (size < step)\
    {\
        size=0;\
        continue;\
    } else\
    {\
        size -= step;\
        buffer += + step;\
    }

    while (size>=1)
    {
        unsigned int option_delta;
        unsigned int option_length;

        if (*buffer == COAP_PAYLOAD_START)
        {
            size--;
            break;
        }

        option_delta = (*buffer & 0xf0) >> 4;
        option_length = *buffer & 0x0f;

        switch(option_delta)
        {
        case 15:
            //debug("ignored reserved option delta 15\n");
            return E_BAD_FORMAT;

        case 14:
            /* Handle two-byte value: First, the MSB + 269 is stored as delta value.
            * After that, the option pointer is advanced to the LSB which is handled
            * just like case delta == 13. */
            ADVANCE_BUFFER(1);
            option_delta = ((*buffer & 0xff) << 8) + 269;
            if (option_delta < 269)
            {
                //debug("delta too large\n");
                //printf("delta too large\r\n");
                return E_BAD_FORMAT;
            }
            /* fall through */

        case 13:
            ADVANCE_BUFFER(1);
            option_delta += *buffer & 0xff;
            break;

        default:
            ;
        }

        switch(option_length)
        {
        case 15:
            //debug("found reserved option length 15\n");
            //printf("found reserved option length 15\r\n");
            return E_BAD_FORMAT;

        case 14:
            /* Handle two-byte value: First, the MSB + 269 is stored as delta value.
            * After that, the option pointer is advanced to the LSB which is handled
            * just like case delta == 13. */
            ADVANCE_BUFFER(1);
            option_length = ((*buffer & 0xff) << 8) + 269;
            /* fall through */

        case 13:
            ADVANCE_BUFFER(1);
            option_length += *buffer & 0xff;
            break;

        default:
            ;
        }

        ADVANCE_BUFFER(1);
        /* buffer now points to value, if present */
        if (size < option_length)
        {
            //debug("invalid option length\n");
            //printf("invalid option length\r\n");
            return E_BAD_FORMAT;
        }

        ADVANCE_BUFFER(option_length);
        /* buffer now points to next option or payload, if present */
    }

    parser->payload_offset = parser->size - size;
#undef  ADVANCE_BUFFER

    return 0;
}

unsigned int  CoapMessageParser_GetId(coap_message_parser_t *parser)
{
    return (parser->buffer[2]<<8) | (parser->buffer[3]);
}

unsigned char CoapMessageParser_GetVersion(coap_message_parser_t *parser)
{
    return (COAP_HEADER_VERSION_MASK & parser->buffer[0])>>COAP_HEADER_VERSION_POSITION;
}

unsigned char CoapMessageParser_GetType(coap_message_parser_t *parser)
{
    return (COAP_HEADER_TYPE_MASK & parser->buffer[0])>>COAP_HEADER_TYPE_POSITION;
}

unsigned char CoapMessageParser_GetCode(coap_message_parser_t *parser)
{
    return parser->buffer[1];
}

unsigned char CoapMessageParser_GetTokenSize(coap_message_parser_t *parser)
{
    return ((COAP_HEADER_TOKEN_LEN_MASK & parser->buffer[0])>>COAP_HEADER_TOKEN_LEN_POSITION);
}

void* CoapMessageParser_GetTokenPtr(coap_message_parser_t *parser,unsigned char *size)
{
    unsigned char token_size=((COAP_HEADER_TOKEN_LEN_MASK & parser->buffer[0])>>COAP_HEADER_TOKEN_LEN_POSITION);
    if (token_size!=0)
    {
        if (size != NULL)
        {
            *size=token_size;
        }
        return &parser->buffer[4];
    }

    return NULL;
}

unsigned char CoapMessageParser_GetToken(coap_message_parser_t *parser, void *buffer, unsigned char size)
{
    unsigned char token_size=((COAP_HEADER_TOKEN_LEN_MASK & parser->buffer[0])>>COAP_HEADER_TOKEN_LEN_POSITION);
    if (token_size!=0)
    {
        if (size>token_size)
        {
            size=token_size;
        }
        memcpy(buffer, &parser->buffer[4], size);
    }

    return token_size;
}

unsigned int CoapMessageParser_GetPayloadSize(coap_message_parser_t *parser)
{
    return parser->size - parser->payload_offset;
}

unsigned int CoapMessageParser_GetPayload(coap_message_parser_t *parser, void *buffer, unsigned int size)
{
    unsigned int payload_size=parser->size - parser->payload_offset;
    if (payload_size!=0)
    {
        if (size>payload_size)
        {
            size=payload_size;
        }
        memcpy(buffer, &parser->buffer[parser->payload_offset], size);
    }

    return payload_size;
}

void* CoapMessageParser_GetPayloadPtr(coap_message_parser_t *parser, unsigned int *size)
{
    unsigned int payload_size=parser->size - parser->payload_offset;
    if (payload_size!=0)
    {
        if (size != NULL)
        {
            *size=payload_size;
        }
        return &parser->buffer[parser->payload_offset];
    }

    return NULL;
}

int CoapMessageParser_GetIntOption(coap_message_parser_t *parser, unsigned int number, unsigned long *value)
{
    unsigned int   current_number=0;
    unsigned char *buffer=parser->buffer + parser->option_offset;
    unsigned int size=parser->size - parser->option_offset;

#undef  ADVANCE_BUFFER
#define ADVANCE_BUFFER(step)\
    if (size < step)\
    {\
        size=0;\
        continue;\
    } else\
    {\
        size -= step;\
        buffer += + step;\
    }

    while (size>=1)
    {
        unsigned int option_delta;
        unsigned int option_length;

        if (*buffer == COAP_PAYLOAD_START)
        {
            break;
        }

        option_delta = (*buffer & 0xf0) >> 4;
        option_length = *buffer & 0x0f;

        switch(option_delta)
        {
        case 15:
            //debug("ignored reserved option delta 15\n");
            return E_BAD_FORMAT;

        case 14:
            /* Handle two-byte value: First, the MSB + 269 is stored as delta value.
            * After that, the option pointer is advanced to the LSB which is handled
            * just like case delta == 13. */
            ADVANCE_BUFFER(1);
            option_delta = ((*buffer & 0xff) << 8) + 269;
            if (option_delta < 269)
            {
                //debug("delta too large\n");
                return E_BAD_FORMAT;
            }
            /* fall through */

        case 13:
            ADVANCE_BUFFER(1);
            option_delta += *buffer & 0xff;
            break;

        default:
            ;
        }

        switch(option_length)
        {
        case 15:
            //debug("found reserved option length 15\n");
            return E_BAD_FORMAT;

        case 14:
            /* Handle two-byte value: First, the MSB + 269 is stored as delta value.
            * After that, the option pointer is advanced to the LSB which is handled
            * just like case delta == 13. */
            ADVANCE_BUFFER(1);
            option_length = ((*buffer & 0xff) << 8) + 269;
            /* fall through */

        case 13:
            ADVANCE_BUFFER(1);
            option_length += *buffer & 0xff;
            break;

        default:
            ;
        }

        ADVANCE_BUFFER(1);
        /* buffer now points to value, if present */
        if (size < option_length)
        {
            //debug("invalid option length\n");
            return E_BAD_FORMAT;
        }

        current_number += option_delta;
        if (current_number ==  number)
        {
            if (value!=NULL)
            {
                int i;

                *value = 0;
                i=0;
                while (i < option_length)
                {
                    *value <<= 8;
                    *value |= buffer[i++];
                }
            }

            return option_length;

        }

        ADVANCE_BUFFER(option_length);
        /* buffer now points to next option or payload, if present */
    }
#undef  ADVANCE_BUFFER

    return E_NOT_FOUND;
}

char* CoapMessageParser_GetStringOption(coap_message_parser_t *parser, unsigned int number, unsigned int *length)
{
    unsigned int   current_number=0;
    unsigned char *buffer=parser->buffer + parser->option_offset;
    unsigned int   size=parser->size - parser->option_offset;

#undef  ADVANCE_BUFFER
#define ADVANCE_BUFFER(step)\
    if (size < step)\
    {\
        size=0;\
        continue;\
    } else\
    {\
        size -= step;\
        buffer += + step;\
    }

    while (size>=1)
    {
        unsigned int option_delta;
        unsigned int option_length;

        if (*buffer == COAP_PAYLOAD_START)
        {
            break;
        }

        option_delta = (*buffer & 0xf0) >> 4;
        option_length = *buffer & 0x0f;

        switch(option_delta)
        {
        case 15:
            //debug("ignored reserved option delta 15\n");
            return NULL;

        case 14:
            /* Handle two-byte value: First, the MSB + 269 is stored as delta value.
            * After that, the option pointer is advanced to the LSB which is handled
            * just like case delta == 13. */
            ADVANCE_BUFFER(1);
            option_delta = ((*buffer & 0xff) << 8) + 269;
            if (option_delta < 269)
            {
                //debug("delta too large\n");
                return NULL;
            }
            /* fall through */

        case 13:
            ADVANCE_BUFFER(1);
            option_delta += *buffer & 0xff;
            break;

        default:
            ;
        }

        switch(option_length)
        {
        case 15:
            //debug("found reserved option length 15\n");
            return NULL;

        case 14:
            /* Handle two-byte value: First, the MSB + 269 is stored as delta value.
            * After that, the option pointer is advanced to the LSB which is handled
            * just like case delta == 13. */
            ADVANCE_BUFFER(1);
            option_length = ((*buffer & 0xff) << 8) + 269;
            /* fall through */

        case 13:
            ADVANCE_BUFFER(1);
            option_length += *buffer & 0xff;
            break;

        default:
            ;
        }

        ADVANCE_BUFFER(1);
        /* buffer now points to value, if present */
        if (size < option_length)
        {
            //debug("invalid option length\n");
            return NULL;
        }

        current_number += option_delta;
        if (current_number ==  number)
        {
            if (length!=NULL)
            {
                *length=option_length;
            }

            return (char*)buffer;

        }

        ADVANCE_BUFFER(option_length);
        /* buffer now points to next option or payload, if present */
    }
#undef  ADVANCE_BUFFER

    return NULL;
}

void* CoapMessageParser_GetBinaryOption(coap_message_parser_t *parser, unsigned int number, unsigned int *length)
{
    unsigned int   current_number=0;
    unsigned char *buffer=parser->buffer + parser->option_offset;
    unsigned int   size=parser->size - parser->option_offset;

#undef  ADVANCE_BUFFER
#define ADVANCE_BUFFER(step)\
    if (size < step)\
    {\
        size=0;\
        continue;\
    } else\
    {\
        size -= step;\
        buffer += + step;\
    }

    while (size>=1)
    {
        unsigned int option_delta;
        unsigned int option_length;

        if (*buffer == COAP_PAYLOAD_START)
        {
            break;
        }

        option_delta = (*buffer & 0xf0) >> 4;
        option_length = *buffer & 0x0f;

        switch(option_delta)
        {
        case 15:
            //debug("ignored reserved option delta 15\n");
            return NULL;

        case 14:
            /* Handle two-byte value: First, the MSB + 269 is stored as delta value.
            * After that, the option pointer is advanced to the LSB which is handled
            * just like case delta == 13. */
            ADVANCE_BUFFER(1);
            option_delta = ((*buffer & 0xff) << 8) + 269;
            if (option_delta < 269)
            {
                //debug("delta too large\n");
                return NULL;
            }
            /* fall through */

        case 13:
            ADVANCE_BUFFER(1);
            option_delta += *buffer & 0xff;
            break;

        default:
            ;
        }

        switch(option_length)
        {
        case 15:
            //debug("found reserved option length 15\n");
            return NULL;

        case 14:
            /* Handle two-byte value: First, the MSB + 269 is stored as delta value.
            * After that, the option pointer is advanced to the LSB which is handled
            * just like case delta == 13. */
            ADVANCE_BUFFER(1);
            option_length = ((*buffer & 0xff) << 8) + 269;
            /* fall through */

        case 13:
            ADVANCE_BUFFER(1);
            option_length += *buffer & 0xff;
            break;

        default:
            ;
        }

        ADVANCE_BUFFER(1);
        /* buffer now points to value, if present */
        if (size < option_length)
        {
            //debug("invalid option length\n");
            return NULL;
        }

        current_number += option_delta;
        if (current_number ==  number)
        {
            if (length!=NULL)
            {
                *length=option_length;
            }

            return buffer;

        }

        ADVANCE_BUFFER(option_length);
        /* buffer now points to next option or payload, if present */
    }
#undef  ADVANCE_BUFFER

    return NULL;
}

int CoapOptionIterator_GetFirst(coap_message_parser_t  *parser
                               ,coap_option_iterator_t *iterator)
{
    //unsigned int   current_number=0;
    unsigned char *buffer=parser->buffer + parser->option_offset;
    unsigned int size=parser->size - parser->option_offset;

#undef  ADVANCE_BUFFER
#define ADVANCE_BUFFER(step)\
    if (size < step)\
    {\
        size=0;\
        continue;\
    } else\
    {\
        size -= step;\
        buffer += + step;\
    }

    while (size>=1)
    {
        unsigned int option_delta;
        unsigned int option_length;

        if (*buffer == COAP_PAYLOAD_START)
        {
            break;
        }

        option_delta = (*buffer & 0xf0) >> 4;
        option_length = *buffer & 0x0f;

        switch(option_delta)
        {
        case 15:
            //debug("ignored reserved option delta 15\n");
            return E_BAD_FORMAT;

        case 14:
            /* Handle two-byte value: First, the MSB + 269 is stored as delta value.
            * After that, the option pointer is advanced to the LSB which is handled
            * just like case delta == 13. */
            ADVANCE_BUFFER(1);
            option_delta = ((*buffer & 0xff) << 8) + 269;
            if (option_delta < 269)
            {
                //debug("delta too large\n");
                return E_BAD_FORMAT;
            }
            /* fall through */

        case 13:
            ADVANCE_BUFFER(1);
            option_delta += *buffer & 0xff;
            break;

        default:
            ;
        }

        switch(option_length)
        {
        case 15:
            //debug("found reserved option length 15\n");
            return E_BAD_FORMAT;

        case 14:
            /* Handle two-byte value: First, the MSB + 269 is stored as delta value.
            * After that, the option pointer is advanced to the LSB which is handled
            * just like case delta == 13. */
            ADVANCE_BUFFER(1);
            option_length = ((*buffer & 0xff) << 8) + 269;
            /* fall through */

        case 13:
            ADVANCE_BUFFER(1);
            option_length += *buffer & 0xff;
            break;

        default:
            ;
        }

        ADVANCE_BUFFER(1);
        /* buffer now points to value, if present */
        if (size < option_length)
        {
            //debug("invalid option length\n");
            return E_BAD_FORMAT;
        }

        if (iterator!=NULL)
        {
            iterator->rest_size=size-option_length;
            iterator->number=option_delta;
            iterator->length=option_length;
            iterator->buffer=buffer;
        }

        return option_length;
    }
#undef  ADVANCE_BUFFER

    return E_NOT_FOUND;
}

int CoapOptionIterator_GetNext(coap_option_iterator_t *iterator)
{
    unsigned char *buffer = iterator->buffer + iterator->length;
    unsigned int size = iterator->rest_size;

#undef  ADVANCE_BUFFER
#define ADVANCE_BUFFER(step)\
    if (size < step)\
    {\
        size=0;\
        continue;\
    } else\
    {\
        size -= step;\
        buffer += + step;\
    }

    while (size >= 1)
    {
        unsigned int option_delta;
        unsigned int option_length;

        if (*buffer == COAP_PAYLOAD_START)
        {
            break;
        }

        option_delta = (*buffer & 0xf0) >> 4;
        option_length = *buffer & 0x0f;

        switch(option_delta)
        {
        case 15:
            //debug("ignored reserved option delta 15\n");
            return E_BAD_FORMAT;

        case 14:
            /* Handle two-byte value: First, the MSB + 269 is stored as delta value.
            * After that, the option pointer is advanced to the LSB which is handled
            * just like case delta == 13. */
            ADVANCE_BUFFER(1);
            option_delta = ((*buffer & 0xff) << 8) + 269;
            if (option_delta < 269)
            {
                //debug("delta too large\n");
                return E_BAD_FORMAT;
            }
            /* fall through */

        case 13:
            ADVANCE_BUFFER(1);
            option_delta += *buffer & 0xff;
            break;

        default:
            ;
        }

        switch(option_length) {
        case 15:
            //debug("found reserved option length 15\n");
            return E_BAD_FORMAT;

        case 14:
            /* Handle two-byte value: First, the MSB + 269 is stored as delta value.
            * After that, the option pointer is advanced to the LSB which is handled
            * just like case delta == 13. */
            ADVANCE_BUFFER(1);
            option_length = ((*buffer & 0xff) << 8) + 269;
            /* fall through */

        case 13:
            ADVANCE_BUFFER(1);
            option_length += *buffer & 0xff;
            break;

        default:
            ;
        }

        ADVANCE_BUFFER(1);
        /* buffer now points to value, if present */
        if (size < option_length)
        {
            //debug("invalid option length\n");
            return E_BAD_FORMAT;
        }

        iterator->rest_size=size-option_length;
        iterator->number += option_delta;
        iterator->length=option_length;
        iterator->buffer=buffer;

        return option_length;
    }
#undef  ADVANCE_BUFFER

    return E_NOT_FOUND;
}

unsigned int CoapOptionIterator_GetNumber(coap_option_iterator_t *iterator)
{
    return iterator->number;
}
unsigned int CoapOptionIterator_GetLength(coap_option_iterator_t *iterator)
{
    return iterator->length;
}
unsigned char* CoapOptionIterator_GetPointer(coap_option_iterator_t *iterator)
{
    return iterator->buffer;
}
int CoapOptionIterator_GetIntValue(coap_option_iterator_t *iterator, unsigned long *value)
{
    *value = 0;
    if (iterator->buffer != NULL)
    {
        int i;

        i=0;
        while (i < iterator->length)
        {
            *value <<= 8;
            *value |= iterator->buffer[i++];
        }
    }

    return iterator->length;
}
unsigned long CoapOptionIterator_GetInt(coap_option_iterator_t *iterator)
{
    unsigned long value = 0;
    if (iterator->buffer != NULL)
    {
        int i;

        i=0;
        while (i < iterator->length)
        {
            value <<= 8;
            value |= iterator->buffer[i++];
        }
    }

    return value;
}
