#ifndef COAP_H_
#define COAP_H_

#define COAP_HEADER_LEN                      4 /* | version:0x03 type:0x0C tkl:0xF0 | code | mid:0x00FF | mid:0xFF00 | */
#define COAP_ETAG_LEN                        8 /* The maximum number of bytes for the ETag */
#define COAP_TOKEN_LEN                       8 /* The maximum number of bytes for the Token */
#define COAP_MAX_ACCEPT_NUM                  2 /* The maximum number of accept preferences to parse/store */

#define COAP_HEADER_VERSION                  1
#define COAP_HEADER_VERSION_MASK             0xC0
#define COAP_HEADER_VERSION_POSITION         6
#define COAP_HEADER_TYPE_MASK                0x30
#define COAP_HEADER_TYPE_POSITION            4
#define COAP_HEADER_TOKEN_LEN_MASK           0x0F
#define COAP_HEADER_TOKEN_LEN_POSITION       0

#define COAP_HEADER_OPTION_DELTA_MASK        0xF0
#define COAP_HEADER_OPTION_SHORT_LENGTH_MASK 0x0F

#define COAP_PAYLOAD_START                   0xFF /* payload marker */

/* CoAP message types */
#define COAP_MESSAGE_CON       0 /* confirmable message (requires ACK/RST) */
#define COAP_MESSAGE_NON       1 /* non-confirmable message (one-shot message) */
#define COAP_MESSAGE_ACK       2 /* used to acknowledge confirmable messages */
#define COAP_MESSAGE_RST       3 /* indicates error in received messages */

/* CoAP request methods */
#define COAP_REQUEST_GET       1
#define COAP_REQUEST_POST      2
#define COAP_REQUEST_PUT       3
#define COAP_REQUEST_DELETE    4

/* CoAP option types (be sure to update check_critical when adding options */
#define COAP_OPTION_IF_MATCH        1  /* C, opaque, 0-8 B, (none) */
#define COAP_OPTION_URI_HOST        3  /* C, String, 1-255 B, destination address */
#define COAP_OPTION_ETAG            4  /* E, opaque, 1-8 B, (none) */
#define COAP_OPTION_IF_NONE_MATCH   5  /* empty, 0 B, (none) */
#define COAP_OPTION_URI_PORT        7  /* C, uint, 0-2 B, destination port */
#define COAP_OPTION_LOCATION_PATH   8  /* E, String, 0-255 B, - */
#define COAP_OPTION_URI_PATH        11 /* C, String, 0-255 B, (none) */
#define COAP_OPTION_CONTENT_FORMAT  12 /* E, uint, 0-2 B, (none) */
#define COAP_OPTION_CONTENT_TYPE    COAP_OPTION_CONTENT_FORMAT
#define COAP_OPTION_MAXAGE          14 /* E, uint, 0--4 B, 60 Seconds */
#define COAP_OPTION_URI_QUERY       15 /* C, String, 1-255 B, (none) */
#define COAP_OPTION_ACCEPT          17 /* C, uint,   0-2 B, (none) */
#define COAP_OPTION_LOCATION_QUERY  20 /* E, String,   0-255 B, (none) */
#define COAP_OPTION_PROXY_URI       35 /* C, String, 1-1034 B, (none) */
#define COAP_OPTION_PROXY_SCHEME    39 /* C, String, 1-255 B, (none) */
#define COAP_OPTION_SIZE1           60 /* E, uint, 0-4 B, (none) */

/* option types from draft-ietf-coap-observe-09 */

#define COAP_OPTION_OBSERVE         6 /* E, empty/uint, 0 B/0-3 B, (none) */
#define COAP_OPTION_SUBSCRIPTION    COAP_OPTION_OBSERVE

/* selected option types from draft-core-block-04 */

#define COAP_OPTION_BLOCK2          23 /* C, uint, 0--3 B, (none) */
#define COAP_OPTION_BLOCK1          27 /* C, uint, 0--3 B, (none) */

#define COAP_MAX_OPT                63 /**< the highest option number we know */

//CoAP CODE (c.dd)
#define COAP_CODE_CLASS_REQUEST         0
#define COAP_CODE_CLASS_SUCCESS         2
#define COAP_CODE_CLASS_CLIENT_ERROR    4
#define COAP_CODE_CLASS_SERVER_ERROR    5
#define COAP_CODE_MAKE(CLASS,DETAIL)    (((CLASS) << 5) | (DETAIL))
#define COAP_CODE_GET_CLASS(C)          (((C) >> 5) & 0x03)
#define COAP_CODE_GET_DETAIL(C)         ((C) & 0x1f)

/* CoAP result codes (HTTP-Code / 100 * 40 + HTTP-Code % 100) */

/* As of draft-ietf-core-coap-04, response codes are encoded to base
 * 32, i.e.  the three upper bits determine the response class while
 * the remaining five fine-grained information specific to that class.
 */
#define COAP_RESPONSE_CODE(N) ((((N)/100) << 5) | ((N)%100))

/* Determines the class of response code C */
#define COAP_RESPONSE_CLASS(C) (((C) >> 5) & 0x03)

/* CoAP result codes */
/* 2.xx success */
#define COAP_RESPONSE_200      COAP_RESPONSE_CODE(200)  /* 2.00 OK */
#define COAP_RESPONSE_201      COAP_RESPONSE_CODE(201)  /* 2.01 Created */
#define COAP_RESPONSE_202      COAP_RESPONSE_CODE(202)  /* 2.02 Deleted */
#define COAP_RESPONSE_203      COAP_RESPONSE_CODE(203)  /* 2.03 Valid(Not modified) */
#define COAP_RESPONSE_204      COAP_RESPONSE_CODE(204)  /* 2.04 Changed */
#define COAP_RESPONSE_205      COAP_RESPONSE_CODE(205)  /* 2.05 Content */

/* 4.xx client error */
#define COAP_RESPONSE_400      COAP_RESPONSE_CODE(400)  /* 4.00 Bad Request */
#define COAP_RESPONSE_401      COAP_RESPONSE_CODE(401)  /* 4.01 Unauthorized */
#define COAP_RESPONSE_402      COAP_RESPONSE_CODE(402)  /* 4.02 Bad Option */
#define COAP_RESPONSE_403      COAP_RESPONSE_CODE(403)  /* 4.03 Forbidden */
#define COAP_RESPONSE_404      COAP_RESPONSE_CODE(404)  /* 4.04 Not Found */
#define COAP_RESPONSE_405      COAP_RESPONSE_CODE(405)  /* 4.05 Method Not Allowed */
#define COAP_RESPONSE_406      COAP_RESPONSE_CODE(406)  /* 4.06 Not Acceptable */
#define COAP_RESPONSE_412      COAP_RESPONSE_CODE(412)  /* 4.12 Precondition Failed */
#define COAP_RESPONSE_413      COAP_RESPONSE_CODE(413)  /* 4.13 Request Entity Too Large */
#define COAP_RESPONSE_415      COAP_RESPONSE_CODE(415)  /* 4.15 Unsupported Content-Format */

/* 5.xx server error */
#define COAP_RESPONSE_500      COAP_RESPONSE_CODE(500)  /* 5.00 Internal Server Error */
#define COAP_RESPONSE_501      COAP_RESPONSE_CODE(501)  /* 5.01 Not Implemented */
#define COAP_RESPONSE_502      COAP_RESPONSE_CODE(502)  /* 5.02 Bad Gateway */
#define COAP_RESPONSE_503      COAP_RESPONSE_CODE(503)  /* 5.03 Service Unavailable */
#define COAP_RESPONSE_504      COAP_RESPONSE_CODE(504)  /* 5.04 Gateway Timeout */
#define COAP_RESPONSE_505      COAP_RESPONSE_CODE(505)  /* 5.05 Proxying Not Supported */

/* CoAP media type encoding */
#define COAP_MEDIATYPE_TEXT_PLAIN                     0 /* text/plain (UTF-8) */
#define COAP_MEDIATYPE_APPLICATION_LINK_FORMAT       40 /* application/link-format */
#define COAP_MEDIATYPE_APPLICATION_XML               41 /* application/xml */
#define COAP_MEDIATYPE_APPLICATION_OCTET_STREAM      42 /* application/octet-stream */
#define COAP_MEDIATYPE_APPLICATION_RDF_XML           43 /* application/rdf+xml */
#define COAP_MEDIATYPE_APPLICATION_EXI               47 /* application/exi  */
#define COAP_MEDIATYPE_APPLICATION_JSON              50 /* application/json  */

/* Note that identifiers for registered media types are in the range 0-65535. We
 * use an unallocated type here and hope for the best. */
#define COAP_MEDIATYPE_ANY                         0xff /* any media type */
#endif //COAP_H_
