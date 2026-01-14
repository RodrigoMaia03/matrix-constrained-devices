#!/usr/bin/env python3

# This file is part of the CoMatrix project.
#
# CoMatrix Gateway - enables usage of the Matrix protocol for constrained IoT devices
#
# 2021 Tobi Buchberger <tobias.buchberger@fh-campuswien.ac.at>
# 2021 Ines Kramer <ines.kramer@fh-campuswien.ac.at>
#
# CoMatrix is free software, this file is published under the GPLv3 license as
# described in the accompanying LICENSE file.
# This Software is for educational purposes only, do not use in production environments.

"""
CoMatrix gateway enables the usage of the Matrix CS-API for constrained IoT devices via CoAP and CBOR in e.g. a 6LoWPAN network.

The CoMatrix gateway is a CoAP server which acts as HTTP forward proxy ("cross-proxy").
It creates valid Matrix CS-API (r0.6.1) HTTP requests based on incoming CoAP requests.
By default it listens on all addresses and the standard CoAP port (5683).
Unfortunately, the gateway currently only supports plaintext CoAP because DTLS is only supported for CoAP clients in aiocoap
at the moment.
The IP address and port to listen on can be configured by passing CLI arguments.
Caution: in case of a IPv6 link-local address the zone identifier needs to be specified (e.g. `fe80::1%lowpan0`).

```
$ ./comatrix_gateway.py -h
usage: comatrix_gateway.py [-h] [-i IP] [-p PORT]

CoMatrix gateway - enables usage of the Matrix protocol for constrained IoT
devices

optional arguments://
  -h, --help            show this help message and exit
  -i IP, --ip IP        IP address to listen on (default: ::)
  -p PORT, --port PORT  Port to listen on (default: 5683)
```

The gateway provides the following CoAP resources:
- `coap://[::]/.well-known/core` - Lists all available resources
- `coap://[::]/register` - Enables registration of a new Matrix-Synapse user
- `coap://[::]/login` - Enables login of an existing Matrix-Synapse user
- `coap://[::]/join` - Enables joining of a Matrix room after an invitation
- `coap://[::]/getmsg` - Enables retrieving of the last message sent to a Matrix room
- `coap://[::]/send` - Enables sending of a message to a Matrix room
- `coap://[::]/time` - Non-Matrix-related resource, provides a Unix timestamp
- `coap://[::]/logout` - Enables logout of an existing Matrix-Synapse user

Detailed descriptions of the resources are available in the corresponding classes.

By default some debugging information is logged, e.g. information contained in the CoAP request like content format
and message type.
"""

import argparse
import logging

import asyncio
import random

import aiocoap.resource as resource
import aiocoap

# CBOR
from cbor2 import dumps, loads
# HTTP
import requests
import json
# To generate current Unix timestamp
import time
# regular expressions
import re

# TODO: Set (Optional) Hardcoded access token for Matrix Synapse HS
ACCESS_TOKEN_HC = 'syt_dGNjX3VzZXI_TvfjcrCmHiqVQshCJihv_1Zpaa1'
CONTENT_FORMAT_CBOR = 60
CONTENT_FORMAT_TEXT_PLAIN = 0
# Matrix suggests CoAP option 256 to transport access tokens
# cf. https://github.com/matrix-org/matrix-doc/blob/7d20c1d9c19972fa63d1d9c124c3656928c28c29/proposals/3079-low-bandwidth-csapi.md#access-tokens
ACCESS_TOKEN_OPTION_ID = 256


# Future Work: add Synapse information via gateway? Currently info needs to be provided by client via Proxy-Uri option
# MATRIX_HS_HOST_IP = 'localhost'
# MATRIX_HS_PORT = '8008'
# MATRIX_HS_NAME = 'synapse.name'
# MATRIX_ROOM_ID = '!test:synapse.name'


class RegistrationResource(resource.Resource):
    """
    The RegistrationResource enables the registration of a new Matrix user at a specific Matrix-Synapse homeserver
    via a CoAP request. It waits for CoAP _POST_ requests (CoAPS is currently not supported by aiocoap on server-side).
    These requests need to contain the CoAP options "Content-Format" and "Proxy-Uri". The Content-Format needs to be set
    to `application/cbor` and the Proxy-Uri needs to contain the Matrix-Synapse homeserver URL. It is recommended to send
    the CoAP request as Message type _CONfirmable_, to be sure the client receives the CoAP response (i.e. if the
    registration was successful or not). Further a payload is required in the CoAP request. The information contained in
    the Proxy-Uri option and the payload data are used to construct the HTTP request which conforms with the Matrix
    CS-API to register a new user at the target Matrix-Synapse homeserver.

    The homeserver URL may be supplied in short or full format via the Proxy-Uri CoAP option:
    - Short URL format:
        - `http(s)://IP_domain:PORT/4` => e.g. `http://localhost:8008/4`
        - The port is optional and only necessary if non-standard HTTP/HTTPS ports are used
        - Short URLs are provided by the CoMatrix gateway to reduce the amount of data to be transferred via
        a constrained network (e.g. 802.15.4/6LoWPAN).
        - This short URL is defined in "MSC3079: Low Bandwidth Client-Server API" in "Appendix B: CoAP Path Enums".
        - cf. https://github.com/matrix-org/matrix-doc/blob/7d20c1d9c19972fa63d1d9c124c3656928c28c29/proposals/3079-low-bandwidth-csapi.md#appendix-b-coap-path-enums
    - Full URL format:
        - `http(s)://IP_domain:PORT/_matrix/client/r0/register` => e.g. `http://localhost:8008/_matrix/client/r0/register`
        - cf. https://matrix.org/docs/spec/client_server/r0.6.1#post-matrix-client-r0-register

    To register a Matrix user at a Synapse homeserver there needs to be a payload in the following format in the CoAP
    request (encoded as CBOR):
    - `{"username":"<username>", "password":"<password>", "auth": {"type":"m.login.dummy"}}`
        - `<username>` and `<password>` can be freely chosen, but `"auth": {"type":"m.login.dummy"}` is fixed.
            - Information regarding the JSON body parameter `"auth"`:
                - > "Additional authentication information for the user-interactive authentication API.
                Note that this information is not used to define how the registered user should be authenticated, but is
                instead used to authenticate the register call itself."
                (cf. https://matrix.org/docs/spec/client_server/r0.6.1#post-matrix-client-r0-register )
                - > "Dummy authentication always succeeds and requires no extra parameters.
                Its purpose is to allow servers to not require any form of User-Interactive
                Authentication to perform a request."
                (cf. https://matrix.org/docs/spec/client_server/r0.6.1#dummy-auth )

    Every CoAP request will be checked for the correct CoAP options and payload format.
    If incorrect, a CoAP response with a code from class 4 (client error) will be sent (e.g. 4.00/BAD_REQUEST).
    If options and payload are ok, a HTTP request will be sent to the Synapse homeserver based on the supplied data.

    This HTTP request can be successful or unsuccessful. If it was successful, the CoAP response code is 2.04/CHANGED.
    The CoAP response payload looks as follows:
    - The full payload of the HTTP response (sent by Synapse) after registering looks like this:
        - e.g. `{"user_id":"@testuser:synapse.name","home_server":"synapse.name","access_token":"XXXYYYZZZZ","device_id":"ACAXYHVGDE"}`
        - This contains information which is already available at the client (i.e. username and homeserver name are
        necessary to send a valid CoAP request) and is therefore filtered for the CoAP response. The relevant information
        for the client on a constrained device is the access token. Further this reduces the necessary packet size for
        the CoAP response.
        - Device IDs are currently not used. For more information regarding device IDs see:
            - https://matrix.org/docs/spec/client_server/r0.6.1#relationship-between-access-tokens-and-devices
            - https://matrix.org/docs/spec/index#devices
    - Therefore the response includes only the access token in the following format (encoded as CBOR):
        - e.g. `{'access_token': 'XXXYYYZZZ'}`

    If the HTTP request was unsuccessful, the CoAP response code is 4.00/BAD_REQUEST. The payload contains the HTTP
    response JSON (from Synapse) encoded as CBOR.
    """

    def __init__(self):
        super().__init__()

    async def render_post(self, request):
        # print_request_info(request)
        log_request_info(request)

        # Verify if Payload is CBOR => i.e. content type is CBOR
        if request.opt.content_format != CONTENT_FORMAT_CBOR:
            # message type is managed by client side
            return aiocoap.Message(code=aiocoap.UNSUPPORTED_CONTENT_FORMAT, payload=b"CBOR payload expected!",
                                   content_format=CONTENT_FORMAT_TEXT_PLAIN)
        # Verify if Proxy-Uri is contained in request
        elif not request.opt.proxy_uri:
            return aiocoap.Message(code=aiocoap.BAD_REQUEST, payload=b"Missing Proxy-Uri!",
                                   content_format=CONTENT_FORMAT_TEXT_PLAIN)
        # Verify if payload is not empty
        elif not request.payload:
            return aiocoap.Message(code=aiocoap.BAD_REQUEST, payload=b"Missing payload!",
                                   content_format=CONTENT_FORMAT_TEXT_PLAIN)
        else:
            # construct Matrix-Synapse URL for HTTP request
            proxy_uri = request.opt.proxy_uri
            proxy_uri_parts = proxy_uri.split('/')
            # pattern matches for /4 at the end of a string => $ is endmarker
            re_result = re.fullmatch(r'.*/4$', proxy_uri)
            # Case short URL in CoAP request
            if re_result is not None and len(proxy_uri_parts) == 4:
                # i.e. 'http:' or 'https:'
                protocol = proxy_uri_parts[0]
                # i.e. hostname / domain / IP; optionally including a port
                host_port = proxy_uri_parts[2]
                # Build together full matrix register API URL
                proxy_uri_new = protocol + '//' + host_port + '/_matrix/client/r0/register'
            # Case full URL in request
            elif "/_matrix/client/r0/register" in proxy_uri:
                proxy_uri_new = proxy_uri
            else:
                return aiocoap.Message(code=aiocoap.BAD_REQUEST, payload=b"Unsupported Proxy-Uri!",
                                       content_format=CONTENT_FORMAT_TEXT_PLAIN)
            # received CBOR to json/dict
            json_payload = loads(request.payload)
            logging.info('CoAP request payload (JSON): %s' % json_payload)

        # check JSON for necessary keys for registration
        try:
            if 'username' not in json_payload or 'password' not in json_payload \
                    or not json_payload['auth']['type'] == "m.login.dummy":
                return aiocoap.Message(code=aiocoap.NOT_ACCEPTABLE,
                                       payload=b"Username/password missing or wrong auth.type!",
                                       content_format=CONTENT_FORMAT_TEXT_PLAIN)
        # Case if auth/type is not available in json
        except KeyError as e:
            payload = b"Wrong CBOR content!"
            return aiocoap.Message(code=aiocoap.BAD_REQUEST, payload=payload, content_format=CONTENT_FORMAT_TEXT_PLAIN)

        # send HTTP request to Matrix-Synapse
        try:
            # json = json_payload (i.e. Content-Type: application/json) instead of 'data = json_payload'
            # "Using the json parameter in the request will change the Content-Type in the header to application/json."
            http_response = requests.post(proxy_uri_new, json=json_payload, timeout=10)
        except requests.exceptions.RequestException as e:
            payload = b"Request to HS not possible!"
            return aiocoap.Message(code=aiocoap.BAD_REQUEST, payload=payload, content_format=CONTENT_FORMAT_TEXT_PLAIN)
        logging.info('HTTP(S) response code: %d => payload: %s' % (http_response.status_code, http_response.text))

        # verify if http_response is HTTP 200 and contains 'access_token' JSON field
        if http_response.status_code == 200 and "access_token" in http_response.text:
            response_json = json.loads(http_response.text)
            # extract access token from HTTP response
            access_token = response_json['access_token']
            # shorten CoAP response payload to just contain access_token
            payload_json = {'access_token': access_token}
            cbor_response = dumps(payload_json)
            # Answer CoAP request or after received ok from Synapse => HTTP 200 + JSON with access token
            # rfc7252#section-10.1.4: If the action performed by the POST method does not result in a
            #    resource that can be identified by a URI, a 2.04 (Changed) response
            #    MUST be returned to the client.  If a resource has been created on
            #    the origin server, a 2.01 (Created) response MUST be returned.
            return aiocoap.Message(code=aiocoap.CHANGED, payload=cbor_response, content_format=CONTENT_FORMAT_CBOR)
        else:
            # send http response text (from Synapse) as CBOR
            cbor_response = dumps(json.loads(http_response.text))
            return aiocoap.Message(code=aiocoap.BAD_REQUEST, payload=cbor_response, content_format=CONTENT_FORMAT_CBOR)


class LoginResource(resource.Resource):
    """
    The LoginResource enables the registration of a new Matrix user at a specific Matrix-Synapse homeserver
    via a CoAP request. It waits for CoAP _POST_ requests (CoAPS is currently not supported by aiocoap on server-side).
    These requests need to contain the CoAP options "Content-Format" and "Proxy-Uri". The Content-Format needs to be set
    to `application/cbor` and the Proxy-Uri needs to contain the Matrix-Synapse homeserver URL. It is recommended to send
    the CoAP request as Message type _CONfirmable_, to be sure the client receives the CoAP response (i.e. if the
    login was successful or not). Further a payload is required in the CoAP request. The information of the
    Proxy-Uri option and the payload data are used to construct the HTTP request which conforms with the Matrix CS-API
    to login an existing user at the target Matrix-Synapse homeserver.

    The homeserver URL may be supplied in short or full format via the Proxy-Uri CoAP option:
    - Short URL format:
        - `http(s)://IP_domain:PORT/1` => e.g. `http://localhost:8008/1`
        - The port is optional and only necessary if non-standard HTTP/HTTPS ports are used
        - This short URL is defined in "MSC3079: Low Bandwidth Client-Server API" in "Appendix B: CoAP Path Enums"
        - cf. https://github.com/matrix-org/matrix-doc/blob/7d20c1d9c19972fa63d1d9c124c3656928c28c29/proposals/3079-low-bandwidth-csapi.md#appendix-b-coap-path-enums
    - Full URL format:
        - `http(s)://IP_domain:PORT/_matrix/client/r0/login` => e.g. `http://localhost:8008/_matrix/client/r0/login`
        - cf. https://matrix.org/docs/spec/client_server/r0.6.1#post-matrix-client-r0-login

    To login a Matrix user at a Synapse homeserver there needs to be a payload in the following format in the CoAP
    request (encoded as CBOR):
    - `{"type":"m.login.password", "identifier": {"type":"m.id.user", "user":"<username>"}, "password":"<password>"}`
        - `<username>` and `<password>` can be freely chosen, but `"type":"m.login.password"` and `"type":"m.id.user"`
        are fixed (only password-based login is supported currently).

    Every CoAP request will be checked for the correct CoAP options and payload format.
    If incorrect, a CoAP response with a code from class 4 (client error) will be sent (e.g. 4.00/BAD_REQUEST).
    If options and payload are ok, a HTTP request will be sent to the Synapse homeserver based on the supplied data.

    This HTTP request can be successful or unsuccessful. If it was successful, the CoAP response code is 2.04/CHANGED.
    The CoAP response payload looks as follows:
    - The full payload of the HTTP response (sent by Synapse) after registering looks like this:
        - e.g. `{"user_id":"@example:synapse.name","access_token":"XXXYYYZZZ","home_server":"synapse.name","device_id":"VJEHIKSYUX"}`
        - This contains information which is already available at the client (i.e. username and homeserver name are
        necessary to send a valid CoAP request) and is therefore filtered for the CoAP response. The relevant information
        for the client on a constrained device is the access token. Further this reduces the necessary packet size for
        the CoAP response.
        - Device IDs are currently not used. For more information see:
            - https://matrix.org/docs/spec/client_server/r0.6.1#relationship-between-access-tokens-and-devices
            - https://matrix.org/docs/spec/index#devices
    - Therefore the response only includes the access token in the following format (encoded as CBOR):
        - e.g. `{'access_token': 'XXXYYYZZZ'}`

    If the HTTP request was unsuccessful, the CoAP response code is 4.00/BAD_REQUEST. The payload contains the HTTP
    response JSON (from Synapse) encoded as CBOR.
    """

    def __init__(self):
        super().__init__()

    async def render_post(self, request):
        # print_request_info(request)
        log_request_info(request)

        # Verify if Payload is CBOR => i.e. content type is CBOR
        if request.opt.content_format != CONTENT_FORMAT_CBOR:
            # message type is managed by client side
            return aiocoap.Message(code=aiocoap.UNSUPPORTED_CONTENT_FORMAT, payload=b"CBOR payload expected!",
                                   content_format=CONTENT_FORMAT_TEXT_PLAIN)
        # Verify if Proxy-Uri is contained in request
        elif not request.opt.proxy_uri:
            return aiocoap.Message(code=aiocoap.BAD_REQUEST, payload=b"Missing Proxy-Uri!",
                                   content_format=CONTENT_FORMAT_TEXT_PLAIN)
        # Verify if payload is not empty
        elif not request.payload:
            return aiocoap.Message(code=aiocoap.BAD_REQUEST, payload=b"Missing payload!",
                                   content_format=CONTENT_FORMAT_TEXT_PLAIN)
        else:
            proxy_uri = request.opt.proxy_uri
            proxy_uri_parts = proxy_uri.split('/')
            # pattern matches for /1 at the end of a string => $ is endmarker
            re_result = re.fullmatch(r'.*/1$', proxy_uri)
            # Case short URL used in CoAP request
            if re_result is not None and len(proxy_uri_parts) == 4:
                # i.e. http: or https:
                protocol = proxy_uri_parts[0]
                # i.e. hostname / domain / IP; optionally including a port
                host_port = proxy_uri_parts[2]
                # Build together full matrix send API URL
                proxy_uri_new = protocol + '//' + host_port + '/_matrix/client/r0/login'
            elif "/_matrix/client/r0/login" in proxy_uri:
                proxy_uri_new = proxy_uri
            else:
                return aiocoap.Message(code=aiocoap.BAD_REQUEST, payload=b"Unsupported Proxy-Uri!",
                                       content_format=CONTENT_FORMAT_TEXT_PLAIN)

            # received CBOR to json/dict
            json_payload = loads(request.payload)
            logging.info('CoAP request payload (JSON): %s' % json_payload)

        # check JSON for necessary keys for registration ("user" in JSON instead of "identifier" -> deprecated!)
        # try:
        #     if 'user' not in json_payload or 'password' not in json_payload \
        #             or not json_payload['type'] == "m.login.password":
        #         return aiocoap.Message(code=aiocoap.NOT_ACCEPTABLE,
        #                                payload=b"Username/password missing or wrong type!",
        #                                content_format=CONTENT_FORMAT_TEXT_PLAIN)
        # check JSON for necessary keys for registration
        try:
            if 'user' not in json_payload['identifier'] or 'password' not in json_payload \
                    or json_payload['type'] != "m.login.password" or json_payload['identifier']['type'] != "m.id.user":
                return aiocoap.Message(code=aiocoap.NOT_ACCEPTABLE,
                                       payload=b"Username/password missing or wrong type!",
                                       content_format=CONTENT_FORMAT_TEXT_PLAIN)
        # Case if auth/type or identifier/type is not available in json
        except KeyError as e:
            payload = b"Wrong CBOR content!"
            return aiocoap.Message(code=aiocoap.BAD_REQUEST, payload=payload,
                                   content_format=CONTENT_FORMAT_TEXT_PLAIN)

        # Send HTTP request to Synapse
        try:
            # json = json_payload (i.e. Content-Type: application/json) instead of data = json_payload
            # "Using the json parameter in the request will change the Content-Type in the header to application/json."
            http_response = requests.post(proxy_uri_new, json=json_payload, timeout=10)
        except requests.exceptions.RequestException as e:
            payload = b"Request to HS not possible!"
            return aiocoap.Message(code=aiocoap.BAD_REQUEST, payload=payload, content_format=CONTENT_FORMAT_TEXT_PLAIN)
        logging.info('HTTP(S) response code: %d => payload: %s' % (http_response.status_code, http_response.text))

        # verify if http_response is HTTP 200 and contains 'access_token' JSON key
        if http_response.status_code == 200 and "access_token" in http_response.text:
            response_json = json.loads(http_response.text)
            # extract access token from HTTP response
            access_token = response_json['access_token']
            # shorten response payload to just contain access_token
            payload_json = {'access_token': access_token}
            cbor_response = dumps(payload_json)
            # Answer CoAP request after received ok from Synapse => HTTP 200 + JSON with access token
            # rfc7252#section-10.1.4: If the action performed by the POST method does not result in a
            #    resource that can be identified by a URI, a 2.04 (Changed) response
            #    MUST be returned to the client.  If a resource has been created on
            #    the origin server, a 2.01 (Created) response MUST be returned.
            return aiocoap.Message(code=aiocoap.CHANGED, payload=cbor_response, content_format=CONTENT_FORMAT_CBOR)
        else:
            # send http response text (from Synapse) as CBOR
            cbor_response = dumps(json.loads(http_response.text))
            return aiocoap.Message(code=aiocoap.BAD_REQUEST, payload=cbor_response, content_format=CONTENT_FORMAT_CBOR)


class JoinResource(resource.Resource):
    """
    The JoinResource enables the joining of a new Matrix room at a specific Matrix-Synapse homeserver via a CoAP request
    (after the user received an invitation for the room). It waits for CoAP _POST_ requests (CoAPS is currently not
    supported by aiocoap on server-side). These requests need to contain the CoAP option "Proxy-Uri" and (_optionally_)
    a custom CoAP option with ID 256. The option with ID 256 is suggested by "MSC3079: Low Bandwidth CS API" and is
    required because RFC7252 defines no option mapping for `Authorization` headers (IDs 0-255 are reserved for IETF review).
    The plain access token must be used in this CoAP option without a prefix (e.g. "Bearer "). If option 256 is not
    contained in the CoAP request, the gateway will add a hardcoded access token for the HTTP request.
    The Proxy-Uri needs to contain the Matrix-Synapse homeserver URL. It is recommended to send the CoAP request as
    message type _CONfirmable_, to be sure the client receives the CoAP response (i.e. if the joining of the room was
    successful or not). The information of the Proxy-Uri option is used to construct the HTTP request which conforms
    with the Matrix CS-API to join a Matrix room after an invite from another user at the target Matrix-Synapse
    homeserver.

    The homeserver URL may be supplied in short or full format via the Proxy-Uri CoAP option:
    - Short URL format:
        - `http(s)://IP_domain:PORT/K/<room_id>` => e.g. `http://localhost:8008/K/!SdTxduioYPCZWsKsRC:synapse.name`
        - The port is optional and only necessary if non-standard HTTP/HTTPS ports are used
        - This short URL is defined in "MSC3079: Low Bandwidth Client-Server API" in "Appendix B: CoAP Path Enums"
        - cf. https://github.com/matrix-org/matrix-doc/blob/7d20c1d9c19972fa63d1d9c124c3656928c28c29/proposals/3079-low-bandwidth-csapi.md#appendix-b-coap-path-enums
    - Full URL format:
        - `http(s)://IP_domain:PORT/_matrix/client/r0/rooms/<room_id>/join` => e.g. `http://localhost:8008/_matrix/client/r0/rooms/!SdTxduioYPCZWsKsRC:synapse.name/join`
        - cf. https://matrix.org/docs/spec/client_server/r0.6.1#post-matrix-client-r0-rooms-roomid-join

    To join a Matrix room at a Synapse homeserver there is no payload required in the CoAP request.

    Every CoAP request will be checked for the correct CoAP options.
    If incorrect, a CoAP response with a code from class 4 (client error) will be sent (e.g. 4.00/BAD_REQUEST).
    If the options are ok, a HTTP request will be sent to the Synapse homeserver based on the supplied data.

    This HTTP request can be successful or unsuccessful. If it was successful, the CoAP response code is 2.04/CHANGED.
    The CoAP response payload looks as follows:
    - The payload of the HTTP response (sent by Synapse) after registering looks like this:
        e.g. `{"room_id":"!SdTxduioYPCZWsKsRC:synapse.name"}`
    - The CoAP response contains the room ID encoded as CBOR:
        e.g. `{"room_id":"!SdTxduioYPCZWsKsRC:synapse.name"}`

    If the HTTP request was unsuccessful, the CoAP response code is 4.00/BAD_REQUEST. The payload contains the HTTP
    response JSON (from Synapse) encoded as CBOR.
    """

    def __init__(self):
        super().__init__()

    async def render_post(self, request):
        # print_request_info(request)
        log_request_info(request)

        # Verify if Proxy-Uri is contained in request
        if not request.opt.proxy_uri:
            return aiocoap.Message(code=aiocoap.BAD_REQUEST, payload=b"Missing Proxy-Uri!",
                                   content_format=CONTENT_FORMAT_TEXT_PLAIN)

        # Check for access token in request or use hardcoded access token
        # access token length seems to vary, therefore just checking for presence of option 256 in CoAP header
        if request.opt.get_option(ACCESS_TOKEN_OPTION_ID):
            access_token_option = request.opt.get_option(ACCESS_TOKEN_OPTION_ID)[0].value
            access_token = access_token_option.decode("utf-8")
        else:
            access_token = ACCESS_TOKEN_HC
        headers = {"Authorization": "Bearer " + access_token}

        # Verify Proxy-Uri format
        proxy_uri = request.opt.proxy_uri
        if "/K/" in proxy_uri:
            proxy_uri_parts = proxy_uri.split('/')
            protocol = proxy_uri_parts[0]
            host_port = proxy_uri_parts[2]
            room_id = proxy_uri_parts[4]
            proxy_uri_new = protocol + '//' + host_port + '/_matrix/client/r0/rooms/' + room_id + '/join'
        elif "/_matrix/client/r0/rooms/" in proxy_uri:
            proxy_uri_new = proxy_uri
        else:
            return aiocoap.Message(code=aiocoap.BAD_REQUEST, payload=b"Unsupported Proxy-Uri!",
                                   content_format=CONTENT_FORMAT_TEXT_PLAIN)

        # Send HTTP request to join Matrix room to Synapse
        try:
            http_response = requests.post(proxy_uri_new, headers=headers, timeout=10)
        except requests.exceptions.RequestException as e:
            payload = b"Request to HS not possible!"
            return aiocoap.Message(code=aiocoap.BAD_REQUEST, payload=payload, content_format=CONTENT_FORMAT_TEXT_PLAIN)
        logging.info('HTTP(S) response code: %d => payload: %s' % (http_response.status_code, http_response.text))

        cbor_response = dumps(json.loads(http_response.text))

        # verify if http_response is HTTP 200 and contains 'room_id' JSON field
        if http_response.status_code == 200 and "room_id" in http_response.text:
            # rfc7252#section-10.1.4: If the action performed by the POST method does not result in a
            #    resource that can be identified by a URI, a 2.04 (Changed) response
            #    MUST be returned to the client.  If a resource has been created on
            #    the origin server, a 2.01 (Created) response MUST be returned.
            return aiocoap.Message(code=aiocoap.CHANGED, payload=cbor_response, content_format=CONTENT_FORMAT_CBOR)
        else:
            # send http response text (from Synapse) as CBOR
            return aiocoap.Message(code=aiocoap.BAD_REQUEST, payload=cbor_response, content_format=CONTENT_FORMAT_CBOR)


class MessagesResource(resource.Resource):
    """
    The MessagesResource enables the receiving of the last (text) message sent to a Matrix room at a specific
    Matrix-Synapse homeserver via a CoAP request. It waits for CoAP _GET_ requests (CoAPS is currently not supported by
    aiocoap on server-side). These requests need to contain the CoAP option "Proxy-Uri" and (optionally) a custom CoAP
    option with ID 256. The option with ID 256 is suggested by "MSC3079: Low Bandwidth CS API" and is required because
    RFC7252 defines no option mapping for `Authorization` headers (IDs 0-255 are reserved for IETF review). The plain access
    token must be used in this CoAP option without a prefix (e.g. "Bearer "). If option 256 is not contained in the CoAP
    request, the gateway will add a hardcoded access token for the HTTP request. The Proxy-Uri needs to contain the
    Matrix-Synapse homeserver URL. It is recommended to send the CoAP request as message type _CONfirmable_, to be sure
    the client receives the CoAP response (i.e. the message). The information of the Proxy-Uri option is used to
    construct the HTTP request to receive the last message of a Matrix room, but the used URL is not completely
    compliant with the Matrix CS-API (see below for more information).

    The homeserver URL may be supplied in short or full format via the Proxy-Uri CoAP option:
    - Short URL format:
        - `http(s)://IP_domain:PORT/E/<room_id>` => e.g. `http://localhost:8008/E/!SdTxduioYPCZWsKsRC:synapse.name`
        - The port is optional and only necessary if non-standard HTTP/HTTPS ports are used
        - This short URL is defined in "MSC3079: Low Bandwidth Client-Server API" in "Appendix B: CoAP Path Enums"
        - cf. https://github.com/matrix-org/matrix-doc/blob/7d20c1d9c19972fa63d1d9c124c3656928c28c29/proposals/3079-low-bandwidth-csapi.md#appendix-b-coap-path-enums
    - Full URL format:
        - `http(s)://IP_domain:PORT/_matrix/client/r0/rooms/<room_id>/messages?dir=b&limit=1` => e.g. `http://localhost:8008/_matrix/client/r0/rooms/!SdTxduioYPCZWsKsRC:synapse.name/messages?dir=b&limit=1`
        - `limit=1` specifies to receive the last message. According to the Matrix CS-API spec `from` is required as
        query parameter, but Synapse seems to not enforce the usage of `from`. This behavior is used to reduce the
        overhead to just receive the last message of room. Otherwise it would be necessary to perform "syncing" and
        exfiltrate the `from` field for the specified room from the extensive HTTP response JSON from Synapse on the
        gateway. This would make it necessary for the client to send a CoAP request to receive the current `from` for
        the room, to be able to send another CoAP request to receive the last message for this room.
        - cf. https://matrix.org/docs/spec/client_server/r0.6.1#get-matrix-client-r0-rooms-roomid-messages

    To receive the last message of a Matrix room there is no payload required in the CoAP request.

    Every CoAP request will be checked for the correct CoAP options.
    If incorrect, a CoAP response with a code from class 4 (client error) will be sent (e.g. 4.00/BAD_REQUEST).
    If the options are ok, a HTTP request will be sent to the Synapse homeserver based on the supplied data.

    This HTTP request can be successful or unsuccessful. If it was successful, the CoAP response code is 2.04/CHANGED.
    The CoAP response payload looks as follows:
    - The full payload of the HTTP response (sent by Synapse) receiving the last message looks like this:
        - e.g. `{"chunk":[{"type":"m.room.message","room_id":"!MauTnKoZREb:synapse.name",
        "sender":"@testuser:synapse.name","content":{"msgtype":"m.text","body":"Temp: 27.8"},
        "origin_server_ts":1620302891950,"unsigned":{"age":83203254},"event_id":"$eCSmJ0",
        "user_id":"@test_account:matrix.localhost","age":83203254}],"start":"s273_0_0_0_0_0_0_0_0","end":"t221-272_0_0_0_0_0_0_0_0"}`
        - Currently only textual messages are supported, i.e. events of type `m.room.message` and of message type
        `m.text`. Therefore the response JSON is checked to be of event type `m.room.message` and message type `m.text`.
            - Other event types would be e.g. `m.room.name` and `m.room.avatar`.
                - https://matrix.org/docs/spec/client_server/r0.6.1#m-room-message
            - Other message types would be e.g. `m.emote` and `m.image`
                - https://matrix.org/docs/spec/client_server/r0.6.1#m-room-message-msgtypes
    - The CoAP response contains the sender and body of the message encoded as CBOR:
        - e.g. `{'sender': '@test_account:matrix.localhost', 'body': 'Temp: 27.8'}`
        - To reduce the necessary packet size for the CoAP response, only the sender and the body of the last message
        are included.

    If the HTTP request was unsuccessful, the CoAP response code is 4.00/BAD_REQUEST. The payload contains the HTTP
    response JSON (from Synapse) encoded as CBOR.
    """

    async def render_get(self, request):
        # print_request_info(request)
        log_request_info(request)

        # Check for access token in request or use hardcoded access token
        # access token length seems to vary, therefore just checking for presence of option 256 in CoAP header
        if request.opt.get_option(ACCESS_TOKEN_OPTION_ID):
            access_token_option = request.opt.get_option(ACCESS_TOKEN_OPTION_ID)[0].value
            access_token = access_token_option.decode("utf-8")
        else:
            access_token = ACCESS_TOKEN_HC
        headers = {"Authorization": "Bearer " + access_token}

        # Verify if Proxy-Uri is contained in request
        if not request.opt.proxy_uri:
            return aiocoap.Message(code=aiocoap.BAD_REQUEST, payload=b"Missing Proxy-Uri!",
                                   content_format=CONTENT_FORMAT_TEXT_PLAIN)
        else:
            proxy_uri = request.opt.proxy_uri
            # Case short URL used in CoAP request
            if "/E/" in proxy_uri:
                proxy_uri_parts = proxy_uri.split('/')
                protocol = proxy_uri_parts[0]
                host_port = proxy_uri_parts[2]
                room_id = proxy_uri_parts[4]
                # gets the last message of the room => limit=1
                proxy_uri_new = protocol + '//' + host_port + '/_matrix/client/r0/rooms/' + room_id + \
                                '/messages?dir=b&limit=1'
            # Case full URL used in CoAP request
            elif "/_matrix/client/r0/rooms/" in proxy_uri:
                proxy_uri_new = proxy_uri
            else:
                return aiocoap.Message(code=aiocoap.BAD_REQUEST, payload=b"Unsupported Proxy-Uri!",
                                       content_format=CONTENT_FORMAT_TEXT_PLAIN)

        # Send HTTP request to retrieve last message from room to Synapse
        try:
            http_response = requests.get(proxy_uri_new, headers=headers, timeout=10)
        except requests.exceptions.RequestException as e:
            payload = b"Request to HS not possible!"
            return aiocoap.Message(code=aiocoap.BAD_REQUEST, payload=payload, content_format=CONTENT_FORMAT_TEXT_PLAIN)
        logging.info('HTTP(S) response code: %d => payload: %s' % (http_response.status_code, http_response.text))

        response_json = json.loads(http_response.text)

        # check for type:m.room.message, extract sender and content.body if msgtype==m.text
        if http_response.status_code == 200:
            # print('Number of messages rceived: %s' % len(response_json['chunk']))
            # check if only one messages was retrieved (currently only one/last message supported)
            if len(response_json['chunk']) == 1:
                # create CoAP response if there is only one message of message type "m.text"
                if response_json['chunk'][0]['type'] == "m.room.message" \
                        and response_json['chunk'][0]['content']['msgtype'] == "m.text":
                    # extract message sender
                    sender = response_json['chunk'][0]['sender']
                    # extract message body
                    body = response_json['chunk'][0]['content']['body']
                    # create new json for CoAP response only containing sender and message body
                    payload_json = {'sender': sender, 'body': body}
                    logging.info('CoAP response JSON: %s' % payload_json)
                    payload_cbor = dumps(payload_json)
                    # rfc7252#section-10.1.1: Upon success, a 2.05 (Content) Response Code SHOULD be returned.
                    return aiocoap.Message(code=aiocoap.CONTENT, content_format=CONTENT_FORMAT_CBOR,
                                           payload=payload_cbor)
                else:
                    return aiocoap.Message(code=aiocoap.BAD_REQUEST, payload=b"Incompatible eventtype or msgtype!",
                                           content_format=CONTENT_FORMAT_TEXT_PLAIN)
            else:
                return aiocoap.Message(code=aiocoap.BAD_REQUEST, payload=b"Multiple messages not supported!",
                                       content_format=CONTENT_FORMAT_TEXT_PLAIN)
        else:
            # send http response text (from Synapse) as CBOR
            return aiocoap.Message(code=aiocoap.BAD_REQUEST, payload=dumps(response_json),
                                   content_format=CONTENT_FORMAT_CBOR)


class SendResource(resource.Resource):
    """
    Versão simplificada do envio de mensagens para uma sala Matrix via CoAP.
    Aceita JSON puro e usa configurações fixas para facilitar o lado do ESP32.
    """
    def __init__(self):
        super().__init__()

    async def render_put(self, request):
        logging.info('Recebido PUT CoAP do ESP32')

        # Decodificar Payload (De JSON String para Objeto Python)
        try:
            # O ESP32 manda texto, nós convertemos
            payload_str = request.payload.decode('utf-8')
            json_payload = json.loads(payload_str)
            logging.info(f"Payload recebido: {json_payload}")
        except Exception as e:
            logging.error(f"Erro ao ler JSON: {e}")
            return aiocoap.Message(code=aiocoap.BAD_REQUEST, payload=b"Erro JSON")

        # Configurações Fixas (Para não precisar mandar no pacote CoAP)
        HARDCODED_ROOM_ID = "!VYSmukJWlGoZbnYKBs:localhost" # Sala de destino
        synapse_url = "http://localhost:8008"
        
        # Gera um ID de transação único (timestamp)
        txn_id = str(int(time.time())) + str(random.randint(100,999))
        
        # Monta a URL final da API do Matrix
        # Formato: /_matrix/client/r0/rooms/{roomId}/send/{eventType}/{txnId}
        api_url = f"{synapse_url}/_matrix/client/r0/rooms/{HARDCODED_ROOM_ID}/send/m.room.message/{txn_id}"

        # Autenticação
        headers = {"Authorization": "Bearer " + ACCESS_TOKEN_HC}

        # Envia para o Synapse via HTTP
        try:
            # O Matrix exige que o JSON tenha "msgtype" e "body"
            # Se o ESP32 mandar apenas um dado de telemetria, colocamos ele como corpo da mensagem
            matrix_payload = {
                "msgtype": "m.text",
                "body": str(json_payload) # Converte o JSON do sensor em texto para o chat
            }
            
            r = requests.put(api_url, json=matrix_payload, headers=headers, timeout=5)
            logging.info(f"Resposta Synapse: {r.status_code} - {r.text}")
            
            if r.status_code == 200:
                return aiocoap.Message(code=aiocoap.CHANGED)
            else:
                return aiocoap.Message(code=aiocoap.BAD_REQUEST)

        except Exception as e:
            logging.error(f"Erro ao conectar no Synapse: {e}")
            return aiocoap.Message(code=aiocoap.INTERNAL_SERVER_ERROR)


class UnixTimeResource(resource.Resource):
    """
    The UnixTimeResource provides the current Unix timestamp.
    It can be used by the client to generate idempotent transaction IDs (txnIds) based on the timestamp for sending
    messages to a Matrix room.
    """

    async def render_get(self, request):
        # payload contains current Unix timestamp encoded as ascii
        payload = str(int(time.time())).encode('ascii')
        return aiocoap.Message(payload=payload, content_format=CONTENT_FORMAT_TEXT_PLAIN)


class LogoutResource(resource.Resource):
    """
    The LogoutResource enables the logout of a Matrix user at a specific Matrix-Synapse homeserver via a CoAP request.
    It waits for CoAP _POST_ requests (CoAPS is currently not supported by aiocoap on server-side).
    These requests need to contain the CoAP option "Proxy-Uri" and a _mandatory_ custom CoAP option with ID 256.
    The option with ID 256 is suggested by "MSC3079: Low Bandwidth CS API" and is required because RFC7252 defines no
    option mapping for `Authorization` headers (IDs 0-255 are reserved for IETF review). The plain access token must be
    used in this CoAP option without a prefix (e.g. "Bearer "). In case of the LogoutResource the access token needs to
    be provided and the hardcoded access token cannot be used. This is in place to prevent the client to invalidate the
    access token for other clients using the same (hardcoded) access token. The Proxy-Uri needs to contain the Matrix-Synapse
    homeserver URL. It is recommended to send the CoAP request as message type _CONfirmable_, to be sure the client
    receives the CoAP response (i.e. if the logout of the user was successful or not). The information of the
    Proxy-Uri option is used to construct the HTTP request which conforms with the Matrix CS-API to logout an existing
    user at the target Matrix-Synapse homeserver and therefore invalidate the provided access token.

    The homeserver URL may be supplied in short or full format via the Proxy-Uri CoAP option:
    - Short URL format:
        - `http(s)://IP_domain:PORT/3` => e.g. `http://localhost:8008/3`
        - The port is optional and only necessary if non-standard HTTP/HTTPS ports are used
        - This short URL is defined in "MSC3079: Low Bandwidth Client-Server API" in "Appendix B: CoAP Path Enums"
        - cf. https://github.com/matrix-org/matrix-doc/blob/7d20c1d9c19972fa63d1d9c124c3656928c28c29/proposals/3079-low-bandwidth-csapi.md#appendix-b-coap-path-enums
    - Full URL format:
        - `http(s)://IP_domain:PORT/_matrix/client/r0/logout` => e.g. `http://localhost:8008/_matrix/client/r0/logout`
        - cf. https://matrix.org/docs/spec/client_server/r0.6.1#post-matrix-client-r0-logout
    - _OPTIONAL_ URL format: http://localhost:8008/_matrix/client/r0/logout/all
        - Invalidates all access tokens for a user, so that they can no longer be used for authorization.
        - `/logout/all` is only possible via full URL, there is no short URL defined in MSC3079.
        - cf. https://matrix.org/docs/spec/client_server/r0.6.1#post-matrix-client-r0-logout-all

    To logout a Matrix user at a Synapse homeserver there is no payload required in the CoAP request.

    Every CoAP request will be checked for the correct CoAP options.
    If incorrect, a CoAP response with a code from class 4 (client error) will be sent (e.g. 4.00/BAD_REQUEST).
    If the options are ok, a HTTP request will be sent to the Synapse homeserver based on the supplied data.

    This HTTP request can be successful or unsuccessful. If it was successful, the CoAP response code is 2.04/CHANGED.
    The CoAP response contains no payload.

    If the HTTP request was unsuccessful, the CoAP response code is 4.00/BAD_REQUEST. The payload contains the HTTP
    response JSON (from Synapse) encoded as CBOR (e.g. `{"errcode":"M_UNKNOWN_TOKEN","error":"Invalid macaroon passed.","soft_logout":false}`).
    """
    def __init__(self):
        super().__init__()

    async def render_post(self, request):
        # print_request_info(request)
        log_request_info(request)

        # Verify if Proxy-Uri is contained in request
        if not request.opt.proxy_uri:
            return aiocoap.Message(code=aiocoap.BAD_REQUEST, payload=b"Missing Proxy-Uri!",
                                   content_format=CONTENT_FORMAT_TEXT_PLAIN)

        # For the logout it is mandatory to supply an access token to not invalidate the hardcoded one
        if request.opt.get_option(ACCESS_TOKEN_OPTION_ID):
            access_token_option = request.opt.get_option(ACCESS_TOKEN_OPTION_ID)[0].value
            access_token = access_token_option.decode("utf-8")
            headers = {"Authorization": "Bearer " + access_token}
        else:
            payload = b"Missing access token!"
            return aiocoap.Message(code=aiocoap.BAD_REQUEST, payload=payload, content_format=CONTENT_FORMAT_TEXT_PLAIN)

        proxy_uri = request.opt.proxy_uri
        proxy_uri_parts = proxy_uri.split('/')
        # pattern matches for /3 at the end of a string => $ is endmarker
        re_result = re.fullmatch(r'.*/3$', proxy_uri)
        # Case: Short URL provided in CoAP request
        if re_result is not None and len(proxy_uri_parts) == 4:
            # i.e. http: or https:
            protocol = proxy_uri_parts[0]
            # i.e. hostname / domain / IP; optionally including a port
            host_port = proxy_uri_parts[2]
            # Build together full matrix logout API URL
            proxy_uri_new = protocol + '//' + host_port + '/_matrix/client/r0/logout'
        # Case: Full URL provided in CoAP request
        elif "/_matrix/client/r0/logout" in proxy_uri:
            proxy_uri_new = proxy_uri
        elif "/_matrix/client/r0/logout/all" in proxy_uri:
            proxy_uri_new = proxy_uri
        else:
            return aiocoap.Message(code=aiocoap.BAD_REQUEST, payload=b"Unsupported Proxy-Uri!",
                                   content_format=CONTENT_FORMAT_TEXT_PLAIN)

        # Perform HTTP request to Synapse
        try:
            http_response = requests.post(proxy_uri_new, headers=headers, timeout=10)
        except requests.exceptions.RequestException as e:
            payload = b"Request to HS not possible!"
            return aiocoap.Message(code=aiocoap.BAD_REQUEST, payload=payload, content_format=CONTENT_FORMAT_TEXT_PLAIN)
        logging.info('HTTP(S) response code: %d => payload: %s' % (http_response.status_code, http_response.text))

        # verify if http_response is HTTP 200
        if http_response.status_code == 200:
            # Answer CoAP request or after received ok from Synapse => HTTP 200
            # rfc7252#section-10.1.4: If the action performed by the POST method does not result in a
            #    resource that can be identified by a URI, a 2.04 (Changed) response
            #    MUST be returned to the client.  If a resource has been created on
            #    the origin server, a 2.01 (Created) response MUST be returned.
            return aiocoap.Message(code=aiocoap.CHANGED)
        else:
            cbor_response = dumps(json.loads(http_response.text))
            return aiocoap.Message(code=aiocoap.BAD_REQUEST, payload=cbor_response, content_format=CONTENT_FORMAT_CBOR)


def print_request_info(request):
    """Method to print CoAP header and payload information"""

    print('CoAP request remote: %s' % request.remote)
    print('CoAP request remote hostinfo: %s' % request.remote.hostinfo)
    if request.payload:
        print('CoAP request payload (CBOR): %s' % request.payload)
    print('CoAP request content format: %s' % request.opt.content_format)
    print('CoAP request type: %s' % request.mtype)
    print('CoAP request message ID: %s' % request.mid)
    print('CoAP request token: %s' % request.token)
    print('CoAP request Proxy-Uri: %s' % request.opt.proxy_uri)
    if request.opt.get_option(ACCESS_TOKEN_OPTION_ID):
        # print('CoAP request option 256: %s' % request.opt.get_option(ACCESS_TOKEN_OPTION_ID))
        print('CoAP request Synapse access token (Option ID 256):' % request.opt.get_option(ACCESS_TOKEN_OPTION_ID)[0].value)
        # print attributes of object
        # print(request.opt.get_option(ACCESS_TOKEN_OPTION_ID)[0].__dict__)
        # does also work with e.g. Proxy Uri option
        # proxy_uri_test = request.opt.get_option(aiocoap.OptionNumber.PROXY_URI)[0].value
        # print(proxy_uri_test)
    # if hasattr(request.opt, 'etag'):
    #    print('Request etag: %s' % request.opt.etag)


def log_request_info(request):
    """Method to log CoAP header and payload information"""

    logging.debug('CoAP request remote: %s' % request.remote)
    logging.debug('CoAP request remote hostinfo: %s' % request.remote.hostinfo)
    if request.payload:
        logging.debug('CoAP request payload (CBOR): %s' % request.payload)
    logging.debug('CoAP request content format: %s' % request.opt.content_format)
    logging.debug('CoAP request type: %s' % request.mtype)
    logging.debug('CoAP request message ID: %s' % request.mid)
    logging.debug('CoAP request token: %s' % request.token)
    logging.debug('CoAP request Proxy-Uri: %s' % request.opt.proxy_uri)
    if request.opt.get_option(ACCESS_TOKEN_OPTION_ID):
        # logging.debug('CoAP request option 256: %s' % request.opt.get_option(ACCESS_TOKEN_OPTION_ID))
        logging.debug('CoAP request Synapse access token (Option ID 256):' % request.opt.get_option(ACCESS_TOKEN_OPTION_ID)[0].value)
        # print attributes of object
        # logging.debug(request.opt.get_option(256)[0].__dict__)
        # does also work with e.g. Proxy Uri option
        # proxy_uri_test = request.opt.get_option(aiocoap.OptionNumber.PROXY_URI)[0].value
        # logging.debug(proxy_uri_test)
    # if hasattr(request.opt, 'etag'):
    #    logging.debug('Request etag: %s' % request.opt.etag)


# logging setup
logging.basicConfig(level=logging.DEBUG)
logging.getLogger("coap-server").setLevel(logging.DEBUG)


def main():
    parser = argparse.ArgumentParser(description='CoMatrix gateway - '
                                                 'enables usage of the Matrix protocol for constrained IoT devices')

    parser.add_argument('-i', '--ip', help="IP address to listen on (default: %(default)s)", default="::", type=str)
    parser.add_argument('-p', '--port', help="UDP Port to listen on (default: %(default)s)", default="5683", type=int)

    args = parser.parse_args()

    ip = args.ip
    # Case link-local address
    if ip.startswith("fe80"):
        # Checks for existing zone identifier in case of IPv6 link local address
        re_result = re.fullmatch(r'fe80.+%.+$', ip)
        if not re_result:
            print("CAUTION: Zone identifier necessary for IPv6 link-local address => e.g. " + ip + "%lowpan0")
            exit()
    port = args.port

    # Resource tree creation
    root = resource.Site()

    root.add_resource(['.well-known', 'core'], resource.WKCResource(root.get_resources_as_linkheader))
    root.add_resource(['register'], RegistrationResource())
    root.add_resource(['login'], LoginResource())
    root.add_resource(['join'], JoinResource())
    root.add_resource(['getmsg'], MessagesResource())
    root.add_resource(['send'], SendResource())
    # helper resource for clients to be able to add txnid client-side (for /send)
    root.add_resource(['time'], UnixTimeResource())
    root.add_resource(['logout'], LogoutResource())

    bind = [ip, port]

    asyncio.Task(aiocoap.Context.create_server_context(root, bind=bind))

    asyncio.get_event_loop().run_forever()


if __name__ == "__main__":
    main()
