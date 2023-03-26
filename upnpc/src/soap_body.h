#ifndef _SOAP_H_
#define _SOAP_H_

#define HEADER "POST /UD/?6 HTTP/1.1\r\nHost: %s:%d\r\nContent-Length: %d\r\nContent-Type: text/xml; charset='utf-8'\r\nConnection: Close\r\nSOAPACTION: 'urn:schemas-upnp-org:service:WANPPPConnection:1#%s'\r\n\r\n"

#define GET_EXTRERNAL_SOAP "<?xml version='1.0'?>\r\n<s:Envelope xmlns:s='http://schemas.xmlsoap.org/soap/envelope/' s:encodingStyle='http://schemas.xmlsoap.org/soap/encoding/'>\r\n<s:Body>\r\n<u:GetExternalIPAddress xmlns:u='urn:schemas-upnp-org:service:WANPPPConnection:1'>\r\n</u:GetExternalIPAddress>\r\n</s:Body>\r\n</s:Envelope>\r\n\r\n"

#define ADD_PORT_MAPPING_SOAP "<?xml version='1.0'?>\r\n<s:Envelope xmlns:s='http://schemas.xmlsoap.org/soap/envelope/' s:encodingStyle='http://schemas.xmlsoap.org/soap/encoding/'>\r\n<s:Body>\r\n<m:AddPortMapping xmlns:m='urn:schemas-upnp-org:service:WANPPPConnection:1'>\r\n<NewRemoteHost></NewRemoteHost>\r\n<NewExternalPort>%d</NewExternalPort>\r\n<NewProtocol>%s</NewProtocol>\r\n<NewInternalPort>%d</NewInternalPort>\r\n<NewInternalClient>%s</NewInternalClient>\r\n<NewEnabled>1</NewEnabled>\r\n<NewPortMappingDescription>%s</NewPortMappingDescription>\r\n<NewLeaseDuration>%d</NewLeaseDuration>\r\n</m:AddPortMapping>\r\n</s:Body>\r\n</s:Envelope>\r\n\r\n"

#define DELETE_PORT_MAPPING_SOAP "<?xml version='1.0'?>\r\n<s:Envelope xmlns:s='http://schemas.xmlsoap.org/soap/envelope/' s:encodingStyle='http://schemas.xmlsoap.org/soap/encoding/'>\r\n<s:Body>\r\n<m:DeletePortMapping xmlns:m='urn:schemas-upnp-org:service:WANPPPConnection:1'>\r\n<NewRemoteHost></NewRemoteHost>\r\n<NewExternalPort>%d</NewExternalPort>\r\n<NewProtocol>%s</NewProtocol>\r\n</m:DeletePortMapping>\r\n</s:Body>\r\n</s:Envelope>\r\n\r\n"

#define GET_GENERIC_PORT_MAPPING_ENTRY_SOAP "<?xml version='1.0'?>\r\n<s:Envelope xmlns:s='http://schemas.xmlsoap.org/soap/envelope/' s:encodingStyle='http://schemas.xmlsoap.org/soap/encoding/'>\r\n<s:Body>\r\n<m:GetGenericPortMappingEntry xmlns:m='urn:schemas-upnp-org:service:WANPPPConnection:1'>\r\n<NewPortMappingIndex>%d</NewPortMappingIndex>\r\n</m:GetGenericPortMappingEntry>\r\n</s:Body>\r\n</s:Envelope>\r\n\r\n"

#define GET_UPNP_REQUEST_SOAP "M-SEARCH * HTTP/1.1\r\nMX: 3\r\nHOST: %s:%d\r\nMAN: 'ssdp:discover'\r\nST: urn:schemas-upnp-org:service:WANIPConnection:1\r\n\r\n"

#define HEADER_BODY_SIZE strlen(HEADER) + 60
#define GET_EXTRERNAL_SIZE strlen(GET_EXTRERNAL_SOAP) + 30
#define ADD_PORT_MAP_SIZE strlen(ADD_PORT_MAPPING_SOAP) + 120
#define DELETE_PORT_MAP_SIZE strlen(DELETE_PORT_MAPPING_SOAP) + 30
#define GET_GENERIC_PORT_MAP_ENTRY_SIZE strlen(GET_GENERIC_PORT_MAPPING_ENTRY_SOAP) + 6
#define GET_UPNP_REQUEST_SIZE strlen(GET_UPNP_REQUEST_SIZE) + 24

#define GET_EXTRERNAL_MODE "GetExternalIPAddress"
#define ADD_PORT_MAP_MODE "AddPortMapping"
#define DELETE_PORT_MAP_MODE "DeletePortMapping"
#define GET_GENERIC_PORT_MAP_ENTRY_MODE "GetGenericPortMappingEntry"

#endif 
