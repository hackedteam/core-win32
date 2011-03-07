#ifndef CONVERTERSESSION_H_INCLUDED
#define CONVERTERSESSION_H_INCLUDED

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#include <comdef.h>
#include <Guiddef.h>

#define MDEFINE_GUID(name, l, w1, w2, b1, b2, b3, b4, b5, b6, b7, b8)  EXTERN_C const GUID DECLSPEC_SELECTANY name = { l, w1, w2, { b1, b2,  b3,  b4,  b5,  b6,  b7,  b8 } }

//#if !defined(INITGUID) || defined(USES_IID_IConverterSession)
// {4e3a7680-b77a-11d0-9da5-00c04fd65685}
MDEFINE_GUID(CLSID_IConverterSession, 0x4e3a7680, 0xb77a, 0x11d0, 0x9d, 0xa5, 0x0, 0xc0, 0x4f, 0xd6, 0x56, 0x85);
// { }
MDEFINE_GUID(IID_IConverterSession, 0x4b401570, 0xb77b, 0x11d0, 0x9d, 0xa5, 0x0, 0xc0, 0x4f, 0xd6, 0x56, 0x85);
//#endif // #if !defined(INITGUID) || defined(USES_IID_IConverterSession)

typedef enum tagENCODINGTYPE {
IET_BINARY = 0,
IET_BASE64 = 1,
IET_UUENCODE = 2,
IET_QP = 3,
IET_7BIT = 4,
IET_8BIT = 5,
IET_INETCSET = 6,
IET_UNICODE = 7,
IET_RFC1522 = 8,
IET_ENCODED = 9,
IET_CURRENT = 10,
IET_UNKNOWN = 11,
IET_BINHEX40 = 12,
IET_LAST = 13
} ENCODINGTYPE;


typedef enum tagMIMESAVETYPE {
SAVE_RFC822 = 0,
SAVE_RFC1521 = 1
} MIMESAVETYPE;

typedef enum tagCCSF {
CCSF_SMTP        = 0x0002,
CCSF_NOHEADERS   = 0x0004,
CCSF_NO_MSGID    = 0x4000,
CCSF_USE_RTF     = 0x0080,
CCSF_INCLUDE_BCC = 0x0020
} CCSF;

class __declspec(uuid("4e3a7680-b77a-11d0-9da5-00c04fd65685"))
CConverterSession;
/*#define CLSID_IConverterSession __uuidof(CConverterSession)*/
interface __declspec(uuid("4b401570-b77b-11d0-9da5-00c04fd65685"))
IConverterSession;
_COM_SMARTPTR_TYPEDEF(IConverterSession,__uuidof(IConverterSession));
/*#define IID_IConverterSession __uuidof(IConverterSession)*/

/**
* Allows conversions between MIME objects and MAPI messages.
* This can be useful in transporting messages across the Internet.
*
* @remarks Only these methods are supported in this interface:
*
* IConverterSession::SetEncoding, IConverterSession::MAPIToMIMEStm,
* and IConverterSession::MIMEToMAPI.
*
* Call SetEncoding before using the other methods to perform
conversion.
*/
interface IConverterSession : public IUnknown
{
//private:
//STDMETHOD(placeholder0)() PURE;
public:

/**
* Undocumented Function: Call this function before the
MAPIToMIME conversion
* to populate to, from, cc, and bcc fields with email address
information.
* @retval E_INVALIDARG The encoding type passed was invalid.
*/

STDMETHOD(SetAddressBook) ( LPADRBOOK pAddrBook ) PURE;

/**
* Initializes the encoding to be used during conversion.
*
* @retval E_INVALIDARG The encoding type passed was invalid.
*/
STDMETHOD(SetEncoding)(
/**
* An ENCODINGTYPE value. Only the following values are
supported:
*
* IET_BASE64, IET_UUENCODE, IET_QP, IET_7BIT, IET_8BIT
*/
ENCODINGTYPE et) PURE;

private:
STDMETHOD(placeholder1)() PURE;
public:
/**
* Converts a MIME stream to a MAPI message.
*
* @retval E_INVALIDARG pstm is NULL, pmsg is NULL,
*                      or ulFlags is invalid.
*/
STDMETHOD(MIMEToMAPI)(
/** [in] IStream interface to a MIME stream. */
LPSTREAM pstm,
/** [out] Pointer to the message to load. */
LPMESSAGE pmsg,
/** [in] This value must be NULL. */
LPCSTR pszSrcSrv,
/** [in] Flags. Zero (0) is the only supported value. */
ULONG ulFlags) PURE;
/**
* Converts a MAPI message to a MIME stream.
*
* @retval E_INVALIDARG Invalid flags were passed,
*                      or pmsg or pstm is NULL.
*
* @remarks Supported only for standard Outlook message types.
*/
STDMETHOD(MAPIToMIMEStm)(
/** [in] Pointer to the message to convert. */
LPMESSAGE pmsg,
/** [out] IStream interface to output the stream. */
LPSTREAM pstm,
/** [in] A flag of one of the following types:
*  CCSF_NO_MSGID
*    Do not include Message-Id field in outgoing messages.
*  CCSF_NOHEADERS
*    The converter should ignore the headers of the outside
message.
*  CCSF_SMTP
*    The converter is being passed an SMTP message.
*/
ULONG ulFlags) PURE;
private:
STDMETHOD(placeholder2)() PURE;
STDMETHOD(placeholder3)() PURE;
STDMETHOD(placeholder4)() PURE;
public:
STDMETHOD(SetTextWrapping(
/** [in] Whether to wrap text or not. */
BOOL fWrapText,
/** [in] The text wrapping width to use. */
ULONG ulWrapWidth)) PURE;

STDMETHOD(SetSaveFormat(
/** [in] The save format to be used for a MIME stream. For more
information, see the enum type MIMESAVETYPE.
SAVE_RFC1521 */
MIMESAVETYPE mstSaveFormat)) PURE;
private:
STDMETHOD(placeholder5)() PURE;
STDMETHOD(placeholder6)() PURE;
};

#endif // #ifndef CONVERTERSESSION_H_INCLUDED

