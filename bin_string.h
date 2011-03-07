#define ELEM_DELIMITER 0xABADC0DE
class bin_buf {
public :
	bin_buf(void) { buf_ptr = NULL; buf_len = 0; }
	~bin_buf(void) { if (buf_ptr) free(buf_ptr); }

	BOOL add(void *abuf, int alen) {
		BYTE *tmp_buf;
		if (alen<=0 || abuf == NULL)
			return FALSE;
		tmp_buf = (BYTE *)realloc(buf_ptr, buf_len + alen);
		if (!tmp_buf)
			return FALSE;
		buf_ptr = tmp_buf;
		memcpy(buf_ptr+buf_len, abuf, alen);
		buf_len += alen;
		return TRUE;
	}

	BYTE *get_buf(void) { return buf_ptr; }
	DWORD get_len(void) { return buf_len; }
private:
	BYTE *buf_ptr;
	DWORD buf_len;
};


#define GET_TIME(x)	{__int64 aclock;\
	                 _time64( &aclock );\
					 _gmtime64_s(&x, &aclock);\
					 x.tm_year += 1900;\
					 x.tm_mon ++;}
