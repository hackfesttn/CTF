#!/usr/bin/python3.11

import marshal

bytecode = b"\xe3\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x07\x00\x00\x00\x00\x00\x00\x00\xf3\xf6\x04\x00\x00\x97\x00d\x00Z\x00d\x01Z\x01d\x02\\\x03\x00\x00Z\x02Z\x03Z\x04\x02\x00e\x05\xa6\x00\x00\x00\xab\x00\x00\x00\x00\x00\x00\x00\x00\x00Z\x06g\x00Z\x07\x02\x00e\x08d\x03\xa6\x01\x00\x00\xab\x01\x00\x00\x00\x00\x00\x00\x00\x00D\x00]\x07Z\te\te\x06e\t<\x00\x00\x00\x8c\x08\x02\x00e\x08d\x03\xa6\x01\x00\x00\xab\x01\x00\x00\x00\x00\x00\x00\x00\x00D\x00]<Z\te\x03e\x06e\t\x19\x00\x00\x00\x00\x00\x00\x00\x00\x00z\x00\x00\x00e\x01e\t\x02\x00e\ne\x01\xa6\x01\x00\x00\xab\x01\x00\x00\x00\x00\x00\x00\x00\x00z\x06\x00\x00\x19\x00\x00\x00\x00\x00\x00\x00\x00\x00z\x00\x00\x00d\x03z\x06\x00\x00Z\x03e\x06e\x03\x19\x00\x00\x00\x00\x00\x00\x00\x00\x00e\x06e\t\x19\x00\x00\x00\x00\x00\x00\x00\x00\x00c\x02e\x06e\t<\x00\x00\x00e\x06e\x03<\x00\x00\x00\x8c=e\x00D\x00]kZ\x0be\x02d\x04z\x00\x00\x00d\x03z\x06\x00\x00Z\x02e\x03e\x06e\x02\x19\x00\x00\x00\x00\x00\x00\x00\x00\x00z\x00\x00\x00d\x03z\x06\x00\x00Z\x03e\x06e\x03\x19\x00\x00\x00\x00\x00\x00\x00\x00\x00e\x06e\x02\x19\x00\x00\x00\x00\x00\x00\x00\x00\x00c\x02e\x06e\x02<\x00\x00\x00e\x06e\x03<\x00\x00\x00e\x06e\x06e\x02\x19\x00\x00\x00\x00\x00\x00\x00\x00\x00e\x06e\x03\x19\x00\x00\x00\x00\x00\x00\x00\x00\x00z\x00\x00\x00d\x03z\x06\x00\x00\x19\x00\x00\x00\x00\x00\x00\x00\x00\x00Z\x04e\x07\xa0\x0c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00e\re\x0be\x04z\x0c\x00\x00g\x01\xa6\x01\x00\x00\xab\x01\x00\x00\x00\x00\x00\x00\x00\x00\xa6\x01\x00\x00\xab\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x8cld\x05\xa0\x0e\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00e\x07\xa6\x01\x00\x00\xab\x01\x00\x00\x00\x00\x00\x00\x00\x00Z\x01\x02\x00e\x0fd\x06\xa6\x01\x00\x00\xab\x01\x00\x00\x00\x00\x00\x00\x00\x00j\x10\x00\x00\x00\x00\x00\x00\x00\x00\xa0\x11\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00d\x07\xa6\x01\x00\x00\xab\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x02\x00e\x0fd\x06\xa6\x01\x00\x00\xab\x01\x00\x00\x00\x00\x00\x00\x00\x00j\x10\x00\x00\x00\x00\x00\x00\x00\x00\xa0\x12\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xa6\x00\x00\x00\xab\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x02\x00e\x0fd\x08\xa6\x01\x00\x00\xab\x01\x00\x00\x00\x00\x00\x00\x00\x00\xa0\x13\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00d\td\x03\xa6\x02\x00\x00\xab\x02\x00\x00\x00\x00\x00\x00\x00\x00\xa0\x14\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xa6\x00\x00\x00\xab\x00\x00\x00\x00\x00\x00\x00\x00\x00Z\x00d\x02\\\x03\x00\x00Z\x02Z\x03Z\x04\x02\x00e\x05\xa6\x00\x00\x00\xab\x00\x00\x00\x00\x00\x00\x00\x00\x00Z\x06g\x00Z\x07\x02\x00e\x08d\x03\xa6\x01\x00\x00\xab\x01\x00\x00\x00\x00\x00\x00\x00\x00D\x00]\x07Z\te\te\x06e\t<\x00\x00\x00\x8c\x08\x02\x00e\x08d\x03\xa6\x01\x00\x00\xab\x01\x00\x00\x00\x00\x00\x00\x00\x00D\x00]<Z\te\x03e\x06e\t\x19\x00\x00\x00\x00\x00\x00\x00\x00\x00z\x00\x00\x00e\x01e\t\x02\x00e\ne\x01\xa6\x01\x00\x00\xab\x01\x00\x00\x00\x00\x00\x00\x00\x00z\x06\x00\x00\x19\x00\x00\x00\x00\x00\x00\x00\x00\x00z\x00\x00\x00d\x03z\x06\x00\x00Z\x03e\x06e\x03\x19\x00\x00\x00\x00\x00\x00\x00\x00\x00e\x06e\t\x19\x00\x00\x00\x00\x00\x00\x00\x00\x00c\x02e\x06e\t<\x00\x00\x00e\x06e\x03<\x00\x00\x00\x8c=e\x00D\x00]kZ\x0be\x02d\x04z\x00\x00\x00d\x03z\x06\x00\x00Z\x02e\x03e\x06e\x02\x19\x00\x00\x00\x00\x00\x00\x00\x00\x00z\x00\x00\x00d\x03z\x06\x00\x00Z\x03e\x06e\x03\x19\x00\x00\x00\x00\x00\x00\x00\x00\x00e\x06e\x02\x19\x00\x00\x00\x00\x00\x00\x00\x00\x00c\x02e\x06e\x02<\x00\x00\x00e\x06e\x03<\x00\x00\x00e\x06e\x06e\x02\x19\x00\x00\x00\x00\x00\x00\x00\x00\x00e\x06e\x03\x19\x00\x00\x00\x00\x00\x00\x00\x00\x00z\x00\x00\x00d\x03z\x06\x00\x00\x19\x00\x00\x00\x00\x00\x00\x00\x00\x00Z\x04e\x07\xa0\x0c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00e\re\x0be\x04z\x0c\x00\x00g\x01\xa6\x01\x00\x00\xab\x01\x00\x00\x00\x00\x00\x00\x00\x00\xa6\x01\x00\x00\xab\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x8cld\x05\xa0\x0e\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00e\x07\xa6\x01\x00\x00\xab\x01\x00\x00\x00\x00\x00\x00\x00\x00Z\x07e\x07d\nk\x02\x00\x00\x00\x00r\r\x02\x00e\x15d\x0b\xa6\x01\x00\x00\xab\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00d\rS\x00\x02\x00e\x15d\x0c\xa6\x01\x00\x00\xab\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00d\rS\x00)\x0es\x0b\x00\x00\x00:l!l-\x03\x0f\x1aZ\xbf\x90s\x08\x00\x00\x00CHEBIYED)\x03\xe9\x00\x00\x00\x00r\x02\x00\x00\x00r\x02\x00\x00\x00\xe9\x00\x01\x00\x00\xe9\x01\x00\x00\x00\xf3\x00\x00\x00\x00\xda\x03sysz\x02> \xda\x02osr\x02\x00\x00\x00s\x19\x00\x00\x00\x8d\x8e!\x12\xc0\xb1y\xdf\xad\xf7NY\xf1\xa7\xaa\x14\x81G\xaa\x83XzR\xb4jz\nWell Done!z\x06Wrong!N)\x16\xda\x04text\xda\x04hiha\xda\x01a\xda\x01b\xda\x01c\xda\x04dict\xda\x01s\xda\x03out\xda\x05range\xda\x01i\xda\x03len\xda\x04char\xda\x06append\xda\tbytearray\xda\x04join\xda\n__import__\xda\x06stdout\xda\x05write\xda\x05flush\xda\x04read\xda\x05strip\xda\x05print\xa9\x00r\x05\x00\x00\x00\xfa\x08<string>\xfa\x08<module>r \x00\x00\x00\x01\x00\x00\x00s\x0f\x03\x00\x00\xf0\x03\x01\x01\x01\xe0\x07$\x80\x04\xd8\x07\x12\x80\x04\xd8\n\x11\x81\x07\x80\x01\x801\x80a\xd8\x04\x08\x80D\x81F\x84F\x80\x01\xd8\x06\x08\x80\x03\xe0\t\x0e\x88\x15\x88s\x89\x1a\x8c\x1a\xf0\x00\x01\x01\r\xf0\x00\x01\x01\r\x80A\xd8\x0b\x0c\x80A\x80a\x81D\x80D\xe0\t\x0e\x88\x15\x88s\x89\x1a\x8c\x1a\xf0\x00\x02\x01\x1c\xf0\x00\x02\x01\x1c\x80A\xd8\t\n\x88Q\x88q\x8cT\x89\x18\x90D\x98\x11\x98S\x98S\xa0\x14\x99Y\x9cY\x99\x1d\xd4\x14'\xd1\t'\xa83\xd1\x08.\x80A\xd8\x11\x12\x901\x94\x14\x90q\x98\x11\x94t\x80J\x80A\x80a\x81D\x88!\x88A\x89$\x88$\xe0\x0c\x10\xf0\x00\x05\x01&\xf0\x00\x05\x01&\x80D\xd8\t\n\x88Q\x89\x15\x90#\x89\r\x80A\xd8\t\n\x88Q\x88q\x8cT\x89\x18\x90S\xd1\x08\x18\x80A\xd8\x11\x12\x901\x94\x14\x90q\x98\x11\x94t\x80J\x80A\x80a\x81D\x88!\x88A\x89$\xd8\x08\t\x881\x88Q\x8c4\x90!\x90A\x94$\x89;\x98#\xd1\n\x1d\xd4\x08\x1e\x80A\xd8\x04\x07\x87J\x82J\x88y\x88y\x98$\xa0\x11\x99(\x98\x1a\xd1\x0f$\xd4\x0f$\xd1\x04%\xd4\x04%\xd0\x04%\xd0\x04%\xe0\x07\n\x87x\x82x\x90\x03\x81}\x84}\x80\x04\xe0\x00\n\x80\n\x885\xd1\x00\x11\xd4\x00\x11\xd4\x00\x18\xd7\x00\x1e\xd2\x00\x1e\x98t\xd1\x00$\xd4\x00$\xd0\x00$\xd8\x00\n\x80\n\x885\xd1\x00\x11\xd4\x00\x11\xd4\x00\x18\xd7\x00\x1e\xd2\x00\x1e\xd1\x00 \xd4\x00 \xd0\x00 \xd8\x07\x11\x80z\x90$\xd1\x07\x17\xd4\x07\x17\xd7\x07\x1c\xd2\x07\x1c\x98Q\xa0\x05\xd1\x07&\xd4\x07&\xd7\x07,\xd2\x07,\xd1\x07.\xd4\x07.\x80\x04\xd8\n\x11\x81\x07\x80\x01\x801\x80a\xd8\x04\x08\x80D\x81F\x84F\x80\x01\xd8\x06\x08\x80\x03\xe0\t\x0e\x88\x15\x88s\x89\x1a\x8c\x1a\xf0\x00\x01\x01\r\xf0\x00\x01\x01\r\x80A\xd8\x0b\x0c\x80A\x80a\x81D\x80D\xe0\t\x0e\x88\x15\x88s\x89\x1a\x8c\x1a\xf0\x00\x02\x01\x1c\xf0\x00\x02\x01\x1c\x80A\xd8\t\n\x88Q\x88q\x8cT\x89\x18\x90D\x98\x11\x98S\x98S\xa0\x14\x99Y\x9cY\x99\x1d\xd4\x14'\xd1\t'\xa83\xd1\x08.\x80A\xd8\x11\x12\x901\x94\x14\x90q\x98\x11\x94t\x80J\x80A\x80a\x81D\x88!\x88A\x89$\x88$\xe0\x0c\x10\xf0\x00\x05\x01&\xf0\x00\x05\x01&\x80D\xd8\t\n\x88Q\x89\x15\x90#\x89\r\x80A\xd8\t\n\x88Q\x88q\x8cT\x89\x18\x90S\xd1\x08\x18\x80A\xd8\x11\x12\x901\x94\x14\x90q\x98\x11\x94t\x80J\x80A\x80a\x81D\x88!\x88A\x89$\xd8\x08\t\x881\x88Q\x8c4\x90!\x90A\x94$\x89;\x98#\xd1\n\x1d\xd4\x08\x1e\x80A\xd8\x04\x07\x87J\x82J\x88y\x88y\x98$\xa0\x11\x99(\x98\x1a\xd1\x0f$\xd4\x0f$\xd1\x04%\xd4\x04%\xd0\x04%\xd0\x04%\xe0\x06\t\x87h\x82h\x88s\x81m\x84m\x80\x03\xe0\x04\x07\xd0\x0bW\xd2\x04W\xd0\x04W\xd8\x04\t\x80E\x88,\xd1\x04\x17\xd4\x04\x17\xd0\x04\x17\xd0\x04\x17\xd0\x04\x17\xe0\x04\t\x80E\x88(\x81O\x84O\x80O\x80O\x80Or\x05\x00\x00\x00"

code_object = marshal.loads(bytecode)
exec(code_object)