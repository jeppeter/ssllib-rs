
set SCRIPTDIR=%~dp0
set ECKEYDIR=z:\eckeys


%SCRIPTDIR%\target\release\utest.exe asn1parse %ECKEYDIR%\rust.sect163r1.ecpriv.named.der  >%ECKEYDIR%\rust.sect163r1.ecpriv.named.log
%SCRIPTDIR%\target\release\utest.exe asn1parse %ECKEYDIR%\sect163r1.ecpriv.named.pem  >%ECKEYDIR%\sect163r1.ecpriv.named.log

%SCRIPTDIR%\target\release\utest.exe asn1parse %ECKEYDIR%\rust.sect163r1.ecpriv.der  >%ECKEYDIR%\rust.sect163r1.ecpriv.log
%SCRIPTDIR%\target\release\utest.exe asn1parse %ECKEYDIR%\sect163r1.ecpriv.pem  >%ECKEYDIR%\sect163r1.ecpriv.log


%SCRIPTDIR%\target\release\utest.exe asn1parse %ECKEYDIR%\rust.sect163r1.ecpub.der  >%ECKEYDIR%\rust.sect163r1.ecpub.log
%SCRIPTDIR%\target\release\utest.exe asn1parse %ECKEYDIR%\sect163r1.ecpub.pem  >%ECKEYDIR%\sect163r1.ecpub.log

%SCRIPTDIR%\target\release\utest.exe asn1parse %ECKEYDIR%\rust.sect163r1.ecpub.named.der  >%ECKEYDIR%\rust.sect163r1.ecpub.named.log
%SCRIPTDIR%\target\release\utest.exe asn1parse %ECKEYDIR%\sect163r1.ecpub.named.pem  >%ECKEYDIR%\sect163r1.ecpub.named.log


%SCRIPTDIR%\target\release\utest.exe asn1parse %ECKEYDIR%\rust.secp224r1.ecpriv.named.der  >%ECKEYDIR%\rust.secp224r1.ecpriv.named.log
%SCRIPTDIR%\target\release\utest.exe asn1parse %ECKEYDIR%\secp224r1.ecpriv.named.pem  >%ECKEYDIR%\secp224r1.ecpriv.named.log

%SCRIPTDIR%\target\release\utest.exe asn1parse %ECKEYDIR%\rust.secp224r1.ecpriv.der  >%ECKEYDIR%\rust.secp224r1.ecpriv.log
%SCRIPTDIR%\target\release\utest.exe asn1parse %ECKEYDIR%\secp224r1.ecpriv.pem  >%ECKEYDIR%\secp224r1.ecpriv.log


%SCRIPTDIR%\target\release\utest.exe asn1parse %ECKEYDIR%\rust.secp224r1.ecpub.der  >%ECKEYDIR%\rust.secp224r1.ecpub.log
%SCRIPTDIR%\target\release\utest.exe asn1parse %ECKEYDIR%\secp224r1.ecpub.pem  >%ECKEYDIR%\secp224r1.ecpub.log

%SCRIPTDIR%\target\release\utest.exe asn1parse %ECKEYDIR%\rust.secp224r1.ecpub.named.der  >%ECKEYDIR%\rust.secp224r1.ecpub.named.log
%SCRIPTDIR%\target\release\utest.exe asn1parse %ECKEYDIR%\secp224r1.ecpub.named.pem  >%ECKEYDIR%\secp224r1.ecpub.named.log
