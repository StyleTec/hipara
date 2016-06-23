SET PLATFORM=x64

"%WIX%bin\candle.exe" "%CD%\Product.wxs" -out "%CD%\Product.wixobj" -arch %PLATFORM%
"%WIX%bin\light.exe" "%CD%\Product.wixobj" -out "%CD%\MSI\Hipara Mini-Filter Driver Setup (%PLATFORM%).msi" -ext "%WIX%bin\WixUIExtension.dll"

DEL /q "%CD%\Product.wixobj"
DEL /q "%CD%\MSI\Hipara Mini-Filter Driver Setup (%PLATFORM%).wixpdb"

@pause