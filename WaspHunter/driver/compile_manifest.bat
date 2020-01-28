call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat"
mc.exe -km manifest.xml
rc.exe manifest.rc
link.exe  /dll /noentry /machine:x64 manifest.res /OUT:ObCallbackETW.dll