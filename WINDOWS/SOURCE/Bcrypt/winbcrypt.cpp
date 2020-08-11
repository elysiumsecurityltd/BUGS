//---------------------------------------------------------------------------
#include <vcl.h>
#pragma hdrstop
USERES("winbcrypt.res");
USEFORM("bcrypt.cpp", Form_Main);
//USEUNIT("func_bcrypt.cpp");
USELIB("bcrypt.lib");
//---------------------------------------------------------------------------
WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int)
{
        try
        {
                 Application->Initialize();
                 Application->Title = "Bcrypt";
                 Application->CreateForm(__classid(TForm_Main), &Form_Main);
                 Application->Run();
        }
        catch (Exception &exception)
        {
                 Application->ShowException(&exception);
        }
        return 0;
}
//---------------------------------------------------------------------------
